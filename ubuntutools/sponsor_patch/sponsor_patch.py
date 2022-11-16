#
# main.py - main function for sponsor-patch script
#
# Copyright (C) 2010, Benjamin Drung <bdrung@ubuntu.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import os
import pwd
import shutil
import subprocess
import sys

from distro_info import UbuntuDistroInfo

from launchpadlib.launchpad import Launchpad

from ubuntutools.update_maintainer import (update_maintainer,
                                           MaintainerUpdateException)
from ubuntutools.question import input_number

from ubuntutools.sponsor_patch.bugtask import BugTask, is_sync
from ubuntutools.sponsor_patch.patch import Patch
from ubuntutools.sponsor_patch.question import ask_for_manual_fixing
from ubuntutools.sponsor_patch.source_package import SourcePackage

import logging
Logger = logging.getLogger(__name__)


def is_command_available(command, check_sbin=False):
    "Is command in $PATH?"
    path = os.environ.get('PATH', '/usr/bin:/bin').split(':')
    if check_sbin:
        path += [directory[:-3] + 'sbin'
                 for directory in path if directory.endswith('/bin')]
    return any(os.access(os.path.join(directory, command), os.X_OK)
               for directory in path)


def check_dependencies():
    "Do we have all the commands we need for full functionality?"
    missing = []
    for cmd in ('patch', 'bzr', 'quilt', 'dput', 'lintian'):
        if not is_command_available(cmd):
            missing.append(cmd)
    if not is_command_available('bzr-buildpackage'):
        missing.append('bzr-builddeb')
    if not any(is_command_available(cmd, check_sbin=True)
               for cmd in ('pbuilder', 'sbuild', 'cowbuilder')):
        missing.append('pbuilder/cowbuilder/sbuild')

    if missing:
        Logger.warning("sponsor-patch requires %s to be installed for full "
                       "functionality", ', '.join(missing))


def get_source_package_name(bug_task):
    package = None
    if bug_task.bug_target_name != "ubuntu":
        assert bug_task.bug_target_name.endswith("(Ubuntu)")
        package = bug_task.bug_target_name.split(" ")[0]
    return package


def get_user_shell():
    try:
        shell = os.environ["SHELL"]
    except KeyError:
        shell = pwd.getpwuid(os.getuid())[6]
    return shell


def edit_source():
    # Spawn shell to allow modifications
    cmd = [get_user_shell()]
    Logger.debug(' '.join(cmd))
    print("""An interactive shell was launched in
file://%s
Edit your files. When you are done, exit the shell. If you wish to abort the
process, exit the shell such that it returns an exit code other than zero.
""" % (os.getcwd()), end=' ')
    returncode = subprocess.call(cmd)
    if returncode != 0:
        Logger.error("Shell exited with exit value %i." % (returncode))
        sys.exit(1)


def ask_for_patch_or_branch(bug, attached_patches, linked_branches):
    patch = None
    branch = None
    if len(attached_patches) == 0:
        msg = "https://launchpad.net/bugs/%i has %i branches linked:" % \
              (bug.id, len(linked_branches))
    elif len(linked_branches) == 0:
        msg = "https://launchpad.net/bugs/%i has %i patches attached:" % \
              (bug.id, len(attached_patches))
    else:
        branches = "%i branch" % len(linked_branches)
        if len(linked_branches) > 1:
            branches += "es"
        patches = "%i patch" % len(attached_patches)
        if len(attached_patches) > 1:
            patches += "es"
        msg = "https://launchpad.net/bugs/%i has %s linked and %s attached:" % \
              (bug.id, branches, patches)
    Logger.info(msg)
    i = 0
    for linked_branch in linked_branches:
        i += 1
        print("%i) %s" % (i, linked_branch.display_name))
    for attached_patch in attached_patches:
        i += 1
        print("%i) %s" % (i, attached_patch.title))
    selected = input_number("Which branch or patch do you want to download",
                            1, i, i)
    if selected <= len(linked_branches):
        branch = linked_branches[selected - 1].bzr_identity
    else:
        patch = Patch(attached_patches[selected - len(linked_branches) - 1])
    return (patch, branch)


def get_patch_or_branch(bug):
    patch = None
    branch = None
    if not is_sync(bug):
        attached_patches = [a for a in bug.attachments if a.type == "Patch"]
        linked_branches = [b.branch for b in bug.linked_branches]
        if len(attached_patches) == 0 and len(linked_branches) == 0:
            if len(bug.attachments) == 0:
                Logger.error("No attachment and no linked branch found on "
                             "bug #%i. Add the tag sync to the bug if it is "
                             "a sync request.", bug.id)
            else:
                Logger.error("No attached patch and no linked branch found. "
                             "Go to https://launchpad.net/bugs/%i and mark an "
                             "attachment as patch.", bug.id)
            sys.exit(1)
        elif len(attached_patches) == 1 and len(linked_branches) == 0:
            patch = Patch(attached_patches[0])
        elif len(attached_patches) == 0 and len(linked_branches) == 1:
            branch = linked_branches[0].bzr_identity
        else:
            patch, branch = ask_for_patch_or_branch(bug, attached_patches,
                                                    linked_branches)
    return (patch, branch)


def download_branch(branch):
    dir_name = os.path.basename(branch)
    if os.path.isdir(dir_name):
        shutil.rmtree(dir_name)
    cmd = ["bzr", "branch", branch]
    Logger.debug(' '.join(cmd))
    if subprocess.call(cmd) != 0:
        Logger.error("Failed to download branch %s." % (branch))
        sys.exit(1)
    return dir_name


def merge_branch(branch):
    edit = False
    cmd = ["bzr", "merge", branch]
    Logger.debug(' '.join(cmd))
    if subprocess.call(cmd) != 0:
        Logger.error("Failed to merge branch %s." % (branch))
        ask_for_manual_fixing()
        edit = True
    return edit


def extract_source(dsc_file, verbose=False):
    cmd = ["dpkg-source", "--skip-patches", "-x", dsc_file]
    if not verbose:
        cmd.insert(1, "-q")
    Logger.debug(' '.join(cmd))
    if subprocess.call(cmd) != 0:
        Logger.error("Extraction of %s failed." % (os.path.basename(dsc_file)))
        sys.exit(1)


def get_open_ubuntu_bug_task(launchpad, bug, branch=None):
    """Returns an open Ubuntu bug task for a given Launchpad bug.

    The bug task needs to be open (not complete) and target Ubuntu. The user
    will be ask to select one if multiple open Ubuntu bug task exits for the
    bug.
    """
    bug_tasks = [BugTask(x, launchpad) for x in bug.bug_tasks]
    ubuntu_tasks = [x for x in bug_tasks if x.is_ubuntu_task()]
    bug_id = bug.id
    if branch:
        branch = branch.split('/')
        # Non-production LP?
        if len(branch) > 5:
            branch = branch[3:]

    if len(ubuntu_tasks) == 0:
        Logger.error("No Ubuntu bug task found on bug #%i." % (bug_id))
        sys.exit(1)
    elif len(ubuntu_tasks) == 1:
        task = ubuntu_tasks[0]
    if len(ubuntu_tasks) > 1 and branch and branch[1] == 'ubuntu':
        tasks = [t for t in ubuntu_tasks if
                 t.get_series() == branch[2] and t.package == branch[3]]
        if len(tasks) > 1:
            # A bug targeted to the development series?
            tasks = [t for t in tasks if t.series is not None]
        assert len(tasks) == 1
        task = tasks[0]
    elif len(ubuntu_tasks) > 1:
        task_list = [t.get_short_info() for t in ubuntu_tasks]
        Logger.debug("%i Ubuntu tasks exist for bug #%i.\n%s", len(ubuntu_tasks),
                     bug_id, "\n".join(task_list))
        open_ubuntu_tasks = [x for x in ubuntu_tasks if not x.is_complete()]
        if len(open_ubuntu_tasks) == 1:
            task = open_ubuntu_tasks[0]
        else:
            Logger.info("https://launchpad.net/bugs/%i has %i Ubuntu tasks:" %
                        (bug_id, len(ubuntu_tasks)))
            for i in range(len(ubuntu_tasks)):
                print("%i) %s" % (i + 1,
                                  ubuntu_tasks[i].get_package_and_series()))
            selected = input_number("To which Ubuntu task does the patch belong",
                                    1, len(ubuntu_tasks))
            task = ubuntu_tasks[selected - 1]
    Logger.debug("Selected Ubuntu task: %s" % (task.get_short_info()))
    return task


def _create_and_change_into(workdir):
    """Create (if it does not exits) and change into given working directory."""

    if not os.path.isdir(workdir):
        try:
            os.makedirs(workdir)
        except os.error as error:
            Logger.error("Failed to create the working directory %s [Errno %i]: %s." %
                         (workdir, error.errno, error.strerror))
            sys.exit(1)
    if workdir != os.getcwd():
        Logger.debug("cd " + workdir)
        os.chdir(workdir)


def _update_maintainer_field():
    """Update the Maintainer field in debian/control."""
    Logger.debug("update-maintainer")
    try:
        update_maintainer("debian", Logger.isEnabledFor(logging.DEBUG))
    except MaintainerUpdateException as e:
        Logger.error("update-maintainer failed: %s", str(e))
        sys.exit(1)


def _update_timestamp():
    """Run dch to update the timestamp of debian/changelog."""
    cmd = ["dch", "--maintmaint", "--release", ""]
    Logger.debug(' '.join(cmd))
    if subprocess.call(cmd) != 0:
        Logger.debug("Failed to update timestamp in debian/changelog.")


def _download_and_change_into(task, dsc_file, patch, branch):
    """Downloads the patch and branch and changes into the source directory."""

    if branch:
        branch_dir = download_branch(task.get_branch_link())

        # change directory
        Logger.debug("cd " + branch_dir)
        os.chdir(branch_dir)
    else:
        if patch:
            patch.download()

        Logger.debug("Ubuntu package: %s" % (task.package))
        if task.is_merge():
            Logger.debug("The task is a merge request.")
        if task.is_sync():
            Logger.debug("The task is a sync request.")

        extract_source(dsc_file, Logger.isEnabledFor(logging.DEBUG))

        # change directory
        directory = task.package + '-' + task.get_version().upstream_version
        Logger.debug("cd " + directory)
        os.chdir(directory)


def sponsor_patch(bug_number, build, builder, edit, keyid, lpinstance, update,
                  upload, workdir):
    workdir = os.path.realpath(os.path.expanduser(workdir))
    _create_and_change_into(workdir)

    launchpad = Launchpad.login_with("sponsor-patch", lpinstance)
    bug = launchpad.bugs[bug_number]

    (patch, branch) = get_patch_or_branch(bug)
    task = get_open_ubuntu_bug_task(launchpad, bug, branch)

    dsc_file = task.download_source()

    _download_and_change_into(task, dsc_file, patch, branch)

    source_package = SourcePackage(task.package, builder, workdir, branch)

    if is_sync(bug) and not edit:
        successful = source_package.reload_changelog()

        if successful:
            source_package.check_sync_request_version(bug_number, task)
            previous_version = task.get_previous_version()
            successful = source_package.check_version(previous_version)

        if successful:
            if build:
                dist = UbuntuDistroInfo().devel()
                successful = source_package.build(update, dist)
                update = False
            else:
                # We are going to run lintian, so we need a source package
                successful = source_package.build_source(None, upload,
                                                         previous_version)

        if successful:
            series = task.get_debian_source_series()
            if source_package.sync(upload, series, bug_number, bug.owner.name):
                return
            else:
                edit = True
        else:
            edit = True

    if patch:
        edit |= patch.apply(task)
    elif branch:
        edit |= merge_branch(branch)

    while True:
        if edit:
            edit_source()
        # All following loop executions require manual editing.
        edit = True

        _update_maintainer_field()
        if not source_package.reload_changelog():
            continue

        if not source_package.check_version(task.get_version()):
            continue

        _update_timestamp()

        if not source_package.build_source(keyid, upload,
                                           task.get_previous_version()):
            continue

        source_package.generate_debdiff(dsc_file)

        # Make sure that the Launchpad bug will be closed
        if not source_package.is_fixed(bug):
            continue

        if not source_package.check_target(upload, launchpad):
            continue

        if build:
            successful_built = source_package.build(update)
            update = False
            if not successful_built:
                continue

        if not source_package.ask_and_upload(upload):
            continue

        # Leave while loop if everything worked
        break
