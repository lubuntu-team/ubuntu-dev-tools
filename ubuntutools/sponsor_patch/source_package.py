#
# source_package.py - Internal helper class for sponsor-patch
#
# Copyright (C) 2011, Benjamin Drung <bdrung@ubuntu.com>
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

from __future__ import print_function

import os
import re
import sys

import debian.changelog
import debian.deb822

from ubuntutools import subprocess
from ubuntutools.logger import Logger
from ubuntutools.question import Question, YesNoQuestion

from ubuntutools.sponsor_patch.question import (ask_for_ignoring_or_fixing,
                                                ask_for_manual_fixing,
                                                user_abort)


def _get_series(launchpad):
    """Returns a tuple with the development and list of supported series."""
    ubuntu = launchpad.distributions['ubuntu']
    devel_series = ubuntu.current_series.name
    supported_series = [series.name for series in ubuntu.series
                        if series.active and series.name != devel_series]
    return (devel_series, supported_series)


def strip_epoch(version):
    """Removes the epoch from a Debian version string.

    strip_epoch(1:1.52-1) will return "1.52-1" and strip_epoch(1.1.3-1) will
    return "1.1.3-1".
    """

    parts = version.full_version.split(':')
    if len(parts) > 1:
        del parts[0]
    version_without_epoch = ':'.join(parts)
    return version_without_epoch


class SourcePackage(object):
    """This class represents a source package."""

    def __init__(self, package, builder, workdir, branch):
        self._package = package
        self._builder = builder
        self._workdir = workdir
        self._branch = branch
        self._changelog = None
        self._version = None
        self._build_log = None

    def ack_sync(self, upload, task, launchpad):
        """Acknowledge a sync request and subscribe ubuntu-archive."""

        if upload == "ubuntu":
            self._print_logs()
            question = Question(["yes", "edit", "no"])
            answer = question.ask("Do you want to acknowledge the sync request",
                                  "no")
            if answer == "edit":
                return False
            elif answer == "no":
                user_abort()

            bug = task.bug
            task.status = "Confirmed"
            if task.importance == "Undecided":
                task.importance = "Wishlist"
            task.lp_save()
            Logger.info("Set bug #%i status to Confirmed.", bug.id)

            msg = "Sync request ACK'd."
            if self._build_log:
                msg = ("%s %s builds on %s. " + msg) % \
                      (self._package, self._version,
                       self._builder.get_architecture())
            bug.newMessage(content=msg, subject="sponsor-patch")
            Logger.info("Acknowledged sync request bug #%i.", bug.id)

            bug.subscribe(person=launchpad.people['ubuntu-archive'])
            Logger.info("Subscribed ubuntu-archive to bug #%i.", bug.id)

            bug.subscribe(person=launchpad.me)
            Logger.info("Subscribed me to bug #%i.", bug.id)

            sponsorsteam = launchpad.people['ubuntu-sponsors']
            for sub in bug.subscriptions:
                if sub.person == sponsorsteam and sub.canBeUnsubscribedByUser():
                    bug.unsubscribe(person=launchpad.people['ubuntu-sponsors'])
                    Logger.info("Unsubscribed ubuntu-sponsors from bug #%i.",
                                bug.id)
                elif sub.person == sponsorsteam:
                    Logger.info("Couldn't unsubscribe ubuntu-sponsors from "
                                "bug #%i.", bug.id)

            Logger.normal("Successfully acknowledged sync request bug #%i.",
                          bug.id)
        else:
            Logger.error("Sync requests can only be acknowledged when the "
                         "upload target is Ubuntu.")
            sys.exit(1)
        return True

    def ask_and_upload(self, upload):
        """Ask the user before uploading the source package.

        Returns true if the source package is uploaded successfully. Returns
        false if the user wants to change something.
        """

        # Upload package
        if upload:
            self._print_logs()
            if upload == "ubuntu":
                target = "the official Ubuntu archive"
            else:
                target = upload
            question = Question(["yes", "edit", "no"])
            answer = question.ask("Do you want to upload the package to %s" % target, "no")
            if answer == "edit":
                return False
            elif answer == "no":
                user_abort()
            cmd = ["dput", "--force", upload, self._changes_file]
            Logger.command(cmd)
            if subprocess.call(cmd) != 0:
                Logger.error("Upload of %s to %s failed." %
                             (os.path.basename(self._changes_file), upload))
                sys.exit(1)

            # Push the branch if the package is uploaded to the Ubuntu archive.
            if upload == "ubuntu" and self._branch:
                cmd = ['debcommit']
                Logger.command(cmd)
                if subprocess.call(cmd) != 0:
                    Logger.error('Bzr commit failed.')
                    sys.exit(1)
                cmd = ['bzr', 'mark-uploaded']
                Logger.command(cmd)
                if subprocess.call(cmd) != 0:
                    Logger.error('Bzr tagging failed.')
                    sys.exit(1)
                cmd = ['bzr', 'push', ':parent']
                Logger.command(cmd)
                if subprocess.call(cmd) != 0:
                    Logger.error('Bzr push failed.')
                    sys.exit(1)
        return True

    def build(self, update, dist=None):
        """Tries to build the package.

        Returns true if the package was built successfully. Returns false
        if the user wants to change something.
        """

        if dist is None:
            dist = re.sub("-.*$", "", self._changelog.distributions)
        build_name = "{}_{}_{}.build".format(self._package, strip_epoch(self._version),
                                             self._builder.get_architecture())
        self._build_log = os.path.join(self._buildresult, build_name)

        successful_built = False
        while not successful_built:
            if update:
                ret = self._builder.update(dist)
                if ret != 0:
                    ask_for_manual_fixing()
                    break
                # We want to update the build environment only once, but not
                # after every manual fix.
                update = False

            # build package
            result = self._builder.build(self._dsc_file, dist,
                                         self._buildresult)
            if result != 0:
                question = Question(["yes", "update", "retry", "no"])
                answer = question.ask("Do you want to resolve this issue manually", "yes")
                if answer == "yes":
                    break
                elif answer == "update":
                    update = True
                    continue
                elif answer == "retry":
                    continue
                else:
                    user_abort()
            successful_built = True
        if not successful_built:
            # We want to do a manual fix if the build failed.
            return False
        return True

    @property
    def _buildresult(self):
        """Returns the directory for the build result."""
        return os.path.join(self._workdir, "buildresult")

    def build_source(self, keyid, upload, previous_version):
        """Tries to build the source package.

        Returns true if the source package was built successfully. Returns false
        if the user wants to change something.
        """

        if self._branch:
            cmd = ['bzr', 'builddeb', '--builder=debuild', '-S',
                   '--', '--no-lintian', '-nc']
        else:
            cmd = ['debuild', '--no-lintian', '-nc', '-S']
        cmd.append("-v" + previous_version.full_version)
        if previous_version.upstream_version == \
           self._changelog.upstream_version and upload == "ubuntu":
            # FIXME: Add proper check that catches cases like changed
            # compression (.tar.gz -> tar.bz2) and multiple orig source tarballs
            cmd.append("-sd")
        else:
            cmd.append("-sa")
        if keyid is not None:
            cmd += ["-k" + keyid]
        env = os.environ
        if upload == 'ubuntu':
            env['DEB_VENDOR'] = 'Ubuntu'
        Logger.command(cmd)
        if subprocess.call(cmd, env=env) != 0:
            Logger.error("Failed to build source tarball.")
            # TODO: Add a "retry" option
            ask_for_manual_fixing()
            return False
        return True

    @property
    def _changes_file(self):
        """Returns the file name of the .changes file."""
        return os.path.join(self._workdir, "{}_{}_source.changes"
                            .format(self._package, strip_epoch(self._version)))

    def check_target(self, upload, launchpad):
        """Make sure that the target is correct.

        Returns true if the target is correct. Returns false if the user
        wants to change something.
        """

        (devel_series, supported_series) = _get_series(launchpad)

        if upload == "ubuntu":
            allowed = supported_series + \
                      [s + "-proposed" for s in supported_series] + \
                      [devel_series]
            if self._changelog.distributions not in allowed:
                Logger.error("%s is not an allowed series. It needs to be one of %s." %
                             (self._changelog.distributions, ", ".join(allowed)))
                return ask_for_ignoring_or_fixing()
        elif upload and upload.startswith("ppa/"):
            allowed = supported_series + [devel_series]
            if self._changelog.distributions not in allowed:
                Logger.error("%s is not an allowed series. It needs to be one of %s." %
                             (self._changelog.distributions, ", ".join(allowed)))
                return ask_for_ignoring_or_fixing()
        return True

    def check_version(self, previous_version):
        """Check if the version of the package is greater than the given one.

        Return true if the version of the package is newer. Returns false
        if the user wants to change something.
        """

        if self._version <= previous_version:
            Logger.error("The version %s is not greater than the already "
                         "available %s.", self._version, previous_version)
            return ask_for_ignoring_or_fixing()
        return True

    def check_sync_request_version(self, bug_number, task):
        """Check if the downloaded version of the package is mentioned in the
           bug title."""

        if not task.title_contains(self._version):
            print("Bug #%i title: %s" % (bug_number, task.get_bug_title()))
            msg = "Is %s %s the version that should be synced" % (self._package, self._version)
            answer = YesNoQuestion().ask(msg, "no")
            if answer == "no":
                user_abort()

    @property
    def _debdiff_filename(self):
        """Returns the file name of the .debdiff file."""
        debdiff_name = "{}_{}.debdiff".format(self._package, strip_epoch(self._version))
        return os.path.join(self._workdir, debdiff_name)

    @property
    def _dsc_file(self):
        """Returns the file name of the .dsc file."""
        return os.path.join(self._workdir, "{}_{}.dsc".format(self._package,
                                                              strip_epoch(self._version)))

    def generate_debdiff(self, dsc_file):
        """Generates a debdiff between the given .dsc file and this source
           package."""

        assert os.path.isfile(dsc_file), "%s does not exist." % (dsc_file)
        assert os.path.isfile(self._dsc_file), "%s does not exist." % \
                                               (self._dsc_file)
        cmd = ["debdiff", dsc_file, self._dsc_file]
        if not Logger.verbose:
            cmd.insert(1, "-q")
        Logger.command(cmd + [">", self._debdiff_filename])
        debdiff = subprocess.check_output(cmd, encoding='utf-8')

        # write debdiff file
        debdiff_file = open(self._debdiff_filename, "w")
        debdiff_file.writelines(debdiff)
        debdiff_file.close()

    def is_fixed(self, lp_bug):
        """Make sure that the given Launchpad bug is closed.

        Returns true if the bug is closed. Returns false if the user wants to
        change something.
        """

        assert os.path.isfile(self._changes_file), "%s does not exist." % (self._changes_file)
        changes = debian.deb822.Changes(open(self._changes_file))
        fixed_bugs = []
        if "Launchpad-Bugs-Fixed" in changes:
            fixed_bugs = changes["Launchpad-Bugs-Fixed"].split(" ")
        fixed_bugs = [int(bug) for bug in fixed_bugs]

        # Check if the given bug is marked as duplicate. In this case get the
        # master bug.
        while lp_bug.duplicate_of:
            lp_bug = lp_bug.duplicate_of

        if lp_bug.id not in fixed_bugs:
            Logger.error("Launchpad bug #%i is not closed by new version." % (lp_bug.id))
            return ask_for_ignoring_or_fixing()
        return True

    def _print_logs(self):
        """Print things that should be checked before uploading a package."""

        lintian_filename = self._run_lintian()
        print("\nPlease check %s %s carefully:" % (self._package, self._version))
        if os.path.isfile(self._debdiff_filename):
            print("file://" + self._debdiff_filename)
        print("file://" + lintian_filename)
        if self._build_log:
            print("file://" + self._build_log)

    def reload_changelog(self):
        """Reloads debian/changelog and updates the version.

        Returns true if the changelog was reloaded successfully. Returns false
        if the user wants to correct a broken changelog.
        """

        # Check the changelog
        self._changelog = debian.changelog.Changelog()
        try:
            self._changelog.parse_changelog(open("debian/changelog"),
                                            max_blocks=1, strict=True)
        except debian.changelog.ChangelogParseError as error:
            Logger.error("The changelog entry doesn't validate: %s", str(error))
            ask_for_manual_fixing()
            return False

        # Get new version of package
        try:
            self._version = self._changelog.get_version()
        except IndexError:
            Logger.error("Debian package version could not be determined. "
                         "debian/changelog is probably malformed.")
            ask_for_manual_fixing()
            return False

        return True

    def _run_lintian(self):
        """Runs lintian on either the source or binary changes file.

        Returns the filename of the created lintian output file.
        """

        # Determine whether to use the source or binary build for lintian
        if self._build_log:
            build_changes = self._package + "_" + strip_epoch(self._version) + \
                           "_" + self._builder.get_architecture() + ".changes"
            changes_for_lintian = os.path.join(self._buildresult, build_changes)
        else:
            changes_for_lintian = self._changes_file

        # Check lintian
        assert os.path.isfile(changes_for_lintian), "%s does not exist." % \
                                                    (changes_for_lintian)
        cmd = ["lintian", "-IE", "--pedantic", "-q", "--profile", "ubuntu",
               changes_for_lintian]
        lintian_filename = os.path.join(self._workdir,
                                        self._package + "_" +
                                        strip_epoch(self._version) + ".lintian")
        Logger.command(cmd + [">", lintian_filename])
        report = subprocess.check_output(cmd, encoding='utf-8')

        # write lintian report file
        lintian_file = open(lintian_filename, "w")
        lintian_file.writelines(report)
        lintian_file.close()

        return lintian_filename

    def sync(self, upload, series, bug_number, requester):
        """Does a sync of the source package."""

        if upload == "ubuntu":
            cmd = ["syncpackage", self._package, "-b", str(bug_number), "-f",
                   "-s", requester, "-V", str(self._version),
                   "-d", series]
            Logger.command(cmd)
            if subprocess.call(cmd) != 0:
                Logger.error("Syncing of %s %s failed.", self._package,
                             str(self._version))
                sys.exit(1)
        else:
            # FIXME: Support this use case!
            Logger.error("Uploading a synced package other than to Ubuntu "
                         "is not supported yet!")
            sys.exit(1)
        return True
