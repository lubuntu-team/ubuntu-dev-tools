# -*- coding: utf-8 -*-
#
#   lp.py - methods used by requestsync while interacting
#           directly with Launchpad
#
#   Copyright © 2009 Michael Bienia <geser@ubuntu.com>
#
#   This module may contain code written by other authors/contributors to
#   the main requestsync script. See there for their names.
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; version 2
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   Please see the /usr/share/common-licenses/GPL-2 file for the full text
#   of the GNU General Public License license.

import logging
import re

from debian.deb822 import Changes
from distro_info import DebianDistroInfo, DistroDataOutdated
from httplib2 import Http, HttpLib2Error

from ubuntutools.lp import udtexceptions
from ubuntutools.lp.lpapicache import (
    Distribution,
    DistributionSourcePackage,
    Launchpad,
    PersonTeam,
)
from ubuntutools.question import confirmation_prompt

Logger = logging.getLogger(__name__)


def get_debian_srcpkg(name, release):
    debian = Distribution("debian")
    debian_archive = debian.getArchive()

    try:
        release = DebianDistroInfo().codename(release, None, release)
    except DistroDataOutdated as e:
        Logger.warning(e)

    return debian_archive.getSourcePackage(name, release)


def get_ubuntu_srcpkg(name, release, pocket="Release"):
    ubuntu = Distribution("ubuntu")
    ubuntu_archive = ubuntu.getArchive()

    try:
        return ubuntu_archive.getSourcePackage(name, release, pocket)
    except udtexceptions.PackageNotFoundException:
        if pocket != "Release":
            parent_pocket = "Release"
            if pocket == "Updates":
                parent_pocket = "Proposed"
            return get_ubuntu_srcpkg(name, release, parent_pocket)
        raise


def need_sponsorship(name, component, release):
    """
    Check if the user has upload permissions for either the package
    itself or the component
    """
    archive = Distribution("ubuntu").getArchive()
    distroseries = Distribution("ubuntu").getSeries(release)

    need_sponsor = not PersonTeam.me.canUploadPackage(archive, distroseries, name, component)
    if need_sponsor:
        print(
            """You are not able to upload this package directly to Ubuntu.
Your sync request shall require an approval by a member of the appropriate
sponsorship team, who shall be subscribed to this bug report.
This must be done before it can be processed by a member of the Ubuntu Archive
team."""
        )
        confirmation_prompt()

    return need_sponsor


def check_existing_reports(srcpkg):
    """
    Check existing bug reports on Launchpad for a possible sync request.

    If found ask for confirmation on filing a request.
    """

    # Fetch the package's bug list from Launchpad
    pkg = Distribution("ubuntu").getSourcePackage(name=srcpkg)
    pkg_bug_list = pkg.searchTasks(
        status=["Incomplete", "New", "Confirmed", "Triaged", "In Progress", "Fix Committed"],
        omit_duplicates=True,
    )

    # Search bug list for other sync requests.
    for bug in pkg_bug_list:
        # check for Sync or sync and the package name
        if not bug.is_complete and f"ync {srcpkg}" in bug.title:
            print(
                f"The following bug could be a possible duplicate sync bug on Launchpad:\n"
                f" * {bug.title} ({bug.web_link})\n"
                f"Please check the above URL to verify this before continuing."
            )
            confirmation_prompt()


def get_ubuntu_delta_changelog(srcpkg):
    """
    Download the Ubuntu changelog and extract the entries since the last sync
    from Debian.
    """
    archive = Distribution("ubuntu").getArchive()
    spph = archive.getPublishedSources(
        source_name=srcpkg.getPackageName(), exact_match=True, pocket="Release"
    )
    debian_info = DebianDistroInfo()
    name_chars = "[-+0-9a-z.]"
    topline = re.compile(
        rf"^(\w%({name_chars})s*) \(([^\(\) \t]+)\)((\s+%({name_chars})s+)+)\;", re.IGNORECASE
    )
    delta = []
    for record in spph:
        changes_url = record.changesFileUrl()
        if changes_url is None:
            # Native sync
            break
        try:
            response = Http().request(changes_url)[0]
        except HttpLib2Error as e:
            Logger.error(str(e))
            break
        if response.status != 200:
            Logger.error("%s: %s %s", changes_url, response.status, response.reason)
            break

        changes = Changes(Http().request(changes_url)[1])
        for line in changes["Changes"].splitlines():
            line = line[1:]
            match = topline.match(line)
            if match:
                distribution = match.group(3).split()[0].split("-")[0]
                if debian_info.valid(distribution):
                    break
            if line.startswith("  "):
                delta.append(line)
        else:
            continue
        break

    return "\n".join(delta)


def post_bug(srcpkg, subscribe, status, bugtitle, bugtext):
    """
    Use the LP API to file the sync request.
    """

    print(f"The final report is:\nSummary: {bugtitle}\nDescription:\n{bugtext}\n")
    confirmation_prompt()

    if srcpkg:
        # pylint: disable=protected-access
        bug_target = DistributionSourcePackage(f"{Launchpad._root_uri}ubuntu/+source/{srcpkg}")
    else:
        # new source package
        bug_target = Distribution("ubuntu")

    # create bug
    bug = Launchpad.bugs.createBug(title=bugtitle, description=bugtext, target=bug_target())

    # newly created bugreports have only one task
    task = bug.bug_tasks[0]
    # only members of ubuntu-bugcontrol can set importance
    if PersonTeam.me.isLpTeamMember("ubuntu-bugcontrol"):
        task.importance = "Wishlist"
    task.status = status
    task.lp_save()

    bug.subscribe(person=PersonTeam(subscribe)())

    print(f"Sync request filed as bug #{bug.id}: {bug.web_link}")
