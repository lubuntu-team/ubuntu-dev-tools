#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018  Canonical Ltd.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import time
import subprocess
import tempfile
import argparse
import requests
import logging

from ubuntu_archive_assistant.command import AssistantCommand
from ubuntu_archive_assistant.utils import urlhandling, launchpad, bugtools
from ubuntu_archive_assistant.logging import ReviewResult, AssistantTaskLogger


class MIRReview(AssistantCommand):

    def __init__(self, logger):
        super().__init__(command_id='mir',
                         description='Review Main Inclusion Requests',
                         logger=logger,
                         leaf=True)

    def run(self):
        self.parser.add_argument('-b', '--bug', dest='bug',
                                 help='the MIR bug to evaluate')
        self.parser.add_argument('-s', '--source', dest='source',
                                 help='the MIR bug to evaluate')
        self.parser.add_argument('--skip-review', action="store_true",
                                 help='skip dropping to a subshell for code review')
        self.parser.add_argument('--unprocessed', action="store_true",
                                 default=False,
                                 help='show MIRs accepted but not yet processed')

        self.func = self.mir_review

        self.parse_args()
        self.run_command()

    def mir_review(self):
        lp = launchpad.LaunchpadInstance()
        self.mir_team = lp.lp.people["ubuntu-mir"]

        if not self.source and not self.bug:
            self.log.debug("showing MIR report. show unprocessed=%s" % self.unprocessed)
            bugs = self.get_mir_bugs(show_unprocessed=self.unprocessed)
            sys.exit(0)
        else:
            completed_statuses = ("Won't Fix", "Invalid", "Fix Committed", "Fix Released")
            if self.bug:
                self.log.debug("show MIR by bug")
                bug_no = int(self.bug)
                bug = lp.lp.bugs[bug_no]
                for bug_task in bug.bug_tasks:
                    if self.source:
                        if self.source != bug_task.target.name:
                            continue

                    if bug_task.status in completed_statuses:
                        print("MIR for %s is %s\n" % (bug_task.target.name,
                                                      bug_task.status))
                        continue
                    self.process(bug_task.target, bug_task)
            else:
                self.log.debug("show MIR by source")
                source_pkg = self.get_source_package(self.source)
                mir_bug = source_pkg.searchTasks(omit_duplicates=True,
                                                 bug_subscriber=self.mir_team,
                                                 order_by="id")[0]
                self.process(source_pkg, mir_bug)

    def get_source_package(self, binary):
        lp = launchpad.LaunchpadInstance()
        cache_name = None
        name = None

        source_pkg = lp.ubuntu.getSourcePackage(name=binary)
        if source_pkg:
            return source_pkg

        try:
            cache_name = subprocess.check_output(
                "apt-cache show %s | grep Source:" % binary,
                shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            cache_name = subprocess.check_output(
                "apt-cache show %s | grep Package:" % binary,
                shell=True, universal_newlines=True)

        if cache_name is not None:
            if source.startswith("Source:") or source.startswith("Package:"):
                name = source.split()[1]

        if name:
            source_pkg = lp.ubuntu.getSourcePackage(name=name)

        return source_pkg

    def lp_build_logs(self, source):
        lp = launchpad.LaunchpadInstance()
        archive = lp.ubuntu_archive()
        spph = archive.getPublishedSources(exact_match=True,
                                           source_name=source,
                                           distro_series=lp.current_series(),
                                           pocket="Release",
                                           order_by_date=True)

        builds = spph[0].getBuilds()
        for build in builds:
            if "Successfully" not in build.buildstate:
                print("%s has failed to build" % build.arch_tag)
            print(build.build_log_url)

    def process(self, source_pkg, task=None):
        lp = launchpad.LaunchpadInstance()
        source_name = source_pkg.name
        print("== MIR report for source package '%s' ==" % source_name)

        print("\n=== Details ===")
        print("LP: %s" % source_pkg.web_link)

        if task and task.bug:
            print("MIR bug: %s\n" % task.bug.web_link)
            print(task.bug.description)

        print("\n\n=== MIR assessment ===")
        latest = lp.ubuntu_archive().getPublishedSources(exact_match=True,
                                                        source_name=source_name,
                                                        distro_series=lp.current_series())[0]

        if not source_pkg:
            print("\n%s does not exist in Ubuntu")
            sys.exit(1)
        if latest.pocket == "Proposed":
            print("\nThere is a version of %s in -proposed: %s" % (source, latest.source_package_version))

        if task:
            if task.assignee:
                print("MIR for %s is assigned to %s (%s)" % (task.target.display_name,
                                                             task.assignee.display_name,
                                                             task.status))
            else:
                print("MIR for %s is %s" % (task.target.display_name,
                                            task.status))

        print("\nPackage bug subscribers:")
        for sub in source_pkg.getSubscriptions():
            sub_text = "  - %s" % sub.subscriber.display_name
            if sub.subscribed_by:
                sub_text += ", subscribed by %s" % sub.subscribed_by.display_name
            print(sub_text)

        print("\nBuild logs:")
        self.lp_build_logs(source_name)

        if not self.skip_review:
            self.open_source_tmpdir(source_name)

    def get_mir_bugs(self, show_unprocessed=False):
        bug_statuses = ("New", "Incomplete", "Confirmed", "Triaged",
                        "In Progress")

        def only_ubuntu(task):
            if 'ubuntu/+source' not in task.target_link:
                return True
            return False

        if show_unprocessed:
            unprocessed = self.mir_team.searchTasks(omit_duplicates=True, bug_subscriber=self.mir_team, status="Fix Committed")
            if any(unprocessed):
                print("== Open MIRs reviewed but not processed ==")
                bugtools.list_bugs(print, unprocessed, filter=only_ubuntu, file=sys.stderr)

        tasks = self.mir_team.searchTasks(omit_duplicates=True, bug_subscriber=self.mir_team, status=bug_statuses)

        bugtools.list_bugs(print, tasks, filter=only_ubuntu, file=sys.stderr)

        result = None

        return result

    def open_source_tmpdir(self, source_name):
        print("\nDropping to a shell for code review:\n")
        with tempfile.TemporaryDirectory() as temp_dir:
            os.system('cd %s; pull-lp-source %s; bash -l' % (temp_dir, source_name))
