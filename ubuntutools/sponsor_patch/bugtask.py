#
# bugtask.py - Internal helper class for sponsor-patch
#
# Copyright (C) 2010-2011, Benjamin Drung <bdrung@ubuntu.com>
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

import logging
import os
import re
from urllib.parse import unquote
from urllib.request import urlretrieve

import distro_info
import httplib2

from ubuntutools.version import Version

Logger = logging.getLogger(__name__)


def is_sync(bug):
    """Checks if a Launchpad bug is a sync request.

    Either the title contains the word sync or the bug contains the tag sync."""

    return "sync" in bug.title.lower().split(" ") or "sync" in bug.tags


class BugTask(object):
    def __init__(self, bug_task, launchpad):
        self.bug_task = bug_task
        self.launchpad = launchpad

        components = re.split(r" \(| ", self.bug_task.bug_target_name.strip(")"))
        assert len(components) >= 1 and len(components) <= 3
        if len(components) == 1:
            self.package = None
            self.project = components[0]
            self.series = None
        elif len(components) == 2:
            self.package = components[0]
            self.project = components[1].lower()
            self.series = None
        elif len(components) == 3:
            self.package = components[0]
            self.project = components[1].lower()
            self.series = components[2].lower()

        if self.package is None:
            title_re = r"^Sync ([a-z0-9+.-]+) [a-z0-9.+:~-]+ \([a-z]+\) from.*"
            match = re.match(title_re, self.get_bug_title(), re.U | re.I)
            if match is not None:
                self.package = match.group(1)

    def download_source(self):
        source_files = self.get_source().sourceFileUrls()
        dsc_file = ""
        for url in source_files:
            filename = unquote(os.path.basename(url))
            Logger.debug("Downloading %s...", filename)
            # HttpLib2 isn't suitable for large files (it reads into memory),
            # but we want its https certificate validation on the .dsc
            if url.endswith(".dsc"):
                response, data = httplib2.Http().request(url)
                assert response.status == 200
                with open(filename, "wb") as f:
                    f.write(data)

                dsc_file = os.path.join(os.getcwd(), filename)
            else:
                urlretrieve(url, filename)
        assert os.path.isfile(dsc_file), "%s does not exist." % (dsc_file)
        return dsc_file

    def get_branch_link(self):
        return "lp:" + self.project + "/" + self.get_series() + "/" + self.package

    def get_bug_title(self):
        """Returns the title of the related bug."""
        return self.bug_task.bug.title

    def get_long_info(self):
        return (
            "Bug task: "
            + str(self.bug_task)
            + "\n"
            + "Package: "
            + str(self.package)
            + "\n"
            + "Project: "
            + str(self.project)
            + "\n"
            + "Series: "
            + str(self.series)
        )

    def get_lp_task(self):
        """Returns the Launchpad bug task object."""
        return self.bug_task

    def get_package_and_series(self):
        result = self.package
        if self.series:
            result += " (" + self.series + ")"
        return result

    def get_previous_version(self):
        if self.is_derived_from_debian():
            previous_version = self.get_latest_released_version()
        else:
            previous_version = self.get_version()
        return previous_version

    def get_series(self, latest_release=False):
        if self.series is None or latest_release:
            dist = self.launchpad.distributions[self.project]
            return dist.current_series.name
        else:
            return self.series

    def get_short_info(self):
        return self.bug_task.bug_target_name + ": " + self.bug_task.status

    def get_source(self, latest_release=False):
        assert self.package is not None

        if self.is_derived_from_debian() and not latest_release:
            project = "debian"
            series = self.get_debian_source_series()
        else:
            project = self.project
            series = self.get_series(latest_release)

        dist = self.launchpad.distributions[project]
        archive = dist.getArchive(name="primary")
        distro_series = dist.getSeries(name_or_version=series)
        published = archive.getPublishedSources(
            source_name=self.package,
            distro_series=distro_series,
            status="Published",
            exact_match=True,
        )

        latest_source = None
        for source in published:
            if source.pocket in ("Release", "Security", "Updates", "Proposed"):
                latest_source = source
                break
        return latest_source

    def get_version(self):
        source_package_version = self.get_source().source_package_version
        return Version(source_package_version)

    def get_latest_released_version(self):
        source = self.get_source(True)
        if source is None:  # Not currently published in Ubuntu
            version = "~"
        else:
            version = source.source_package_version
        return Version(version)

    def get_debian_source_series(self):
        title = self.bug_task.bug.title.lower().split()
        if "experimental" in title:
            series = "experimental"
        elif "testing" in title:
            series = distro_info.DebianDistroInfo().testing()
        else:
            series = distro_info.DebianDistroInfo().devel()
        return series

    def is_complete(self):
        return self.bug_task.is_complete

    def is_derived_from_debian(self):
        """Checks if this task get's the source from Debian."""
        return self.is_merge() or self.is_sync()

    def is_merge(self):
        bug = self.bug_task.bug
        return "merge" in bug.title.lower().split(" ") or "merge" in bug.tags

    def is_sync(self):
        return is_sync(self.bug_task.bug)

    def is_ubuntu_task(self):
        return self.project == "ubuntu"

    def title_contains(self, word):
        """Checks if the bug title contains the given word."""
        return word in self.bug_task.bug.title.split(" ")
