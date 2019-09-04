#
# patch.py - Internal helper class for sponsor-patch
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

import os
import re

from ubuntutools import subprocess
from ubuntutools.logger import Logger
from ubuntutools.sponsor_patch.question import ask_for_manual_fixing
from functools import reduce


class Patch(object):
    """This object represents a patch that can be downloaded from Launchpad."""

    def __init__(self, patch):
        self._patch = patch
        self._patch_file = re.sub(" |/", "_", patch.title)
        if not reduce(lambda r, x: r or self._patch.title.endswith(x),
                      (".debdiff", ".diff", ".patch"), False):
            Logger.info("Patch %s does not have a proper file extension." %
                        (self._patch.title))
            self._patch_file += ".patch"
        self._full_path = os.path.realpath(self._patch_file)
        self._changed_files = None

    def apply(self, task):
        """Applies the patch in the current directory."""
        assert self._changed_files is not None, "You forgot to download the patch."
        edit = False
        if self.is_debdiff():
            cmd = ["patch", "--merge", "--force", "-p",
                   str(self.get_strip_level()), "-i", self._full_path]
            Logger.command(cmd)
            if subprocess.call(cmd) != 0:
                Logger.error("Failed to apply debdiff %s to %s %s.",
                             self._patch_file, task.package, task.get_version())
                if not edit:
                    ask_for_manual_fixing()
                    edit = True
        else:
            cmd = ["add-patch", self._full_path]
            Logger.command(cmd)
            if subprocess.call(cmd) != 0:
                Logger.error("Failed to apply diff %s to %s %s.",
                             self._patch_file, task.package, task.get_version())
                if not edit:
                    ask_for_manual_fixing()
                    edit = True
        return edit

    def download(self):
        """Downloads the patch from Launchpad."""
        Logger.info("Downloading %s." % (self._patch_file))
        patch_f = open(self._patch_file, "w")
        patch_f.write(self._patch.data.open().read())
        patch_f.close()

        cmd = ["diffstat", "-l", "-p0", self._full_path]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, encoding='utf-8')
        changed_files = process.communicate()[0]
        self._changed_files = [f for f in changed_files.split("\n") if f != ""]

    def get_strip_level(self):
        """Returns the stript level for the patch."""
        assert self._changed_files is not None, "You forgot to download the patch."
        strip_level = None
        if self.is_debdiff():
            changelog = [f for f in self._changed_files
                         if f.endswith("debian/changelog")][0]
            strip_level = len(changelog.split(os.sep)) - 2
        return strip_level

    def is_debdiff(self):
        """Checks if the patch is a debdiff (= modifies debian/changelog)."""
        assert self._changed_files is not None, "You forgot to download the patch."
        return len([f for f in self._changed_files
                    if f.endswith("debian/changelog")]) > 0
