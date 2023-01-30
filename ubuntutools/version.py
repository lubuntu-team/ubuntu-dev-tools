# Copyright (C) 2014, Benjamin Drung <bdrung@ubuntu.com>
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

import debian.debian_support


class Version(debian.debian_support.Version):
    def strip_epoch(self):
        """Removes the epoch from a Debian version string.

        strip_epoch(1:1.52-1) will return "1.52-1" and strip_epoch(1.1.3-1)
        will return "1.1.3-1".
        """
        parts = self.full_version.split(":")
        if len(parts) > 1:
            del parts[0]
        version_without_epoch = ":".join(parts)
        return version_without_epoch

    def get_related_debian_version(self):
        """Strip the ubuntu-specific bits off the version"""
        related_debian_version = self.full_version
        uidx = related_debian_version.find("ubuntu")
        if uidx > 0:
            related_debian_version = related_debian_version[:uidx]
        uidx = related_debian_version.find("build")
        if uidx > 0:
            related_debian_version = related_debian_version[:uidx]
        return Version(related_debian_version)

    def is_modified_in_ubuntu(self):
        """Did Ubuntu modify this (and mark the version appropriately)?"""
        return "ubuntu" in self.full_version
