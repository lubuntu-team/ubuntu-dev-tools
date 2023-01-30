# example_package.py - Creates an example package
#
# Copyright (C) 2010-2011, Stefano Rivera <stefanor@ubuntu.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import os
import subprocess
import tempfile

from pathlib import Path
from ubuntutools.version import Version


class ExamplePackage(object):
    def __init__(self, source="example", version="1.0-1", destdir="test-data"):
        self.source = source
        self.version = Version(version)
        self.destdir = Path(destdir)

        self.env = dict(os.environ)
        self.env["DEBFULLNAME"] = "Example"
        self.env["DEBEMAIL"] = "example@example.net"

    @property
    def orig(self):
        return self.destdir / f"{self.source}_{self.version.upstream_version}.orig.tar.xz"

    @property
    def debian(self):
        return self.destdir / f"{self.source}_{self.version}.debian.tar.xz"

    @property
    def dsc(self):
        return self.destdir / f"{self.source}_{self.version}.dsc"

    @property
    def dirname(self):
        return f"{self.source}-{self.version.upstream_version}"

    @property
    def content_filename(self):
        return "content"

    @property
    def content_text(self):
        return "my content"

    def create(self):
        with tempfile.TemporaryDirectory() as d:
            self._create(Path(d))

    def _create(self, d):
        pkgdir = d / self.dirname
        pkgdir.mkdir()
        (pkgdir / self.content_filename).write_text(self.content_text)

        # run dh_make to create orig tarball
        subprocess.run(
            "dh_make -sy --createorig".split(),
            check=True,
            env=self.env,
            cwd=str(pkgdir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # run dpkg-source -b to create debian tar and dsc
        subprocess.run(
            f"dpkg-source -b {self.dirname}".split(),
            check=True,
            env=self.env,
            cwd=str(d),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # move tarballs and dsc to destdir
        self.destdir.mkdir(parents=True, exist_ok=True)
        (d / self.orig.name).rename(self.orig)
        (d / self.debian.name).rename(self.debian)
        (d / self.dsc.name).rename(self.dsc)
