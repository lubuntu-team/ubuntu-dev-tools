# test_archive.py - Test suite for ubuntutools.archive
#
# Copyright (C) 2010-2012, Stefano Rivera <stefanor@ubuntu.com>
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


import filecmp
import tempfile
import unittest

import ubuntutools.archive

from pathlib import Path

from ubuntutools.test.example_package import ExamplePackage


class BaseVerificationTestCase(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.pkg = ExamplePackage(destdir=Path(d.name))
        self.pkg.create()
        self.dsc = ubuntutools.archive.Dsc(self.pkg.dsc.read_bytes())


class DscVerificationTestCase(BaseVerificationTestCase):
    def test_good(self):
        self.assertTrue(self.dsc.verify_file(self.pkg.orig))
        self.assertTrue(self.dsc.verify_file(self.pkg.debian))

    def test_missing(self):
        self.assertFalse(self.dsc.verify_file(self.pkg.destdir / 'does.not.exist'))

    def test_bad(self):
        data = self.pkg.orig.read_bytes()
        last_byte = chr(data[-1] ^ 8).encode()
        data = data[:-1] + last_byte
        self.pkg.orig.write_bytes(data)
        self.assertFalse(self.dsc.verify_file(self.pkg.orig))

    def test_sha1(self):
        del self.dsc['Checksums-Sha256']
        self.test_good()
        self.test_bad()

    def test_md5(self):
        del self.dsc['Checksums-Sha256']
        del self.dsc['Checksums-Sha1']
        self.test_good()
        self.test_bad()


class LocalSourcePackageTestCase(BaseVerificationTestCase):
    SourcePackage = ubuntutools.archive.UbuntuSourcePackage

    def setUp(self):
        super().setUp()
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.workdir = Path(d.name)

    def pull(self, **kwargs):
        ''' Do the pull from pkg dir to the workdir, return the SourcePackage '''
        srcpkg = self.SourcePackage(dscfile=self.pkg.dsc, workdir=self.workdir, **kwargs)
        srcpkg.pull()
        return srcpkg

    def test_pull(self, **kwargs):
        srcpkg = self.pull(**kwargs)
        self.assertTrue(filecmp.cmp(self.pkg.dsc, self.workdir / self.pkg.dsc.name))
        self.assertTrue(filecmp.cmp(self.pkg.orig, self.workdir / self.pkg.orig.name))
        self.assertTrue(filecmp.cmp(self.pkg.debian, self.workdir / self.pkg.debian.name))
        return srcpkg

    def test_unpack(self, **kwargs):
        srcpkg = kwargs.get('srcpkg', self.pull(**kwargs))
        srcpkg.unpack()
        content = self.workdir / self.pkg.dirname / self.pkg.content_filename
        self.assertEqual(self.pkg.content_text, content.read_text())
        debian = self.workdir / self.pkg.dirname / 'debian'
        self.assertTrue(debian.exists())
        self.assertTrue(debian.is_dir())

    def test_pull_and_unpack(self, **kwargs):
        self.test_unpack(srcpkg=self.test_pull(**kwargs))

    def test_with_package(self):
        self.test_pull_and_unpack(package=self.pkg.source)

    def test_with_package_version(self):
        self.test_pull_and_unpack(package=self.pkg.source, version=self.pkg.version)

    def test_with_package_version_component(self):
        self.test_pull_and_unpack(package=self.pkg.source,
                                  version=self.pkg.version,
                                  componet='main')

    def test_verification(self):
        corruption = b'CORRUPTION'

        self.pull()

        testfile = self.workdir / self.pkg.debian.name
        self.assertTrue(testfile.exists())
        self.assertTrue(testfile.is_file())
        self.assertNotEqual(testfile.read_bytes(), corruption)
        testfile.write_bytes(corruption)
        self.assertEqual(testfile.read_bytes(), corruption)

        self.test_pull()
        self.assertTrue(testfile.exists())
        self.assertTrue(testfile.is_file())
        self.assertNotEqual(testfile.read_bytes(), corruption)
