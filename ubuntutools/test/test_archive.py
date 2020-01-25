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


import mock
import os.path
import shutil
import tempfile
from io import BytesIO

import ubuntutools.archive
from ubuntutools.test import unittest

from ubuntutools.test.example_package import ExamplePackage


def setUpModule():
    if not os.path.exists('test-data/example-0.1-1.dsc'):
        ex_pkg = ExamplePackage()
        ex_pkg.create_orig()
        ex_pkg.create()
        ex_pkg.cleanup()


class DscVerificationTestCase(unittest.TestCase):
    def setUp(self):
        with open('test-data/example_1.0-1.dsc', 'rb') as f:
            self.dsc = ubuntutools.archive.Dsc(f.read())

    def test_good(self):
        self.assertTrue(self.dsc.verify_file(
            'test-data/example_1.0.orig.tar.gz'))
        self.assertTrue(self.dsc.verify_file(
            'test-data/example_1.0-1.debian.tar.xz'))

    def test_missing(self):
        self.assertFalse(self.dsc.verify_file(
            'test-data/does.not.exist'))

    def test_bad(self):
        fn = 'test-data/example_1.0.orig.tar.gz'
        with open(fn, 'rb') as f:
            data = f.read()
        last_byte = chr(data[-1] ^ 8).encode()
        data = data[:-1] + last_byte
        m = mock.MagicMock(name='open', spec=open)
        m.return_value = BytesIO(data)
        with mock.patch('builtins.open', m):
            self.assertFalse(self.dsc.verify_file(fn))

    def test_sha1(self):
        del self.dsc['Checksums-Sha256']
        self.test_good()
        self.test_bad()

    def test_md5(self):
        del self.dsc['Checksums-Sha256']
        del self.dsc['Checksums-Sha1']
        self.test_good()
        self.test_bad()


class LocalSourcePackageTestCase(unittest.TestCase):
    SourcePackage = ubuntutools.archive.UbuntuSourcePackage

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix='udt-test')

    def tearDown(self):
        shutil.rmtree(self.workdir)

    def test_local_copy(self):
        pkg = self.SourcePackage(package='example',
                                 version='1.0-1',
                                 component='main',
                                 dscfile='test-data/example_1.0-1.dsc',
                                 workdir=self.workdir,
                                 verify_signature=False)
        pkg.pull()
        pkg.unpack()

    def test_workdir_srcpkg_noinfo(self):
        shutil.copy2('test-data/example_1.0-1.dsc', self.workdir)
        shutil.copy2('test-data/example_1.0.orig.tar.gz', self.workdir)
        shutil.copy2('test-data/example_1.0-1.debian.tar.xz', self.workdir)

        pkg = self.SourcePackage(dscfile=os.path.join(self.workdir,
                                                      'example_1.0-1.dsc'),
                                 workdir=self.workdir,
                                 verify_signature=False)
        pkg.pull()
        pkg.unpack()

    def test_workdir_srcpkg_info(self):
        shutil.copy2('test-data/example_1.0-1.dsc', self.workdir)
        shutil.copy2('test-data/example_1.0.orig.tar.gz', self.workdir)
        shutil.copy2('test-data/example_1.0-1.debian.tar.xz', self.workdir)

        pkg = self.SourcePackage(package='example', version='1.0-1',
                                 component='main',
                                 dscfile=os.path.join(self.workdir,
                                                      'example_1.0-1.dsc'),
                                 workdir=self.workdir,
                                 verify_signature=False)
        pkg.pull()
        pkg.unpack()

    def test_verification(self):
        shutil.copy2('test-data/example_1.0-1.dsc', self.workdir)
        shutil.copy2('test-data/example_1.0.orig.tar.gz', self.workdir)
        shutil.copy2('test-data/example_1.0-1.debian.tar.xz', self.workdir)
        with open(os.path.join(self.workdir, 'example_1.0-1.debian.tar.xz'),
                  'r+b') as f:
            f.write(b'CORRUPTION')

        pkg = self.SourcePackage(package='example',
                                 version='1.0-1',
                                 component='main',
                                 dscfile='test-data/example_1.0-1.dsc',
                                 workdir=self.workdir,
                                 verify_signature=False)
        pkg.pull()
