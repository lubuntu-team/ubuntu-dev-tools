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

import os.path
import shutil
import subprocess

from ubuntutools.version import Version


class ExamplePackage(object):
    def __init__(self, source='example', version='1.0-1'):
        self.source = source
        self.version = Version(version)
        self.srcdir = os.path.join('test-data', '%s-%s' % (source,
                                   self.version.upstream_version))
        if os.path.exists(self.srcdir):
            shutil.rmtree(self.srcdir)
        shutil.copytree('test-data/blank-example', self.srcdir)

    def create_orig(self):
        "Create .orig.tar.gz"
        orig = '%s_%s.orig.tar.gz' % (self.source,
                                      self.version.upstream_version)
        subprocess.check_call(
            (
                'tar',
                '-czf', orig,
                '--exclude', 'debian',
                os.path.basename(self.srcdir),
            ),
            cwd='test-data'
        )

    def changelog_entry(self, version=None, create=False):
        "Add a changelog entry"
        cmd = ['dch', '--noconf', '--preserve', '--package', self.source]
        if create:
            cmd.append('--create')
        cmd += ['--newversion', version or self.version.full_version]
        cmd.append('')
        env = dict(os.environ)
        env['DEBFULLNAME'] = 'Example'
        env['DEBEMAIL'] = 'example@example.net'
        subprocess.check_call(cmd, env=env, cwd=self.srcdir)

    def create(self):
        "Build source package"
        self.changelog_entry(create=True)
        (basename, dirname) = os.path.split(self.srcdir)
        subprocess.check_call(('dpkg-source', '-b', dirname), cwd=basename)

    def cleanup(self):
        "Remove srcdir"
        shutil.rmtree(self.srcdir)
