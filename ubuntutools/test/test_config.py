# test_config.py - Test suite for ubuntutools.config
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010, Stefano Rivera <stefanor@ubuntu.com>
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

import locale
import mock
import os
# import sys
from io import StringIO

from ubuntutools.config import UDTConfig, ubu_email
from ubuntutools.test import unittest


class ConfigTestCase(unittest.TestCase):
    _config_files = {
        'system': '',
        'user': '',
    }

    def _fake_open(self, filename, mode='r'):
        if mode != 'r':
            raise IOError("Read only fake-file")
        files = {
            '/etc/devscripts.conf': self._config_files['system'],
            os.path.expanduser('~/.devscripts'): self._config_files['user'],
        }
        if filename not in files:
            raise IOError("No such file or directory: '%s'" % filename)
        return StringIO(files[filename])

    def setUp(self):
        super(ConfigTestCase, self).setUp()
        m = mock.mock_open()
        m.side_effect = self._fake_open
        patcher = mock.patch('builtins.open', m)
        self.addCleanup(patcher.stop)
        patcher.start()

        # Logger.stdout = StringIO()
        # Logger.stderr = StringIO()

        self.clean_environment()

    def tearDown(self):
        # self.assertEqual(Logger.stdout.getvalue(), '')
        # self.assertEqual(Logger.stderr.getvalue(), '')
        # Logger.stdout = sys.stdout
        # Logger.stderr = sys.stderr

        self.clean_environment()

    def clean_environment(self):
        self._config_files['system'] = ''
        self._config_files['user'] = ''
        for k in list(os.environ.keys()):
            if k.startswith(('UBUNTUTOOLS_', 'TEST_')):
                del os.environ[k]

    def test_config_parsing(self):
        self._config_files['user'] = """#COMMENT=yes
\tTAB_INDENTED=yes
 SPACE_INDENTED=yes
SPACE_SUFFIX=yes
SINGLE_QUOTE='yes no'
DOUBLE_QUOTE="yes no"
QUOTED_QUOTE="it's"
PAIR_QUOTES="yes "a' no'
COMMAND_EXECUTION=a b
INHERIT=user
REPEAT=no
REPEAT=yes
"""
        self._config_files['system'] = 'INHERIT=system'
        self.assertEqual(UDTConfig(prefix='TEST').config, {
            'TAB_INDENTED': 'yes',
            'SPACE_INDENTED': 'yes',
            'SPACE_SUFFIX': 'yes',
            'SINGLE_QUOTE': 'yes no',
            'DOUBLE_QUOTE': 'yes no',
            'QUOTED_QUOTE': "it's",
            'PAIR_QUOTES': 'yes a no',
            'COMMAND_EXECUTION': 'a',
            'INHERIT': 'user',
            'REPEAT': 'yes',
        })
        # errs = Logger.stderr.getvalue().strip()
        # Logger.stderr = StringIO()
        # self.assertEqual(len(errs.splitlines()), 1)
        # self.assertRegex(errs,
        # r'Warning: Cannot parse.*\bCOMMAND_EXECUTION=a')

    def get_value(self, *args, **kwargs):
        config = UDTConfig(prefix='TEST')
        return config.get_value(*args, **kwargs)

    def test_defaults(self):
        self.assertEqual(self.get_value('BUILDER'), 'pbuilder')

    def test_provided_default(self):
        self.assertEqual(self.get_value('BUILDER', default='foo'), 'foo')

    def test_scriptname_precedence(self):
        self._config_files['user'] = """TEST_BUILDER=foo
                                        UBUNTUTOOLS_BUILDER=bar"""
        self.assertEqual(self.get_value('BUILDER'), 'foo')

    def test_configfile_precedence(self):
        self._config_files['system'] = "UBUNTUTOOLS_BUILDER=foo"
        self._config_files['user'] = "UBUNTUTOOLS_BUILDER=bar"
        self.assertEqual(self.get_value('BUILDER'), 'bar')

    def test_environment_precedence(self):
        self._config_files['user'] = "UBUNTUTOOLS_BUILDER=bar"
        os.environ['UBUNTUTOOLS_BUILDER'] = 'baz'
        self.assertEqual(self.get_value('BUILDER'), 'baz')

    def test_general_environment_specific_config_precedence(self):
        self._config_files['user'] = "TEST_BUILDER=bar"
        os.environ['UBUNTUTOOLS_BUILDER'] = 'foo'
        self.assertEqual(self.get_value('BUILDER'), 'bar')

    def test_compat_keys(self):
        self._config_files['user'] = 'COMPATFOOBAR=bar'
        self.assertEqual(self.get_value('QUX', compat_keys=['COMPATFOOBAR']),
                         'bar')
        # errs = Logger.stderr.getvalue().strip()
        # Logger.stderr = StringIO()
        # self.assertEqual(len(errs.splitlines()), 1)
        # self.assertRegex(errs,
        # r'deprecated.*\bCOMPATFOOBAR\b.*\bTEST_QUX\b')

    def test_boolean(self):
        self._config_files['user'] = "TEST_BOOLEAN=yes"
        self.assertEqual(self.get_value('BOOLEAN', boolean=True), True)
        self._config_files['user'] = "TEST_BOOLEAN=no"
        self.assertEqual(self.get_value('BOOLEAN', boolean=True), False)
        self._config_files['user'] = "TEST_BOOLEAN=true"
        self.assertEqual(self.get_value('BOOLEAN', boolean=True), None)

    def test_nonpackagewide(self):
        self._config_files['user'] = 'UBUNTUTOOLS_FOOBAR=a'
        self.assertEqual(self.get_value('FOOBAR'), None)


class UbuEmailTestCase(unittest.TestCase):
    def setUp(self):
        self.clean_environment()

    def tearDown(self):
        self.clean_environment()

    def clean_environment(self):
        for k in ('UBUMAIL', 'DEBEMAIL', 'DEBFULLNAME'):
            if k in os.environ:
                del os.environ[k]

    def test_pristine(self):
        os.environ['DEBFULLNAME'] = name = 'Joe Developer'
        os.environ['DEBEMAIL'] = email = 'joe@example.net'
        self.assertEqual(ubu_email(), (name, email))

    def test_two_hat(self):
        os.environ['DEBFULLNAME'] = name = 'Joe Developer'
        os.environ['DEBEMAIL'] = 'joe@debian.org'
        os.environ['UBUMAIL'] = email = 'joe@ubuntu.com'
        self.assertEqual(ubu_email(), (name, email))
        self.assertEqual(os.environ['DEBFULLNAME'], name)
        self.assertEqual(os.environ['DEBEMAIL'], email)

    def test_two_hat_cmdlineoverride(self):
        os.environ['DEBFULLNAME'] = 'Joe Developer'
        os.environ['DEBEMAIL'] = 'joe@debian.org'
        os.environ['UBUMAIL'] = 'joe@ubuntu.com'
        name = 'Foo Bar'
        email = 'joe@example.net'
        self.assertEqual(ubu_email(name, email), (name, email))
        self.assertEqual(os.environ['DEBFULLNAME'], name)
        self.assertEqual(os.environ['DEBEMAIL'], email)

    def test_two_hat_noexport(self):
        os.environ['DEBFULLNAME'] = name = 'Joe Developer'
        os.environ['DEBEMAIL'] = demail = 'joe@debian.org'
        os.environ['UBUMAIL'] = uemail = 'joe@ubuntu.com'
        self.assertEqual(ubu_email(export=False), (name, uemail))
        self.assertEqual(os.environ['DEBFULLNAME'], name)
        self.assertEqual(os.environ['DEBEMAIL'], demail)

    def test_two_hat_with_name(self):
        os.environ['DEBFULLNAME'] = 'Joe Developer'
        os.environ['DEBEMAIL'] = 'joe@debian.org'
        name = 'Joe Ubuntunista'
        email = 'joe@ubuntu.com'
        os.environ['UBUMAIL'] = '%s <%s>' % (name, email)
        self.assertEqual(ubu_email(), (name, email))
        self.assertEqual(os.environ['DEBFULLNAME'], name)
        self.assertEqual(os.environ['DEBEMAIL'], email)

    def test_debemail_with_name(self):
        name = 'Joe Developer'
        email = 'joe@example.net'
        os.environ['DEBEMAIL'] = orig = '%s <%s>' % (name, email)
        self.assertEqual(ubu_email(), (name, email))
        self.assertEqual(os.environ['DEBEMAIL'], orig)

    def test_unicode_name(self):
        encoding = locale.getdefaultlocale()[1]
        if not encoding:
            encoding = 'utf-8'
        name = 'Jöe Déveloper'
        env_name = name
        if isinstance(name, bytes):
            name = 'Jöe Déveloper'.decode('utf-8')
            env_name = name.encode(encoding)
        try:
            os.environ['DEBFULLNAME'] = env_name
        except UnicodeEncodeError:
            raise unittest.SkipTest("python interpreter is not running in an "
                                    "unicode capable locale")
        os.environ['DEBEMAIL'] = email = 'joe@example.net'
        self.assertEqual(ubu_email(), (name, email))
