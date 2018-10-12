# test_update_maintainer.py - Test suite for ubuntutools.update_maintainer
#
# Copyright (C) 2010, Benjamin Drung <bdrung@ubuntu.com>
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

"""Test suite for ubuntutools.update_maintainer"""

import mock
import os
# import sys
from io import StringIO

from ubuntutools.test import unittest
from ubuntutools.update_maintainer import update_maintainer

_LUCID_CHANGELOG = """\
axis2c (1.6.0-0ubuntu8) lucid; urgency=low

  * rebuild rest of main for armel armv7/thumb2 optimization;
    UbuntuSpec:mobile-lucid-arm-gcc-v7-thumb2

 -- Alexander Sack <asac@ubuntu.com>  Fri, 05 Mar 2010 03:10:28 +0100
"""

_AXIS2C_CONTROL = """\
Source: axis2c
Section: libs
Priority: optional
DM-Upload-Allowed: yes
XSBC-Original-Maintainer: Soren Hansen <soren@ubuntu.com>
Maintainer: Kyo Lee <kyo.lee@eucalyptus.com>
Standards-Version: 3.9.1
Homepage: http://ws.apache.org/axis2/c/

Package: libaxis2c0
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
"""

_AXIS2C_UPDATED = """\
Source: axis2c
Section: libs
Priority: optional
DM-Upload-Allowed: yes
XSBC-Original-Maintainer: Kyo Lee <kyo.lee@eucalyptus.com>
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Standards-Version: 3.9.1
Homepage: http://ws.apache.org/axis2/c/

Package: libaxis2c0
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}
"""

_UNSTABLE_CHANGELOG = """\
adblock-plus (1.3.3-1) unstable; urgency=low

  * New upstream release.

 -- Benjamin Drung <bdrung@ubuntu.com>  Sat, 25 Dec 2010 20:17:41 +0100
"""

_ABP_CONTROL = """\
Source: adblock-plus
Section: web
Priority: optional
Maintainer: Dmitry E. Oboukhov <unera@debian.org>
Uploaders: Debian Mozilla Extension Maintainers <pkg-mozext-maintainers@lists.alioth.debian.org>,
           Benjamin Drung <bdrung@ubuntu.com>
Build-Depends: debhelper (>= 7.0.50~), mozilla-devscripts (>= 0.19~)
Standards-Version: 3.9.1
DM-Upload-Allowed: yes
Homepage: http://adblockplus.org/
VCS-Browser: http://git.debian.org/?p=pkg-mozext/adblock-plus.git;a=summary
VCS-Git: git://git.debian.org/pkg-mozext/adblock-plus.git

Package: xul-ext-adblock-plus
"""

_ABP_UPDATED = """\
Source: adblock-plus
Section: web
Priority: optional
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
XSBC-Original-Maintainer: Dmitry E. Oboukhov <unera@debian.org>
Uploaders: Debian Mozilla Extension Maintainers <pkg-mozext-maintainers@lists.alioth.debian.org>,
           Benjamin Drung <bdrung@ubuntu.com>
Build-Depends: debhelper (>= 7.0.50~), mozilla-devscripts (>= 0.19~)
Standards-Version: 3.9.1
DM-Upload-Allowed: yes
Homepage: http://adblockplus.org/
VCS-Browser: http://git.debian.org/?p=pkg-mozext/adblock-plus.git;a=summary
VCS-Git: git://git.debian.org/pkg-mozext/adblock-plus.git

Package: xul-ext-adblock-plus
"""

_ABP_OLD_MAINTAINER = """\
Source: adblock-plus
Section: web
Priority: optional
Maintainer: Ubuntu MOTU Developers <ubuntu-motu@lists.ubuntu.com>
XSBC-Original-Maintainer: Dmitry E. Oboukhov <unera@debian.org>
Uploaders: Debian Mozilla Extension Maintainers <pkg-mozext-maintainers@lists.alioth.debian.org>,
           Benjamin Drung <bdrung@ubuntu.com>
Build-Depends: debhelper (>= 7.0.50~), mozilla-devscripts (>= 0.19~)
Standards-Version: 3.9.1
DM-Upload-Allowed: yes
Homepage: http://adblockplus.org/
VCS-Browser: http://git.debian.org/?p=pkg-mozext/adblock-plus.git;a=summary
VCS-Git: git://git.debian.org/pkg-mozext/adblock-plus.git

Package: xul-ext-adblock-plus
"""

_SIMPLE_RULES = """\
#!/usr/bin/make -f
%:
\tdh $@
"""

_COMPLEX_RULES = """\
#!/usr/bin/make -f
... from python2.6 ...
distribution := $(shell lsb_release -is)

control-file:
\tsed -e "s/@PVER@/$(PVER)/g" \\
\t\t-e "s/@VER@/$(VER)/g" \\
\t\t-e "s/@PYSTDDEP@/$(PYSTDDEP)/g" \\
\t\t-e "s/@PRIO@/$(PY_PRIO)/g" \\
\t\t-e "s/@MINPRIO@/$(PY_MINPRIO)/g" \\
\t\tdebian/control.in > debian/control.tmp
ifeq ($(distribution),Ubuntu)
  ifneq (,$(findstring ubuntu, $(PKGVERSION)))
\tm='Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>'; \\
\t\tsed -i "/^Maintainer:/s/\\(.*\\)/Maintainer: $$m\nXSBC-Original-\1/" \\
\t\tdebian/control.tmp
  endif
endif
\t[ -e debian/control ] \\
\t\t&& cmp -s debian/control debian/control.tmp \\
\t\t&& rm -f debian/control.tmp && exit 0; \\
\t\tmv debian/control.tmp debian/control
... from python2.6 ...
"""

_SEAHORSE_PLUGINS_CONTROL = """\
# This file is autogenerated. DO NOT EDIT!
#
# Modifications should be made to debian/control.in instead.
# This file is regenerated automatically in the clean target.

Source: seahorse-plugins
Section: gnome
Priority: optional
Maintainer: Emilio Pozuelo Monfort <pochu@debian.org>
Build-Depends: debhelper (>= 5),
               cdbs (>= 0.4.41)
Standards-Version: 3.8.3
Homepage: http://live.gnome.org/Seahorse

Package: seahorse-plugins
"""

_SEAHORSE_PLUGINS_UPDATED = """\
# This file is autogenerated. DO NOT EDIT!
#
# Modifications should be made to debian/control.in instead.
# This file is regenerated automatically in the clean target.

Source: seahorse-plugins
Section: gnome
Priority: optional
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
XSBC-Original-Maintainer: Emilio Pozuelo Monfort <pochu@debian.org>
Build-Depends: debhelper (>= 5),
               cdbs (>= 0.4.41)
Standards-Version: 3.8.3
Homepage: http://live.gnome.org/Seahorse

Package: seahorse-plugins
"""


# pylint: disable=R0904
class UpdateMaintainerTestCase(unittest.TestCase):
    """TestCase object for ubuntutools.update_maintainer"""

    _directory = "/"
    _files = {
        "changelog": None,
        "control": None,
        "control.in": None,
        "rules": None,
    }

    def _fake_isfile(self, filename):
        """Check only for existing fake files."""
        directory, base = os.path.split(filename)
        return (directory == self._directory and base in self._files and
                self._files[base] is not None)

    def _fake_open(self, filename, mode='r'):
        """Provide StringIO objects instead of real files."""
        directory, base = os.path.split(filename)
        if (directory != self._directory or base not in self._files or
                (mode == "r" and self._files[base] is None)):
            raise IOError("No such file or directory: '%s'" % filename)
        if mode == "w":
            self._files[base] = StringIO()
            self._files[base].close = lambda: None
        return self._files[base]

    # pylint: disable=C0103
    def setUp(self):
        m = mock.mock_open()
        m.side_effect = self._fake_open
        patcher = mock.patch('builtins.open', m)
        self.addCleanup(patcher.stop)
        patcher.start()
        m = mock.MagicMock(side_effect=self._fake_isfile)
        patcher = mock.patch('os.path.isfile', m)
        self.addCleanup(patcher.stop)
        patcher.start()
        self._files["rules"] = StringIO(_SIMPLE_RULES)
        # Logger.stdout = StringIO()
        # Logger.stderr = StringIO()

    def tearDown(self):
        # self.assertEqual(Logger.stdout.getvalue(), '')
        # self.assertEqual(Logger.stderr.getvalue(), '')
        self._files["changelog"] = None
        self._files["control"] = None
        self._files["control.in"] = None
        self._files["rules"] = None
        # Logger.stdout = sys.stdout
        # Logger.stderr = sys.stderr

    # pylint: enable=C0103
    def test_debian_package(self):
        """Test: Don't update Maintainer field if target is Debian."""
        self._files["changelog"] = StringIO(_UNSTABLE_CHANGELOG)
        self._files["control"] = StringIO(_ABP_CONTROL)
        update_maintainer(self._directory)
        self.assertEqual(self._files["control"].getvalue(), _ABP_CONTROL)

    def test_original_ubuntu_maintainer(self):
        """Test: Original maintainer is Ubuntu developer.

           The Maintainer field needs to be update even if
           XSBC-Original-Maintainer has an @ubuntu.com address."""
        self._files["changelog"] = StringIO(_LUCID_CHANGELOG)
        self._files["control"] = StringIO(_AXIS2C_CONTROL)
        update_maintainer(self._directory)
        self.assertEqual(self._files["control"].getvalue(), _AXIS2C_UPDATED)
        # warnings = Logger.stderr.getvalue().strip()
        # Logger.stderr = StringIO()
        # self.assertEqual(len(warnings.splitlines()), 1)
        # self.assertRegex(warnings, "Warning: Overwriting original maintainer: "
        # "Soren Hansen <soren@ubuntu.com>")

    def test_update_maintainer(self):
        """Test: Update Maintainer field."""
        self._files["changelog"] = StringIO(_LUCID_CHANGELOG)
        self._files["control"] = StringIO(_ABP_CONTROL)
        update_maintainer(self._directory)
        self.assertEqual(self._files["control"].getvalue(), _ABP_UPDATED)

    def test_update_old_maintainer(self):
        """Test: Update old MOTU address."""
        self._files["changelog"] = StringIO(_UNSTABLE_CHANGELOG)
        self._files["control.in"] = StringIO(_ABP_OLD_MAINTAINER)
        update_maintainer(self._directory, True)
        self.assertEqual(self._files["control.in"].getvalue(), _ABP_UPDATED)

    def test_comments_in_control(self):
        """Test: Update Maintainer field in a control file containing
           comments."""
        self._files["changelog"] = StringIO(_LUCID_CHANGELOG)
        self._files["control"] = StringIO(_SEAHORSE_PLUGINS_CONTROL)
        update_maintainer(self._directory)
        self.assertEqual(self._files["control"].getvalue(),
                         _SEAHORSE_PLUGINS_UPDATED)

    def test_skip_smart_rules(self):
        """Test: Skip update when XSBC-Original in debian/rules."""
        self._files["changelog"] = StringIO(_LUCID_CHANGELOG)
        self._files["control"] = StringIO(_ABP_CONTROL)
        self._files["rules"] = StringIO(_COMPLEX_RULES)
        update_maintainer(self._directory)
        self.assertEqual(self._files["control"].getvalue(), _ABP_CONTROL)

    def test_missing_rules(self):
        """Test: Skip XSBC-Original test when debian/rules is missing."""
        self._files["changelog"] = StringIO(_LUCID_CHANGELOG)
        self._files["control"] = StringIO(_ABP_CONTROL)
        self._files["rules"] = None
        update_maintainer(self._directory)
        self.assertEqual(self._files["control"].getvalue(), _ABP_UPDATED)
