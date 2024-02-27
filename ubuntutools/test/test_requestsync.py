# Copyright (C) 2024 Canonical Ltd.
# Author: Chris Peterson <chris.peterson@canonical.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import unittest


# Binary Tests
class BinaryTests(unittest.TestCase):

    # The requestsync binary has the option of using the launchpad api
    # to log in but requires python3-keyring in addition to
    # python3-launchpadlib. Testing the integrated login functionality
    # automatically isn't very feasbile, but we can at least write a smoke
    # test to make sure the required packages are installed.
    # See LP: #2049217
    def test_keyring_installed(self):
        """Smoke test for required lp api dependencies"""
        try:
            import keyring  # noqa: F401
        except ModuleNotFoundError:
            raise ModuleNotFoundError(
                "package python3-keyring is not installed"
            )
