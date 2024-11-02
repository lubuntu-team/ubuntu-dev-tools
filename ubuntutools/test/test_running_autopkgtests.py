# Copyright (C) 2024 Canonical Ltd.
# Author: Chris Peterson <chris.peterson@canonical.com>
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
""" Tests for running_autopkgtests
Tests using cached data from autopkgtest servers.

These tests only ensure code changes don't change parsing behavior
of the response data. If the response format changes, then the cached
responses will need to change as well.
"""

import unittest
from unittest.mock import patch

from ubuntutools.running_autopkgtests import (
    URL_QUEUED,
    URL_RUNNING,
    _get_jobs,
    get_queued,
    get_running,
)

# Cached binary response data from autopkgtest server
RUN_DATA = (
    b'{"pyatem": {'
    b" \"submit-time_2024-01-19 19:37:36;triggers_['python3-defaults/3.12.1-0ubuntu1'];\":"
    b' {"noble": {"arm64": [{"triggers": ["python3-defaults/3.12.1-0ubuntu1"],'
    b' "submit-time": "2024-01-19 19:37:36"}, 380, "<omitted log>"]}}}}'
)
QUEUED_DATA = (
    b'{"ubuntu": {"noble": {"arm64": ["libobject-accessor-perl {\\"requester\\": \\"someone\\",'
    b' \\"submit-time\\": \\"2024-01-18 01:08:55\\",'
    b' \\"triggers\\": [\\"perl/5.38.2-3\\", \\"liblocale-gettext-perl/1.07-6build1\\"]}"]}}}'
)

# Expected result(s) of parsing the above JSON data
RUNNING_JOB = {
    "pyatem": {
        "submit-time_2024-01-19 19:37:36;triggers_['python3-defaults/3.12.1-0ubuntu1'];": {
            "noble": {
                "arm64": [
                    {
                        "triggers": ["python3-defaults/3.12.1-0ubuntu1"],
                        "submit-time": "2024-01-19 19:37:36",
                    },
                    380,
                    "<omitted log>",
                ]
            }
        }
    }
}

QUEUED_JOB = {
    "ubuntu": {
        "noble": {
            "arm64": [
                'libobject-accessor-perl {"requester": "someone",'
                ' "submit-time": "2024-01-18 01:08:55",'
                ' "triggers": ["perl/5.38.2-3", "liblocale-gettext-perl/1.07-6build1"]}'
            ]
        }
    }
}


PRIVATE_JOB = {"ppa": {"noble": {"arm64": ["private job"]}}}


# Expected textual output of the program based on the above data
RUNNING_OUTPUT = (
    "R     0:06:20 pyatem                         -          noble    arm64"
    "    -                               python3-defaults/3.12.1-0ubuntu1 -\n"
)
QUEUED_OUTPUT = (
    "Q0001   -:-- libobject-accessor-perl        ubuntu     noble    arm64"
    "    -                               perl/5.38.2-3,liblocale-gettext-perl/1.07-6build1\n"
)
PRIVATE_OUTPUT = (
    "Q0001   -:-- private job                    ppa        noble    arm64"
    "    private job                     private job\n"
)


class RunningAutopkgtestTestCase(unittest.TestCase):
    """Assert helper functions parse data correctly"""

    maxDiff = None

    @patch("urllib.request.urlopen")
    def test_get_running_jobs(self, mock_response):
        """Test: Correctly parse autopkgtest json data for running tests"""
        mock_response.return_value.__enter__.return_value.read.return_value = RUN_DATA
        jobs = _get_jobs(URL_RUNNING)
        self.assertEqual(RUNNING_JOB, jobs)

    @patch("urllib.request.urlopen")
    def test_get_queued_jobs(self, mock_response):
        """Test: Correctly parse autopkgtest json data for queued tests"""
        mock_response.return_value.__enter__.return_value.read.return_value = QUEUED_DATA
        jobs = _get_jobs(URL_QUEUED)
        self.assertEqual(QUEUED_JOB, jobs)

    def test_get_running_output(self):
        """Test: Correctly print running tests"""
        with patch("ubuntutools.running_autopkgtests._get_jobs", return_value=RUNNING_JOB):
            self.assertEqual(get_running(), RUNNING_OUTPUT)

    def test_get_queued_output(self):
        """Test: Correctly print queued tests"""
        with patch("ubuntutools.running_autopkgtests._get_jobs", return_value=QUEUED_JOB):
            self.assertEqual(get_queued(), QUEUED_OUTPUT)

    def test_private_queued_job(self):
        """Test: Correctly print queued private job"""
        with patch("ubuntutools.running_autopkgtests._get_jobs", return_value=PRIVATE_JOB):
            self.assertEqual(get_queued(), PRIVATE_OUTPUT)
