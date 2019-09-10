# Copyright (C) 2010, Stefano Rivera <stefanor@ubuntu.com>
# Copyright (C) 2017-2018, Benjamin Drung <bdrung@ubuntu.com>
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

"""test_pylint.py - Run pylint in errors-only mode."""

import os
import re
import subprocess
import sys

from ubuntutools.test import get_source_files, unittest, unittest_verbosity

CONFIG = os.path.join(os.path.dirname(__file__), "pylint.conf")


class PylintTestCase(unittest.TestCase):
    """
    This unittest class provides a test that runs the pylint code check
    on the Python source code. The list of source files is provided by
    the get_source_files() function and pylint is configured via a
    config file.
    """

    def test_pylint(self):
        """Test: Run pylint on Python source code"""

        cmd = ["pylint", "--rcfile=" + CONFIG,
               "-E", "--"] + get_source_files()
        if unittest_verbosity() >= 2:
            sys.stderr.write("Running following command:\n{}\n".format(" ".join(cmd)))
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            encoding='utf-8')
        out, err = process.communicate()

        if process.returncode != 0:  # pragma: no cover
            # Strip trailing summary (introduced in pylint 1.7). This summary might look like:
            #
            # ------------------------------------
            # Your code has been rated at 10.00/10
            #
            out = re.sub("^(-+|Your code has been rated at .*)$", "", out,
                         flags=re.MULTILINE).rstrip()

            # Strip logging of used config file (introduced in pylint 1.8)
            err = re.sub("^Using config file .*\n", "", err).rstrip()

            msgs = []
            if err:
                msgs.append("pylint exited with code {} and has unexpected output on stderr:\n{}"
                            .format(process.returncode, err))
            if out:
                msgs.append("pylint found issues:\n{}".format(out))
            if not msgs:
                msgs.append("pylint exited with code {} and has no output on stdout or stderr."
                            .format(process.returncode))
            self.fail("\n".join(msgs))
