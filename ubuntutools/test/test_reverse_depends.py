# test_reverse_depends.py - Test suite for reverse-depends
#
# Copyright (C) 2026, Nadzeya Hutsko <nadzeya.hutsko@canonical.com>
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

"""Test suite for the reverse-depends script"""

import importlib.machinery
import importlib.util
import os
import unittest
from unittest import mock


def _load_reverse_depends():
    script_path = os.path.join(os.path.dirname(__file__), "..", "..", "reverse-depends")
    script_path = os.path.abspath(script_path)
    loader = importlib.machinery.SourceFileLoader("reverse_depends", script_path)
    spec = importlib.util.spec_from_loader("reverse_depends", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


reverse_depends = _load_reverse_depends()


class DisplayVerboseTestCase(unittest.TestCase):
    """Tests for display_verbose output when no reverse dependencies are found"""

    def test_no_results_at_all(self):
        """Empty values dict prints 'No reverse dependencies found'"""
        with mock.patch.object(reverse_depends.Logger, "info") as mock_info:
            reverse_depends.display_verbose("some-package", {})
        mock_info.assert_called_once_with("No reverse dependencies found")

    def test_results_filtered_out(self):
        """Package present in values but with empty data prints filtered message"""
        # Simulate the case where rdeps exist but are all filtered out (e.g. by
        # -R), so build_results populates `result[package] = {}` when all fields
        # are filtered
        values = {"r-cran-bdgraph": {}}
        with mock.patch.object(reverse_depends.Logger, "info") as mock_info:
            reverse_depends.display_verbose("r-cran-bdgraph", values)
        mock_info.assert_called_once_with("No reverse dependencies found with the current filters")

    def test_results_found(self):
        """Non-empty results are displayed without the 'not found' messages"""
        values = {
            "r-cran-bdgraph": {
                "Reverse-Depends": [
                    {"Package": "r-cran-qgraph", "Architectures": ["amd64"]},
                ]
            }
        }
        with mock.patch.object(reverse_depends.Logger, "info") as mock_info:
            reverse_depends.display_verbose("r-cran-bdgraph", values)
        calls = [str(c) for c in mock_info.call_args_list]
        self.assertFalse(
            any("No reverse dependencies found" in c for c in calls),
            "Should not print 'no rdeps' message when results exist",
        )


if __name__ == "__main__":
    unittest.main()
