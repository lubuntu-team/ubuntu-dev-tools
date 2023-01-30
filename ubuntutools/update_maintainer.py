# update_maintainer.py - updates the Maintainer field of an Ubuntu package
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

"""This module is for updating the Maintainer field of an Ubuntu package."""

import logging
import os
import re

import debian.changelog

Logger = logging.getLogger(__name__)

# Prior May 2009 these Maintainers were used:
_PREVIOUS_UBUNTU_MAINTAINER = (
    "ubuntu core developers <ubuntu-devel@lists.ubuntu.com>",
    "ubuntu core developers <ubuntu-devel-discuss@lists.ubuntu.com>",
    "ubuntu motu developers <ubuntu-motu@lists.ubuntu.com>",
)
_UBUNTU_MAINTAINER = "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"


class MaintainerUpdateException(Exception):
    pass


class Control(object):
    """Represents a debian/control file"""

    def __init__(self, filename):
        assert os.path.isfile(filename), "%s does not exist." % (filename)
        self._filename = filename
        self._content = open(filename).read()

    def get_maintainer(self):
        """Returns the value of the Maintainer field."""
        maintainer = re.search("^Maintainer: ?(.*)$", self._content, re.MULTILINE)
        if maintainer:
            maintainer = maintainer.group(1)
        return maintainer

    def get_original_maintainer(self):
        """Returns the value of the XSBC-Original-Maintainer field."""
        orig_maintainer = re.search(
            "^(?:[XSBC]*-)?Original-Maintainer: ?(.*)$", self._content, re.MULTILINE
        )
        if orig_maintainer:
            orig_maintainer = orig_maintainer.group(1)
        return orig_maintainer

    def save(self, filename=None):
        """Saves the control file."""
        if filename:
            self._filename = filename
        control_file = open(self._filename, "w")
        control_file.write(self._content)
        control_file.close()

    def set_maintainer(self, maintainer):
        """Sets the value of the Maintainer field."""
        pattern = re.compile("^Maintainer: ?.*$", re.MULTILINE)
        self._content = pattern.sub("Maintainer: " + maintainer, self._content)

    def set_original_maintainer(self, original_maintainer):
        """Sets the value of the XSBC-Original-Maintainer field."""
        original_maintainer = "XSBC-Original-Maintainer: " + original_maintainer
        if self.get_original_maintainer():
            pattern = re.compile("^(?:[XSBC]*-)?Original-Maintainer:.*$", re.MULTILINE)
            self._content = pattern.sub(original_maintainer, self._content)
        else:
            pattern = re.compile("^(Maintainer:.*)$", re.MULTILINE)
            self._content = pattern.sub(r"\1\n" + original_maintainer, self._content)

    def remove_original_maintainer(self):
        """Strip out out the XSBC-Original-Maintainer line"""
        pattern = re.compile(
            "^(?:[XSBC]*-)?Original-Maintainer:.*?$.*?^", re.MULTILINE | re.DOTALL
        )
        self._content = pattern.sub("", self._content)


def _get_distribution(changelog_file):
    """get distribution of latest changelog entry"""
    changelog = debian.changelog.Changelog(open(changelog_file), strict=False, max_blocks=1)
    distribution = changelog.distributions.split()[0]
    # Strip things like "-proposed-updates" or "-security" from distribution
    return distribution.split("-", 1)[0]


def _find_files(debian_directory, verbose):
    """Find possible control files.
    Returns (changelog, control files list)
    Raises an exception if none can be found.
    """
    possible_contol_files = [os.path.join(debian_directory, f) for f in ["control.in", "control"]]

    changelog_file = os.path.join(debian_directory, "changelog")
    control_files = [f for f in possible_contol_files if os.path.isfile(f)]

    # Make sure that a changelog and control file is available
    if len(control_files) == 0:
        raise MaintainerUpdateException("No control file found in %s." % debian_directory)
    if not os.path.isfile(changelog_file):
        raise MaintainerUpdateException("No changelog file found in %s." % debian_directory)

    # If the rules file accounts for XSBC-Original-Maintainer, we should not
    # touch it in this package (e.g. the python package).
    rules_file = os.path.join(debian_directory, "rules")
    if os.path.isfile(rules_file) and "XSBC-Original-" in open(rules_file).read():
        if verbose:
            print("XSBC-Original is managed by 'rules' file. Doing nothing.")
        control_files = []

    return (changelog_file, control_files)


def update_maintainer(debian_directory, verbose=False):
    """updates the Maintainer field of an Ubuntu package

    * No modifications are made if the Maintainer field contains an ubuntu.com
      email address. Otherwise, the Maintainer field will be set to
      Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
    * The old value will be saved in a field named XSBC-Original-Maintainer
      if the Maintainer field is modified.

    Policy: https://wiki.ubuntu.com/DebianMaintainerField
    """
    try:
        changelog_file, control_files = _find_files(debian_directory, verbose)
    except MaintainerUpdateException as e:
        Logger.error(str(e))
        raise

    distribution = _get_distribution(changelog_file)
    for control_file in control_files:
        control = Control(control_file)
        original_maintainer = control.get_maintainer()

        if original_maintainer is None:
            Logger.error("No Maintainer field found in %s.", control_file)
            raise MaintainerUpdateException("No Maintainer field found")

        if original_maintainer.strip().lower() in _PREVIOUS_UBUNTU_MAINTAINER:
            if verbose:
                print("The old maintainer was: %s" % original_maintainer)
                print("Resetting as: %s" % _UBUNTU_MAINTAINER)
            control.set_maintainer(_UBUNTU_MAINTAINER)
            control.save()
            continue

        if original_maintainer.strip().endswith("ubuntu.com>"):
            if verbose:
                print("The Maintainer email is set to an ubuntu.com address. Doing nothing.")
            continue

        if distribution in ("stable", "testing", "unstable", "experimental"):
            if verbose:
                print("The package targets Debian. Doing nothing.")
            return

        if control.get_original_maintainer() is not None:
            Logger.warning(
                "Overwriting original maintainer: %s", control.get_original_maintainer()
            )

        if verbose:
            print("The original maintainer is: %s" % original_maintainer)
            print("Resetting as: %s" % _UBUNTU_MAINTAINER)
        control.set_original_maintainer(original_maintainer)
        control.set_maintainer(_UBUNTU_MAINTAINER)
        control.save()

    return


def restore_maintainer(debian_directory, verbose=False):
    """Restore the original maintainer"""
    try:
        changelog_file, control_files = _find_files(debian_directory, verbose)
    except MaintainerUpdateException as e:
        Logger.error(str(e))
        raise

    for control_file in control_files:
        control = Control(control_file)
        orig_maintainer = control.get_original_maintainer()
        if not orig_maintainer:
            continue
        if verbose:
            print("Restoring original maintainer: %s" % orig_maintainer)
        control.set_maintainer(orig_maintainer)
        control.remove_original_maintainer()
        control.save()
