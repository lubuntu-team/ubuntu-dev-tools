#!/usr/bin/python3

import glob
import pathlib
import re

from setuptools import setup


def get_debian_version() -> str:
    """Look what Debian version we have."""
    changelog = pathlib.Path(__file__).parent / "debian" / "changelog"
    with changelog.open("r", encoding="utf-8") as changelog_f:
        head = changelog_f.readline()
    match = re.compile(r".*\((.*)\).*").match(head)
    if not match:
        raise ValueError(f"Failed to extract Debian version from '{head}'.")
    return match.group(1)


def make_pep440_compliant(version: str) -> str:
    """Convert the version into a PEP440 compliant version."""
    public_version_re = re.compile(r"^([0-9][0-9.]*(?:(?:a|b|rc|.post|.dev)[0-9]+)*)\+?")
    _, public, local = public_version_re.split(version, maxsplit=1)
    if not local:
        return version
    sanitized_local = re.sub("[+~]+", ".", local).strip(".")
    pep440_version = f"{public}+{sanitized_local}"
    assert re.match("^[a-zA-Z0-9.]+$", sanitized_local), f"'{pep440_version}' not PEP440 compliant"
    return pep440_version


scripts = [
    "backportpackage",
    "bitesize",
    "check-mir",
    "check-symbols",
    "dch-repeat",
    "grab-merge",
    "grep-merges",
    "import-bug-from-debian",
    "merge-changelog",
    "mk-sbuild",
    "pbuilder-dist",
    "pbuilder-dist-simple",
    "pull-pkg",
    "pull-debian-debdiff",
    "pull-debian-source",
    "pull-debian-debs",
    "pull-debian-ddebs",
    "pull-debian-udebs",
    "pull-lp-source",
    "pull-lp-debs",
    "pull-lp-ddebs",
    "pull-lp-udebs",
    "pull-ppa-source",
    "pull-ppa-debs",
    "pull-ppa-ddebs",
    "pull-ppa-udebs",
    "pull-uca-source",
    "pull-uca-debs",
    "pull-uca-ddebs",
    "pull-uca-udebs",
    "requestbackport",
    "requestsync",
    "reverse-depends",
    "seeded-in-ubuntu",
    "setup-packaging-environment",
    "sponsor-patch",
    "submittodebian",
    "syncpackage",
    "ubuntu-build",
    "ubuntu-iso",
    "ubuntu-upload-permission",
    "update-maintainer",
]
data_files = [
    ("share/bash-completion/completions", glob.glob("bash_completion/*")),
    ("share/man/man1", glob.glob("doc/*.1")),
    ("share/man/man5", glob.glob("doc/*.5")),
    ("share/ubuntu-dev-tools", ["enforced-editing-wrapper"]),
]

if __name__ == "__main__":
    setup(
        name="ubuntu-dev-tools",
        version=make_pep440_compliant(get_debian_version()),
        scripts=scripts,
        packages=[
            "ubuntutools",
            "ubuntutools/lp",
            "ubuntutools/requestsync",
            "ubuntutools/sponsor_patch",
            "ubuntutools/test",
        ],
        data_files=data_files,
        test_suite="ubuntutools.test",
    )
