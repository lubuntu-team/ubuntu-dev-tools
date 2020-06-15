#!/usr/bin/python3

from setuptools import setup
import glob
import os
import re

# look/set what version we have
changelog = "debian/changelog"
if os.path.exists(changelog):
    head = open(changelog, 'r', encoding='utf-8').readline()
    match = re.compile(r".*\((.*)\).*").match(head)
    if match:
        version = match.group(1)

scripts = [
    'backportpackage',
    'bitesize',
    'check-mir',
    'check-symbols',
    'dch-repeat',
    'grab-merge',
    'grep-merges',
    'hugdaylist',
    'import-bug-from-debian',
    'merge-changelog',
    'mk-sbuild',
    'pbuilder-dist',
    'pbuilder-dist-simple',
    'pull-pkg',
    'pull-debian-debdiff',
    'pull-debian-source',
    'pull-debian-debs',
    'pull-debian-ddebs',
    'pull-debian-udebs',
    'pull-lp-source',
    'pull-lp-debs',
    'pull-lp-ddebs',
    'pull-lp-udebs',
    'pull-ppa-source',
    'pull-ppa-debs',
    'pull-ppa-ddebs',
    'pull-ppa-udebs',
    'pull-revu-source',
    'pull-uca-source',
    'pull-uca-debs',
    'pull-uca-ddebs',
    'pull-uca-udebs',
    'requestbackport',
    'requestsync',
    'reverse-depends',
    'seeded-in-ubuntu',
    'setup-packaging-environment',
    'sponsor-patch',
    'submittodebian',
    'syncpackage',
    'ubuntu-build',
    'ubuntu-iso',
    'ubuntu-upload-permission',
    'update-maintainer',
]
data_files = [
    ('share/bash-completion/completions', glob.glob("bash_completion/*")),
    ('share/man/man1', glob.glob("doc/*.1")),
    ('share/man/man5', glob.glob("doc/*.5")),
    ('share/ubuntu-dev-tools', ['enforced-editing-wrapper']),
]

if __name__ == '__main__':
    setup(
        name='ubuntu-dev-tools',
        version=version,
        scripts=scripts,
        packages=[
            'ubuntutools',
            'ubuntutools/lp',
            'ubuntutools/requestsync',
            'ubuntutools/sponsor_patch',
            'ubuntutools/test',
        ],
        data_files=data_files,
        test_suite='ubuntutools.test',
    )
