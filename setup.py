#!/usr/bin/python

from setuptools import setup
import glob
import os
import re
import sys
import codecs

# look/set what version we have
changelog = "debian/changelog"
if os.path.exists(changelog):
    head = codecs.open(changelog, 'r', 'utf-8', 'replace').readline()
    match = re.compile(r".*\((.*)\).*").match(head)
    if match:
        version = match.group(1)

if sys.version_info[0] >= 3:
    scripts = [
        'backportpackage',
        'bitesize',
        'check-mir',
        'check-symbols',
        'dch-repeat',
        'grab-merge',
        'grep-merges',
        'hugdaylist',
        'mk-sbuild',
        'pbuilder-dist',
        'pbuilder-dist-simple',
        'pull-debian-debdiff',
        'pull-debian-source',
        'pull-lp-source',
        'pull-revu-source',
        'pull-uca-source',
        'requestbackport',
        'requestsync',
        'reverse-build-depends',
        'reverse-depends',
        'seeded-in-ubuntu',
        'setup-packaging-environment',
    ]
    data_files = [
        ('share/bash-completion/completions', glob.glob("bash_completion/*")),
        ('share/man/man1', glob.glob("doc/*.1")),
        ('share/man/man5', glob.glob("doc/*.5")),
        ('share/ubuntu-dev-tools', ['enforced-editing-wrapper']),
    ]
else:
    scripts = [
        'import-bug-from-debian',
        'merge-changelog',
        'sponsor-patch',
        'submittodebian',
        'syncpackage',
        'ubuntu-build',
        'ubuntu-iso',
        'ubuntu-upload-permission',
        'update-maintainer',
    ]
    data_files = []

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
        test_suite='ubuntutools.test.discover',
    )
