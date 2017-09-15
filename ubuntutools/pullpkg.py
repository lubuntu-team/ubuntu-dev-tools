#!/usr/bin/python3
#
# pull-pkg -- pull package files for debian/ubuntu/uca
# Basic usage: pull-pkg -D distro -p type <package name> [version] [release]
#
# Copyright (C) 2008,      Iain Lane <iain@orangesquash.org.uk>,
#               2010-2011, Stefano Rivera <stefanor@ubuntu.com>
#               2017,      Dan Streetman <dan.streetman@canonical.com>
#
# ##################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See file /usr/share/common-licenses/GPL for more details.
#
# ##################################################################


import re
import sys
from optparse import OptionParser

from distro_info import DebianDistroInfo

from ubuntutools.archive import (UbuntuSourcePackage, DebianSourcePackage,
                                 UbuntuCloudArchiveSourcePackage,
                                 DownloadError)
from ubuntutools.config import UDTConfig
from ubuntutools.lp.lpapicache import (Distribution, Launchpad)
from ubuntutools.lp.udtexceptions import (SeriesNotFoundException,
                                          PackageNotFoundException,
                                          PocketDoesNotExistError)
from ubuntutools.logger import Logger
from ubuntutools.misc import (split_release_pocket, host_architecture)

PULL_SOURCE = 'source'
PULL_DEBS = 'debs'
PULL_DDEBS = 'ddebs'
PULL_UDEBS = 'udebs'
PULL_LIST = 'list'

DEFAULT_PULL = PULL_SOURCE
VALID_PULLS = [PULL_SOURCE, PULL_DEBS, PULL_DDEBS, PULL_UDEBS, PULL_LIST]


DISTRO_DEBIAN = 'debian'
DISTRO_UBUNTU = 'ubuntu'
DISTRO_UCA = 'uca'

DEFAULT_DISTRO = DISTRO_UBUNTU
DISTRO_PKG_CLASS = {
    DISTRO_DEBIAN: DebianSourcePackage,
    DISTRO_UBUNTU: UbuntuSourcePackage,
    DISTRO_UCA: UbuntuCloudArchiveSourcePackage,
}
VALID_DISTROS = DISTRO_PKG_CLASS.keys()


def parse_pull(pull):
    if not pull:
        pull = DEFAULT_PULL
        Logger.normal("Defaulting to pull %s", pull)

    # allow 'dbgsym' as alias for 'ddebs'
    if pull == 'dbgsym':
        Logger.debug("Pulling '%s' for '%s'", PULL_DDEBS, pull)
        pull = PULL_DDEBS
    # assume anything starting with 'bin' means 'debs'
    if str(pull).startswith('bin'):
        Logger.debug("Pulling '%s' for '%s'", PULL_DEBS, pull)
        pull = PULL_DEBS
    # verify pull action is valid
    if pull not in VALID_PULLS:
        Logger.error("Invalid pull action '%s'", pull)
        sys.exit(1)

    return pull


def parse_distro(distro):
    if not distro:
        distro = DEFAULT_DISTRO
        Logger.normal("Defaulting to distro %s", distro)

    distro = distro.lower()

    # allow 'lp' for 'ubuntu'
    if distro == 'lp':
        Logger.debug("Using distro '%s' for '%s'", DISTRO_UBUNTU, distro)
        distro = DISTRO_UBUNTU
    # assume anything with 'cloud' is UCA
    if re.match(r'.*cloud.*', distro):
        Logger.debug("Using distro '%s' for '%s'", DISTRO_UCA, distro)
        distro = DISTRO_UCA
    # verify distro is valid
    if distro not in VALID_DISTROS:
        Logger.error("Invalid distro '%s'", distro)
        sys.exit(1)

    return distro


def parse_release(release, distro):
    if distro == DISTRO_UCA:
        # UCA is special; it is specified UBUNTURELEASE-UCARELEASE or just
        # UCARELEASE.  The user could also specify UCARELEASE-POCKET.  But UCA
        # archives always correspond to only one UBUNTURELEASE, and UCA archives
        # have only the Release pocket, so only UCARELEASE matters to us.
        for r in release.split('-'):
            if r in UbuntuCloudArchiveSourcePackage.getReleaseNames():
                Logger.debug("Using UCA release '%s'", r)
                return (r, None)
        raise SeriesNotFoundException('UCA release {} not found.'.format(release))

    # Check if release[-pocket] is specified
    (release, pocket) = split_release_pocket(release, default=None)
    Logger.debug("Parsed release '%s' pocket '%s'", release, pocket)

    if distro == DISTRO_DEBIAN:
        # This converts from the aliases like 'unstable'
        debian_info = DebianDistroInfo()
        codename = debian_info.codename(release)
        if codename:
            Logger.normal("Using release '%s' for '%s'", codename, release)
            release = codename

    try:
        d = Distribution(distro)
        Logger.debug("Distro '%s' is valid", distro)
    except:
        Logger.debug("Distro '%s' not valid", distro)
        raise SeriesNotFoundException("Distro {} not found".format(distro))

    # let SeriesNotFoundException flow up
    d.getSeries(release)

    Logger.debug("Using distro '%s' release '%s' pocket '%s'",
                 distro, release, pocket)
    return (release, pocket)


def main():
    usage = "Usage: %prog <package> [release[-pocket]|version]"
    opt_parser = OptionParser(usage)
    opt_parser.add_option('-v', '--verbose',
                          dest='verbose', default=False,
                          action='store_true',
                          help="Print verbose/debug messages")
    opt_parser.add_option('-d', '--download-only',
                          dest='download_only', default=False,
                          action='store_true',
                          help="Do not extract the source package")
    opt_parser.add_option('-m', '--mirror', dest='mirror',
                          help='Preferred mirror')
    opt_parser.add_option('--no-conf',
                          dest='no_conf', default=False, action='store_true',
                          help="Don't read config files or environment "
                               "variables")
    opt_parser.add_option('-a', '--arch',
                          dest='arch', default=None,
                          help="Get binary packages for specified architecture "
                               "(default: {})".format(host_architecture()))
    opt_parser.add_option('-p', '--pull',
                          dest='pull', default=None,
                          help="What to pull: {} (default: {})"
                               .format(", ".join(VALID_PULLS), DEFAULT_PULL))
    opt_parser.add_option('-D', '--distro',
                          dest='distro', default=None,
                          help="Pull from: {} (default: {})"
                               .format(", ".join(VALID_DISTROS), DEFAULT_DISTRO))
    (options, args) = opt_parser.parse_args()
    if not args:
        opt_parser.error("Must specify package name")

    distro = parse_distro(options.distro)
    mirrors = []

    config = UDTConfig(options.no_conf)
    if options.mirror is None:
        options.mirror = config.get_value(distro.upper() + '_MIRROR')
    if options.mirror:
        mirrors.append(options.mirror)

    pull = parse_pull(options.pull)
    if pull == PULL_DDEBS:
        ddebs_mirror = config.get_value(distro.upper() + '_DDEBS_MIRROR')
        if ddebs_mirror:
            mirrors.append(ddebs_mirror)

    # Login anonymously to LP
    Launchpad.login_anonymously()

    Logger.set_verbosity(options.verbose)

    package = str(args[0]).lower()
    version = None
    release = None
    pocket = None

    if len(args) > 1:
        try:
            (release, pocket) = parse_release(args[1], distro)
            if len(args) > 2:
                version = args[2]
        except (SeriesNotFoundException, PocketDoesNotExistError):
            version = args[1]
            Logger.debug("Param '%s' not valid series, must be version", version)
            if len(args) > 2:
                try:
                    (release, pocket) = parse_release(args[2], distro)
                except (SeriesNotFoundException, PocketDoesNotExistError):
                    Logger.error("Can't find series for '%s' or '%s'",
                                 args[1], args[2])
                    sys.exit(1)

    try:
        pkgcls = DISTRO_PKG_CLASS[distro]
        srcpkg = pkgcls(package=package, version=version,
                        series=release, pocket=pocket,
                        mirrors=mirrors)
        spph = srcpkg.lp_spph
    except PackageNotFoundException as e:
        Logger.error(str(e))
        sys.exit(1)

    Logger.normal('Found %s', spph.display_name)

    if pull == PULL_LIST:
        Logger.normal("Source files:")
        for f in srcpkg.dsc['Files']:
            Logger.normal("  %s", f['name'])
        Logger.normal("Binary files:")
        for f in spph.getBinaries(options.arch):
            Logger.normal("  %s", f.getFileName())
        sys.exit(0)

    try:
        if pull == PULL_SOURCE:
            srcpkg.pull()
            if not options.download_only:
                srcpkg.unpack()
        else:
            name = '.*'
            if package != spph.getPackageName():
                Logger.normal("Pulling binary package '%s'", package)
                Logger.normal("Use package name '%s' to pull all binary packages",
                              spph.getPackageName())
                name = package
            if pull == PULL_DEBS:
                name = r'{}(?<!-di)(?<!-dbgsym)$'.format(name)
            elif pull == PULL_DDEBS:
                name += '-dbgsym$'
            elif pull == PULL_UDEBS:
                name += '-di$'
            else:
                Logger.error("Unknown action '%s'", pull)
                sys.exit(1)
            total = srcpkg.pull_binaries(name=name, arch=options.arch)
            if total < 1:
                Logger.error("No %s found for %s", pull, spph.display_name)
                sys.exit(1)
    except DownloadError as e:
        Logger.error('Failed to download: %s', str(e))
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        Logger.normal('User abort.')
