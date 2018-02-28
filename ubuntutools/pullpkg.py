# pullpkg.py -- pull package files for debian/ubuntu/uca
#               modified from ../pull-lp-source and converted to module
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
from argparse import ArgumentParser

from distro_info import DebianDistroInfo

from ubuntutools.archive import (UbuntuSourcePackage, DebianSourcePackage,
                                 UbuntuCloudArchiveSourcePackage)
from ubuntutools.config import UDTConfig
from ubuntutools.lp.lpapicache import (Distribution, Launchpad)
from ubuntutools.lp.udtexceptions import (SeriesNotFoundException,
                                          PackageNotFoundException,
                                          PocketDoesNotExistError,
                                          InvalidDistroValueError)
from ubuntutools.logger import Logger
from ubuntutools.misc import (split_release_pocket, host_architecture)

PULL_SOURCE = 'source'
PULL_DEBS = 'debs'
PULL_DDEBS = 'ddebs'
PULL_UDEBS = 'udebs'
PULL_LIST = 'list'

VALID_PULLS = [PULL_SOURCE, PULL_DEBS, PULL_DDEBS, PULL_UDEBS, PULL_LIST]

DISTRO_DEBIAN = 'debian'
DISTRO_UBUNTU = 'ubuntu'
DISTRO_UCA = 'uca'

DISTRO_PKG_CLASS = {
    DISTRO_DEBIAN: DebianSourcePackage,
    DISTRO_UBUNTU: UbuntuSourcePackage,
    DISTRO_UCA: UbuntuCloudArchiveSourcePackage,
}
VALID_DISTROS = DISTRO_PKG_CLASS.keys()


class InvalidPullValueError(ValueError):
    """ Thrown when --pull value is invalid """
    pass


def create_argparser(default_pull=None, default_distro=None, default_arch=None):
    help_default_pull = "What to pull: " + ", ".join(VALID_PULLS)
    if default_pull:
        help_default_pull += (" (default: %s)" % default_pull)
    help_default_distro = "Pull from: " + ", ".join(VALID_DISTROS)
    if default_distro:
        help_default_distro += (" (default: %s)" % default_distro)
    if not default_arch:
        default_arch = host_architecture()
    help_default_arch = ("Get binary packages for arch (default: %s)" % default_arch)

    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Print verbose/debug messages")
    parser.add_argument('-d', '--download-only', action='store_true',
                        help="Do not extract the source package")
    parser.add_argument('-m', '--mirror', action='append',
                        help='Preferred mirror(s)')
    parser.add_argument('--no-conf', action='store_true',
                        help="Don't read config files or environment variables")
    parser.add_argument('--no-verify-signature', action='store_true',
                        help="Don't fail if dsc signature can't be verified")
    parser.add_argument('-a', '--arch', default=default_arch,
                        help=help_default_arch)
    parser.add_argument('-p', '--pull', default=default_pull,
                        help=help_default_pull)
    parser.add_argument('-D', '--distro', default=default_distro,
                        help=help_default_distro)
    parser.add_argument('package', help="Package name to pull")
    parser.add_argument('release', nargs='?', help="Release to pull from")
    parser.add_argument('version', nargs='?', help="Package version to pull")
    return parser


def parse_pull(pull):
    if not pull:
        raise InvalidPullValueError("Must specify --pull")

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
        raise InvalidPullValueError("Invalid pull action '%s'" % pull)

    return pull


def parse_distro(distro):
    if not distro:
        raise InvalidDistroValueError("Must specify --distro")

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
        raise InvalidDistroValueError("Invalid distro '%s'" % distro)

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

    d = Distribution(distro)

    # let SeriesNotFoundException flow up
    d.getSeries(release)

    Logger.debug("Using distro '%s' release '%s' pocket '%s'",
                 distro, release, pocket)
    return (release, pocket)


def pull(options):
    # required options asserted below
    # 'release' and 'version' are optional strings
    # 'mirror' is optional list of strings
    # these are type bool
    assert hasattr(options, 'verbose')
    assert hasattr(options, 'download_only')
    assert hasattr(options, 'no_conf')
    assert hasattr(options, 'no_verify_signature')
    # these are type string
    assert hasattr(options, 'arch')
    assert hasattr(options, 'pull')
    assert hasattr(options, 'distro')
    assert hasattr(options, 'package')

    Logger.set_verbosity(options.verbose)

    Logger.debug("pullpkg options: %s", options)

    # Login anonymously to LP
    Launchpad.login_anonymously()

    pull = parse_pull(options.pull)

    distro = parse_distro(options.distro)

    config = UDTConfig(options.no_conf)

    mirrors = []
    if hasattr(options, 'mirror') and options.mirror:
        mirrors += options.mirror
    if pull == PULL_DDEBS:
        ddebs_mirror = config.get_value(distro.upper() + '_DDEBS_MIRROR')
        if ddebs_mirror:
            mirrors.append(ddebs_mirror)
    if mirrors:
        Logger.debug("using mirrors %s", ", ".join(mirrors))

    package = options.package
    release = getattr(options, 'release', None)
    version = getattr(options, 'version', None)
    pocket = None
    dscfile = None

    if package.endswith('.dsc') and not release and not version:
        dscfile = package
        package = None

    if release:
        try:
            (release, pocket) = parse_release(release, distro)
        except (SeriesNotFoundException, PocketDoesNotExistError):
            Logger.debug("Param '%s' not valid series, must be version", release)
            release, version = version, release
            if release:
                try:
                    (release, pocket) = parse_release(release, distro)
                except (SeriesNotFoundException, PocketDoesNotExistError):
                    Logger.error("Can't find series for '%s' or '%s'",
                                 release, version)
                    raise

    try:
        pkgcls = DISTRO_PKG_CLASS[distro]
        srcpkg = pkgcls(package=package, version=version,
                        series=release, pocket=pocket,
                        mirrors=mirrors, dscfile=dscfile,
                        verify_signature=(not options.no_verify_signature))
        spph = srcpkg.lp_spph
    except PackageNotFoundException as e:
        Logger.error(str(e))
        raise

    Logger.normal('Found %s', spph.display_name)

    if pull == PULL_LIST:
        Logger.normal("Source files:")
        for f in srcpkg.dsc['Files']:
            Logger.normal("  %s", f['name'])
        Logger.normal("Binary files:")
        for f in spph.getBinaries(options.arch):
            Logger.normal("  %s", f.getFileName())
        return

    # allow DownloadError to flow up to caller
    if pull == PULL_SOURCE:
        srcpkg.pull()
        if options.download_only:
            Logger.debug("--download-only specified, not extracting")
        else:
            srcpkg.unpack()
    else:
        name = '.*'
        if package != spph.getPackageName():
            Logger.normal("Pulling only binary package '%s'", package)
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
            raise InvalidPullValueError("Invalid pull value %s" % pull)
        total = srcpkg.pull_binaries(name=name, arch=options.arch)
        if total < 1:
            Logger.error("No %s found for %s %s", pull,
                         package, spph.getVersion())
