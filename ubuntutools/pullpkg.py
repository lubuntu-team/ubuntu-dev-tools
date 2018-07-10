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
import sys
import errno

from argparse import ArgumentParser

from distro_info import DebianDistroInfo

from ubuntutools.archive import (UbuntuSourcePackage, DebianSourcePackage,
                                 UbuntuCloudArchiveSourcePackage,
                                 PersonalPackageArchiveSourcePackage)
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
DISTRO_PPA = 'ppa'

DISTRO_PKG_CLASS = {
    DISTRO_DEBIAN: DebianSourcePackage,
    DISTRO_UBUNTU: UbuntuSourcePackage,
    DISTRO_UCA: UbuntuCloudArchiveSourcePackage,
    DISTRO_PPA: PersonalPackageArchiveSourcePackage,
}
VALID_DISTROS = DISTRO_PKG_CLASS.keys()


class InvalidPullValueError(ValueError):
    """ Thrown when --pull value is invalid """
    pass


class PullPkg(object):
    """Class used to pull file(s) associated with a specific package"""
    @classmethod
    def main(cls, *args, **kwargs):
        """For use by stand-alone cmdline scripts.

        This will handle catching certain exceptions or kbd interrupts,
        and printing out (via Logger) the error message, instead of
        allowing the exception to flow up to the script.  This does
        not catch unexpected exceptions, such as internal errors.
        On (expected) error, this will call sys.exit(error);
        unexpected errors will flow up to the caller.
        On success, this simply returns.
        """
        try:
            cls(*args, **kwargs).pull()
            return
        except KeyboardInterrupt:
            Logger.normal('User abort.')
        except (PackageNotFoundException, SeriesNotFoundException,
                PocketDoesNotExistError, InvalidDistroValueError) as e:
            Logger.error(str(e))
            sys.exit(errno.ENOENT)

    def __init__(self, *args, **kwargs):
        self._default_pull = kwargs.get('pull')
        self._default_distro = kwargs.get('distro')
        self._default_arch = kwargs.get('arch', host_architecture())
        self._parser = None
        self._ppa_parser = None

    @property
    def argparser(self):
        if self._parser:
            return self._parser

        help_default_pull = "What to pull: " + ", ".join(VALID_PULLS)
        if self._default_pull:
            help_default_pull += (" (default: %s)" % self._default_pull)
        help_default_distro = "Pull from: " + ", ".join(VALID_DISTROS)
        if self._default_distro:
            help_default_distro += (" (default: %s)" % self._default_distro)
        help_default_arch = ("Get binary packages for arch")
        help_default_arch += ("(default: %s)" % self._default_arch)

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
        parser.add_argument('-a', '--arch', default=self._default_arch,
                            help=help_default_arch)
        parser.add_argument('-p', '--pull', default=self._default_pull,
                            help=help_default_pull)
        parser.add_argument('-D', '--distro', default=self._default_distro,
                            help=help_default_distro)
        parser.add_argument('--ppa', help='PPA to pull from')
        parser.add_argument('package', help="Package name to pull")
        parser.add_argument('release', nargs='?', help="Release to pull from")
        parser.add_argument('version', nargs='?', help="Package version to pull")
        self._parser = parser
        return self._parser

    def parse_ppa_args(self, args):
        """When pulling from PPA, convert from bare ppa:USER/NAME to --ppa option"""
        if not args:
            myargs = sys.argv[1:]

        options = vars(self.argparser.parse_known_args(myargs)[0])
        # we use these, which all should be always provided by the parser,
        # even if their value is None
        assert 'distro' in options
        assert 'ppa' in options
        assert 'release' in options
        assert 'version' in options

        # if we're not pulling from a PPA, or if we are but --ppa was given,
        # then no change to the args is needed
        if options['distro'] != DISTRO_PPA or options['ppa'] is not None:
            return args

        # check if release or version is a ppa:
        # if it is, move it to a --ppa param
        for param in ['release', 'version']:
            if str(options[param]).startswith('ppa:'):
                myargs.remove(options[param])
                myargs.insert(0, options[param])
                myargs.insert(0, '--ppa')

        return myargs

    def parse_pull(self, pull):
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

    def parse_distro(self, distro):
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

    def parse_release(self, distro, release):
        if distro == DISTRO_UCA:
            # UCA is special; it is specified UBUNTURELEASE-UCARELEASE or just
            # UCARELEASE.  The user could also specify UCARELEASE-POCKET.  But UCA
            # archives always correspond to only one UBUNTURELEASE, and UCA archives
            # have only the Release pocket, so only UCARELEASE matters to us.
            for r in release.split('-'):
                if UbuntuCloudArchiveSourcePackage.isValidRelease(r):
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

        if distro == DISTRO_PPA:
            # PPAs are part of Ubuntu distribution
            d = Distribution(DISTRO_UBUNTU)
        else:
            d = Distribution(distro)

        # let SeriesNotFoundException flow up
        d.getSeries(release)

        Logger.debug("Using distro '%s' release '%s' pocket '%s'",
                     distro, release, pocket)
        return (release, pocket)

    def parse_release_and_version(self, distro, release, version, try_swap=True):
        # Verify specified release is valid, and params in correct order
        pocket = None
        try:
            (release, pocket) = self.parse_release(distro, release)
        except (SeriesNotFoundException, PocketDoesNotExistError):
            if try_swap:
                Logger.debug("Param '%s' not valid series, must be version", release)
                release, version = version, release
                if release:
                    return self.parse_release_and_version(distro, release, version, False)
            else:
                Logger.error("Can't find series for '%s' or '%s'", release, version)
                raise
        return (release, version, pocket)

    def parse_options(self, options):
        # if any of these fail, there is a problem with the parser
        # they should all be provided, though the optional ones may be None

        # type bool
        assert 'download_only' in options
        assert 'no_conf' in options
        assert 'no_verify_signature' in options
        # type string
        assert 'pull' in options
        assert 'distro' in options
        assert 'arch' in options
        assert 'package' in options
        # type string, optional
        assert 'ppa' in options
        assert 'release' in options
        assert 'version' in options
        # type list of strings, optional
        assert 'mirror' in options

        pull = self.parse_pull(options['pull'])
        distro = self.parse_distro(options['distro'])

        params = {}
        params['package'] = options['package']

        if options['release']:
            (r, v, p) = self.parse_release_and_version(distro, options['release'],
                                                       options['version'])
            params['series'] = r
            params['version'] = v
            params['pocket'] = p

        if (params['package'].endswith('.dsc') and not params['series'] and not params['version']):
            params['dscfile'] = params['package']
            params.pop('package')

        if options['ppa']:
            if options['ppa'].startswith('ppa:'):
                params['ppa'] = options['ppa'][4:]
            else:
                params['ppa'] = options['ppa']
        elif distro == DISTRO_PPA:
            raise ValueError('Must specify PPA to pull from')

        mirrors = []
        if options['mirror']:
            mirrors.append(options['mirror'])
        if pull == PULL_DDEBS:
            config = UDTConfig(options['no_conf'])
            ddebs_mirror = config.get_value(distro.upper() + '_DDEBS_MIRROR')
            if ddebs_mirror:
                mirrors.append(ddebs_mirror)
        if mirrors:
            Logger.debug("using mirrors %s", ", ".join(mirrors))
            params['mirrors'] = mirrors

        params['verify_signature'] = not options['no_verify_signature']

        return (pull, distro, params)

    def pull(self, args=None):
        """Pull (download) specified package file(s)"""
        # pull-ppa-* may need conversion from ppa:USER/NAME to --ppa USER/NAME
        args = self.parse_ppa_args(args)

        options = vars(self.argparser.parse_args(args))

        assert 'verbose' in options
        if options['verbose'] is not None:
            Logger.set_verbosity(options['verbose'])

        Logger.debug("pullpkg options: %s", options)

        # Login anonymously to LP
        Launchpad.login_anonymously()

        (pull, distro, params) = self.parse_options(options)

        # call implementation, and allow exceptions to flow up to caller
        srcpkg = DISTRO_PKG_CLASS[distro](**params)
        spph = srcpkg.lp_spph

        Logger.normal('Found %s', spph.display_name)

        if pull == PULL_LIST:
            Logger.normal("Source files:")
            for f in srcpkg.dsc['Files']:
                Logger.normal("  %s", f['name'])
            Logger.normal("Binary files:")
            for f in spph.getBinaries(options['arch']):
                Logger.normal("  %s", f.getFileName())
        elif pull == PULL_SOURCE:
            # allow DownloadError to flow up to caller
            srcpkg.pull()
            if options['download_only']:
                Logger.debug("--download-only specified, not extracting")
            else:
                srcpkg.unpack()
        else:
            name = '.*'
            if params['package'] != spph.getPackageName():
                Logger.normal("Pulling only binary package '%s'", params['package'])
                Logger.normal("Use package name '%s' to pull all binary packages",
                              spph.getPackageName())
                name = params['package']
            if pull == PULL_DEBS:
                name = r'{}(?<!-di)(?<!-dbgsym)$'.format(name)
            elif pull == PULL_DDEBS:
                name += '-dbgsym$'
            elif pull == PULL_UDEBS:
                name += '-di$'
            else:
                raise InvalidPullValueError("Invalid pull value %s" % pull)

            # allow DownloadError to flow up to caller
            total = srcpkg.pull_binaries(name=name, arch=options['arch'])
            if total < 1:
                Logger.error("No %s found for %s %s", pull,
                             params['package'], spph.getVersion())
