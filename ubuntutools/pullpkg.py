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


import os
import re
import sys
import errno

from argparse import ArgumentParser

from distro_info import DebianDistroInfo

from urllib.parse import urlparse

from ubuntutools.archive import (UbuntuSourcePackage, DebianSourcePackage,
                                 UbuntuCloudArchiveSourcePackage,
                                 PersonalPackageArchiveSourcePackage)
from ubuntutools.config import UDTConfig
from ubuntutools.lp.lpapicache import (Distribution, Launchpad)
from ubuntutools.lp.udtexceptions import (SeriesNotFoundException,
                                          PackageNotFoundException,
                                          PocketDoesNotExistError,
                                          InvalidDistroValueError)
from ubuntutools.misc import (split_release_pocket,
                              host_architecture,
                              download,
                              UPLOAD_QUEUE_STATUSES,
                              STATUSES)

from ubuntutools import _loggingBasicConfig

import logging
Logger = logging.getLogger(__name__)

PULL_SOURCE = 'source'
PULL_DEBS = 'debs'
PULL_DDEBS = 'ddebs'
PULL_UDEBS = 'udebs'
PULL_LIST = 'list'

VALID_PULLS = [PULL_SOURCE, PULL_DEBS, PULL_DDEBS, PULL_UDEBS, PULL_LIST]
VALID_BINARY_PULLS = [PULL_DEBS, PULL_DDEBS, PULL_UDEBS]

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
        setting up the root logger level to INFO, and printing out
        (via Logger) a caught error message, instead of allowing the
        exception to flow up to the script.  This does not catch
        unexpected exceptions, such as internal errors.

        On (expected) error, this will call sys.exit(error);
        unexpected errors will flow up to the caller.
        On success, this simply returns.
        """
        _loggingBasicConfig()

        try:
            cls(*args, **kwargs).pull()
            return
        except KeyboardInterrupt:
            Logger.info('User abort.')
        except (PackageNotFoundException, SeriesNotFoundException,
                PocketDoesNotExistError, InvalidDistroValueError,
                InvalidPullValueError) as e:
            Logger.error(str(e))
            sys.exit(errno.ENOENT)

    def __init__(self, *args, **kwargs):
        self._default_pull = kwargs.get('pull')
        self._default_distro = kwargs.get('distro')
        self._default_arch = kwargs.get('arch', host_architecture())

    def parse_args(self, args):
        args = args[:]

        help_default_pull = "What to pull: " + ", ".join(VALID_PULLS)
        if self._default_pull:
            help_default_pull += (" (default: %s)" % self._default_pull)
        help_default_distro = "Pull from: " + ", ".join(VALID_DISTROS)
        if self._default_distro:
            help_default_distro += (" (default: %s)" % self._default_distro)
        help_default_arch = ("Get binary packages for arch")
        help_default_arch += ("(default: %s)" % self._default_arch)

        # use add_help=False because we do parse_known_args() below, and if
        # that sees --help then it exits immediately
        parser = ArgumentParser(add_help=False)
        parser.add_argument('-v', '--verbose', action='count', default=0,
                            help="Increase verbosity/debug")
        parser.add_argument('-d', '--download-only', action='store_true',
                            help="Do not extract the source package")
        parser.add_argument('-m', '--mirror', action='append',
                            help='Preferred mirror(s)')
        parser.add_argument('--no-conf', action='store_true',
                            help="Don't read config files or environment variables")
        parser.add_argument('--no-verify-signature', action='store_true',
                            help="Don't fail if dsc signature can't be verified")
        parser.add_argument('-s', '--status', action='append', default=[],
                            help="Search for packages with specific status(es)")
        parser.add_argument('-a', '--arch', default=self._default_arch,
                            help=help_default_arch)
        parser.add_argument('-p', '--pull', default=self._default_pull,
                            help=help_default_pull)
        parser.add_argument('-D', '--distro', default=self._default_distro,
                            help=help_default_distro)

        # add distro-specific params
        try:
            distro = self.parse_distro(parser.parse_known_args(args)[0].distro)
        except InvalidDistroValueError:
            # don't fail at this point, finish setting up parser help/usage
            distro = None

        if distro == DISTRO_UBUNTU:
            parser.add_argument('--security', action='store_true',
                                help='Pull from the Ubuntu Security Team (proposed) PPA')
            parser.add_argument('--upload-queue', action='store_true',
                                help='Pull from the Ubuntu upload queue')
        if distro == DISTRO_PPA:
            parser.add_argument('--ppa', help='PPA to pull from')
            if parser.parse_known_args(args)[0].ppa is None:
                # check for any param starting with "ppa:"
                # if found, move it to a --ppa param
                for param in args:
                    if param.startswith('ppa:'):
                        args.remove(param)
                        args.insert(0, param)
                        args.insert(0, '--ppa')
                        break

        # add the positional params
        parser.add_argument('package', help="Package name to pull")
        parser.add_argument('release', nargs='?', help="Release to pull from")
        parser.add_argument('version', nargs='?', help="Package version to pull")

        epilog = ("Note on --status: if a version is provided, all status types "
                  "will be searched; if no version is provided, by default only "
                  "'Pending' and 'Published' status will be searched.")

        # since parser has no --help handler, create a new parser that does
        newparser = ArgumentParser(parents=[parser], epilog=epilog)

        return self.parse_options(vars(newparser.parse_args(args)))

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
                Logger.info("Using release '%s' for '%s'", codename, release)
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
        assert 'verbose' in options
        assert 'download_only' in options
        assert 'no_conf' in options
        assert 'no_verify_signature' in options
        assert 'status' in options
        # type string
        assert 'pull' in options
        assert 'distro' in options
        assert 'arch' in options
        assert 'package' in options
        # type string, optional
        assert 'release' in options
        assert 'version' in options
        # type list of strings, optional
        assert 'mirror' in options

        options['pull'] = self.parse_pull(options['pull'])
        options['distro'] = self.parse_distro(options['distro'])

        # ensure these are always included so we can just check for None/False later
        options['ppa'] = options.get('ppa', None)
        options['security'] = options.get('security', False)
        options['upload_queue'] = options.get('upload_queue', False)

        return options

    def _get_params(self, options):
        distro = options['distro']
        pull = options['pull']

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

        if options['security']:
            if options['ppa']:
                Logger.warning('Both --security and --ppa specified, ignoring --ppa')
            Logger.debug('Checking Ubuntu Security PPA')
            # --security is just a shortcut for --ppa ppa:ubuntu-security-proposed/ppa
            options['ppa'] = 'ubuntu-security-proposed/ppa'

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

        params['status'] = STATUSES if 'all' in options['status'] else options['status']

        # special handling for upload queue
        if options['upload_queue']:
            if len(options['status']) > 1:
                raise ValueError("Too many --status provided, "
                                 "can only search for a single status or 'all'")
            if not options['status']:
                params['status'] = None
            elif options['status'][0].lower() == 'all':
                params['status'] = 'all'
            elif options['status'][0].capitalize() in UPLOAD_QUEUE_STATUSES:
                params['status'] = options['status'][0].capitalize()
            else:
                msg = ("Invalid upload queue status '%s': valid values are %s" %
                       (options['status'][0], ', '.join(UPLOAD_QUEUE_STATUSES)))
                raise ValueError(msg)

        return params

    def pull(self, args=sys.argv[1:]):
        """Pull (download) specified package file(s)"""
        options = self.parse_args(args)

        if options['verbose']:
            Logger.setLevel(logging.DEBUG)
            if options['verbose'] > 1:
                logging.getLogger(__package__).setLevel(logging.DEBUG)

        Logger.debug("pullpkg options: %s", options)

        # Login anonymously to LP
        Launchpad.login_anonymously()

        pull = options['pull']
        distro = options['distro']

        params = self._get_params(options)
        package = params['package']

        if options['upload_queue']:
            # upload queue API is different/simpler
            self.pull_upload_queue(pull, arch=options['arch'], **params)
            return

        # call implementation, and allow exceptions to flow up to caller
        srcpkg = DISTRO_PKG_CLASS[distro](**params)
        spph = srcpkg.lp_spph

        Logger.info('Found %s', spph.display_name)

        if pull == PULL_LIST:
            Logger.info("Source files:")
            for f in srcpkg.dsc['Files']:
                Logger.info("  %s", f['name'])
            Logger.info("Binary files:")
            for f in spph.getBinaries(options['arch']):
                archtext = ''
                name = f.getFileName()
                if name.rpartition('.')[0].endswith('all'):
                    archtext = f" ({f.arch})"
                Logger.info(f"  {name}{archtext}")
        elif pull == PULL_SOURCE:
            # allow DownloadError to flow up to caller
            srcpkg.pull()
            if options['download_only']:
                Logger.debug("--download-only specified, not extracting")
            else:
                srcpkg.unpack()
        elif pull in VALID_BINARY_PULLS:
            name = None
            if package != spph.getPackageName():
                Logger.info("Pulling only binary package '%s'", package)
                Logger.info("Use package name '%s' to pull all binary packages",
                            spph.getPackageName())
                name = package

            # e.g. 'debs' -> 'deb'
            ext = pull.rstrip('s')

            if distro == DISTRO_DEBIAN:
                # Debian ddebs don't use .ddeb extension, unfortunately :(
                if pull in [PULL_DEBS, PULL_DDEBS]:
                    name = name or '.*'
                    ext = 'deb'
                if pull == PULL_DEBS:
                    name += r'(?<!-dbgsym)$'
                if pull == PULL_DDEBS:
                    name += r'-dbgsym$'

            # allow DownloadError to flow up to caller
            total = srcpkg.pull_binaries(name=name, ext=ext, arch=options['arch'])
            if total < 1:
                Logger.error("No %s found for %s %s", pull,
                             package, spph.getVersion())
        else:
            Logger.error("Internal error: invalid pull value after parse_pull()")
            raise InvalidPullValueError("Invalid pull value '%s'" % pull)

    def pull_upload_queue(self, pull, **params):
        package = params['package']
        version = params['version']
        arch = params['arch']

        if not params['series']:
            Logger.error("Using --upload-queue requires specifying series")
            return

        series = Distribution('ubuntu').getSeries(params['series'])

        queueparams = {'name': package}
        if params['pocket']:
            queueparams['pocket'] = params['pocket']

        if params['status'] == 'all':
            queueparams['status'] = None
            queuetype = 'any'
        elif params['status']:
            queueparams['status'] = params['status']
            queuetype = params['status']
        else:
            queuetype = 'Unapproved'

        packages = [p for p in series.getPackageUploads(**queueparams) if
                    p.package_version == version or
                    str(p.id) == version or
                    not version]

        if pull == PULL_SOURCE:
            packages = [p for p in packages if p.contains_source]
        elif pull in VALID_BINARY_PULLS:
            packages = [p for p in packages if
                        p.contains_build and
                        (arch in ['all', 'any'] or
                         arch in p.display_arches.replace(',', '').split())]

        if not packages:
            msg = ("Package %s not found in %s upload queue for %s" %
                   (package, queuetype, series.name))
            if version:
                msg += " with version/id %s" % version
            if pull in VALID_BINARY_PULLS:
                msg += " for arch %s" % arch
            raise PackageNotFoundException(msg)

        if pull == PULL_LIST:
            for p in packages:
                msg = "Found %s %s (ID %s)" % (p.package_name, p.package_version, p.id)
                if p.display_arches:
                    msg += " arch %s" % p.display_arches
                Logger.info(msg)
                url = p.changesFileUrl()
                if url:
                    Logger.info("Changes file:")
                    Logger.info("  %s", url)
                else:
                    Logger.info("No changes file")
                urls = p.sourceFileUrls()
                if urls:
                    Logger.info("Source files:")
                    for url in urls:
                        Logger.info("  %s", url)
                else:
                    Logger.info("No source files")
                urls = p.binaryFileUrls()
                if urls:
                    Logger.info("Binary files:")
                    for url in urls:
                        Logger.info("  %s", url)
                        Logger.info("    { %s }" % p.binaryFileProperties(url))
                else:
                    Logger.info("No binary files")
                urls = p.customFileUrls()
                if urls:
                    Logger.info("Custom files:")
                    for url in urls:
                        Logger.info("  %s", url)
            return

        if len(packages) > 1:
            msg = "Found multiple packages"
            if version:
                msg += " with version %s, please specify the ID instead" % version
            else:
                msg += ", please specify the version"
            Logger.error("Available package versions/ids are:")
            for p in packages:
                Logger.error("%s %s (id %s)" % (p.package_name, p.package_version, p.id))
            raise PackageNotFoundException(msg)

        p = packages[0]

        urls = set(p.customFileUrls())
        if p.changesFileUrl():
            urls.add(p.changesFileUrl())

        if pull == PULL_SOURCE:
            urls |= set(p.sourceFileUrls())
            if not urls:
                Logger.error("No source files to download")
            for url in urls:
                download(url)
        else:
            name = '.*'
            if pull == PULL_DEBS:
                name = r'{}(?<!-di)(?<!-dbgsym)$'.format(name)
            elif pull == PULL_DDEBS:
                name += '-dbgsym$'
            elif pull == PULL_UDEBS:
                name += '-di$'
            else:
                raise InvalidPullValueError("Invalid pull value %s" % pull)

            urls |= set(p.binaryFileUrls())
            if not urls:
                Logger.error("No binary files to download")
            for url in urls:
                filename = os.path.basename(urlparse(url).path)
                if re.match(name, filename):
                    download(url)
