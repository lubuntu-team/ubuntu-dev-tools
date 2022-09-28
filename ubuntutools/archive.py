# archive.py - Functions for dealing with Debian source packages, archives,
#              and mirrors.
#
# Copyright (C) 2010-2011, Stefano Rivera <stefanor@ubuntu.com>
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

"""Pull source packages from archives.

Approach:
1. Pull dsc from Launchpad (this is over https and can authenticate the
   rest of the source package)
2. Attempt to pull the remaining files from:
   1. existing files
   2. mirrors
   3. Launchpad
3. Verify checksums.
"""

from urllib.request import urlopen, urlparse, urljoin
import codecs
import functools
import json
import os
import re
import subprocess
import sys
import tempfile

from abc import (ABC, abstractmethod)

from debian.changelog import Changelog
import debian.deb822

from contextlib import closing

from pathlib import Path

from ubuntutools.config import UDTConfig
from ubuntutools.lp.lpapicache import (Launchpad,
                                       Distribution,
                                       PersonTeam,
                                       Project,
                                       SourcePackagePublishingHistory,
                                       HTTPError)
from ubuntutools.lp.udtexceptions import (PackageNotFoundException,
                                          SeriesNotFoundException,
                                          PocketDoesNotExistError,
                                          InvalidDistroValueError)
from ubuntutools.misc import (download,
                              download_bytes,
                              verify_file_checksum,
                              verify_file_checksums,
                              DownloadError,
                              NotFoundError)
from ubuntutools.version import Version

import logging
Logger = logging.getLogger(__name__)


class Dsc(debian.deb822.Dsc):
    "Extend deb822's Dsc with checksum verification abilities"

    def get_strongest_checksum(self):
        "Return alg, dict by filename of size, hash_ pairs"
        if 'Checksums-Sha256' in self:
            return ('sha256',
                    dict((entry['name'], (int(entry['size']), entry['sha256']))
                         for entry in self['Checksums-Sha256']))
        if 'Checksums-Sha1' in self:
            return ('sha1',
                    dict((entry['name'], (int(entry['size']), entry['sha1']))
                         for entry in self['Checksums-Sha1']))
        return ('md5',
                dict((entry['name'], (int(entry['size']), entry['md5sum']))
                     for entry in self['Files']))

    def verify_file(self, pathname):
        "Verify that pathname matches the checksums in the dsc"
        p = Path(pathname)
        if not p.is_file():
            return False
        alg, checksums = self.get_strongest_checksum()
        size, digest = checksums[p.name]
        return verify_file_checksum(p, alg, digest, size)

    def compare_dsc(self, other):
        """Check whether any files in these two dscs that have the same name
        also have the same checksum."""
        for field, key in (('Checksums-Sha256', 'sha256'),
                           ('Checksums-Sha1', 'sha1'),
                           ('Files', 'md5sum')):
            if field not in self or field not in other:
                continue
            our_checksums = \
                dict((entry['name'], (int(entry['size']), entry[key]))
                     for entry in self[field])
            their_checksums = \
                dict((entry['name'], (int(entry['size']), entry[key]))
                     for entry in other[field])
            for name, (size, checksum) in our_checksums.items():
                if name not in their_checksums:
                    # file only in one dsc
                    continue
                if size != their_checksums[name][0] or checksum != their_checksums[name][1]:
                    return False
            return True  # one checksum is good enough
        return True


class SourcePackage(ABC):
    """Base class for source package downloading.
    Use DebianSourcePackage or UbuntuSourcePackage instead of using this
    directly.
    """

    @property
    @abstractmethod
    def distribution(self):
        return None

    @property
    def spph_class(self):
        return SourcePackagePublishingHistory

    def __init__(self, package=None, version=None, component=None,
                 *args, **kwargs):
        """Can be initialised using either package or dscfile.
        If package is specified, either the version or series can also be
        specified; using version will get the specific package version,
        while using the series will get the latest version from that series.
        Specifying only the package with no version or series will get the
        latest version from the development series.
        """
        dscfile = kwargs.get('dscfile')
        mirrors = kwargs.get('mirrors', ())
        workdir = kwargs.get('workdir')
        series = kwargs.get('series')
        pocket = kwargs.get('pocket')
        status = kwargs.get('status')
        verify_signature = kwargs.get('verify_signature', False)
        try_binary = kwargs.get('try_binary', True)

        assert (package is not None or dscfile is not None)

        if 'lp' in kwargs:
            # deprecated - please don't use this; if you want to use an
            # existing lp object, just call login_existing() directly
            Logger.warning("Deprecation warning: please don't pass 'lp' to SourcePackage")
            if not Launchpad.logged_in:
                Launchpad.login_existing(kwargs['lp'])

        self.source = package
        self.binary = None
        self.try_binary = try_binary
        self.workdir = Path(workdir) if workdir else Path('.')
        self._series = series
        self._pocket = pocket
        self._status = status
        # dscfile can be either a path or an URL.  misc.py's download() will
        # later fiture it out
        self._dsc_source = dscfile
        self._verify_signature = verify_signature

        # Cached values:
        self._distribution = None
        self._component = component
        self._dsc = None
        self._spph = None
        self._version = Version(version) if version else None

        # Mirrors
        self.mirrors = list(filter(None, mirrors))
        self.masters = list(filter(None,
                                   [UDTConfig.defaults.get(f'{self.distribution.upper()}_{suffix}')
                                    for suffix in ["MIRROR", "PORTS_MIRROR", "INTERNAL_MIRROR"]]))

        # If provided a dscfile, process it now to set our source and version
        if self._dsc_source:
            self._dsc = Dsc(download_bytes(self._dsc_source))
            self.source = self._dsc['Source']
            self._version = Version(self._dsc['Version'])
            self._check_dsc_signature()

    @property
    def lp_spph(self):
        "Return the LP Source Package Publishing History entry"
        if self._spph:
            return self._spph

        archive = self.getArchive()
        params = {}
        if self._version:
            # if version was specified, use that
            params['version'] = self._version.full_version
        elif self._series:
            # if version not specified, get the latest from this series
            params['series'] = self._series
            # note that if not specified, pocket defaults to all EXCEPT -backports
            if self._pocket:
                params['pocket'] = self._pocket
        else:
            # We always want to search all series, if not specified
            params['search_all_series'] = True

        params['status'] = self._status

        try:
            self._spph = archive.getSourcePackage(self.source,
                                                  wrapper=self.spph_class,
                                                  **params)
            return self._spph
        except PackageNotFoundException as pnfe:
            if not self.try_binary or self.binary:
                # either we don't need to bother trying binary name lookup,
                # or we've already tried
                raise pnfe

            Logger.info('Source package lookup failed, '
                        'trying lookup of binary package %s' % self.source)

            try:
                bpph = archive.getBinaryPackage(self.source, **params)
            except PackageNotFoundException as bpnfe:
                # log binary lookup failure, in case it provides hints
                Logger.info(str(bpnfe))
                # raise the original exception for the source lookup
                raise pnfe

            self.binary = self.source
            self.source = bpph.getSourcePackageName()
            Logger.info("Using source package '{}' for binary package '{}'"
                        .format(self.source, self.binary))

            spph = bpph.getBuild().getSourcePackagePublishingHistory()
            if spph:
                self._spph = self.spph_class(spph.self_link)
                return self._spph

            # binary build didn't include source link, unfortunately
            # so try again with the updated self.source name
            if not self._version:
                # Get version first if user didn't specify it, as some
                # binaries have their version hardcoded in their name,
                # such as the kernel package
                self._version = Version(bpph.getVersion())
            return self.lp_spph

    @property
    def version(self):
        "Return Package version"
        if not self._version:
            self._version = Version(self.lp_spph.getVersion())
        return self._version

    @property
    def component(self):
        "Cached archive component, in available"
        if not self._component:
            Logger.debug('Determining component from Launchpad')
            self._component = self.lp_spph.getComponent()
        return self._component

    @property
    def dsc_name(self):
        "Return the source package dsc filename for the given package"
        return f'{self.source}_{self.version.strip_epoch()}.dsc'

    @property
    def dsc_pathname(self):
        "Return the dsc_name, with the workdir path"
        return str(self.workdir / self.dsc_name)

    @property
    def dsc(self):
        "Return the Dsc"
        if not self._dsc:
            if self._dsc_source:
                raise RuntimeError('Internal error: we have a dsc file but dsc not set')
            urls = self._source_urls(self.dsc_name)
            with tempfile.TemporaryDirectory() as d:
                tmpdsc = Path(d) / self.dsc_name
                self._download_file_from_urls(urls, tmpdsc)
                self._dsc = Dsc(tmpdsc.read_bytes())
                self._check_dsc_signature()
        return self._dsc

    def getDistribution(self):
        if not self._distribution:
            self._distribution = Distribution(self.distribution)
        return self._distribution

    def getArchive(self):
        return self.getDistribution().getArchive()

    def _mirror_url(self, mirror, component, filename):
        "Build a source package URL on a mirror"
        if self.source.startswith('lib'):
            group = self.source[:4]
        else:
            group = self.source[0]
        return os.path.join(mirror, 'pool', component, group,
                            self.source, filename)

    def _archive_servers(self):
        "Generator for mirror and master servers"
        # Always provide the mirrors first
        for server in self.mirrors:
            yield server
        # Don't repeat servers that are in both mirrors and masters
        for server in set(self.masters) - set(self.mirrors):
            yield server

    def _source_urls(self, name):
        "Generator of sources for name"
        if self._dsc_source:
            # we only take "" as file, as regardless if for some reason this
            # is a file:// url we still need to handle it with urljoin
            if urlparse(str(self._dsc_source)).scheme == "":
                yield str(Path(self._dsc_source).parent / name)
            else:
                yield urljoin(self._dsc_source, name)
        for server in self._archive_servers():
            yield self._mirror_url(server, self.component, name)
        if self.lp_spph.sourceFileUrl(name):
            yield self.lp_spph.sourceFileUrl(name)

    def _binary_urls(self, name, bpph):
        "Generator of URLs for name"
        for server in self._archive_servers():
            yield self._mirror_url(server, bpph.getComponent(), name)
        if bpph.binaryFileUrl(name):
            yield bpph.binaryFileUrl(name)
        if bpph.getUrl():
            yield bpph.getUrl()

    def _check_dsc_signature(self):
        "Check that the dsc signature matches what we are expecting"
        if not self._verify_signature:
            return
        try:
            gpg_info = self.dsc.get_gpg_info((
                '/usr/share/keyrings/debian-keyring.gpg',
                '/usr/share/keyrings/debian-maintainers.gpg',
            ))
        except IOError:
            Logger.debug('Signature on %s could not be verified, install '
                         'debian-keyring' % self.dsc_name)
            return
        if gpg_info.valid():
            if 'GOODSIG' in gpg_info:
                Logger.info('Good signature by %s (0x%s)'
                            % (gpg_info['GOODSIG'][1], gpg_info['GOODSIG'][0]))
            elif 'VALIDSIG' in gpg_info:
                Logger.info('Valid signature by 0x%s' % gpg_info['VALIDSIG'][0])
            else:
                Logger.info('Valid signature')
        elif 'NO_PUBKEY' in gpg_info:
            Logger.warning('Public key not found, could not verify signature')
        elif 'NODATA' in gpg_info:
            Logger.warning('Package is not signed')
        else:
            Logger.warning('Signature on %s could not be verified' % self.dsc_name)

    def _verify_file(self, pathname, dscverify=False, sha1sum=None, sha256sum=None, size=0):
        p = Path(pathname)
        if not p.exists():
            return False
        if dscverify and not self.dsc.verify_file(p):
            return False
        checksums = {}
        if sha1sum:
            checksums['SHA1'] = sha1sum
        if sha256sum:
            checksums['SHA256'] = sha256sum
        if not verify_file_checksums(p, checksums, size):
            return False
        return True

    def _download_file(self, url, filename, size=0, dscverify=False, sha1sum=None, sha256sum=None):
        "Download url to filename; will be put in workdir unless filename is absolute path."
        if Path(filename).is_absolute():
            p = Path(filename).expanduser().resolve()
        else:
            p = self.workdir / filename

        can_verify = any((dscverify, sha1sum, sha256sum))
        if can_verify and self._verify_file(p, dscverify, sha1sum, sha256sum, size):
            Logger.info(f'Using existing file {p}')
            return True

        download(url, p, size)

        return self._verify_file(p, dscverify, sha1sum, sha256sum, size)

    def _download_file_from_urls(self, urls, filename, size=0, dscverify=False,
                                 sha1sum=None, sha256sum=None):
        "Try to download a file from a list of urls."
        for url in urls:
            try:
                if self._download_file(url, filename, size, dscverify=dscverify,
                                       sha1sum=sha1sum, sha256sum=sha256sum):
                    return
            except NotFoundError:
                # It's ok if the file isn't found, just try the next url
                Logger.debug(f'File not found at {url}')
            except DownloadError as e:
                Logger.error(f'Download Error: {e}')
        raise DownloadError(f'Failed to download {filename}')

    def pull_dsc(self):
        '''DEPRECATED

        This method is badly named and historically has only 'pulled' the
        dsc into memory, not actually to a file. Since the other 'pull' methods
        actually 'pull' to real files, this method makes no sense; additionally
        there is no need for this method since we can 'pull' the dsc into
        memory when the .dsc property is accessed.

        This method no longer does anything at all and should not be used by
        anyone.
        '''
        Logger.debug('Please fix your program: the "pull_dsc" method is deprecated')

    def pull(self):
        "Pull into workdir"
        Path(self.dsc_pathname).write_bytes(self.dsc.raw_text)
        for entry in self.dsc['Files']:
            name = entry['name']
            urls = self._source_urls(name)
            self._download_file_from_urls(urls, name, int(entry['size']), dscverify=True)

    def pull_binaries(self, arch=None, name=None, ext=None):
        """Pull binary debs into workdir.
        If name is specified, only binary packages matching the regex are included.

        If ext is specified, only binary packages with that ext are included; for
        example to only download dbgsym ddebs, specify ext='ddeb'.

        If arch is not specified or is 'all', pull all archs.

        Returns the number of files downloaded.
        """
        Logger.debug("pull_binaries(arch=%s, name=%s, ext=%s)" % (arch, name, ext))

        if arch == 'all':
            arch = None

        total = 0
        for bpph in self.lp_spph.getBinaries(arch=arch, name=name, ext=ext):
            fname = bpph.getFileName()
            fsha1 = bpph.binaryFileSha1(fname)
            fsha256 = bpph.binaryFileSha256(fname)
            fsize = bpph.binaryFileSize(fname)
            urls = self._binary_urls(fname, bpph)
            try:
                self._download_file_from_urls(urls, fname, fsize,
                                              sha1sum=fsha1, sha256sum=fsha256)
                total += 1
            except DownloadError as e:
                # log/print the error, but continue to get the rest of the files
                Logger.error(e)
        return total

    def verify(self):
        """Verify that the source package in workdir matches the dsc.
        Return boolean
        """
        return all(self.dsc.verify_file(self.workdir / entry['name'])
                   for entry in self.dsc['Files'])

    def verify_orig(self):
        """Verify that the .orig files in workdir match the dsc.
        Return boolean
        """
        orig_re = re.compile(r'.*\.orig(-[^.]+)?\.tar\.[^.]+$')
        return all(self.dsc.verify_file(self.workdir / entry['name'])
                   for entry in self.dsc['Files']
                   if orig_re.match(entry['name']))

    def unpack(self, destdir=None):
        "Unpack in workdir"
        cmd = ['dpkg-source', '-x', self.dsc_name]
        if destdir:
            cmd.append(destdir)
        Logger.debug(' '.join(cmd))
        result = subprocess.run(cmd, cwd=str(self.workdir), encoding='utf-8',
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            Logger.error('Source unpack failed.')
            Logger.debug(result.stdout)

    def debdiff(self, newpkg, diffstat=False):
        """Write a debdiff comparing this src pkg to a newer one.
        Optionally print diffstat.
        Return the debdiff filename.
        """
        cmd = ['debdiff', self.dsc_name, newpkg.dsc_name]
        difffn = newpkg.dsc_name[:-3] + 'debdiff'
        Logger.debug(' '.join(cmd) + ('> %s' % difffn))
        with open(difffn, 'w') as f:
            if subprocess.call(cmd, stdout=f, cwd=str(self.workdir)) > 2:
                Logger.error('Debdiff failed.')
                sys.exit(1)
        if diffstat:
            cmd = ('diffstat', '-p1', difffn)
            Logger.debug(' '.join(cmd))
            if subprocess.call(cmd):
                Logger.error('diffstat failed.')
                sys.exit(1)
        return os.path.abspath(difffn)


class DebianSPPH(SourcePackagePublishingHistory):
    """SPPH with getBinaries() overridden,
    as LP doesn't have Debian binaries
    """
    resource_type = 'source_package_publishing_history'

    def __init__(self, *args, **kwargs):
        super(DebianSPPH, self).__init__(*args, **kwargs)
        self._srcpkg = None

    def getBinaries(self, arch=None, name=None, ext=None):
        if not self._srcpkg:
            Logger.info('Using Snapshot to find binary packages')
            self._srcpkg = Snapshot.getSourcePackage(self.getPackageName(),
                                                     version=self.getVersion())
        return self._srcpkg.getSPPH().getBinaries(arch=arch, name=name, ext=ext)


class DebianSourcePackage(SourcePackage):
    "Download / unpack a Debian source package"

    @property
    def distribution(self):
        return 'debian'

    @property
    def spph_class(self):
        return DebianSPPH

    def __init__(self, *args, **kwargs):
        super(DebianSourcePackage, self).__init__(*args, **kwargs)
        self.masters.append(UDTConfig.defaults['DEBSEC_MIRROR'])

        # Cached values:
        self._snapshot_package = None
        self._snapshot_files = None
        # Don't bother searching in LP for debian binaries, they aren't there
        self.try_binary = False

        # Debian doesn't have 'pockets'
        if self._pocket:
            if self._pocket.lower() != 'release':
                Logger.error("Debian does not use 'pockets', ignoring pocket '%s'",
                             self._pocket)
            self._pocket = None

    # Overridden properties/methods:
    @property
    def lp_spph(self):
        "Return the LP Source Package Publishing History entry"
        if not self._spph:
            try:
                # superclass will set self._spph
                return super(DebianSourcePackage, self).lp_spph
            except PackageNotFoundException:
                pass
            except SeriesNotFoundException:
                pass

            Logger.info('Package not found in Launchpad, using Snapshot')
            self._spph = self.snapshot_package.getSPPH()
        return self._spph

    @property
    def component(self):
        "Cached archive component, in available"
        if not self._component:
            Logger.debug('Determining component from Snapshot')
            self._component = Snapshot.getComponent(self.source, self.version)
        return self._component

    def _source_urls(self, name):
        "Generator of sources for name"
        for url in super(DebianSourcePackage, self)._source_urls(name):
            yield url
        if name in self.snapshot_files:
            yield self.snapshot_files[name]

    # Local methods:
    @property
    def snapshot_package(self):
        if not self._snapshot_package:
            if self._version or self._spph:
                # as .version uses .lpph, and our .lpph might use us,
                # only use .version if _version or _spph are set
                version = self.version.full_version
                srcpkg = Snapshot.getSourcePackage(self.source, version=version)
                if not srcpkg:
                    msg = "Package {} {} not found".format(self.source, version)
                    raise PackageNotFoundException(msg)
                self._snapshot_package = srcpkg
            else:
                # we have neither version nor spph, so look up our version using madison
                Logger.info('Using madison to find latest version number')
                series = self._series
                params = {'series': series} if series else {}
                srcpkg = Madison(self.distribution).getSourcePackage(self.source, **params)
                if not srcpkg:
                    raise PackageNotFoundException("Package {} not found".format(self.source))
                if self.source != srcpkg.name:
                    self.binary = self.source
                    self.source = srcpkg.name
                self._snapshot_package = srcpkg
        return self._snapshot_package

    @property
    def snapshot_files(self):
        if not self._snapshot_files:
            files = self.snapshot_package.getFiles()
            self._snapshot_files = {f.name: f.getUrl() for f in files}
        return self._snapshot_files


class UbuntuSourcePackage(SourcePackage):
    "Download / unpack an Ubuntu source package"

    @property
    def distribution(self):
        return 'ubuntu'


class PersonalPackageArchiveSourcePackage(UbuntuSourcePackage):
    "Download / unpack an Ubuntu Personal Package Archive source package"
    def __init__(self, *args, **kwargs):
        super(PersonalPackageArchiveSourcePackage, self).__init__(*args, **kwargs)
        assert 'ppa' in kwargs
        ppa = kwargs['ppa'].split('/')
        if len(ppa) != 2:
            raise ValueError('Invalid PPA value "%s",'
                             'must be "<USER>/<PPA>"' % kwargs['ppa'])
        self._teamname = ppa[0]
        self._ppaname = ppa[1]
        self.masters = []

    @property
    @functools.lru_cache(maxsize=None)
    def team(self):
        try:
            return PersonTeam.fetch(self._teamname)
        except KeyError:
            raise ValueError(f"No user/team '{self._teamname}' found on Launchpad")

    @functools.lru_cache()
    def getArchive(self):
        ppa = self.team.getPPAByName(self._ppaname)
        Logger.debug(f"Using PPA '{ppa.web_link}'")
        return ppa

    def _private_ppa_url(self, filename):
        "Format the URL for a filename using the private PPA server"
        url = self.getArchive().getMySubscriptionURL()
        pkg = self.source
        subdir = pkg[:4] if pkg.startswith('lib') else pkg[:1]
        return f'{url}/pool/main/{subdir}/{pkg}/{filename}'

    def _source_urls(self, name):
        "Generator of sources for name"
        if self.getArchive().private:
            yield self._private_ppa_url(name)
        else:
            yield from super()._source_urls(name)

    def _binary_urls(self, name, bpph):
        "Generator of URLs for name"
        if self.getArchive().private:
            yield self._private_ppa_url(name)
        else:
            yield from super()._binary_urls(name, bpph)


class UbuntuCloudArchiveSourcePackage(PersonalPackageArchiveSourcePackage):
    "Download / unpack an Ubuntu Cloud Archive source package"
    TEAM = 'ubuntu-cloud-archive'
    PROJECT = 'cloud-archive'
    VALID_POCKETS = ['updates', 'proposed', 'staging']

    def __init__(self, *args, **kwargs):
        # Need to determine actual series/pocket ppa now, as it affects getArchive()
        (series, pocket) = self._findReleaseAndPocketForPackage(kwargs.get('series'),
                                                                kwargs.get('pocket'),
                                                                kwargs.get('package'),
                                                                kwargs.get('version'))
        # Drop series/pocket from kwargs, as UCA handles them completely different and we
        # don't want to pass them up to the superclass
        kwargs.pop('series', None)
        orig_pocket = kwargs.pop('pocket', None)
        if orig_pocket and orig_pocket != pocket and pocket == 'staging':
            Logger.info(f"Ubuntu Cloud Archive release '{series}' pocket '{orig_pocket}'"
                        " PPA is not public, using 'staging' pocket instead")

        kwargs['ppa'] = f"{self.TEAM}/{series}-{pocket}"
        super(UbuntuCloudArchiveSourcePackage, self).__init__(*args, **kwargs)

        if pocket == 'staging':
            # Don't bother with the archive; just get directly from the staging ppa, since
            # none of the binaries from the archive will match the staging checksums
            self.masters = []
        else:
            self.masters = ["http://ubuntu-cloud.archive.canonical.com/ubuntu/"]

    def pull_binaries(self, arch=None, name=None, ext=None):
        """Pull binary debs into workdir.

        This is only a wrapper around the superclass method, to log warning if
        pulling binaries when using a 'staging' ppa, since the published binaries
        will not match the 'staging' binaries.
        """
        if self._ppaname.endswith('-staging'):
            Logger.warning("Binaries from 'staging' pocket will not match published binaries; "
                           "see https://bugs.launchpad.net/cloud-archive/+bug/1649979")
        return super(UbuntuCloudArchiveSourcePackage, self).pull_binaries(arch, name, ext)

    @classmethod
    @functools.lru_cache()
    def getUbuntuCloudArchiveProject(cls):
        return Project(cls.PROJECT)

    @classmethod
    def getUbuntuCloudArchiveReleaseNames(cls):
        """Get list of the main UCA release names

        The list will be sorted in descending chronological order.
        """
        return [s.name for s in cls.getUbuntuCloudArchiveProject().series]

    @classmethod
    def ppas(cls):
        """DEPRECATED: use getUbuntuCloudArchiveReleaseNames()"""
        return cls.getUbuntuCloudArchiveReleaseNames()

    @classmethod
    def isValidRelease(cls, release):
        return release in cls.getUbuntuCloudArchiveReleaseNames()

    @classmethod
    def getDevelSeries(cls):
        """Get the current UCA devel release name"""
        return cls.getUbuntuCloudArchiveReleaseNames()[0]

    @classmethod
    @functools.lru_cache()
    def getUbuntuCloudArchiveTeam(cls):
        return PersonTeam.fetch(cls.TEAM)

    @classmethod
    @functools.lru_cache()
    def getUbuntuCloudArchivePPAs(cls, release=None, pocket=None):
        """ Get sorted list of UCA ppa Archive objects

        If release and/or pocket are specified, the list will be
        filtered to return only matching ppa(s).

        This list will only contain ppas relevant to UCA releases;
        it will not contain 'other' ppas, e.g. 'cloud-tools-next'.
        """
        if not any((release, pocket)):
            all_ppas = cls.getUbuntuCloudArchiveTeam().getPPAs()
            ppas = []
            for r in cls.getUbuntuCloudArchiveReleaseNames():
                for p in cls.VALID_POCKETS:
                    name = f"{r}-{p}"
                    if name in all_ppas:
                        ppas.append(all_ppas[name])
            return ppas

        # Use recursive call without params to get the lru-cached list of ppas returned above
        ppas = cls.getUbuntuCloudArchivePPAs()
        if release:
            ppas = list(filter(lambda p: p.name.partition('-')[0] == release, ppas))
        if pocket:
            ppas = list(filter(lambda p: p.name.partition('-')[2] == pocket, ppas))
        if not ppas:
            rname = release or '*'
            pname = pocket or '*'
            raise SeriesNotFoundException(f"UCA release '{rname}-{pname}' not found")
        return ppas

    @classmethod
    def parseReleaseAndPocket(cls, release):
        """Parse the UCA release and pocket for the given string.

        We allow 'release' to be specified as:
           1. UCARELEASE
           2. UCARELEASE-POCKET
           3. UBUNTURELEASE-UCARELEASE
           4. UBUNTURELEASE-UCARELEASE-POCKET
           5. UBUNTURELEASE-POCKET/UCARELEASE
        The UBUNTURELEASE is a standard Ubuntu release name, e.g. 'focal',
        however it is NOT checked for validity.
        The UCARELEASE is a standard Ubuntu Cloud Archive release name, e.g. 'train'.
        The POCKET is limited to the standard pockets 'release', 'updates', or 'proposed',
        or the special pocket 'staging'. The 'release' and 'updates' pockets are
        equivalent (UCA has no 'release' pocket).

        This will return a tuple of (release, pocket), or (release, None) if no
        pocket was specified.

        This will raise SeriesNotFoundException if the release and/or pocket were
        not found.
        """
        release = release.lower().strip()

        # Cases 1 and 2
        PATTERN1 = r'^(?P<ucarelease>[a-z]+)(?:-(?P<pocket>[a-z]+))?$'
        # Cases 3 and 4
        PATTERN2 = r'^(?P<ubunturelease>[a-z]+)-(?P<ucarelease>[a-z]+)(?:-(?P<pocket>[a-z]+))?$'
        # Case 5
        PATTERN3 = r'^(?P<ubunturelease>[a-z]+)-(?P<pocket>[a-z]+)/(?P<ucarelease>[a-z]+)$'

        for pattern in [PATTERN1, PATTERN2, PATTERN3]:
            match = re.match(pattern, release)
            if match:
                r = match.group('ucarelease')
                p = match.group('pocket')
                # For UCA, there is no 'release' pocket, the default is 'updates'
                if p and p == 'release':
                    Logger.warning("Ubuntu Cloud Archive does not use 'release' pocket,"
                                   " using 'updates' instead")
                    p = 'updates'
                if (cls.isValidRelease(r) and (not p or p in cls.VALID_POCKETS)):
                    Logger.debug(f"Using Ubuntu Cloud Archive release '{r}'")
                    return (r, p)
        raise SeriesNotFoundException(f"Ubuntu Cloud Archive release '{release}' not found")

    @classmethod
    def _findReleaseAndPocketForPackage(cls, release, pocket, package, version):
        if release and release not in cls.getUbuntuCloudArchiveReleaseNames():
            raise SeriesNotFoundException(f"Ubuntu Cloud Archive release '{release}' not found")
        if pocket and pocket not in cls.VALID_POCKETS:
            raise PocketDoesNotExistError(f"Ubuntu Cloud Archive pocket '{pocket}' is invalid")
        DEFAULT = tuple(cls.getUbuntuCloudArchivePPAs(release=release or cls.getDevelSeries())[0]
                        .name.split('-', maxsplit=1))
        if not package:
            # not much we can do without a package name
            return DEFAULT
        checked_pocket = False
        for ppa in cls.getUbuntuCloudArchivePPAs(release=release):
            if pocket and pocket != ppa.name.partition('-')[2]:
                # If pocket is specified, only look at the requested pocket, or 'later'
                # This allows using the 'staging' pocket for old releases that do not
                # provide any 'updates' or 'proposed' pockets
                if not checked_pocket:
                    continue
            checked_pocket = True
            params = {'exact_match': True, 'source_name': package}
            if version:
                params['version'] = version
            if ppa.getPublishedSources(**params):
                (r, _, p) = ppa.name.partition('-')
                return (r, p)
        # package/version not found in any ppa
        return DEFAULT


class _WebJSON(object):
    def getHostUrl(self):
        raise Exception("Not implemented")

    def load(self, path=''):
        reader = codecs.getreader('utf-8')
        url = self.getHostUrl() + path
        Logger.debug("Loading %s" % url)
        with closing(urlopen(url)) as data:
            return json.load(reader(data))


# DAKweb madison API
# https://github.com/Debian/dak/blob/master/dakweb/queries/madison.py
# This is really only useful to easily find the latest version of a
# package for a specific series (or unstable).  This does not provide
# any details at all for older-than-latest package versions.
class Madison(_WebJSON):
    urls = {
        'debian': 'https://api.ftp-master.debian.org/madison',
        'ubuntu': 'http://people.canonical.com/~ubuntu-archive/madison.cgi',
    }

    def __init__(self, distro='debian'):
        super(Madison, self).__init__()
        self._distro = distro
        # This currently will NOT work with ubuntu; it doesn't support f=json
        if distro != 'debian':
            raise InvalidDistroValueError("Madison currently only supports Debian")

    def getHostUrl(self):
        return self.urls[self._distro]

    def getSourcePackage(self, name, series='unstable'):
        url = "?f=json&package={name}&s={series}".format(name=name, series=series)
        try:
            result = self.load(url)
        except HTTPError:
            result = None
        if not result:
            msg = "Package {} not found in '{}'".format(name, series)
            raise PackageNotFoundException(msg)
        versions = list(result[0][name].values())[0]
        latest = versions[sorted(versions.keys(), reverse=True)[0]]
        return Snapshot.getSourcePackage(name=latest['source'],
                                         version=latest['source_version'])


# Snapshot API
# https://anonscm.debian.org/cgit/mirror/snapshot.debian.org.git/plain/API
class _Snapshot(_WebJSON):
    DEBIAN_COMPONENTS = ["main", "contrib", "non-free"]

    def getHostUrl(self):
        return "http://snapshot.debian.org"

    def getComponent(self, name, version):
        # unfortunately there is no (easy) way to find the component for older
        # package versions (madison only lists the most recent versions).
        # so we have to parse the file path to determine the component :(
        url = "/mr/package/{}/{}/srcfiles".format(name, version)
        try:
            response = self.load("{}?fileinfo=1".format(url))
        except HTTPError:
            msg = "Package {} version {} not found"
            raise PackageNotFoundException(msg.format(name, version))
        result = response.get('result')
        info = response.get('fileinfo')
        if len(result) < 1:
            msg = "No source files for package {} version {}"
            raise PackageNotFoundException(msg.format(name, version))
        path = info[result[0]['hash']][0]['path']
        # this expects the 'component' to follow 'pool[-*]' in the path
        found_pool = False
        component = None
        for s in path.split('/'):
            if found_pool:
                component = s
                break
            if s.startswith('pool'):
                found_pool = True
        if not component:
            Logger.warning("could not determine component from path %s" % path)
            return self.DEBIAN_COMPONENTS[0]
        if component not in self.DEBIAN_COMPONENTS:
            Logger.warning("unexpected component %s" % component)
        return component

    def _get_package(self, name, url, pkginit, version, sort_key):
        try:
            results = self.load("/mr/{}/{}/".format(url, name))['result']
        except HTTPError:
            raise PackageNotFoundException("Package {} not found.".format(name))

        results = sorted(results, key=lambda r: r[sort_key], reverse=True)
        results = [pkginit(r) for r in results if version == r['version']]
        if not results:
            msg = "Package {name} version {version} not found."
            raise PackageNotFoundException(msg.format(name=name, version=version))
        return results

    def getSourcePackages(self, name, version):
        return self._get_package(name, "package",
                                 lambda obj: SnapshotSourcePackage(obj, name),
                                 version, "version")

    def getSourcePackage(self, name, version):
        return self.getSourcePackages(name, version)[0]

    def getBinaryPackages(self, name, version):
        return self._get_package(name, "binary",
                                 lambda obj: SnapshotBinaryPackage(obj),
                                 version, "binary_version")

    def getBinaryPackage(self, name, version):
        return self.getBinaryPackages(name, version)[0]


Snapshot = _Snapshot()


class SnapshotPackage(object):
    def __init__(self, obj):
        self._obj = obj
        self._files = None
        self._component = None

    @property
    def version(self):
        return self._obj['version']

    @property
    def component(self):
        if not self._component:
            self._component = Snapshot.getComponent(self.name, self.version)
        return self._component


class SnapshotSourcePackage(SnapshotPackage):
    def __init__(self, obj, name):
        # obj required fields: 'version'
        super(SnapshotSourcePackage, self).__init__(obj)
        self.name = name
        self._binary_files = None
        self._spph = None

    def getSPPH(self):
        if not self._spph:
            self._spph = SnapshotSPPH(self)
        return self._spph

    def getAllFiles(self):
        return self.getFiles() + self.getBinaryFiles()

    def getBinaryFiles(self, arch=None, name=None, ext=None):
        if not self._binary_files:
            url = "/mr/package/{}/{}/allfiles".format(self.name, self.version)
            response = Snapshot.load("{}?fileinfo=1".format(url))
            info = response['fileinfo']
            files = [SnapshotBinaryFile(b['name'], b['version'], self.component,
                                        info[r['hash']][0], r['hash'],
                                        r['architecture'], self.name)
                     for b in response['result']['binaries'] for r in b['files']]
            self._binary_files = files
        bins = list(self._binary_files)
        if arch:
            bins = [b for b in bins if b.isArch(arch)]
        if name:
            bins = [b for b in bins if re.match(name, b.package_name)]
        if ext:
            bins = [b for b in bins if re.match(ext, b.ext)]
        return bins

    def getFiles(self):
        if not self._files:
            url = "/mr/package/{}/{}/srcfiles".format(self.name, self.version)
            response = Snapshot.load("{}?fileinfo=1".format(url))
            info = response['fileinfo']
            self._files = [SnapshotSourceFile(self.name, self.version, self.component,
                                              info[r['hash']][0], r['hash'])
                           for r in response['result']]
        return list(self._files)


class SnapshotBinaryPackage(SnapshotPackage):
    def __init__(self, obj):
        # obj required fields: 'version', 'binary_version', 'name', 'source'
        super(SnapshotBinaryPackage, self).__init__(obj)

    @property
    def name(self):
        return self._obj['name']

    @property
    def binary_version(self):
        return self._obj['binary_version']

    @property
    def source(self):
        return self._obj['source']

    def getBPPH(self, arch):
        f = self.getFiles(arch)
        if not f:
            return None
        if not arch:
            raise RuntimeError("Must specify arch")
        # Can only be 1 binary file for this pkg name/version/arch
        return f[0].getBPPH()

    def getFiles(self, arch=None):
        if not self._files:
            url = "/mr/binary/{}/{}/binfiles".format(self.name, self.version)
            response = Snapshot.load("{}?fileinfo=1".format(url))
            info = response['fileinfo']
            self._files = [SnapshotBinaryFile(self.name, self.version, self.component,
                                              info[r['hash']][0], r['hash'],
                                              r['architecture'], self.source)
                           for r in response['result']]
        if not arch:
            return list(self._files)
        return [f for f in self._files if f.isArch(arch)]


class SnapshotFile(object):
    def __init__(self, pkg_name, pkg_version, component, obj, h):
        self.package_name = pkg_name
        self.package_version = pkg_version
        self.component = component
        self._obj = obj
        self._hash = h

    @property
    def getType(self):
        return None

    @property
    def archive_name(self):
        return self._obj['archive_name']

    @property
    def name(self):
        return self._obj['name']

    @property
    def ext(self):
        return self.name.rpartition('.')[2]

    @property
    def path(self):
        return self._obj['path']

    @property
    def size(self):
        return int(self._obj['size'])

    @property
    def date(self):
        if 'run' in self._obj:
            return self._obj['run']
        elif 'first_seen' in self._obj:
            return self._obj['first_seen']
        else:
            Logger.error('File {} has no date information', self.name)
            return 'unknown'

    def getHash(self):
        return self._hash

    def getUrl(self):
        return "{}/file/{}".format(Snapshot.getHostUrl(), self.getHash())

    def __repr__(self):
        return "{}/{} {} bytes {}".format(self.path, self.name, self.size, self.date)


class SnapshotSourceFile(SnapshotFile):
    def __init__(self, name, version, component, obj, h):
        super(SnapshotSourceFile, self).__init__(name, version, component, obj, h)

    def getType(self):
        return 'source'


class SnapshotBinaryFile(SnapshotFile):
    def __init__(self, name, version, component, obj, h, arch, source):
        super(SnapshotBinaryFile, self).__init__(name, version, component, obj, h)
        self.source = source
        self.arch = arch
        self._bpph = None

    def isArch(self, arch):
        if not arch:
            return True
        if self.arch == 'all':
            return True
        return arch == self.arch

    def getType(self):
        return 'binary'

    def getBPPH(self):
        if not self._bpph:
            self._bpph = SnapshotBPPH(self)
        return self._bpph


class SnapshotSPPH(object):
    """Provide the same interface as SourcePackagePublishingHistory"""
    def __init__(self, snapshot_pkg):
        self._pkg = snapshot_pkg

    # LP API defined fields

    @property
    def component_name(self):
        return self.getComponent()

    @property
    def display_name(self):
        return ("{name} {version}"
                .format(name=self.getPackageName(),
                        version=self.getVersion()))

    @property
    def pocket(self):
        # Debian does not use 'pockets'
        return 'Release'

    @property
    def source_package_name(self):
        return self.getPackageName()

    @property
    def source_package_version(self):
        return self.getVersion()

    # SPPH functions

    def getPackageName(self):
        return self._pkg.name

    def getVersion(self):
        return self._pkg.version

    def getComponent(self):
        return self._pkg.component

    def sourceFileUrls(self, include_meta=False):
        if include_meta:
            return [{'url': f.getUrl(),
                     'filename': f.name,
                     'sha1': f.getHash(),
                     'sha256': None,
                     'size': f.size}
                    for f in self._pkg.getFiles()]
        return [f.getUrl() for f in self._pkg.getFiles()]

    def sourceFileUrl(self, filename):
        for f in self.sourceFileUrls(include_meta=True):
            if filename == f['filename']:
                return f['url']
        return None

    def sourceFileSha1(self, url_or_filename):
        for f in self.sourceFileUrls(include_meta=True):
            if url_or_filename in [f['url'], f['filename']]:
                return f['sha1']
        return None

    def sourceFileSha256(self, url_or_filename):
        return None

    def sourceFileSize(self, url_or_filename):
        for f in self.sourceFileUrls(include_meta=True):
            if url_or_filename in [f['url'], f['filename']]:
                return int(f['size'])
        return 0

    def getChangelog(self, since_version=None):
        '''
        Return the changelog, optionally since a particular version
        May return None if the changelog isn't available
        '''
        if self._changelog is None:
            name = self.getPackageName()
            if name.startswith('lib'):
                subdir = 'lib%s' % name[3]
            else:
                subdir = name[0]
            pkgversion = Version(self.getVersion()).strip_epoch()
            base = 'http://packages.debian.org/'

            url = os.path.join(base, 'changelogs', 'pool',
                               self.getComponent(), subdir, name,
                               name + '_' + pkgversion,
                               'changelog.txt')
            try:
                with closing(urlopen(url)) as f:
                    self._changelog = f.read()
            except HTTPError as error:
                Logger.error('{}: {}'.format(url, error))
                return None

        if since_version is None:
            return self._changelog

        if isinstance(since_version, str):
            since_version = Version(since_version)

        new_entries = []
        for block in Changelog(self._changelog):
            if block.version <= since_version:
                break
            new_entries.append(str(block))
        return ''.join(new_entries)

    def getBinaries(self, arch=None, name=None, ext=None):
        return [b.getBPPH()
                for b in self._pkg.getBinaryFiles(arch=arch, name=name, ext=ext)]


class SnapshotBPPH(object):
    """Provide the same interface as BinaryPackagePublishingHistory"""
    def __init__(self, snapshot_binfile):
        self._file = snapshot_binfile

    # LP API defined fields
    @property
    def architecture_specific(self):
        return self._file.arch != 'all'

    @property
    def binary_package_name(self):
        return self.getPackageName()

    @property
    def binary_package_version(self):
        return self.getVersion()

    @property
    def component_name(self):
        return self.getComponent()

    @property
    def display_name(self):
        return ("{name} {version}"
                .format(name=self.getPackageName(),
                        version=self.getVersion()))

    @property
    def pocket(self):
        # Debian does not use 'pockets'
        return 'Release'

    # BPPH functions

    @property
    def arch(self):
        return self._file.arch

    def getSourcePackageName(self):
        return self._file.source

    def getPackageName(self):
        return self._file.package_name

    def getVersion(self):
        return self._file.package_version

    def getComponent(self):
        return self._file.component

    def binaryFileUrls(self, include_meta=False):
        if include_meta:
            return [{'url': self.getUrl(),
                     'filename': self.getFileName(),
                     'sha1': self._file.getHash(),
                     'sha256': None,
                     'size': self._file.size}]
        return [self.getUrl()]

    def binaryFileUrl(self, filename):
        if filename == self.getFileName():
            return self.getUrl()
        return None

    def binaryFileSha1(self, url_or_filename):
        if url_or_filename in [self.getUrl(), self.getFileName()]:
            return self._file.getHash()
        return None

    def binaryFileSha256(self, url_or_filename):
        return None

    def binaryFileSize(self, url_or_filename):
        if url_or_filename in [self.getUrl(), self.getFileName()]:
            return int(self._file.size)
        return 0

    def getBuild(self):
        return None

    def getUrl(self):
        return self._file.getUrl()

    def getFileVersion(self):
        return self.getVersion()

    def getFileArch(self):
        return self.arch

    def getFileExt(self):
        return self._file.ext

    def getFileName(self):
        return self._file.name
