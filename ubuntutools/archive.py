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

from urllib.error import (URLError, HTTPError)
from urllib.parse import (quote, urlparse)
from urllib.request import urlopen
import codecs
import hashlib
import json
import os.path
import re
import shutil
import subprocess
import sys

from debian.changelog import Changelog
import debian.deb822
import httplib2

from contextlib import closing

from ubuntutools.config import UDTConfig
from ubuntutools.lp.lpapicache import (Launchpad, Distribution, PersonTeam,
                                       SourcePackagePublishingHistory)
from ubuntutools.lp.udtexceptions import (PackageNotFoundException,
                                          SeriesNotFoundException,
                                          InvalidDistroValueError)
from ubuntutools.version import Version

import logging
Logger = logging.getLogger(__name__)


class DownloadError(Exception):
    "Unable to pull a source package"
    pass


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
        if os.path.isfile(pathname):
            alg, checksums = self.get_strongest_checksum()
            size, digest = checksums[os.path.basename(pathname)]
            if os.path.getsize(pathname) != size:
                return False
            hash_func = getattr(hashlib, alg)()
            f = open(pathname, 'rb')
            while True:
                buf = f.read(hash_func.block_size)
                if buf == b'':
                    break
                hash_func.update(buf)
            f.close()
            return hash_func.hexdigest() == digest
        return False

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


class SourcePackage(object):
    """Base class for source package downloading.
    Use DebianSourcePackage or UbuntuSourcePackage instead of using this
    directly.
    """
    distribution = None
    spph_class = SourcePackagePublishingHistory

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
        lp = kwargs.get('lp')
        mirrors = kwargs.get('mirrors', ())
        workdir = kwargs.get('workdir', '.')
        series = kwargs.get('series')
        pocket = kwargs.get('pocket')
        status = kwargs.get('status')
        verify_signature = kwargs.get('verify_signature', False)
        try_binary = kwargs.get('try_binary', True)

        assert (package is not None or dscfile is not None)

        self.source = package
        self._lp = lp
        self.binary = None
        self.try_binary = try_binary
        self.workdir = workdir
        self._series = series
        self._pocket = pocket
        self._status = status
        self._dsc_source = dscfile
        self._verify_signature = verify_signature

        # Cached values:
        self._distribution = None
        self._component = component
        self._dsc = None
        self._spph = None
        self._version = Version(version) if version else None

        # Mirrors
        self.mirrors = list(mirrors)
        if self.distribution:
            self.masters = [UDTConfig.defaults['%s_MIRROR'
                                               % self.distribution.upper()]]

        # if a dsc was specified, pull it to get the source/version info
        if self._dsc_source:
            self.pull_dsc()

    @property
    def lp_spph(self):
        "Return the LP Source Package Publishing History entry"
        if self._spph:
            return self._spph

        if not Launchpad.logged_in:
            if self._lp:
                Launchpad.login_existing(self._lp)
            else:
                Launchpad.login_anonymously()

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
        return '%s_%s.dsc' % (self.source, self.version.strip_epoch())

    @property
    def dsc_pathname(self):
        "Return the dsc_name, with the workdir path"
        return os.path.join(self.workdir, self.dsc_name)

    @property
    def dsc(self):
        "Return a the Dsc"
        if self._dsc is None:
            self.pull_dsc()
        return self._dsc

    def getDistribution(self):
        if not self._distribution:
            self._distribution = Distribution(self.distribution)

        return self._distribution

    def getArchive(self):
        return self.getDistribution().getArchive()

    def _mirror_url(self, mirror, filename):
        "Build a source package URL on a mirror"
        if self.source.startswith('lib'):
            group = self.source[:4]
        else:
            group = self.source[0]
        return os.path.join(mirror, 'pool', self.component, group,
                            self.source, filename)

    def _lp_url(self, filename, source=False):
        "Build an archive file URL on Launchpad"
        if source:
            suffix = '+sourcefiles/%s/%s/%s' % (
                quote(self.source), quote(self.version.full_version),
                quote(filename))
        else:
            suffix = '+files/%s' % quote(filename)
        return 'https://launchpad.net/%s/+archive/primary/%s' % (
            quote(self.distribution), suffix)

    def _source_urls(self, name):
        "Generator of sources for name"
        if self._dsc_source:
            yield os.path.join(os.path.dirname(self._dsc_source), name)
        for mirror in self.mirrors:
            yield self._mirror_url(mirror, name)
        for mirror in self.masters:
            if mirror not in self.mirrors:
                yield self._mirror_url(mirror, name)
        if self.lp_spph.sourceFileUrl(name):
            yield self.lp_spph.sourceFileUrl(name)
        yield self._lp_url(name, source=True)

    def _binary_urls(self, name, bpph):
        "Generator of URLs for name"
        for mirror in self.mirrors:
            yield self._mirror_url(mirror, name)
        for mirror in self.masters:
            if mirror not in self.mirrors:
                yield self._mirror_url(mirror, name)
        if bpph.binaryFileUrl(name):
            yield bpph.binaryFileUrl(name)
        if bpph.getUrl():
            yield bpph.getUrl()
        yield self._lp_url(name)

    def pull_dsc(self):
        "Retrieve dscfile and parse"
        if self._dsc_source:
            parsed = urlparse(self._dsc_source)
            if parsed.scheme == '':
                self._dsc_source = 'file://' + os.path.abspath(self._dsc_source)
                parsed = urlparse(self._dsc_source)
            url = self._dsc_source
        else:
            url = self._lp_url(self.dsc_name, source=True)
        self._download_dsc(url)

        self._check_dsc()

    def _download_dsc(self, url):
        "Download specified dscfile and parse"
        parsed = urlparse(url)
        if parsed.scheme == 'file':
            Logger.debug("Using dsc file '%s'" % parsed.path)
            with open(parsed.path, 'rb') as f:
                body = f.read()
        else:
            try:
                Logger.debug("Trying dsc url '%s'" % url)
                response, body = httplib2.Http().request(url)
            except httplib2.HttpLib2Error as e:
                raise DownloadError(e)
            if response.status != 200:
                raise DownloadError("%s: %s %s" % (url, response.status,
                                                   response.reason))
        self._dsc = Dsc(body)

    def _check_dsc(self):
        "Check that the dsc matches what we are expecting"
        assert self._dsc is not None
        self.source = self.dsc['Source']
        self._version = Version(self.dsc['Version'])

        valid = False
        no_pub_key = False
        message = None
        gpg_info = None
        try:
            gpg_info = self.dsc.get_gpg_info((
                '/usr/share/keyrings/debian-keyring.gpg',
                '/usr/share/keyrings/debian-maintainers.gpg',
            ))
            valid = gpg_info.valid()
        except IOError:
            message = ('Signature on %s could not be verified, install '
                       'debian-keyring' % self.dsc_name)
        if message is None:
            if valid:
                message = 'Valid signature'
            else:
                message = ('Signature on %s could not be verified'
                           % self.dsc_name)
        if gpg_info is not None:
            if 'GOODSIG' in gpg_info:
                message = ('Good signature by %s (0x%s)'
                           % (gpg_info['GOODSIG'][1], gpg_info['GOODSIG'][0]))
            elif 'VALIDSIG' in gpg_info:
                message = 'Valid signature by 0x%s' % gpg_info['VALIDSIG'][0]
            elif 'NO_PUBKEY' in gpg_info:
                no_pub_key = True
                message = 'Public key not found, could not verify signature'
        if self._verify_signature:
            if valid:
                Logger.info(message)
            elif no_pub_key:
                Logger.warning(message)
            else:
                Logger.error(message)
                raise DownloadError(message)
        else:
            Logger.debug(message)

    def _write_dsc(self):
        "Write dsc file to workdir"
        if self._dsc is None:
            self.pull_dsc()
        with open(self.dsc_pathname, 'wb') as f:
            f.write(self.dsc.raw_text)

    def _download_file_helper(self, f, pathname, size):
        "Perform the dowload."
        BLOCKSIZE = 16 * 1024

        with open(pathname, 'wb') as out:
            if not (Logger.isEnabledFor(logging.INFO) and
                    sys.stderr.isatty() and
                    size):
                shutil.copyfileobj(f, out, BLOCKSIZE)
                return

            XTRALEN = len('[] 99%')
            downloaded = 0
            bar_width = 60
            term_width = os.get_terminal_size(sys.stderr.fileno())[0]
            if term_width < bar_width + XTRALEN + 1:
                bar_width = term_width - XTRALEN - 1

            try:
                while True:
                    block = f.read(BLOCKSIZE)
                    if not block:
                        break
                    out.write(block)
                    downloaded += len(block)
                    pct = float(downloaded) / size
                    bar = ('=' * int(pct * bar_width))[:-1] + '>'
                    fmt = '[{bar:<%d}]{pct:>3}%%\r' % bar_width
                    sys.stderr.write(fmt.format(bar=bar, pct=int(pct * 100)))
                    sys.stderr.flush()
            finally:
                sys.stderr.write(' ' * (bar_width + XTRALEN) + '\r')
                if downloaded < size:
                    Logger.error('Partial download: %0.3f MiB of %0.3f MiB' %
                                 (downloaded / 1024.0 / 1024,
                                  size / 1024.0 / 1024))

    def _download_file(self, url, filename, dscverify=False, size=0):
        "Download url to filename in workdir."
        pathname = os.path.join(self.workdir, filename)
        if dscverify and self.dsc.verify_file(pathname):
            Logger.debug('Using existing %s', filename)
            return True

        if urlparse(url).scheme in ["", "file"]:
            frompath = os.path.abspath(urlparse(url).path)
            if frompath == pathname:
                Logger.info("Using %s" % pathname)
            else:
                Logger.info("Copying %s from %s" % (filename, frompath))
                shutil.copyfile(frompath, pathname)
        else:
            try:
                with closing(urlopen(url)) as f:
                    Logger.debug("Using URL '%s'", f.geturl())
                    if not size:
                        try:
                            size = int(f.info().get('Content-Length'))
                        except (AttributeError, TypeError, ValueError):
                            pass

                    Logger.info('Downloading %s from %s%s' %
                                (filename, urlparse(url).hostname,
                                 ' (%0.3f MiB)' % (size / 1024.0 / 1024)
                                 if size else ''))

                    self._download_file_helper(f, pathname, size)
            except HTTPError as e:
                # It's ok if the file isn't found; we try multiple places to download
                if e.code == 404:
                    return False
                raise e

        if dscverify and not self.dsc.verify_file(pathname):
            Logger.error('Checksum for %s does not match.', filename)
            return False
        return True

    def pull(self):
        "Pull into workdir"
        self._write_dsc()
        for entry in self.dsc['Files']:
            name = entry['name']
            for url in self._source_urls(name):
                try:
                    if self._download_file(url, name, dscverify=True, size=int(entry['size'])):
                        break
                except HTTPError as e:
                    Logger.info('HTTP Error %i: %s', e.code, str(e))
                except URLError as e:
                    Logger.info('URL Error: %s', e.reason)
            else:
                raise DownloadError('File %s could not be found' % name)

    def pull_binaries(self, arch=None, name=None, ext=None):
        """Pull binary debs into workdir.
        If name is specified, only binary packages matching the regex are included.

        If ext is specified, only binary packages with that ext are included; for
        example to only download dbgsym ddebs, specify ext='ddeb'.

        If arch is not specified or is 'all', pull all archs.

        Returns the number of files downloaded.
        """
        total = 0

        Logger.debug("pull_binaries(arch=%s, name=%s, ext=%s)" % (arch, name, ext))

        if arch == 'all':
            arch = None

        for bpph in self.lp_spph.getBinaries(arch=arch, name=name, ext=ext):
            fname = bpph.getFileName()
            fsha1 = bpph.binaryFileSha1(fname)
            fsha256 = bpph.binaryFileSha256(fname)
            fsize = bpph.binaryFileSize(fname)
            for url in self._binary_urls(fname, bpph):
                try:
                    if self._download_file(url, fname, False, fsize):
                        total += 1
                        break
                except HTTPError as e:
                    Logger.info('HTTP Error %i: %s', e.code, str(e))
                except URLError as e:
                    Logger.info('URL Error: %s', e.reason)
            else:
                Logger.info("Could not download from any location: %s", fname)
        return total

    def verify(self):
        """Verify that the source package in workdir matches the dsc.
        Return boolean
        """
        return all(self.dsc.verify_file(os.path.join(self.workdir,
                                                     entry['name']))
                   for entry in self.dsc['Files'])

    def verify_orig(self):
        """Verify that the .orig files in workdir match the dsc.
        Return boolean
        """
        orig_re = re.compile(r'.*\.orig(-[^.]+)?\.tar\.[^.]+$')
        return all(self.dsc.verify_file(os.path.join(self.workdir,
                                                     entry['name']))
                   for entry in self.dsc['Files']
                   if orig_re.match(entry['name']))

    def unpack(self, destdir=None):
        "Unpack in workdir"
        cmd = ['dpkg-source', '-x', self.dsc_name]
        if destdir:
            cmd.append(destdir)
        Logger.debug(' '.join(cmd))
        if subprocess.call(cmd, cwd=self.workdir):
            Logger.error('Source unpack failed.')
            sys.exit(1)

    def debdiff(self, newpkg, diffstat=False):
        """Write a debdiff comparing this src pkg to a newer one.
        Optionally print diffstat.
        Return the debdiff filename.
        """
        cmd = ['debdiff', self.dsc_name, newpkg.dsc_name]
        difffn = newpkg.dsc_name[:-3] + 'debdiff'
        Logger.debug(' '.join(cmd) + ('> %s' % difffn))
        with open(difffn, 'w') as f:
            if subprocess.call(cmd, stdout=f, cwd=self.workdir) > 2:
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
    distribution = 'debian'
    spph_class = DebianSPPH

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

    def pull_dsc(self):
        "Retrieve dscfile and parse"
        try:
            super(DebianSourcePackage, self).pull_dsc()
            return
        except DownloadError:
            pass

        # Not all Debian Source packages get imported to LP
        # (or the importer could be lagging)
        for url in self._source_urls(self.dsc_name):
            try:
                self._download_dsc(url)
            except DownloadError:
                continue
            break
        else:
            raise DownloadError('dsc could not be found anywhere')
        self._check_dsc()

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
    distribution = 'ubuntu'


class PersonalPackageArchiveSourcePackage(UbuntuSourcePackage):
    "Download / unpack an Ubuntu Personal Package Archive source package"
    def __init__(self, *args, **kwargs):
        super(PersonalPackageArchiveSourcePackage, self).__init__(*args, **kwargs)
        assert 'ppa' in kwargs
        ppa = kwargs['ppa'].split('/')
        if len(ppa) != 2:
            raise ValueError('Invalid PPA value "%s",'
                             'must be "<USER>/<PPA>"' % kwargs['ppa'])
        self._set_ppa(ppa[0], ppa[1])
        self.masters = []

    def getArchive(self):
        if not self._ppa:
            try:
                self._team = PersonTeam.fetch(self._ppateam)
            except KeyError:
                raise ValueError('No user/team "%s" found on Launchpad' % self._ppateam)
            self._ppa = self._team.getPPAByName(self._ppaname)
            Logger.debug('Using PPA %s' % self._ppa.web_link)
        return self._ppa

    def _set_ppa(self, team, name):
        self._ppateam = team
        self._ppaname = name
        self._team = None
        self._ppa = None

    def _lp_url(self, filename, source=False):
        "Build an archive file URL on Launchpad"
        if source:
            suffix = '+sourcefiles/%s/%s/%s' % (
                quote(self.source), quote(self.version.full_version),
                quote(filename))
        else:
            suffix = '+files/%s' % quote(filename)
        return 'https://launchpad.net/~%s/+archive/%s/%s/%s' % (
            quote(self._ppateam), quote(self.distribution),
            quote(self._ppaname), suffix)


class UbuntuCloudArchiveSourcePackage(PersonalPackageArchiveSourcePackage):
    "Download / unpack an Ubuntu Cloud Archive source package"
    _ppateam = 'ubuntu-cloud-archive'
    _ppas = None

    def __init__(self, *args, **kwargs):
        series = kwargs.pop('series', None)
        check_all_series = series is None
        if not series:
            series = UbuntuCloudArchiveSourcePackage.getDevelSeries()
        kwargs['ppa'] = ('%s/%s-staging' %
                         (UbuntuCloudArchiveSourcePackage._ppateam, series))
        super(UbuntuCloudArchiveSourcePackage, self).__init__(*args, **kwargs)
        self._uca_release = series
        self._check_all_series = check_all_series
        self.masters = ["http://ubuntu-cloud.archive.canonical.com/ubuntu/"]

    @classmethod
    def getDevelSeries(cls):
        return cls.ppas()[0]

    @classmethod
    def ppas(cls):
        if not cls._ppas:
            ppas = PersonTeam.fetch(cls._ppateam).getPPAs().keys()
            ppas = filter(lambda p: p.endswith('-staging'), ppas)
            ppas = map(lambda p: p.rsplit('-', 1)[0], ppas)
            ppas = sorted(ppas, reverse=True)
            if not ppas:
                raise SeriesNotFoundException('Internal Error: No UCA series found...?')
            cls._ppas = ppas
        return list(cls._ppas)

    @classmethod
    def isValidRelease(cls, release):
        return release in cls.ppas()

    @property
    def lp_spph(self):
        "Return the LP Source Package Publishing History entry"
        while True:
            try:
                return super(UbuntuCloudArchiveSourcePackage, self).lp_spph
            except PackageNotFoundException as pnfe:
                if self._check_all_series and self._set_next_release():
                    continue
                raise pnfe

    def _set_next_release(self):
        ppas = UbuntuCloudArchiveSourcePackage.ppas()
        try:
            r = ppas[ppas.index(self._uca_release) + 1]
        except IndexError:
            return False
        self._uca_release = r
        self._set_ppa(UbuntuCloudArchiveSourcePackage._ppateam, '%s-staging' % r)
        return True

    def getArchive(self):
        try:
            return super(UbuntuCloudArchiveSourcePackage, self).getArchive()
        except ValueError:
            raise SeriesNotFoundException('UCA release {} not found.'.format(self._uca_release))


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
