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

from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, build_opener, urlopen
import codecs
import hashlib
import json
import os.path
import re
import subprocess
import sys

from debian.changelog import Changelog
import debian.deb822
import httplib2

from ubuntutools.config import UDTConfig
from ubuntutools.lp.lpapicache import (Launchpad, Distribution,
                                       SourcePackagePublishingHistory,
                                       BinaryPackagePublishingHistory)
from ubuntutools.logger import Logger
from ubuntutools.version import Version


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

    def __init__(self, package=None, version=None, component=None,
                 dscfile=None, lp=None, mirrors=(), workdir='.', quiet=False):
        "Can be initialised either using package, version or dscfile"
        assert ((package is not None and version is not None)
                or dscfile is not None)

        self.source = package
        self._lp = lp
        self.workdir = workdir
        self.quiet = quiet

        # Cached values:
        self._component = component
        self._dsc = None
        self._spph = None

        # State:
        self._dsc_fetched = False

        # Mirrors
        self._dsc_source = dscfile
        self.mirrors = list(mirrors)
        if self.distribution:
            self.masters = [UDTConfig.defaults['%s_MIRROR'
                                               % self.distribution.upper()]]
        if dscfile is not None:
            if self.source is None:
                self.source = 'unknown'
            if version is None:
                version = 'unknown'

        self.version = Version(version)

        # uses default proxies from the environment
        proxy = ProxyHandler()
        self.url_opener = build_opener(proxy)

    @property
    def lp_spph(self):
        "Return the LP Source Package Publishing History entry"
        if not self._spph:
            if not Launchpad.logged_in:
                if self._lp:
                    Launchpad.login_existing(self._lp)
                else:
                    Launchpad.login_anonymously()
            spph = Distribution(self.distribution).getArchive().getPublishedSources(
                source_name=self.source,
                version=self.version.full_version,
                exact_match=True,
            )
            self._spph = SourcePackagePublishingHistory(spph[0])
        return self._spph

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

    def _mirror_url(self, mirror, filename):
        "Build a source package URL on a mirror"
        if self.source.startswith('lib'):
            group = self.source[:4]
        else:
            group = self.source[0]
        return os.path.join(mirror, 'pool', self.component, group,
                            self.source, filename)

    def _lp_url(self, filename):
        "Build a source package URL on Launchpad"
        return os.path.join('https://launchpad.net', self.distribution,
                            '+archive', 'primary', '+files', filename)

    def _source_urls(self, name):
        "Generator of sources for name"
        if self._dsc_source:
            yield os.path.join(os.path.dirname(self._dsc_source), name)
        for mirror in self.mirrors:
            yield self._mirror_url(mirror, name)
        for mirror in self.masters:
            if mirror not in self.mirrors:
                yield self._mirror_url(mirror, name)
        yield self._lp_url(name)

    def _binary_urls(self, name, default_url):
        "Generator of URLs for name"
        for mirror in self.mirrors:
            yield self._mirror_url(mirror, name)
        for mirror in self.masters:
            if mirror not in self.mirrors:
                yield self._mirror_url(mirror, name)
        yield self._lp_url(name)
        yield default_url

    def pull_dsc(self, verify_signature=False):
        "Retrieve dscfile and parse"
        if self._dsc_source:
            parsed = urlparse(self._dsc_source)
            if parsed.scheme == '':
                self._dsc_source = 'file://' + os.path.abspath(self._dsc_source)
                parsed = urlparse(self._dsc_source)
            url = self._dsc_source
        else:
            url = self._lp_url(self.dsc_name)
        self._download_dsc(url)

        self._check_dsc(verify_signature=verify_signature)

    def _download_dsc(self, url):
        "Download specified dscfile and parse"
        parsed = urlparse(url)
        if parsed.scheme == 'file':
            with open(parsed.path, 'r') as f:
                body = f.read()
        else:
            try:
                response, body = httplib2.Http().request(url)
            except httplib2.HttpLib2Error as e:
                raise DownloadError(e)
            if response.status != 200:
                raise DownloadError("%s: %s %s" % (url, response.status,
                                                   response.reason))
        self._dsc = Dsc(body)
        self._dsc_fetched = True

    def _check_dsc(self, verify_signature=False):
        "Check that the dsc matches what we are expecting"
        assert self._dsc is not None
        self.source = self.dsc['Source']
        self.version = Version(self.dsc['Version'])

        valid = False
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
        if verify_signature:
            if valid:
                Logger.normal(message)
            else:
                Logger.error(message)
                raise DownloadError(message)
        else:
            Logger.info(message)

    def _write_dsc(self, verify_signature=True):
        "Write dsc file to workdir"
        if self._dsc is None:
            self.pull_dsc(verify_signature=verify_signature)
        with open(self.dsc_pathname, 'wb') as f:
            f.write(self.dsc.raw_text)

    def _download_file(self, url, filename, verify=True):
        "Download url to filename in workdir."
        pathname = os.path.join(self.workdir, filename)
        size = 0
        if verify:
            if self.dsc.verify_file(pathname):
                Logger.debug('Using existing %s', filename)
                return True
            size = [entry['size'] for entry in self.dsc['Files']
                    if entry['name'] == filename]
            assert len(size) == 1
            size = int(size[0])

        parsed = urlparse(url)

        if parsed.scheme == 'file':
            in_ = open(parsed.path, 'rb')
            if not size:
                size = int(os.stat(parsed.path).st_size)
        else:
            try:
                in_ = self.url_opener.open(url)
                Logger.debug("Using URL '%s'", url)
            except URLError as e:
                Logger.debug("URLError opening '%s': %s", url, e)
                return False
            if not size:
                contentlen = in_.info().get('Content-Length')
                if not contentlen:
                    Logger.error("Invalid response, no Content-Length")
                    return False
                size = int(contentlen)

        if not self.quiet:
            Logger.normal('Downloading %s from %s (%0.3f MiB)',
                          filename, parsed.hostname, size / 1024.0 / 1024)

        downloaded = 0
        bar_width = 60
        try:
            with open(pathname, 'wb') as out:
                while True:
                    block = in_.read(10240)
                    if block == b'':
                        break
                    downloaded += len(block)
                    out.write(block)
                    if not self.quiet:
                        percent = downloaded * 100 // size
                        bar = '=' * int(round(downloaded * bar_width / size))
                        bar = (bar + '>' + ' ' * bar_width)[:bar_width]
                        Logger.stdout.write('[%s] %#3i%%\r' % (bar, percent))
                        Logger.stdout.flush()
            in_.close()
        finally:
            if not self.quiet:
                Logger.stdout.write(' ' * (bar_width + 7) + '\r')
                Logger.stdout.flush()
        if verify and not self.dsc.verify_file(pathname):
            Logger.error('Checksum for %s does not match.', filename)
            return False
        return True

    def pull(self, verify_signature=False):
        "Pull into workdir"
        self._write_dsc(verify_signature=verify_signature)
        for entry in self.dsc['Files']:
            name = entry['name']
            for url in self._source_urls(name):
                try:
                    if self._download_file(url, name):
                        break
                except HTTPError as e:
                    Logger.normal('HTTP Error %i: %s', e.code, str(e))
                except URLError as e:
                    Logger.normal('URL Error: %s', e.reason)
            else:
                raise DownloadError('File %s could not be found' % name)

    def pull_binaries(self, arch, name=None):
        """Pull binary debs into workdir.
        If name is specified, only binary packages matching the regex are included.
        Must specify arch, or use 'all' to pull all archs.
        Returns the number of files downloaded.
        """
        total = 0

        if not arch:
            raise RuntimeError("Must specify arch")

        for bpph in self.lp_spph.getBinaries(arch):
            if name and not re.match(name, bpph.binary_package_name):
                continue
            found = False
            for url in self._binary_urls(bpph.getFileName(), bpph.getUrl()):
                try:
                    if self._download_file(url, bpph.getFileName(), verify=False):
                        found = True
                        break
                except HTTPError as e:
                    Logger.normal('HTTP Error %i: %s', e.code, str(e))
                except URLError as e:
                    Logger.normal('URL Error: %s', e.reason)
            if found:
                total += 1
            else:
                Logger.normal("Could not download from any location: %s", bpph.getFileName())
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
        Logger.command(cmd)
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
        Logger.command(cmd + ['> %s' % difffn])
        with open(difffn, 'w') as f:
            if subprocess.call(cmd, stdout=f, cwd=self.workdir) > 2:
                Logger.error('Debdiff failed.')
                sys.exit(1)
        if diffstat:
            cmd = ('diffstat', '-p1', difffn)
            Logger.command(cmd)
            if subprocess.call(cmd):
                Logger.error('diffstat failed.')
                sys.exit(1)
        return os.path.abspath(difffn)


class DebianSourcePackage(SourcePackage):
    "Download / unpack a Debian source package"
    distribution = 'debian'

    def __init__(self, *args, **kwargs):
        super(DebianSourcePackage, self).__init__(*args, **kwargs)
        self.masters.append(UDTConfig.defaults['DEBSEC_MIRROR'])
        # Cached values:
        self._snapshot_list = None

    # Overridden methods:
    @property
    def lp_spph(self):
        "Return the LP Source Package Publishing History entry"
        if not self._spph:
            try:
                return super(DebianSourcePackage, self).lp_spph
            except IndexError:
                pass

            Logger.normal('Using rmadison for component determination')
            comp = 'main'
            for record in rmadison(self.distribution, self.source):
                if record.get('source') != self.source:
                    continue
                comp = record['component']
                if record['version'] == self.version.full_version:
                    self._spph = FakeSPPH(record['source'], record['version'],
                                          comp, 'debian')
                    return self._spph

            Logger.normal('Guessing component from most recent upload')
            self._spph = FakeSPPH(self.source, self.version.full_version, comp,
                                  'debian')
        return self._spph

    def _source_urls(self, name):
        "Generator of sources for name"
        wrapped_iterator = super(DebianSourcePackage, self)._source_urls(name)
        while True:
            try:
                yield next(wrapped_iterator)
            except StopIteration:
                break
        if self.snapshot_list:
            yield self._snapshot_url(name)

    def pull_dsc(self, verify_signature=True):
        "Retrieve dscfile and parse"
        try:
            super(DebianSourcePackage, self).pull_dsc(verify_signature)
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
        self._check_dsc(verify_signature=verify_signature)

    # Local methods:
    @property
    def snapshot_list(self):
        "Return a filename -> hash dictionary from snapshot.debian.org"
        if self._snapshot_list is None:

            try:
                data = self.url_opener.open(
                    'http://snapshot.debian.org/mr/package/%s/%s/srcfiles?fileinfo=1' %
                    (self.source, self.version.full_version))
                reader = codecs.getreader('utf-8')
                srcfiles = json.load(reader(data))

            except HTTPError:
                Logger.error('Version %s of %s not found on '
                             'snapshot.debian.org',
                             self.version.full_version, self.source)
                self._snapshot_list = False
                return False
            self._snapshot_list = dict((info[0]['name'], hash_)
                                       for hash_, info
                                       in srcfiles['fileinfo'].items())
        return self._snapshot_list

    def _snapshot_url(self, name):
        "Return the snapshot.debian.org URL for name"
        return os.path.join('http://snapshot.debian.org/file',
                            self.snapshot_list[name])


class UbuntuSourcePackage(SourcePackage):
    "Download / unpack an Ubuntu source package"
    distribution = 'ubuntu'


class UbuntuCloudArchiveSourcePackage(UbuntuSourcePackage):
    "Download / unpack an Ubuntu Cloud Archive source package"
    def __init__(self, uca_release, *args, **kwargs):
        super(UbuntuCloudArchiveSourcePackage, self).__init__(*args, **kwargs)
        self._uca_release = uca_release
        self.masters = ["http://ubuntu-cloud.archive.canonical.com/ubuntu/"]

    def _lp_url(self, filename):
        "Build a source package URL on Launchpad"
        return os.path.join('https://launchpad.net', "~ubuntu-cloud-archive",
                            '+archive', ("%s-staging" % self._uca_release),
                            '+files', filename)


class FakeSPPH(object):
    """Provide the same interface as
    ubuntutools.lpapicache.SourcePackagePublishingHistory
    """
    def __init__(self, name, version, component, distribution):
        self.name = name
        self.version = version
        self.component = component
        self.distribution = distribution
        self._changelog = None

    def getPackageName(self):
        return self.name

    def getVersion(self):
        return self.version

    def getComponent(self):
        return self.component

    def getChangelog(self, since_version=None):
        '''
        Return the changelog, optionally since a particular version
        May return None if the changelog isn't available
        '''
        if self._changelog is None:
            if self.name.startswith('lib'):
                subdir = 'lib%s' % self.name[3]
            else:
                subdir = self.name[0]
            # Strip epoch from version
            pkgversion = self.version.split(':', 1)[-1]
            extension = ''
            if self.distribution == 'debian':
                base = 'http://packages.debian.org/'
                extension = '.txt'
            elif self.distribution == 'ubuntu':
                base = 'http://changelogs.ubuntu.com/'

            url = os.path.join(base, 'changelogs', 'pool',
                               self.component, subdir, self.name,
                               self.name + '_' + pkgversion,
                               'changelog' + extension)
            try:
                self._changelog = urlopen(url).read()
            except HTTPError as error:
                print(('%s: %s' % (url, error)), file=sys.stderr)
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


def rmadison(url, package, suite=None, arch=None):
    "Call rmadison and parse the result"
    cmd = ['rmadison', '-u', url]
    if suite:
        cmd += ['-s', suite]
    if arch:
        cmd += ['-a', arch]
    cmd.append(package)
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
    output, error_output = process.communicate()
    if process.wait() != 0:
        if error_output:
            Logger.error('rmadison failed with: %s', error_output)
        else:
            Logger.error('rmadison failed')
        sys.exit(1)

    # rmadison uses some shorthand
    if suite:
        suite = suite.replace('-proposed-updates', '-p-u')

    for line in output.strip().splitlines():
        pkg, ver, dist, archs = [x.strip() for x in line.split('|')]
        comp = 'main'
        if '/' in dist:
            dist, comp = dist.split('/')
        archs = set(x.strip() for x in archs.split(','))

        # rmadison returns some results outside the requested set.
        # It'll include backports, and when given an unknown suite,
        # it ignores that argument
        #
        # some versions (2.14.1ubuntu0.1) of rmadison return 'sid' when
        # asked about 'unstable'.  Others return 'unstable'.  Accept either.
        if (suite and dist != suite and not
                (suite == 'sid' and dist == 'unstable')):
            continue

        if 'source' in archs:
            yield {
                'source': pkg,
                'version': ver,
                'suite': dist,
                'component': comp,
            }
        archs.discard('source')
        if archs:
            yield {
                'binary': pkg,
                'version': ver,
                'suite': dist,
                'component': comp,
                'architectures': archs,
            }
