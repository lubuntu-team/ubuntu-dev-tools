#
# misc.py - misc functions for the Ubuntu Developer Tools scripts.
#
# Copyright (C) 2008,      Jonathan Davies <jpds@ubuntu.com>,
#               2008-2009, Siegfried-Angel Gevatter Pujals <rainct@ubuntu.com>,
#               2010,      Stefano Rivera <stefanor@ubuntu.com>
#               2011,      Evan Broder <evan@ebroder.net>
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

import distro_info
import hashlib
import locale
import os
import shutil
import sys
import tempfile

from contextlib import suppress
from subprocess import check_output, CalledProcessError
from urllib.parse import urlparse
from urllib.request import urlopen

from ubuntutools.lp.udtexceptions import PocketDoesNotExistError

import logging
Logger = logging.getLogger(__name__)


DEFAULT_POCKETS = ('Release', 'Security', 'Updates', 'Proposed')
POCKETS = DEFAULT_POCKETS + ('Backports',)

DEFAULT_STATUSES = ('Pending', 'Published')
STATUSES = DEFAULT_STATUSES + ('Superseded', 'Deleted', 'Obsolete')

UPLOAD_QUEUE_STATUSES = ('New', 'Unapproved', 'Accepted', 'Done', 'Rejected')

_system_distribution_chain = []


def system_distribution_chain():
    """ system_distribution_chain() -> [string]

    Detect the system's distribution as well as all of its parent
    distributions and return them as a list of strings, with the
    system distribution first (and the greatest grandparent last). If
    the distribution chain can't be determined, print an error message
    and return an empty list.
    """
    global _system_distribution_chain
    if len(_system_distribution_chain) == 0:
        try:
            vendor = check_output(('dpkg-vendor', '--query', 'Vendor'),
                                  encoding='utf-8').strip()
            _system_distribution_chain.append(vendor)
        except CalledProcessError:
            Logger.error('Could not determine what distribution you are running.')
            return []

        while True:
            try:
                parent = check_output((
                    'dpkg-vendor', '--vendor', _system_distribution_chain[-1],
                    '--query', 'Parent'), encoding='utf-8').strip()
            except CalledProcessError:
                # Vendor has no parent
                break
            _system_distribution_chain.append(parent)

    return _system_distribution_chain


def system_distribution():
    """ system_distro() -> string

    Detect the system's distribution and return it as a string. If the
    name of the distribution can't be determined, print an error message
    and return None.
    """
    return system_distribution_chain()[0]


def host_architecture():
    """ host_architecture -> string

    Detect the host's architecture and return it as a string. If the
    architecture can't be determined, print an error message and return None.
    """

    try:
        arch = check_output(('dpkg', '--print-architecture'),
                            encoding='utf-8').strip()
    except CalledProcessError:
        arch = None

    if not arch or 'not found' in arch:
        Logger.error('Not running on a Debian based system; '
                     'could not detect its architecture.')
        return None

    return arch


def readlist(filename, uniq=True):
    """ readlist(filename, uniq) -> list

    Read a list of words from the indicated file. If 'uniq' is True, filter
    out duplicated words.
    """

    if not os.path.isfile(filename):
        Logger.error('File "%s" does not exist.' % filename)
        return False

    with open(filename) as f:
        content = f.read().replace('\n', ' ').replace(',', ' ')

    if not content.strip():
        Logger.error('File "%s" is empty.' % filename)
        return False

    items = [item for item in content.split() if item]

    if uniq:
        items = list(set(items))

    return items


def split_release_pocket(release, default='Release'):
    '''Splits the release and pocket name.

    If the argument doesn't contain a pocket name then the 'Release' pocket
    is assumed.

    Returns the release and pocket name.
    '''
    pocket = default

    if release is None:
        raise ValueError('No release name specified')

    if '-' in release:
        (release, pocket) = release.rsplit('-', 1)
        pocket = pocket.capitalize()

        if pocket not in POCKETS:
            raise PocketDoesNotExistError("Pocket '%s' does not exist." % pocket)

    return (release, pocket)


def require_utf8():
    '''Can be called by programs that only function in UTF-8 locales'''
    if locale.getpreferredencoding() != 'UTF-8':
        Logger.error("This program only functions in a UTF-8 locale. Aborting.")
        sys.exit(1)


_vendor_to_distroinfo = {"Debian": distro_info.DebianDistroInfo,
                         "Ubuntu": distro_info.UbuntuDistroInfo}


def vendor_to_distroinfo(vendor):
    """ vendor_to_distroinfo(string) -> DistroInfo class

    Convert a string name of a distribution into a DistroInfo subclass
    representing that distribution, or None if the distribution is
    unknown.
    """
    return _vendor_to_distroinfo.get(vendor)


def codename_to_distribution(codename):
    """ codename_to_distribution(string) -> string

    Finds a given release codename in your distribution's genaology
    (i.e. looking at the current distribution and its parents), or
    print an error message and return None if it can't be found
    """
    for distro in system_distribution_chain() + ["Ubuntu", "Debian"]:
        info = vendor_to_distroinfo(distro)
        if not info:
            continue

        if info().valid(codename):
            return distro


def verify_file_checksums(pathname, checksums={}, size=0):
    """ verify checksums of file

    Any failure will log an error.

    pathname: str
        full path to file
    checksums: dict
        keys are alg name, values are expected checksum
    size: int
        size of file, if known

    Returns True if all checks pass, False otherwise
    """
    if not os.path.isfile(pathname):
        Logger.error('File not found: %s', pathname)
        return False
    filename = os.path.basename(pathname)
    if size and size != os.path.getsize(pathname):
        Logger.error('File %s incorrect size, got %s expected %s',
                     filename, os.path.getsize(pathname), size)
        return False

    for (alg, checksum) in checksums.items():
        h = hashlib.new(alg)
        with open(pathname, 'rb') as f:
            while True:
                block = f.read(h.block_size)
                if len(block) == 0:
                    break
                h.update(block)
        match = h.hexdigest() == checksum
        if match:
            Logger.debug('File %s checksum (%s) verified: %s',
                         filename, alg, checksum)
        else:
            Logger.error('File %s checksum (%s) mismatch: got %s expected %s',
                         filename, alg, h.hexdigest(), checksum)
            return False
    return True


def verify_file_checksum(pathname, alg, checksum, size=0):
    """ verify checksum of file

    pathname: str
        full path to file
    alg: str
        name of checksum alg
    checksum: str
        expected checksum
    size: int
        size of file, if known

    Returns True if all checks pass, False otherwise
    """
    return verify_file_checksums(pathname, {alg: checksum}, size)


def download(src, dst, size=0):
    """ download/copy a file/url to local file

    src: str
        Source to copy from (file path or url)
    dst: str
        Destination dir or filename
    size: int
        Size of source, if known

    This calls urllib.request.urlopen() so it may raise the same
    exceptions as that method (URLError or HTTPError)
    """
    if not urlparse(src).scheme:
        src = 'file://%s' % os.path.abspath(os.path.expanduser(src))
    dst = os.path.abspath(os.path.expanduser(dst))

    filename = os.path.basename(urlparse(src).path)

    if os.path.isdir(dst):
        dst = os.path.join(dst, filename)

    if urlparse(src).scheme == 'file':
        srcfile = urlparse(src).path
        if os.path.exists(srcfile) and os.path.exists(dst):
            if os.path.samefile(srcfile, dst):
                Logger.info(f"Using existing file {dst}")
                return

    with urlopen(src) as fsrc, open(dst, 'wb') as fdst:
        url = fsrc.geturl()
        Logger.debug(f"Using URL: {url}")

        if not size:
            with suppress(AttributeError, TypeError, ValueError):
                size = int(fsrc.info().get('Content-Length'))

        hostname = urlparse(url).hostname
        sizemb = ' (%0.3f MiB)' % (size / 1024.0 / 1024) if size else ''
        Logger.info(f'Downloading {filename} from {hostname}{sizemb}')

        if not all((Logger.isEnabledFor(logging.INFO),
                    sys.stderr.isatty(), size)):
            shutil.copyfileobj(fsrc, fdst)
            return

        blocksize = 4096
        XTRALEN = len('[] 99%')
        downloaded = 0
        bar_width = 60
        term_width = os.get_terminal_size(sys.stderr.fileno())[0]
        if term_width < bar_width + XTRALEN + 1:
            bar_width = term_width - XTRALEN - 1

        try:
            while True:
                block = fsrc.read(blocksize)
                if not block:
                    break
                fdst.write(block)
                downloaded += len(block)
                pct = float(downloaded) / size
                bar = ('=' * int(pct * bar_width))[:-1] + '>'
                fmt = '\r[{bar:<%d}]{pct:>3}%%\r' % bar_width
                sys.stderr.write(fmt.format(bar=bar, pct=int(pct * 100)))
                sys.stderr.flush()
        finally:
            sys.stderr.write('\r' + ' ' * (term_width - 1) + '\r')
            if downloaded < size:
                Logger.error('Partial download: %0.3f MiB of %0.3f MiB' %
                             (downloaded / 1024.0 / 1024,
                              size / 1024.0 / 1024))


def download_text(src):
    """ return the text content of a downloaded file

    src: str
        Source to copy from (file path or url)

    Raises the same exceptions as download()

    Returns text content of downloaded file
    """
    with tempfile.TemporaryDirectory() as d:
        dst = os.path.join(d, 'dst')
        download(src, dst)
        with open(dst) as f:
            return f.read()
