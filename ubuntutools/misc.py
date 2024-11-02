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

import hashlib
import locale
import logging
import os
import shutil
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from subprocess import CalledProcessError, check_output
from urllib.parse import urlparse

import distro_info
import requests

from ubuntutools.lp.udtexceptions import PocketDoesNotExistError

Logger = logging.getLogger(__name__)


DEFAULT_POCKETS = ("Release", "Security", "Updates", "Proposed")
POCKETS = DEFAULT_POCKETS + ("Backports",)

DEFAULT_STATUSES = ("Pending", "Published")
STATUSES = DEFAULT_STATUSES + ("Superseded", "Deleted", "Obsolete")

UPLOAD_QUEUE_STATUSES = ("New", "Unapproved", "Accepted", "Done", "Rejected")

DOWNLOAD_BLOCKSIZE_DEFAULT = 8192

_SYSTEM_DISTRIBUTION_CHAIN: list[str] = []


class DownloadError(Exception):
    "Unable to pull a source package"


class NotFoundError(DownloadError):
    "Source package not found"


def system_distribution_chain():
    """system_distribution_chain() -> [string]

    Detect the system's distribution as well as all of its parent
    distributions and return them as a list of strings, with the
    system distribution first (and the greatest grandparent last). If
    the distribution chain can't be determined, print an error message
    and return an empty list.
    """
    if len(_SYSTEM_DISTRIBUTION_CHAIN) == 0:
        try:
            vendor = check_output(("dpkg-vendor", "--query", "Vendor"), encoding="utf-8").strip()
            _SYSTEM_DISTRIBUTION_CHAIN.append(vendor)
        except CalledProcessError:
            Logger.error("Could not determine what distribution you are running.")
            return []

        while True:
            try:
                parent = check_output(
                    (
                        "dpkg-vendor",
                        "--vendor",
                        _SYSTEM_DISTRIBUTION_CHAIN[-1],
                        "--query",
                        "Parent",
                    ),
                    encoding="utf-8",
                ).strip()
            except CalledProcessError:
                # Vendor has no parent
                break
            _SYSTEM_DISTRIBUTION_CHAIN.append(parent)

    return _SYSTEM_DISTRIBUTION_CHAIN


def system_distribution():
    """system_distro() -> string

    Detect the system's distribution and return it as a string. If the
    name of the distribution can't be determined, print an error message
    and return None.
    """
    return system_distribution_chain()[0]


def host_architecture():
    """host_architecture -> string

    Detect the host's architecture and return it as a string. If the
    architecture can't be determined, print an error message and return None.
    """

    try:
        arch = check_output(("dpkg", "--print-architecture"), encoding="utf-8").strip()
    except CalledProcessError:
        arch = None

    if not arch or "not found" in arch:
        Logger.error("Not running on a Debian based system; could not detect its architecture.")
        return None

    return arch


def readlist(filename, uniq=True):
    """readlist(filename, uniq) -> list

    Read a list of words from the indicated file. If 'uniq' is True, filter
    out duplicated words.
    """
    path = Path(filename)

    if not path.is_file():
        Logger.error("File %s does not exist.", path)
        return False

    content = path.read_text(encoding="utf-8").replace("\n", " ").replace(",", " ")

    if not content.strip():
        Logger.error("File %s is empty.", path)
        return False

    items = [item for item in content.split() if item]

    if uniq:
        items = list(set(items))

    return items


def split_release_pocket(release, default="Release"):
    """Splits the release and pocket name.

    If the argument doesn't contain a pocket name then the 'Release' pocket
    is assumed.

    Returns the release and pocket name.
    """
    pocket = default

    if release is None:
        raise ValueError("No release name specified")

    if "-" in release:
        (release, pocket) = release.rsplit("-", 1)
        pocket = pocket.capitalize()

        if pocket not in POCKETS:
            raise PocketDoesNotExistError(f"Pocket '{pocket}' does not exist.")

    return (release, pocket)


def require_utf8():
    """Can be called by programs that only function in UTF-8 locales"""
    if locale.getpreferredencoding() != "UTF-8":
        Logger.error("This program only functions in a UTF-8 locale. Aborting.")
        sys.exit(1)


_vendor_to_distroinfo = {
    "Debian": distro_info.DebianDistroInfo,
    "Ubuntu": distro_info.UbuntuDistroInfo,
}


def vendor_to_distroinfo(vendor):
    """vendor_to_distroinfo(string) -> DistroInfo class

    Convert a string name of a distribution into a DistroInfo subclass
    representing that distribution, or None if the distribution is
    unknown.
    """
    return _vendor_to_distroinfo.get(vendor)


def codename_to_distribution(codename):
    """codename_to_distribution(string) -> string

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
    return None


def verify_file_checksums(pathname, checksums=None, size=0):
    """verify checksums of file

    Any failure will log an error.

    pathname: str or Path
        full path to file
    checksums: dict
        keys are alg name, values are expected checksum
    size: int
        size of file, if known

    Returns True if all checks pass, False otherwise
    """
    if checksums is None:
        checksums = {}
    path = Path(pathname)

    if not path.is_file():
        Logger.error("File %s not found", path)
        return False
    filesize = path.stat().st_size
    if size and size != filesize:
        Logger.error("File %s incorrect size, got %s expected %s", path, filesize, size)
        return False

    for alg, checksum in checksums.items():
        hash_ = hashlib.new(alg)
        with path.open("rb") as f:
            while True:
                block = f.read(hash_.block_size)
                if len(block) == 0:
                    break
                hash_.update(block)
        digest = hash_.hexdigest()
        if digest == checksum:
            Logger.debug("File %s checksum (%s) verified: %s", path, alg, checksum)
        else:
            Logger.error(
                "File %s checksum (%s) mismatch: got %s expected %s", path, alg, digest, checksum
            )
            return False
    return True


def verify_file_checksum(pathname, alg, checksum, size=0):
    """verify checksum of file

    pathname: str or Path
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


def extract_authentication(url):
    """Remove plaintext authentication data from a URL

    If the URL has a username:password in its netloc, this removes it
    and returns the remaining URL, along with the username and password
    separately. If no authentication data is in the netloc, this just
    returns the URL unchanged with None for the username and password.

    This returns a tuple in the form (url, username, password)
    """
    components = urlparse(url)
    if components.username or components.password:
        return (
            components._replace(netloc=components.hostname).geturl(),
            components.username,
            components.password,
        )
    return (url, None, None)


def download(src, dst, size=0, *, blocksize=DOWNLOAD_BLOCKSIZE_DEFAULT):
    """download/copy a file/url to local file

    src: str or Path
        Source to copy from (file path or url)
    dst: str or Path
        Destination dir or filename
    size: int
        Size of source, if known
    blocksize: int or None
        Blocksize to use when downloading

    If the URL contains authentication data in the URL 'netloc',
    it will be stripped from the URL and passed to the requests library.

    This may throw a DownloadError.

    On success, this will return the dst as a Path object.
    """
    src = str(src)
    parsedsrc = urlparse(src)

    dst = Path(dst).expanduser().resolve()
    if dst.is_dir():
        dst = dst / Path(parsedsrc.path).name

    # Copy if src is a local file
    if parsedsrc.scheme in ["", "file"]:
        src = Path(parsedsrc.path).expanduser().resolve()
        if src != parsedsrc.path:
            Logger.info("Parsed %s as %s", parsedsrc.path, src)
        if not src.exists():
            raise NotFoundError(f"Source file {src} not found")
        if dst.exists():
            if src.samefile(dst):
                Logger.info("Using existing file %s", dst)
                return dst
            Logger.info("Replacing existing file %s", dst)
        Logger.info("Copying file %s to %s", src, dst)
        shutil.copyfile(src, dst)
        return dst

    (src, username, password) = extract_authentication(src)
    auth = (username, password) if username or password else None

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdst = Path(tmpdir) / "dst"
        try:
            # We must use "Accept-Encoding: identity" so that Launchpad doesn't
            # compress changes files. See LP: #2025748.
            with requests.get(
                src, stream=True, timeout=60, auth=auth, headers={"accept-encoding": "identity"}
            ) as fsrc:
                with tmpdst.open("wb") as fdst:
                    fsrc.raise_for_status()
                    _download(fsrc, fdst, size, blocksize=blocksize)
        except requests.exceptions.HTTPError as error:
            if error.response is not None and error.response.status_code == 404:
                raise NotFoundError(f"URL {src} not found: {error}") from error
            raise DownloadError(error) from error
        except requests.exceptions.ConnectionError as error:
            # This is likely a archive hostname that doesn't resolve, like 'ftpmaster.internal'
            raise NotFoundError(f"URL {src} not found: {error}") from error
        except requests.exceptions.RequestException as error:
            raise DownloadError(error) from error
        shutil.move(tmpdst, dst)
    return dst


class _StderrProgressBar:
    BAR_WIDTH_MIN = 40
    BAR_WIDTH_DEFAULT = 60

    def __init__(self, max_width):
        self.full_width = min(max_width, self.BAR_WIDTH_DEFAULT)
        self.width = self.full_width - len("[] 99%")
        self.show_progress = self.full_width >= self.BAR_WIDTH_MIN

    def update(self, progress, total):
        if not self.show_progress:
            return
        pct = progress * 100 // total
        pctstr = f"{pct:>3}%"
        barlen = self.width * pct // 100
        barstr = "=" * barlen
        barstr = f"{barstr[:-1]}>"
        barstr = barstr.ljust(self.width)
        fullstr = f"\r[{barstr}]{pctstr}"
        sys.stderr.write(fullstr)
        sys.stderr.flush()

    def finish(self):
        if not self.show_progress:
            return
        sys.stderr.write("\n")
        sys.stderr.flush()


def _download(fsrc, fdst, size, *, blocksize):
    """helper method to download src to dst using requests library."""
    url = fsrc.url
    Logger.debug("Using URL: %s", url)

    if not size:
        with suppress(AttributeError, TypeError, ValueError):
            size = int(fsrc.headers.get("Content-Length"))

    parsed = urlparse(url)
    filename = Path(parsed.path).name
    hostname = parsed.hostname
    sizemb = f" ({size / 1024.0 / 1024:0.3f} MiB)" if size else ""
    Logger.info("Downloading %s from %s%s", filename, hostname, sizemb)

    # Don't show progress if:
    #   logging INFO is suppressed
    #   stderr isn't a tty
    #   we don't know the total file size
    #   the file is content-encoded (i.e. compressed)
    show_progress = all(
        (
            Logger.isEnabledFor(logging.INFO),
            sys.stderr.isatty(),
            size > 0,
            "Content-Encoding" not in fsrc.headers,
        )
    )

    terminal_width = 0
    if show_progress:
        try:
            terminal_width = os.get_terminal_size(sys.stderr.fileno()).columns
        except Exception as e:  # pylint: disable=broad-except
            Logger.error("Error finding stderr width, suppressing progress bar: %s", e)
    progress_bar = _StderrProgressBar(max_width=terminal_width)

    downloaded = 0
    try:
        while True:
            # We use fsrc.raw so that compressed files stay compressed as we
            # write them to disk. For example, if this is a .diff.gz, then it
            # needs to remain compressed and unmodified to remain valid as part
            # of a source package later, even though Launchpad sends
            # "Content-Encoding: gzip" and the requests library therefore would
            # want to decompress it. See LP: #2025748.
            block = fsrc.raw.read(blocksize)
            if not block:
                break
            fdst.write(block)
            downloaded += len(block)
            progress_bar.update(downloaded, size)
    finally:
        progress_bar.finish()
        if size and size > downloaded:
            Logger.error(
                "Partial download: %0.3f MiB of %0.3f MiB",
                downloaded / 1024.0 / 1024,
                size / 1024.0 / 1024,
            )


def _download_text(src, binary, *, blocksize):
    with tempfile.TemporaryDirectory() as tmpdir:
        dst = Path(tmpdir) / "dst"
        download(src, dst, blocksize=blocksize)
        return dst.read_bytes() if binary else dst.read_text()


def download_text(src, mode=None, *, blocksize=DOWNLOAD_BLOCKSIZE_DEFAULT):
    """Return the text content of a downloaded file

    src: str or Path
        Source to copy from (file path or url)
    mode: str
        Deprecated, ignored unless a string that contains 'b'
    blocksize: int or None
        Blocksize to use when downloading

    Raises the same exceptions as download()

    Returns text content of downloaded file
    """
    return _download_text(src, binary="b" in (mode or ""), blocksize=blocksize)


def download_bytes(src, *, blocksize=DOWNLOAD_BLOCKSIZE_DEFAULT):
    """Same as download_text() but returns bytes"""
    return _download_text(src, binary=True, blocksize=blocksize)
