# Copyright (C) 2019-2023 Canonical Ltd.
# Author: Brian Murray <brian.murray@canonical.com> et al.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Portions of archive related code that is re-used by various tools."""

import os
import re
import urllib.request
from datetime import datetime

import dateutil.parser
from dateutil.tz import tzutc


def get_cache_dir():
    cache_dir = os.environ.get("XDG_CACHE_HOME", os.path.expanduser(os.path.join("~", ".cache")))
    uat_cache = os.path.join(cache_dir, "ubuntu-archive-tools")
    os.makedirs(uat_cache, exist_ok=True)
    return uat_cache


def get_url(url, force_cached):
    """Return file to the URL, possibly caching it"""
    cache_file = None

    # ignore bileto urls wrt caching, they're usually too small to matter
    # and we don't do proper cache expiry
    m = re.search("ubuntu-archive-team.ubuntu.com/proposed-migration/([^/]*)/([^/]*)", url)
    if m:
        cache_dir = get_cache_dir()
        cache_file = os.path.join(cache_dir, "%s_%s" % (m.group(1), m.group(2)))
    else:
        # test logs can be cached, too
        m = re.search(
            "https://autopkgtest.ubuntu.com/results/autopkgtest-[^/]*/([^/]*)/([^/]*)"
            "/[a-z0-9]*/([^/]*)/([_a-f0-9]*)@/log.gz",
            url,
        )
        if m:
            cache_dir = get_cache_dir()
            cache_file = os.path.join(
                cache_dir, "%s_%s_%s_%s.gz" % (m.group(1), m.group(2), m.group(3), m.group(4))
            )

    if cache_file:
        try:
            prev_mtime = os.stat(cache_file).st_mtime
        except FileNotFoundError:
            prev_mtime = 0
        prev_timestamp = datetime.fromtimestamp(prev_mtime, tz=tzutc())
        new_timestamp = datetime.now(tz=tzutc()).timestamp()
        if force_cached:
            return open(cache_file, "rb")

    f = urllib.request.urlopen(url)

    if cache_file:
        remote_ts = dateutil.parser.parse(f.headers["last-modified"])
        if remote_ts > prev_timestamp:
            with open("%s.new" % cache_file, "wb") as new_cache:
                for line in f:
                    new_cache.write(line)
            os.rename("%s.new" % cache_file, cache_file)
            os.utime(cache_file, times=(new_timestamp, new_timestamp))
        f.close()
        f = open(cache_file, "rb")
    return f
