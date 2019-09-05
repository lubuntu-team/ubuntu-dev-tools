#
#   libsupport.py - functions which add launchpadlib support to the Ubuntu
#                     Developer Tools package.
#
#   Copyright (C) 2009 Markus Korn <thekorn@gmx.de>
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; either version 3
#   of the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   Please see the /usr/share/common-licenses/GPL file for the full text of
#   the GNU General Public License license.
#

from urllib.parse import urlsplit, urlencode, urlunsplit


def query_to_dict(query_string):
    result = dict()
    options = filter(None, query_string.split("&"))
    for opt in options:
        key, value = opt.split("=")
        result.setdefault(key, set()).add(value)
    return result


def translate_web_api(url, launchpad):
    scheme, netloc, path, query, fragment = urlsplit(url)
    query = query_to_dict(query)

    differences = set(netloc.split('.')).symmetric_difference(
            set(launchpad._root_uri.host.split('.')))
    if ('staging' in differences or 'edge' in differences):
        raise ValueError("url conflict (url: %s, root: %s" %
                         (url, launchpad._root_uri))
    if path.endswith("/+bugs"):
        path = path[:-6]
        if "ws.op" in query:
            raise ValueError("Invalid web url, url: %s" % url)
        query["ws.op"] = "searchTasks"
    scheme, netloc, api_path, _, _ = urlsplit(str(launchpad._root_uri))
    query = urlencode(query)
    url = urlunsplit((scheme, netloc, api_path + path.lstrip("/"), query, fragment))
    return url
