# Copyright (C) 2011, Stefano Rivera <stefanor@ubuntu.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import json
import os

import httplib2


class RDependsException(Exception):
    pass


def query_rdepends(package, release, arch, server="http://qa.ubuntuwire.org/rdepends"):
    """Look up a packages reverse-dependencies on the Ubuntuwire
    Reverse- webservice
    """

    url = os.path.join(server, "v1", release, arch, package)

    response, data = httplib2.Http().request(url)
    if response.status != 200:
        raise RDependsException(data.strip())
    return json.loads(data)
