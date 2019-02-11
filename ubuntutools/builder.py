#   builder.py - Helper classes for building packages
#
#   Copyright (C) 2010, Benjamin Drung <bdrung@ubuntu.com>
#   Copyright (C) 2010, Evan Broder <evan@ebroder.net>
#
#   Permission to use, copy, modify, and/or distribute this software
#   for any purpose with or without fee is hereby granted, provided
#   that the above copyright notice and this permission notice appear
#   in all copies.
#
#   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
#   WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
#   AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
#   CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
#   LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
#   NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
#   CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import os
import subprocess

from ubuntutools.logger import Logger


def _build_preparation(result_directory):
    """prepares the builder for building a package"""
    if not os.path.isdir(result_directory):
        os.makedirs(result_directory)


class Builder(object):
    def __init__(self, name):
        self.name = name
        cmd = ["dpkg-architecture", "-qDEB_BUILD_ARCH_CPU"]
        self.architecture = subprocess.check_output(cmd, encoding='utf-8').strip()

    def _build_failure(self, returncode, dsc_file):
        if returncode != 0:
            Logger.error("Failed to build %s from source with %s." %
                         (os.path.basename(dsc_file), self.name))
        return returncode

    def exists_in_path(self):
        for path in os.environ.get('PATH', os.defpath).split(os.pathsep):
            if os.path.isfile(os.path.join(path, self.name)):
                return True
        return False

    def get_architecture(self):
        return self.architecture

    def get_name(self):
        return self.name

    def _update_failure(self, returncode, dist):
        if returncode != 0:
            Logger.error("Failed to update %s chroot for %s." %
                         (dist, self.name))
        return returncode


class Pbuilder(Builder):
    def __init__(self, name="pbuilder"):
        Builder.__init__(self, name)

    def build(self, dsc_file, dist, result_directory):
        _build_preparation(result_directory)
        cmd = ["sudo", "-E", "ARCH=" + self.architecture, "DIST=" + dist,
               self.name, "--build",
               "--architecture", self.architecture, "--distribution", dist,
               "--buildresult", result_directory, dsc_file]
        Logger.command(cmd)
        returncode = subprocess.call(cmd)
        return self._build_failure(returncode, dsc_file)

    def update(self, dist):
        cmd = ["sudo", "-E", "ARCH=" + self.architecture, "DIST=" + dist,
               self.name, "--update",
               "--architecture", self.architecture, "--distribution", dist]
        Logger.command(cmd)
        returncode = subprocess.call(cmd)
        return self._update_failure(returncode, dist)


class Pbuilderdist(Builder):
    def __init__(self, name="pbuilder-dist"):
        Builder.__init__(self, name)

    def build(self, dsc_file, dist, result_directory):
        _build_preparation(result_directory)
        cmd = [self.name, dist, self.architecture,
               "build", dsc_file, "--buildresult", result_directory]
        Logger.command(cmd)
        returncode = subprocess.call(cmd)
        return self._build_failure(returncode, dsc_file)

    def update(self, dist):
        cmd = [self.name, dist, self.architecture, "update"]
        Logger.command(cmd)
        returncode = subprocess.call(cmd)
        return self._update_failure(returncode, dist)


class Sbuild(Builder):
    def __init__(self):
        Builder.__init__(self, "sbuild")

    def build(self, dsc_file, dist, result_directory):
        _build_preparation(result_directory)
        workdir = os.getcwd()
        Logger.command(["cd", result_directory])
        os.chdir(result_directory)
        cmd = ["sbuild", "--arch-all", "--dist=" + dist,
               "--arch=" + self.architecture, dsc_file]
        Logger.command(cmd)
        returncode = subprocess.call(cmd)
        Logger.command(["cd", workdir])
        os.chdir(workdir)
        return self._build_failure(returncode, dsc_file)

    def update(self, dist):
        cmd = ["schroot", "--list"]
        Logger.command(cmd)
        process = subprocess.run(cmd, stdout=subprocess.PIPE, encoding='utf-8')
        chroots, _ = process.stdout.strip().split()
        if process.returncode != 0:
            return process.returncode

        params = {"dist": dist, "arch": self.architecture}
        for chroot in ("%(dist)s-%(arch)s-sbuild-source",
                       "%(dist)s-sbuild-source",
                       "%(dist)s-%(arch)s-source",
                       "%(dist)s-source"):
            chroot = chroot % params
            if chroot in chroots:
                break
        else:
            return 1

        commands = [["sbuild-update"],
                    ["sbuild-distupgrade"],
                    ["sbuild-clean", "-a", "-c"]]
        for cmd in commands:
            # pylint: disable=W0631
            Logger.command(cmd + [chroot])
            ret = subprocess.call(cmd + [chroot])
            # pylint: enable=W0631
            if ret != 0:
                return self._update_failure(ret, dist)
        return 0


_SUPPORTED_BUILDERS = {
    "cowbuilder": lambda: Pbuilder("cowbuilder"),
    "cowbuilder-dist": lambda: Pbuilderdist("cowbuilder-dist"),
    "pbuilder": lambda: Pbuilder(),
    "pbuilder-dist": lambda: Pbuilderdist(),
    "sbuild": lambda: Sbuild(),
}


def get_builder(name):
    if name in _SUPPORTED_BUILDERS:
        builder = _SUPPORTED_BUILDERS[name]()
        if builder.exists_in_path():
            return builder
        Logger.error("Builder doesn't appear to be installed: %s", name)
    else:
        Logger.error("Unsupported builder specified: %s.", name)
        Logger.error("Supported builders: %s",
                     ", ".join(sorted(_SUPPORTED_BUILDERS.keys())))
