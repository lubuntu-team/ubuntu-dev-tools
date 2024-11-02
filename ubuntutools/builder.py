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

import logging
import os
import subprocess

Logger = logging.getLogger(__name__)


def _build_preparation(result_directory):
    """prepares the builder for building a package"""
    if not os.path.isdir(result_directory):
        os.makedirs(result_directory)


class Builder:
    def __init__(self, name):
        self.name = name
        cmd = ["dpkg-architecture", "-qDEB_BUILD_ARCH_CPU"]
        self.architecture = subprocess.check_output(cmd, encoding="utf-8").strip()

    def _build_failure(self, returncode, dsc_file):
        if returncode != 0:
            Logger.error(
                "Failed to build %s from source with %s.", os.path.basename(dsc_file), self.name
            )
        return returncode

    def exists_in_path(self):
        for path in os.environ.get("PATH", os.defpath).split(os.pathsep):
            if os.path.isfile(os.path.join(path, self.name)):
                return True
        return False

    def get_architecture(self):
        return self.architecture

    def get_name(self):
        return self.name

    def _update_failure(self, returncode, dist):
        if returncode != 0:
            Logger.error("Failed to update %s chroot for %s.", dist, self.name)
        return returncode


class Pbuilder(Builder):
    def __init__(self, name="pbuilder"):
        Builder.__init__(self, name)

    def build(self, dsc_file, dist, result_directory):
        _build_preparation(result_directory)
        cmd = [
            "sudo",
            "-E",
            f"ARCH={self.architecture}",
            f"DIST={dist}",
            self.name,
            "--build",
            "--architecture",
            self.architecture,
            "--distribution",
            dist,
            "--buildresult",
            result_directory,
            dsc_file,
        ]
        Logger.debug(" ".join(cmd))
        returncode = subprocess.call(cmd)
        return self._build_failure(returncode, dsc_file)

    def update(self, dist):
        cmd = [
            "sudo",
            "-E",
            f"ARCH={self.architecture}",
            f"DIST={dist}",
            self.name,
            "--update",
            "--architecture",
            self.architecture,
            "--distribution",
            dist,
        ]
        Logger.debug(" ".join(cmd))
        returncode = subprocess.call(cmd)
        return self._update_failure(returncode, dist)


class Pbuilderdist(Builder):
    def __init__(self, name="pbuilder-dist"):
        Builder.__init__(self, name)

    def build(self, dsc_file, dist, result_directory):
        _build_preparation(result_directory)
        cmd = [
            self.name,
            dist,
            self.architecture,
            "build",
            dsc_file,
            "--buildresult",
            result_directory,
        ]
        Logger.debug(" ".join(cmd))
        returncode = subprocess.call(cmd)
        return self._build_failure(returncode, dsc_file)

    def update(self, dist):
        cmd = [self.name, dist, self.architecture, "update"]
        Logger.debug(" ".join(cmd))
        returncode = subprocess.call(cmd)
        return self._update_failure(returncode, dist)


class Sbuild(Builder):
    def __init__(self):
        Builder.__init__(self, "sbuild")

    def build(self, dsc_file, dist, result_directory):
        _build_preparation(result_directory)
        workdir = os.getcwd()
        Logger.debug("cd %s", result_directory)
        os.chdir(result_directory)
        cmd = ["sbuild", "--arch-all", f"--dist={dist}", f"--arch={self.architecture}", dsc_file]
        Logger.debug(" ".join(cmd))
        returncode = subprocess.call(cmd)
        Logger.debug("cd %s", workdir)
        os.chdir(workdir)
        return self._build_failure(returncode, dsc_file)

    def update(self, dist):
        cmd = ["schroot", "--list"]
        Logger.debug(" ".join(cmd))
        process = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, encoding="utf-8")
        chroots, _ = process.stdout.strip().split()
        if process.returncode != 0:
            return process.returncode

        params = {"dist": dist, "arch": self.architecture}
        for chroot in (
            "%(dist)s-%(arch)s-sbuild-source",
            "%(dist)s-sbuild-source",
            "%(dist)s-%(arch)s-source",
            "%(dist)s-source",
        ):
            chroot = chroot % params
            if chroot in chroots:
                break
        else:
            return 1

        commands = [["sbuild-update"], ["sbuild-distupgrade"], ["sbuild-clean", "-a", "-c"]]
        for cmd in commands:
            # pylint: disable=W0631
            Logger.debug("%s %s", " ".join(cmd), chroot)
            ret = subprocess.call(cmd + [chroot])
            # pylint: enable=W0631
            if ret != 0:
                return self._update_failure(ret, dist)
        return 0


_SUPPORTED_BUILDERS = {
    "cowbuilder": lambda: Pbuilder("cowbuilder"),
    "cowbuilder-dist": lambda: Pbuilderdist("cowbuilder-dist"),
    "pbuilder": Pbuilder,
    "pbuilder-dist": Pbuilderdist,
    "sbuild": Sbuild,
}


def get_builder(name):
    if name in _SUPPORTED_BUILDERS:
        builder = _SUPPORTED_BUILDERS[name]()
        if builder.exists_in_path():
            return builder
        Logger.error("Builder doesn't appear to be installed: %s", name)
    else:
        Logger.error("Unsupported builder specified: %s.", name)
        Logger.error("Supported builders: %s", ", ".join(sorted(_SUPPORTED_BUILDERS.keys())))
    return None
