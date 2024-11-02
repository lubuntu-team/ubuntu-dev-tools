# config.py - Common configuration file and environment variable handling for
#             the ubuntu-dev-tools package.
#
# Copyright (C) 2010, Stefano Rivera <stefanor@ubuntu.com>
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

import locale
import logging
import os
import pwd
import re
import shlex
import socket
import sys

Logger = logging.getLogger(__name__)


class UDTConfig:
    """Ubuntu Dev Tools configuration file (devscripts config file) and
    environment variable parsing.
    """

    no_conf = False
    # Package wide configuration variables.
    # These are reqired to be used by at least two scripts.
    defaults = {
        "BUILDER": "pbuilder",
        "DEBIAN_MIRROR": "http://deb.debian.org/debian",
        "DEBSEC_MIRROR": "http://security.debian.org",
        "DEBIAN_DDEBS_MIRROR": "http://debug.mirrors.debian.org/debian-debug",
        "LPINSTANCE": "production",
        "MIRROR_FALLBACK": True,
        "UBUNTU_MIRROR": "http://archive.ubuntu.com/ubuntu",
        "UBUNTU_PORTS_MIRROR": "http://ports.ubuntu.com",
        "UBUNTU_DDEBS_MIRROR": "http://ddebs.ubuntu.com",
        "UPDATE_BUILDER": False,
        "WORKDIR": None,
        "KEYID": None,
    }
    # Populated from the configuration files:
    config = {}

    def __init__(self, no_conf=False, prefix=None):
        self.no_conf = no_conf
        if prefix is None:
            prefix = os.path.basename(sys.argv[0]).upper().replace("-", "_")
        self.prefix = prefix
        if not no_conf:
            self.config = self.parse_devscripts_config()

    @staticmethod
    def parse_devscripts_config():
        """Read the devscripts configuration files, and return the values as a
        dictionary
        """
        config = {}
        for filename in ("/etc/devscripts.conf", "~/.devscripts"):
            try:
                f = open(os.path.expanduser(filename), "r", encoding="utf-8")
            except IOError:
                continue
            for line in f:
                parsed = shlex.split(line, comments=True)
                if len(parsed) > 1:
                    Logger.warning(
                        "Cannot parse variable assignment in %s: %s",
                        getattr(f, "name", "<config>"),
                        line,
                    )
                if len(parsed) >= 1 and "=" in parsed[0]:
                    key, value = parsed[0].split("=", 1)
                    config[key] = value
            f.close()
        return config

    def get_value(self, key, default=None, boolean=False, compat_keys=()):
        """Retrieve a value from the environment or configuration files.
        keys are prefixed with the script name, falling back to UBUNTUTOOLS for
        package-wide keys.

        Variable Priority: PREFIX_KEY, UBUNTUTOOLS_KEY, compat_keys
        Store Priority: Environment variables, user conf, system conf

        Historical variable names can be supplied via compat_keys, no prefix is
        applied to them.
        """
        if default is None and key in self.defaults:
            default = self.defaults[key]

        keys = [f"{self.prefix}_{key}"]
        if key in self.defaults:
            keys.append(f"UBUNTUTOOLS_{key}")
        keys += compat_keys

        for k in keys:
            for store in (os.environ, self.config):
                if k in store:
                    value = store[k]
                    if boolean:
                        if value in ("yes", "no"):
                            value = value == "yes"
                        else:
                            continue
                    if k in compat_keys:
                        replacements = f"{self.prefix}_{key}"
                        if key in self.defaults:
                            replacements += f"or UBUNTUTOOLS_{key}"
                        Logger.warning(
                            "Using deprecated configuration variable %s. You should use %s.",
                            k,
                            replacements,
                        )
                    return value
        return default


def ubu_email(name=None, email=None, export=True):
    """Find the developer's Ubuntu e-mail address, and export it in
    DEBFULLNAME, DEBEMAIL if necessary (and export isn't False).

    e-mail Priority: arguments, UBUMAIL, DEBEMAIL, EMAIL, user@mailname
    name Priority: arguments, UBUMAIL, DEBFULLNAME, DEBEMAIL, NAME, /etc/passwd

    Name and email are only exported if provided as arguments or found in
    UBUMAIL. Otherwise, wrapped devscripts scripts can be expected to determine
    the values themselves.

    Return name, email.
    """
    name_email_re = re.compile(r"^\s*(.+?)\s*<(.+@.+)>\s*$")

    if email:
        match = name_email_re.match(email)
        if match and not name:
            name = match.group(1)
            email = match.group(2)

    if export and not name and not email and "UBUMAIL" not in os.environ:
        export = False

    for var, target in (
        ("UBUMAIL", "email"),
        ("DEBFULLNAME", "name"),
        ("DEBEMAIL", "email"),
        ("EMAIL", "email"),
        ("NAME", "name"),
    ):
        if name and email:
            break
        if var in os.environ:
            match = name_email_re.match(os.environ[var])
            if match:
                if not name:
                    name = match.group(1)
                if not email:
                    email = match.group(2)
            elif target == "name" and not name:
                name = os.environ[var].strip()
            elif target == "email" and not email:
                email = os.environ[var].strip()

    if not name:
        gecos_name = pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip()
        if gecos_name:
            name = gecos_name

    if not email:
        mailname = socket.getfqdn()
        if os.path.isfile("/etc/mailname"):
            mailname = open("/etc/mailname", "r", encoding="utf-8").read().strip()
        email = f"{pwd.getpwuid(os.getuid()).pw_name}@{mailname}"

    if export:
        os.environ["DEBFULLNAME"] = name
        os.environ["DEBEMAIL"] = email

    # decode env var or gecos raw string with the current locale's encoding
    encoding = locale.getlocale()[1]
    if not encoding:
        encoding = "utf-8"
    if name and isinstance(name, bytes):
        name = name.decode(encoding)
    return name, email
