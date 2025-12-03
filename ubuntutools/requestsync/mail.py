# -*- coding: utf-8 -*-
#
#   mail.py - methods used by requestsync when used in "mail" mode
#
#   Copyright © 2009 Michael Bienia <geser@ubuntu.com>,
#               2011 Stefano Rivera <stefanor@ubuntu.com>
#
#   This module may contain code written by other authors/contributors to
#   the main requestsync script. See there for their names.
#
#   This program is free software; you can redistribute it and/or
#   modify it under the terms of the GNU General Public License
#   as published by the Free Software Foundation; version 2
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   Please see the /usr/share/common-licenses/GPL-2 file for the full text
#   of the GNU General Public License license.

import logging
import os
import re
import smtplib
import socket
import subprocess
import sys
import tempfile

from debian.changelog import Changelog
from distro_info import DebianDistroInfo, DistroDataOutdated

from ubuntutools.archive import DebianSourcePackage, UbuntuSourcePackage
from ubuntutools.lp.udtexceptions import PackageNotFoundException
from ubuntutools.question import YesNoQuestion, confirmation_prompt

Logger = logging.getLogger(__name__)


__all__ = [
    "get_debian_srcpkg",
    "get_ubuntu_srcpkg",
    "need_sponsorship",
    "check_existing_reports",
    "get_ubuntu_delta_changelog",
    "mail_bug",
]


def get_debian_srcpkg(name, release):
    # Canonicalise release:
    debian_info = DebianDistroInfo()
    try:
        codename = debian_info.codename(release, default=release)
        return DebianSourcePackage(package=name, series=codename).lp_spph
    except DistroDataOutdated as e:
        Logger.warning(e)
    except PackageNotFoundException:
        pass
    return DebianSourcePackage(package=name, series=release).lp_spph


def get_ubuntu_srcpkg(name, release, pocket="Proposed"):
    srcpkg = UbuntuSourcePackage(package=name, series=release, pocket=pocket)
    try:
        return srcpkg.lp_spph
    except PackageNotFoundException:
        if pocket != "Release":
            parent_pocket = "Release"
            if pocket == "Updates":
                parent_pocket = "Proposed"
            return get_ubuntu_srcpkg(name, release, parent_pocket)
        raise


def need_sponsorship(name, component, release):
    """
    Ask the user if he has upload permissions for the package or the
    component.
    """

    val = YesNoQuestion().ask(
        f"Do you have upload permissions for the '{component}' component or "
        f"the package '{name}' in Ubuntu {release}?\nIf in doubt answer 'n'.",
        "no",
    )
    return val == "no"


def check_existing_reports(srcpkg):
    """
    Point the user to the URL to manually check for duplicate bug reports.
    """
    print(
        f"Please check on https://bugs.launchpad.net/ubuntu/+source/{srcpkg}/+bugs\n"
        f"for duplicate sync requests before continuing."
    )
    confirmation_prompt()


def get_ubuntu_delta_changelog(srcpkg):
    """
    Download the Ubuntu changelog and extract the entries since the last sync
    from Debian.
    """
    changelog = Changelog(srcpkg.getChangelog())
    if changelog is None:
        return ""
    delta = []
    debian_info = DebianDistroInfo()
    for block in changelog:
        distribution = block.distributions.split()[0].split("-")[0]
        if debian_info.valid(distribution):
            break
        delta += [str(change) for change in block.changes() if change.strip()]

    return "\n".join(delta)


def mail_bug(
    srcpkg,
    subscribe,
    status,
    bugtitle,
    bugtext,
    bug_mail_domain,
    keyid,
    myemailaddr,
    mailserver_host,
    mailserver_port,
    mailserver_user,
    mailserver_pass,
):
    """
    Submit the sync request per email.
    """

    to = f"new@{bug_mail_domain}"

    # generate mailbody
    if srcpkg:
        mailbody = f" affects ubuntu/{srcpkg}\n"
    else:
        mailbody = " affects ubuntu\n"
    mailbody += f"""\
 status {status}
 importance wishlist
 subscribe {subscribe}
 done

{bugtext}"""

    # prepare sign command
    gpg_command = None
    for cmd in ("gnome-gpg", "gpg2", "gpg"):
        if os.access(f"/usr/bin/{cmd}", os.X_OK):
            gpg_command = [cmd]
            break

    if not gpg_command:
        Logger.error("Cannot locate gpg, please install the 'gnupg' package!")
        sys.exit(1)

    gpg_command.append("--clearsign")
    if keyid:
        gpg_command.extend(("-u", keyid))

    # sign the mail body
    gpg = subprocess.Popen(
        gpg_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding="utf-8"
    )
    signed_report = gpg.communicate(mailbody)[0]
    if gpg.returncode != 0:
        Logger.error("%s failed.", gpg_command[0])
        sys.exit(1)

    # generate email
    mail = f"""\
From: {myemailaddr}
To: {to}
Subject: {bugtitle}
Content-Type: text/plain; charset=UTF-8

{signed_report}"""

    print(f"The final report is:\n{mail}")
    confirmation_prompt()

    # save mail in temporary file
    backup = tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        prefix=f"requestsync-{re.sub('[^a-zA-Z0-9_-]', '', bugtitle.replace(' ', '_'))}",
    )
    with backup:
        backup.write(mail)

    Logger.info(
        "The e-mail has been saved in %s and will be deleted after succesful transmission",
        backup.name,
    )

    # connect to the server
    while True:
        try:
            Logger.info("Connecting to %s:%s ...", mailserver_host, mailserver_port)
            smtp = smtplib.SMTP(mailserver_host, mailserver_port)
            break
        except smtplib.SMTPConnectError as error:
            try:
                # py2 path
                # pylint: disable=unsubscriptable-object
                Logger.error(
                    "Could not connect to %s:%s: %s (%i)",
                    mailserver_host,
                    mailserver_port,
                    error[1],
                    error[0],
                )
            except TypeError:
                # pylint: disable=no-member
                Logger.error(
                    "Could not connect to %s:%s: %s (%i)",
                    mailserver_host,
                    mailserver_port,
                    error.strerror,
                    error.errno,
                )
            if error.smtp_code == 421:
                confirmation_prompt(
                    message="This is a temporary error, press [Enter] "
                    "to retry. Press [Ctrl-C] to abort now."
                )
        except socket.error as error:
            try:
                # py2 path
                # pylint: disable=unsubscriptable-object
                Logger.error(
                    "Could not connect to %s:%s: %s (%i)",
                    mailserver_host,
                    mailserver_port,
                    error[1],
                    error[0],
                )
            except TypeError:
                # pylint: disable=no-member
                Logger.error(
                    "Could not connect to %s:%s: %s (%i)",
                    mailserver_host,
                    mailserver_port,
                    error.strerror,
                    error.errno,
                )
            return

    if mailserver_user and mailserver_pass:
        try:
            smtp.login(mailserver_user, mailserver_pass)
        except smtplib.SMTPAuthenticationError:
            Logger.error("Error authenticating to the server: invalid username and password.")
            smtp.quit()
            return
        except smtplib.SMTPException:
            Logger.error("Unknown SMTP error.")
            smtp.quit()
            return

    while True:
        try:
            smtp.sendmail(myemailaddr, to, mail.encode("utf-8"))
            smtp.quit()
            os.remove(backup.name)
            Logger.info("Sync request mailed.")
            break
        except smtplib.SMTPRecipientsRefused as smtperror:
            smtp_code, smtp_message = smtperror.recipients[to]
            Logger.error("Error while sending: %i, %s", smtp_code, smtp_message)
            if smtp_code == 450:
                confirmation_prompt(
                    message="This is a temporary error, press [Enter] "
                    "to retry. Press [Ctrl-C] to abort now."
                )
            else:
                return
        except smtplib.SMTPResponseException as error:
            Logger.error("Error while sending: %i, %s", error.smtp_code, error.smtp_error)
            return
        except smtplib.SMTPServerDisconnected:
            Logger.error("Server disconnected while sending the mail.")
            return
