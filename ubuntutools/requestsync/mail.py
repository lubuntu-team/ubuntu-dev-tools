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

import os
import sys
import smtplib
import socket

from debian.changelog import Changelog, Version
from devscripts.logger import Logger
from distro_info import DebianDistroInfo

from ubuntutools.archive import rmadison, FakeSPPH
from ubuntutools.question import confirmation_prompt, YesNoQuestion
from ubuntutools import subprocess
from ubuntutools.lp.udtexceptions import PackageNotFoundException

__all__ = [
    'get_debian_srcpkg',
    'get_ubuntu_srcpkg',
    'need_sponsorship',
    'check_existing_reports',
    'get_ubuntu_delta_changelog',
    'mail_bug',
]

def _get_srcpkg(distro, name, release):
    if distro == 'debian':
        # Canonicalise release:
        debian_info = DebianDistroInfo()
        release = debian_info.codename(release, default=release)

    lines = list(rmadison(distro, name, suite=release, arch='source'))
    if not lines:
        raise PackageNotFoundException("'%s' doesn't appear to exist "
                                       "in %s '%s'"
                                       % (name, distro.capitalize(), release))
    pkg = max(lines, key=lambda x: Version(x['version']))

    return FakeSPPH(pkg['source'], pkg['version'], pkg['component'], distro)

def get_debian_srcpkg(name, release):
    return _get_srcpkg('debian', name, release)

def get_ubuntu_srcpkg(name, release):
    return _get_srcpkg('ubuntu', name, release)

def need_sponsorship(name, component, release):
    '''
    Ask the user if he has upload permissions for the package or the
    component.
    '''

    val = YesNoQuestion().ask("Do you have upload permissions for the "
                              "'%s' component or the package '%s' in "
                              "Ubuntu %s?\n"
                              "If in doubt answer 'n'."
                               % (component, name, release), 'no')
    return val == 'no'

def check_existing_reports(srcpkg):
    '''
    Point the user to the URL to manually check for duplicate bug reports.
    '''
    print ('Please check on '
           'https://bugs.launchpad.net/ubuntu/+source/%s/+bugs\n'
           'for duplicate sync requests before continuing.' % srcpkg)
    confirmation_prompt()

def get_ubuntu_delta_changelog(srcpkg):
    '''
    Download the Ubuntu changelog and extract the entries since the last sync
    from Debian.
    '''
    changelog = Changelog(srcpkg.getChangelog())
    if changelog is None:
        return u''
    delta = []
    debian_info = DebianDistroInfo()
    for block in changelog:
        distribution = block.distributions.split()[0].split('-')[0]
        if debian_info.valid(distribution):
            break
        delta += [unicode(change) for change in block.changes()
                  if change.strip()]

    return u'\n'.join(delta)

def mail_bug(srcpkg, subscribe, status, bugtitle, bugtext, bug_mail_domain,
             keyid, myemailaddr, mailserver_host, mailserver_port,
             mailserver_user, mailserver_pass):
    '''
    Submit the sync request per email.
    '''

    to = 'new@' + bug_mail_domain

    # generate mailbody
    if srcpkg:
        mailbody = ' affects ubuntu/%s\n' % srcpkg
    else:
        mailbody = ' affects ubuntu\n'
    mailbody += '''\
 status %s
 importance wishlist
 subscribe %s
 done

%s''' % (status, subscribe, bugtext)

    # prepare sign command
    gpg_command = None
    for cmd in ('gnome-gpg', 'gpg2', 'gpg'):
        if os.access('/usr/bin/%s' % cmd, os.X_OK):
            gpg_command = [cmd]
            break

    if not gpg_command:
        Logger.error("Cannot locate gpg, please install the 'gnupg' package!")
        sys.exit(1)

    gpg_command.append('--clearsign')
    if keyid:
        gpg_command.extend(('-u', keyid))

    # sign the mail body
    gpg = subprocess.Popen(gpg_command, stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE)
    signed_report = gpg.communicate(mailbody.encode('utf-8'))[0].decode('utf-8')
    if gpg.returncode != 0:
        Logger.error("%s failed.", gpg_command[0])
        sys.exit(1)

    # generate email
    mail = u'''\
From: %s
To: %s
Subject: %s
Content-Type: text/plain; charset=UTF-8

%s''' % (myemailaddr, to, bugtitle, signed_report)

    print 'The final report is:\n%s' % mail
    confirmation_prompt()

    # save mail in temporary file
    f=open("/tmp/requestsync-" + srcpkg, "w")
    f.write(mail)
    f.close()

    Logger.normal('The e-mail has been saved in %s and will be deleted '
                  'after succesful transmission', f.name)

    # connect to the server
    while True:
        try:
            Logger.info('Connecting to %s:%s ...', mailserver_host, mailserver_port)
            s = smtplib.SMTP(mailserver_host, mailserver_port)
            break
        except socket.error, s:
            Logger.error('Could not connect to %s:%s: %s (%i)',
                         mailserver_host, mailserver_port, s[1], s[0])
            return
        except smtplib.SMTPConnectError, s:
            Logger.error('Could not connect to %s:%s: %s (%i)',
                         mailserver_host, mailserver_port, s[1], s[0])
            if s.smtp_code == 421:
                confirmation_prompt(message='This is a temporary error, press '
                          '[Enter] to retry. Press [Ctrl-C] to abort now.')

    if mailserver_user and mailserver_pass:
        try:
            s.login(mailserver_user, mailserver_pass)
        except smtplib.SMTPAuthenticationError:
            Logger.error('Error authenticating to the server: '
                         'invalid username and password.')
            s.quit()
            return
        except:
            Logger.error('Unknown SMTP error.')
            s.quit()
            return

    try:
        s.sendmail(myemailaddr, to, mail.encode('utf-8'))
        s.quit()
        os.remove(f.name)
        Logger.normal('Sync request mailed.')
    except:
        Logger.error('Unknown error while sending the mail.')
