#
# question.py - Helper class for asking questions
#
# Copyright (C) 2010, Benjamin Drung <bdrung@ubuntu.com>,
#               2011, Stefano Rivera <stefanor@ubuntu.com>
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

import tempfile
import os
import re
import sys

import ubuntutools.subprocess


class Question(object):
    def __init__(self, options, show_help=True):
        assert len(options) >= 2
        self.options = [s.lower() for s in options]
        self.show_help = show_help

    def get_options(self):
        if len(self.options) == 2:
            options = self.options[0] + " or " + self.options[1]
        else:
            options = ", ".join(self.options[:-1]) + ", or " + self.options[-1]
        return options

    def ask(self, question, default=None):
        if default is None:
            default = self.options[0]
        assert default in self.options

        separator = " ["
        for option in self.options:
            if option == default:
                question += separator + option[0].upper()
            else:
                question += separator + option[0]
            separator = "|"
        if self.show_help:
            question += "|?"
        question += "]? "

        selected = None
        while selected not in self.options:
            selected = raw_input(question).strip().lower()
            if selected == "":
                selected = default
            else:
                for option in self.options:
                    # Example: User typed "y" instead of "yes".
                    if selected == option[0]:
                        selected = option
            if selected not in self.options:
                print "Please answer the question with " + \
                      self.get_options() + "."
        return selected


class YesNoQuestion(Question):
    def __init__(self):
        Question.__init__(self, ["yes", "no"], False)


def input_number(question, min_number, max_number, default=None):
    if default:
        question += " [%i]? " % (default)
    else:
        question += "? "
    selected = None
    while selected < min_number or selected > max_number:
        selected = raw_input(question).strip()
        if default and selected == "":
            selected = default
        else:
            try:
                selected = int(selected)
                if selected < min_number or selected > max_number:
                    print "Please input a number between %i and %i." % \
                          (min_number, max_number)
            except ValueError:
                print "Please input a number."
    assert type(selected) == int
    return selected


def confirmation_prompt(message=None, action=None):
    '''Display message, or a stock message including action, and wait for the
       user to press Enter
    '''
    if message is None:
        if action is None:
            action = 'continue'
        message = 'Press [Enter] to %s. Press [Ctrl-C] to abort now.' % action
    try:
        raw_input(message)
    except KeyboardInterrupt:
        print '\nAborting as requested.'
        sys.exit(1)


class EditFile(object):
    def __init__(self, filename, description, placeholders=None):
        self.filename = filename
        self.description = description
        if placeholders is None:
            placeholders = (re.compile(r'^<<<.*>>>$', re.UNICODE),)
        self.placeholders = placeholders

    def optional_edit(self):
        '''Prompt the user to decide if the file needs editing'''
        print "Currently the %s looks like:" % self.description
        with open(self.filename, 'r') as f:
            print f.read()
        if YesNoQuestion().ask("Edit", "no") == "yes":
            self.edit()

    def edit(self):
        done = False
        while not done:
            old_mtime = os.stat(self.filename).st_mtime
            ubuntutools.subprocess.check_call(['sensible-editor',
                                               self.filename])
            modified = old_mtime != os.stat(self.filename).st_mtime
            placeholders_present = False
            if self.placeholders:
                with open(self.filename, 'r') as f:
                    for line in f:
                        for placeholder in self.placeholders:
                            if placeholder.search(line.strip()):
                                placeholders_present = True

            if placeholders_present:
                print ("Placeholders still present in the %s. "
                       "Please replace them with useful information."
                       % self.description)
                confirmation_prompt('edit again')
            elif not modified:
                print "The %s was not modified" % self.description
                if YesNoQuestion().ask("Edit again", "yes") == "no":
                    done = True
            elif self.check_edit():
                done = True

    def check_edit(self):
        '''Override this to implement extra checks on the edited report.
        Should return False if another round of editing is needed,
        and should prompt the user to confirm that, if necessary.
        '''
        return True


class EditBugReport(EditFile):
    split_re = re.compile(r'^Summary.*?:\s+(.*)\s+'
                          r'Description:\s+(.*)$',
                          re.DOTALL | re.UNICODE)

    def __init__(self, subject, body, placeholders=None):
        tmpfile = tempfile.NamedTemporaryFile(prefix=sys.argv[0] + '_',
                                              suffix='.txt',
                                              delete=False)
        tmpfile.write((u'Summary (one line):\n%s\n\nDescription:\n%s'
                       % (subject, body)).encode('utf-8'))
        tmpfile.close()
        super(EditBugReport, self).__init__(tmpfile.name, 'bug report',
                                            placeholders)

    def check_edit(self):
        with open(self.filename, 'r') as f:
            report = f.read().decode('utf-8')

        if self.split_re.match(report) is None:
            print ("The %s doesn't start with 'Summary:' and 'Description:' "
                   "blocks" % self.description)
            confirmation_prompt('edit again')
            return False
        return True

    def get_report(self):
        with open(self.filename, 'r') as f:
            report = f.read().decode('utf-8')

        m = self.split_re.match(report)
        report = (m.group(1), m.group(2))
        os.unlink(self.filename)
        return report
