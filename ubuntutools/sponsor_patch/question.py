#
# question.py - Internal helper class for sponsor-patch
#
# Copyright (C) 2011, Benjamin Drung <bdrung@ubuntu.com>
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

import sys

from ubuntutools.question import Question, YesNoQuestion


def ask_for_ignoring_or_fixing():
    """Ask the user to resolve an issue manually or ignore it.

    Returns false if the user want to fix the issue and returns true if the user
    want to ignore the issue.
    """

    question = Question(["yes", "ignore", "no"])
    answer = question.ask("Do you want to resolve this issue manually", "yes")
    if answer == "no":
        user_abort()
    return answer == "ignore"


def ask_for_manual_fixing():
    """Ask the user to resolve an issue manually."""

    answer = YesNoQuestion().ask("Do you want to resolve this issue manually",
                                 "yes")
    if answer == "no":
        user_abort()


def user_abort():
    """Print abort and quit the program."""

    print("User abort.")
    sys.exit(2)
