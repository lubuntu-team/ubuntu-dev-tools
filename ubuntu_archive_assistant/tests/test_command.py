#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018  Canonical Ltd.

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

import sys
import unittest

from ubuntu_archive_assistant.command import AssistantCommand

# class AssistantCommand():
#    def print_usage(self):
#    def _add_subparser_from_class(self, name, commandclass):
#    def _import_subcommands(self, submodules):

scratch = 0


class MyMainCommand(AssistantCommand):

    def __init__(self):
        super().__init__(command_id="test", description="test", leaf=False)


class MySubCommand(AssistantCommand):

    def __init__(self):
        super().__init__(command_id="subtest", description="subtest", leaf=False)

    def update(self, args):
        super().update(args)
        self._args.append("extra")


def do_nothing():
    return


def do_something():
    global scratch
    scratch = 1337


def do_crash():
    raise Exception("unexpected")


class TestCommand(unittest.TestCase):

    def test_update_args(self):
        main = MyMainCommand()
        sub = MySubCommand()
        sub._args = ['toto', 'tata']
        main.commandclass = sub
        main.func = do_nothing
        self.assertNotIn('titi', sub._args)
        main.update(['titi', 'tutu'])
        main.run_command()
        self.assertIn('titi', main._args)
        self.assertIn('titi', sub._args)

    def test_parse_args(self):
        main = MyMainCommand()
        main._args = [ '--debug', 'help' ]
        main.subcommand = do_nothing
        main.parse_args()
        self.assertNotIn('help', main._args)
        self.assertNotIn('--debug', main._args)
        self.assertTrue(main.debug)

    def test_run_command_with_commandclass(self):
        main = MyMainCommand()
        sub = MySubCommand()
        main._args = ['unknown_arg']
        main.commandclass = sub
        main.func = do_nothing
        self.assertEqual(None, sub._args)
        main.run_command()
        self.assertIn('extra', sub._args)

    def test_run_command(self):
        main = MyMainCommand()
        sub = MySubCommand()
        main.func = do_something
        self.assertEqual(None, sub._args)
        main.run_command()
        self.assertEqual(1337, scratch)


    def test_run_command_crashing(self):
        main = MyMainCommand()
        sub = MySubCommand()
        main.func = do_crash
        try:
            main.run_command()
            self.fail("Did not crash as expected")
        except Exception as e:
            self.assertIn('unexpected', e.args)
