"""Example for starting new command modules.

Copyright (c) 2015 Civic Knowledge. This file is licensed under the terms of
the Revised BSD License, included in this distribution as LICENSE.txt

"""

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'example'


from ambry.cli import prt, fatal, warn, err


def make_parser(cmd):

    config_p = cmd.add_parser(command_name, help='An example of a CLI command')
    config_p.set_defaults(command=command_name)

    asp = config_p.add_subparsers(title='Docker commands', help='Docker commands')

    sp = asp.add_parser('command1', help="The first command")
    sp.set_defaults(subcommand=command1) # CHANGE THIS to the function you want executed for this command
    sp.add_argument('-a', '--option-a', default=False, action='store_true',
                    help="Option A")

    sp.add_argument('-b', '--option-b',  help="Option b")

    sp = asp.add_parser('command2', help="The first command")
    sp.set_defaults(subcommand=command2)
    sp.add_argument('-a', '--option-a', default=False, action='store_true',
                    help="Option A")

    sp.add_argument('-b', '--option-b', help="Option b")


def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    # Only create a library if your commands require it.
    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        l = None

    args.subcommand(args, l, rc) # Note the calls to sp.set_defaults(subcommand=...)


def command1(args, l, rc):
    print args

def command2(args, l, rc):
    print args
