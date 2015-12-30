"""Ambry command extension for remote libraries

Commands inlcude:



"""

# Copyright (c) 2015 Civic Knowledge. This file is licensed under the terms of
# the Revised BSD License, included in this distribution as LICENSE.txt

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'accounts'


from ambry.cli import prt, fatal, warn, err

def make_parser(cmd):

    config_p = cmd.add_parser(command_name, help='Commands for managing library accounts')
    config_p.set_defaults(command=command_name)

    asp = config_p.add_subparsers(title='Accounts commands', help='Accounts commands')

    sp = asp.add_parser('add', help="Add an account")
    sp.set_defaults(subcommand=add_account) # CHANGE THIS to the function you want executed for this command
    sp.add_argument('-v', '--service', help="Service type. Usually 'ambry' or 's3' ")
    sp.add_argument('-a', '--access', help="Access key or username")
    sp.add_argument('-s', '--secret', help="Secret key or password ")
    sp.add_argument('docker_command', nargs='*', type=str, help='Command to run, instead of bash')

    sp = asp.add_parser('list', help="List the remotes")
    sp.set_defaults(subcommand=list_accounts)

    sp = asp.add_parser('sync', help="Synchronize the remotes and accounts from the configuration to the database")
    sp.set_defaults(subcommand=sync)


def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        l = None

    args.subcommand(args, l, rc) # Note the calls to sp.set_defaults(subcommand=...)


def add_account(args, l, rc):
    pass

def list_accounts(args, l, rc):
    from tabulate import tabulate
    from ambry.util import drop_empty

    headers = 'Id Service User Access Url'.split()
    records = []

    for acct in l.accounts.values():
        records.append(
            [
                acct['account_id'],
                acct['major_type'],
                acct['user_id'],
                acct['access_key'],
                acct['url']
            ]
        )

    accounts = [v for k, v in l.accounts.items()]

    if not records:
        return

    records = drop_empty([headers]+ records)


    print tabulate(records[1:], records[0])

def sync(args, l, rc):
    from ambry.library.config import LibraryConfigSyncProxy

    lsp = LibraryConfigSyncProxy(l)

    lsp.sync(force=True)



