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
    sp.set_defaults(subcommand=add_account)
    sp.add_argument('-v', '--service', required=True, help="Service type. Usually 'ambry' or 's3' or 'api' ")
    sp.add_argument('-a', '--access', help="Access key or username")
    sp.add_argument('-s', '--secret', help="Secret key or password ")
    sp.add_argument('-u', '--url', help="Secret key or password ")
    sp.add_argument('account_id', nargs=1, type=str, help='Account identitifier')

    sp = asp.add_parser('remove', help="Remove an account")
    sp.set_defaults(subcommand=remove_account)
    sp.add_argument('account_id', nargs='*', type=str, help='Account identitifier')


    sp = asp.add_parser('list', help="List the remotes")
    sp.set_defaults(subcommand=list_accounts)
    sp.add_argument('-p', '--plain', default=False, action='store_true', help="Only list the ids")
    sp.add_argument('-v', '--service', help="Only list accounts of this service type")
    sp.add_argument('-s', '--secret', default=False, action='store_true',  help="Show secrets")

    sp = asp.add_parser('sync', help="Synchronize the remotes and accounts from the configuration to the database")
    sp.set_defaults(subcommand=sync)


def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        warn('No library: {}'.format(e))
        l = None

    args.subcommand(args, l, rc) # Note the calls to sp.set_defaults(subcommand=...)


def add_account(args, l, rc):

    account = l.find_or_new_account(args.account_id[0])

    if args.service:
        if '/' in args.service:
            account.major_type, account.minor_type = args.service.split('/')
        else:
            account.major_type = args.service

    if args.access:
        account.access_key = args.access

    if args.secret:
        if account.major_type == 'user':
            account.encrypt_password(args.secret.strip())
        else:
            account.encrypt_secret(args.secret.strip())
    if args.url:
        account.url = args.url

    if account.major_type == 'user': # Test the password to make sure the account will work.
        assert account.test(args.secret.strip())

    l.commit()

def remove_account(args, l, rc):
    from ambry.orm.exc import NotFoundError

    for account_name in args.account_id:
        try:
            account = l.account(account_name)
            l.delete_account(account)
            l.commit()
        except NotFoundError:
            warn("No account found for {}".format(account_name))


def list_accounts(args, l, rc):
    from tabulate import tabulate
    from ambry.util import drop_empty
    from ambry.orm import Account

    headers = 'Id Service User Access Url'.split()

    if args.secret:
        headers.append('Secret')

    records = []

    for k in l.accounts.keys():

        acct = l.account(k)

        if not args.service or args.service == acct.major_type:


            if acct.minor_type:
                t = "{}/{}".format(acct.major_type, acct.minor_type)
            else:
                t = acct.major_type

            rec = [acct.account_id,t,acct.user_id,acct.access_key,acct.url]

            if args.secret:
                rec.append(acct.decrypt_secret())

            records.append(rec)

    accounts = [v for k, v in l.accounts.items()]

    if not records:
        return

    records = drop_empty([headers]+ records)

    if not args.plain:
        prt(tabulate(records[1:], records[0]))
    else:
        for r in records[1:]:
            prt(r[0])

def sync(args, l, rc):
    from ambry.library.config import LibraryConfigSyncProxy

    lsp = LibraryConfigSyncProxy(l)

    lsp.sync(force=True)



