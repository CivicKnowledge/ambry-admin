"""Ambry command extension for remote libraries

Commands inlcude:



"""

# Copyright (c) 2015 Civic Knowledge. This file is licensed under the terms of
# the Revised BSD License, included in this distribution as LICENSE.txt

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'remotes'


from ambry.cli import prt, fatal, warn, err

def make_parser(cmd):

    config_p = cmd.add_parser(command_name, help='Commands for managing the local list of remotes')
    config_p.set_defaults(command=command_name)

    asp = config_p.add_subparsers(title='Remotes commands', help='Remotes commands')

    sp = asp.add_parser('add', help="Add a remote")
    sp.set_defaults(subcommand=add_remote) # CHANGE THIS to the function you want executed for this command
    sp.add_argument('-v', '--service', help="Service type. Usually 'ambry' or 's3' ")
    sp.add_argument('-u', '--url', help="URL")
    sp.add_argument('-t', '--api-token', help="API secret")
    sp.add_argument('remote_name', nargs=1, type=str, help='Name of the remote')

    sp = asp.add_parser('list', help="List the remotes")
    sp.set_defaults(subcommand=list_remotes)
    sp.add_argument('-v', '--service', help="Only list accounts of this service type")

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

def add_remote(args, l, rc):
    name = args.remote_name[0]

    r = l.find_or_new_remote(name)

    r.service = args.service
    r.url = args.url
    r.api_token = args.api_token

    l.commit()

def list_remotes(args, l, rc):
    from tabulate import tabulate
    from ambry.util import drop_empty

    def proc_remote(r):
        from collections import OrderedDict
        return  OrderedDict( (k,v) for k,v in r.dict.items() if k in
                             ['short_name','service','url','docker_url','api_token','account_password',
                              'db_dsn','message'])

    remotes = [proc_remote(r) for r in l.remotes if r.service == args.service or not args.service]

    if not remotes:
        return

    headers = remotes[0].keys()

    records = drop_empty([headers]+[r.values() for r in remotes])


    print tabulate(records[1:], records[0])

def sync(args, l, rc):
    from ambry.library.config import LibraryConfigSyncProxy

    lsp = LibraryConfigSyncProxy(l)

    lsp.sync(force=True)

