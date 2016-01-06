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
    sp.add_argument('-d', '--docker-url', help="URL of docker host")
    sp.add_argument('-j', '--jwt-secret', help="JWT Secret")
    sp.add_argument('remote_name', nargs=1, type=str, help='Name of the remote')

    sp = asp.add_parser('remove', help="Remove a remote")
    sp.set_defaults(subcommand=remove_remote)
    sp.add_argument('remote_name', nargs='*', type=str, help='Remote name')

    sp = asp.add_parser('list', help="List the remotes or the cached directly linstings of all remotes")
    sp.set_defaults(subcommand=list_remotes)
    sp.add_argument('-v', '--service', help="Only list accounts of this service type")
    sp.add_argument('-c', '--cached', default=False, action='store_true',
                    help="List the contents of the cached Directory listings")

    sp = asp.add_parser('update', help="Update the cached directory listing for each remote")
    sp.set_defaults(subcommand=update)


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

    if args.service:
        r.service = args.service
    if args.url:
        r.url = args.url
    if args.docker_url:
        r.url = args.docker_url
    if args.jwt_secret:
        r.jwt_secret = args.jwt_secret




    l.commit()

def remove_remote(args, l, rc):
    from ambry.orm.exc import NotFoundError

    for remote_name in args.remote_name:
        try:
            remote = l.remote(remote_name)
            l.delete_remote(remote)
            l.commit()
        except NotFoundError:
            warn("No remote found for {}".format(remote_name))


def list_remotes(args, l, rc):
    from tabulate import tabulate
    from ambry.util import drop_empty

    if args.cached:
        records = []
        for remote in l.remotes:
            if 'list' in remote.data:
                for k, v in remote.data['list'].items():
                    records.append([remote.short_name, k, v['name']])

        print tabulate(records, ['Remote','Vid','VName'])

    else:

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

def update(args,l,rc):
    from ambry.orm.exc import NotFoundError

    for r in l.remotes:

        d = {}

        try:
            for k, v in r.list(full=True):
                if not v:
                    continue

                d[v['vid']] = {
                    'vid':v['vid'],
                    'vname': v.get('vname'),
                    'id': v.get('id'),
                    'name': v.get('name')
                }

            r.data['list'] = d

            prt("Updated {}; {} entries".format(r.short_name, len(d)))

        except NotFoundError as e:
            warn(e)
            continue

        l.commit()