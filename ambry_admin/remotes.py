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
    sp.set_defaults(subcommand=add_remote)
    sp.add_argument('-v', '--service', help="Service type. Usually 'ambry' or 's3' ")
    sp.add_argument('-u', '--url', help="URL")
    sp.add_argument('-d', '--docker-url', help="URL of docker host")
    sp.add_argument('-U', '--username', help="User Name")
    sp.add_argument('-a', '--access-key', help="Access Key")
    sp.add_argument('-s', '--secret-key', help="Secret Key")

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

    args.subcommand(args, l, rc)  # Note the calls to sp.set_defaults(subcommand=...)


def add_remote(args, l, rc):
    from ambry.util import parse_url_to_dict

    name = args.remote_name[0]

    r = l.find_or_new_remote(name)

    if (args.secret_key or args.access_key) and args.url:
        hostname = parse_url_to_dict(args.url)['hostname']
        a = l.find_or_new_account(hostname)
    else:
        a = None

    if args.service:
        r.service = args.service
    elif args.url:
        r.service = parse_url_to_dict(args.url)['scheme']

    if args.url:
        r.url = args.url

    if args.docker_url:
        r.url = args.docker_url

    if args.access_key:
        if not a:
            fatal('access-key argument requires a url')
        a.access_key = args.access_key

    if args.secret_key:
        if not a:
            fatal('secret_key argument requires a url')
        a.encrypt_secret(args.secret_key.strip())

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

        print tabulate(records, ['Remote', 'Vid', 'VName'])

    else:

        if args.service == 's3':
            fields = ['short_name', 'bundle_count', 'url', 'access', 'secret']
        elif args.service == 'ambry':
            fields = ['short_name', 'url', 'access', 'secret', 'admin_pw']

        elif args.service == 'docker':
            fields = ['short_name', 'service', 'url', 'docker_url', 'api_token', 'account_password',
                      'db_dsn', 'message']
        else:
            fields = ['short_name', 'service', 'url']

        def proc_remote(r):
            from collections import OrderedDict
            od = OrderedDict((k, None) for k in fields)
            od.update(OrderedDict((k, v) for k, v in r.dict.items() if k in fields))
            return od


        remotes = [proc_remote(r) for r in l.remotes if r.service == args.service or not args.service]

        if not remotes:
            return



        records = drop_empty([fields] + [r.values() for r in remotes])

        print tabulate(records[1:], records[0])


def sync(args, l, rc):
    from ambry.library.config import LibraryConfigSyncProxy

    lsp = LibraryConfigSyncProxy(l)

    lsp.sync(force=True)


def update(args, l, rc):
    from ambry.orm.remote import RemoteAccessError
    from ambry.orm.exc import NotFoundError
    from requests.exceptions import ConnectionError, HTTPError
    from boto.exception import S3ResponseError

    for r in l.remotes:

        prt("Update {}".format(r.short_name))
        try:
            r.update()
            l.commit()
        except RemoteAccessError as e:
            warn("Failed for {}: {}".format(r.short_name, e))
