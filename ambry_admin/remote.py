"""Ambry command extension for remote libraries

Commands inlcude:



"""

# Copyright (c) 2015 Civic Knowledge. This file is licensed under the terms of
# the Revised BSD License, included in this distribution as LICENSE.txt

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'remote'


from ambry.cli import prt, fatal, warn, err

def make_parser(cmd):

    config_p = cmd.add_parser(command_name, help='Commands for managing remote libraries')
    config_p.set_defaults(command=command_name)

    config_p.add_argument('remote_name', nargs=1, type=str, help='Name of remote to operate on')
    asp = config_p.add_subparsers(title='Remote commands', help='Remote commands')

    sp = asp.add_parser('checkin', help="Check in a bundle")
    sp.set_defaults(subcommand=checkin)
    sp.add_argument('-n', '--no-partitions', default=False, action='store_true',
                               help="Don't check in partitions")
    sp.add_argument('-r', '--remote', help='Specify remote, rather than using default for bundle')
    sp.add_argument('-s', '--source', default=False, action='store_true',
                           help='Only package source files')
    sp.add_argument('bundle_ref', nargs=1, type=str, help='Reference to a bundle')

    sp = asp.add_parser('remove', help="Remote a bundle")
    sp.set_defaults(subcommand=remove)
    sp.add_argument('bundle_ref', nargs=1, type=str, help='Remove a bundle')

    sp = asp.add_parser('list', help="List the contents of the remote")
    sp.set_defaults(subcommand=remote_list)
    sp.add_argument('-s', '--summary',default=False, action='store_true', help="Also display summaries and titles")
    sp.add_argument('-c', '--cached', default=False, action='store_true', help="List the contents of the cached Directory listings")

    sp = asp.add_parser('info', help="Info about remote or a bundle on a remote")
    sp.set_defaults(subcommand=info)
    sp.add_argument('bundle_ref', nargs='?', type=str, help='Reference to a bundle')

    sp = asp.add_parser('syncremote', help="Send remote and associated account information")
    sp.set_defaults(subcommand=syncremote)
    sp.add_argument('remotes', nargs='*', type=str, help='Names of remotes to send')

    sp = asp.add_parser('syncacct', help="Send account information, without a remote")
    sp.set_defaults(subcommand=syncacct)
    sp.add_argument('accounts', nargs='*', type=str, help='Names of accounts to send')

    sp = asp.add_parser('sync', help="Instruct the remote to checkin a remote bundle")
    sp.set_defaults(subcommand=sync)
    sp.add_argument('ref', nargs='*', type=str, help='Bundle references')

    sp = asp.add_parser('update-listing', help="Cache the list of bundles so they can be listed via HTTP")
    sp.set_defaults(subcommand=update_listing)

    sp = asp.add_parser('test', help="Call the API's test interface")
    sp.set_defaults(subcommand=test)


def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        l = None

    args.subcommand(args, l, rc) # Note the calls to sp.set_defaults(subcommand=...)

def get_remote(l, name):
    from argparse import Namespace
    from ambry.orm.exc import NotFoundError

    if isinstance(name, Namespace):
        name = name.remote_name[0]

    try:
        return l.remote(name)
    except NotFoundError:
        fatal("Unknown remote name: '{}'".format(name))

def checkin(args, l, rc):

    from ambry.orm.exc import NotFoundError

    remote = get_remote(l, args)

    for ref in args.bundle_ref:

        b = l.bundle(ref)
        package = b.package(rebuild=False, source_only=args.source)
        prt('Check in {}'.format(b.identity.fqname))

        try:
            remote.checkin(package)
        except NotFoundError as e:
            fatal(e.message)

def remove(args, l, rc):
    from ambry_client import Client
    from ambry.orm.exc import NotFoundError

    remote = get_remote(l, args)

    for ref in args.bundle_ref:

        try:
            remote.remove(ref, cb=l.logger.info)
        except NotFoundError as e:
            fatal(e.message)

def remote_list(args, l, rc):

    remote = get_remote(l,args)

    if args.cached:

        if 'list' in remote.data:
            for k, v in remote.data['list'].items():
                print k, v['vname']
    else:

        for name in remote.list():
            if not args.summary:
                print name
            else:
                e = remote.find(name)
                print '{:12s} {:40s} {}'.format(e['vid'], e['name'], e.get('title'))

def info(args, l, rc):
    from ambry.orm.exc import NotFoundError

    remote = get_remote(l,args)

    if not args.bundle_ref:
        print remote # TODO Print info about the remote
    else:
        try:
            e = remote.find(args.bundle_ref)

            for k, v in e.items():
                print k, v

        except NotFoundError:
            fatal("Failed to find bundle for ref: '{}' ".format(args.bundle_ref))

def test(args, l, rc):

    from ambry.orm.exc import NotFoundError

    remote = get_remote(l, args)

    print remote.api_client.test()

def syncremote(args, l, rc):
    from ambry.util import parse_url_to_dict
    from ambry.orm.exc import NotFoundError

    local_remotes = []
    local_accounts = {}
    for remote_name in  args.remotes:
        r = l.remote(remote_name)
        local_remotes.append(r.dict)

        d = parse_url_to_dict(r.url)

        try:
            a = l.account(d['hostname'])
            local_accounts[a.account_id] = a.dict
        except NotFoundError:
            pass

    foreign_remote = get_remote(l, args)

    foreign_remote.api_client.library.remotes = local_remotes
    foreign_remote.api_client.library.accounts = local_accounts

def syncacct(args, l, rc):
    from ambry.util import parse_url_to_dict
    from ambry.orm.exc import NotFoundError

    local_accounts = {}

    for account_name in  args.accounts:

        try:
            a = l.account(account_name)
            local_accounts[a.account_id] = a.dict
        except NotFoundError:
            warn("No account for id '{}' ".format(account_name))

    foreign_remote = get_remote(l, args)

    foreign_remote.api_client.library.accounts = local_accounts


def sync(args, l, rc):
    raise NotImplementedError()

def update_listing(args, l, rc):

    remote = get_remote(l, args)

    remote._update_fs_list()