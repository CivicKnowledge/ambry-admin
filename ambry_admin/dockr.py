"""Ambry commands for managing docker containers

Copyright (c) 2015 Civic Knowledge. This file is licensed under the terms of
the Revised BSD License, included in this distribution as LICENSE.txt

"""

from __future__ import absolute_import

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'docker'

from six import iterkeys, iteritems
from ambry.cli import prt, fatal, warn, err

class DockerError(Exception):
    """Error while building or setting up docker"""


def make_parser(cmd):
    config_p = cmd.add_parser('docker', help='Install and manipulate docker containers')
    config_p.set_defaults(command='docker')

    asp = config_p.add_subparsers(title='Docker commands', help='Docker commands')

    sp = asp.add_parser('init', help="Initialilze a new data volume and database")
    sp.set_defaults(subcommand='init')
    sp.add_argument('-n', '--new', default=False, action='store_true',
                    help="Initialize a new database and volume, and report the new DSN")
    sp.add_argument('-p', '--public', default=False, action='store_true',
                    help="Map the database port to the host")
    sp.add_argument('-m', '--message', help="Add a message to the record for this container cluster")
    sp.add_argument('-H', '--host', help="Hostname. Start with '.' to prepend the groupname ")
    sp.add_argument('groupname', nargs=1, type=str, help='Name of group to initialize')


    sp = asp.add_parser('shell', help='Run a shell in a container')
    sp.set_defaults(subcommand='shell')
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running shell before starting a new one")

    sp.add_argument('groupname', nargs=1, type=str, help='Name of group creat shell for')
    sp.add_argument('docker_command', nargs='*', type=str, help='Command to run, instead of bash')

    sp = asp.add_parser('tunnel', help='Run an ssh tunnel to the current database container')
    sp.set_defaults(subcommand='tunnel')
    sp.add_argument('-i', '--identity', help="Specify an identity file for loggin into the docker host")
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running tunnel before starting a new one")
    sp.add_argument('groupname', nargs=1, type=str, help='Name of group creat shell for')
    sp.add_argument('ssh_key_file', type=str, nargs=1, help='Path to an ssh key file')

    sp = asp.add_parser('list', help='List docker entries in the accounts file')
    sp.set_defaults(subcommand='list')

    sp = asp.add_parser('kill', help='Destroy all of the containers associated with a username')
    sp.set_defaults(subcommand='kill')
    sp.add_argument('groupname', type=str, nargs='*', help='Group name of set of containers')
    sp.add_argument('-u', '--ui', default=False, action='store_true',
                    help="Kill only the ui")
    sp.add_argument('-v', '--volumes', default=False, action='store_true',
                    help="Also destroy the volumes container, which is preserved by default")



    sp = asp.add_parser('ckan', help='Run the ckan container')
    sp.set_defaults(subcommand='ckan')
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running container before starting a new one")


    sp = asp.add_parser('info', help='Print information about a docker group')
    sp.set_defaults(subcommand='info')
    sp.add_argument('-d', '--dsn', default=False, action='store_true',
                    help="Display the database DSN")
    sp.add_argument('groupname', type=str, nargs=1, help='Group name of set of containers')

    sp = asp.add_parser('build', help='Build a docker container')
    sp.set_defaults(subcommand='build')

    sp.add_argument('-C', '--clean', default=False, action='store_true',
                    help='Build without the image cache -- completely rebuild')
    sp.add_argument('-a', '--all', default=False, action='store_true',
                    help='Build all of the images')
    sp.add_argument('-B', '--base', default=False, action='store_true',
                    help='Build the base docker image, civicknowledge/ambry-base')
    sp.add_argument('-b', '--build', default=False, action='store_true',
                    help='Build the ambry docker image, civicknowledge/ambry')
    sp.add_argument('-d', '--dev', default=False, action='store_true',
                    help='Build the dev version of the ambry docker image, civicknowledge/ambry')
    sp.add_argument('-D', '--db', default=False, action='store_true',
                    help='Build the database image, civicknowledge/postgres')
    sp.add_argument('-n', '--numbers', default=False, action='store_true',
                    help='Build the numbers server docker image, civicknowledge/numbers')
    sp.add_argument('-t', '--tunnel', default=False, action='store_true',
                    help='Build the ssh tunnel docker image, civicknowledge/tunnel')
    sp.add_argument('-u', '--ui', default=False, action='store_true',
                    help='Build the user interface image, civicknowledge/ambryui')
    sp.add_argument('-v', '--volumes', default=False, action='store_true',
                    help='Build the user interface image, civicknowledge/volumes')
    sp.add_argument('-c', '--ckan', default=False, action='store_true',
                    help='Build the CKAN image, civicknowledge/ckan')


    sp = asp.add_parser('import', help='Import basic information about a remote from docker')
    sp.set_defaults(subcommand='import')

    sp = asp.add_parser('sync', help='Send  remotes and accounts to a remote')
    sp.set_defaults(subcommand='sync')
    sp.add_argument('groupname', nargs=1, type=str, help='Name of group to initialize')

def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        l = None

    globals()['docker_' + args.subcommand](args, l, rc)

def docker_client():
    from docker.client import Client
    from docker.utils import kwargs_from_env

    kwargs = kwargs_from_env()
    kwargs['tls'].assert_hostname = False

    client = Client(**kwargs)

    return client


def _docker_mk_volume(rc, client, remote):
    from docker.errors import NotFound, NullResource
    from ambry.orm.exc import NotFoundError
    import os
    #
    # Create the volume container
    #
    volumes_image = 'civicknowledge/volumes'

    try:
        inspect = client.inspect_image(volumes_image)
    except NotFound:
        prt('Pulling image for volumns container: {}'.format(volumes_image))
        client.pull(volumes_image)

    try:
        inspect = client.inspect_container(remote.vol_name)
        prt('Found volume container {}'.format(remote.vol_name))
    except NotFound:
        prt('Creating volume container {}'.format(remote.vol_name))

        r = client.create_container(
            name=remote.vol_name,
            image=volumes_image,
            labels={
                'civick.ambry.group': remote.short_name,
                'civick.ambry.message': remote.message,
                'civick.ambry.role': 'volumes'
            },
            volumes=['/var/ambry', '/var/backups'],
            host_config=client.create_host_config()
        )

        inspect = client.inspect_container(remote.vol_name)

    return inspect['Id']

def _docker_mk_db(rc, client, remote, public_port = False):
    from docker.errors import NotFound, NullResource
    from ambry.orm.exc import NotFoundError
    import os
    #
    # Create the database container
    #

    postgres_image = 'civicknowledge/postgres'

    try:
        inspect = client.inspect_image(postgres_image)
    except NotFound:
        fatal(('Database image {i} not in docker. Run "ambry docker build -d" ').format(i=postgres_image))

    try:
        inspect = client.inspect_container(remote.db_name)
        prt('Found db container {}'.format(remote.db_name))
    except NotFound:
        prt('Creating db container {}'.format(remote.db_name))

        if public_port:
            port_bindings = {5432: ('0.0.0.0',)}
        else:
            port_bindings = None

        kwargs = dict(
            name=remote.db_name,
            image=postgres_image,
            labels={
                'civick.ambry.group': remote.short_name,
                'civick.ambry.message': remote.message,
                'civick.ambry.role': 'db'

            },
            volumes=['/var/ambry', '/var/backups'],
            ports=[5432],
            environment={
                'ENCODING': 'UTF8',
                'BACKUP_ENABLED': 'true',
                'BACKUP_FREQUENCY': 'daily',
                'BACKUP_EMAIL': 'eric@busboom.org',
                'USER': remote.short_name,
                'PASSWORD': remote.tr_db_password,
                'SCHEMA': remote.short_name,
                'POSTGIS': 'true',
            },
            host_config=client.create_host_config(
                volumes_from=[remote.vol_name],
                port_bindings=port_bindings
            )
        )

        r = client.create_container(**kwargs)

        client.start(r['Id'])

        inspect = client.inspect_container(r['Id'])

    try:
        port = inspect['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
    except (TypeError, KeyError):
        port = None

    if port:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=groupname, password=password, database=database, host=db_host_ip, port=port)

    else:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=remote.short_name, password=remote.tr_db_password, database=remote.short_name,
            host='localhost', port='5432')


    remote.db_dsn = dsn

    return inspect['Id']


def _docker_mk_ui(rc, client,remote, hostname):
    from docker.errors import NotFound, NullResource
    from ambry.orm.exc import NotFoundError
    import os

    image = 'civicknowledge/ambryui'

    check_ambry_image(client, image)

    try:
        inspect = client.inspect_container(remote.ui_name)
        prt('Found ui container {}'.format(remote.ui_name))
    except NotFound:
        prt('Creating ui container {}'.format(remote.ui_name))

        envs = remote_envs(rc, remote)
        envs['VIRTUAL_HOST'] = hostname
        envs['AMBRY_JWT_SECRET'] = remote.jwt_secret

        if remote:
            envs['AMBRY_UI_TITLE'] = remote.message

        kwargs = dict(
            name=remote.ui_name,
            image=image,
            labels={
                'civick.ambry.group': remote.short_name,
                'civick.ambry.role': 'ui',
                'civick.ambry.virt_host': envs.get('VIRTUAL_HOST')
            },
            detach=False,
            tty=True,
            stdin_open=True,
            environment=envs,
            host_config=client.create_host_config(
                volumes_from=[remote.vol_name],
                links={
                    remote.db_name: 'db',
                },
                port_bindings={80: ('0.0.0.0',)}
            )
        )

        r = client.create_container(**kwargs)

        while True:
            try:
                inspect = client.inspect_container(r['Id'])
                break
            except NotFound:
                prt('Waiting for container to be created')

        client.start(r['Id'])

        inspect = client.inspect_container(r['Id'])

        try:
            port = inspect['NetworkSettings']['Ports']['80/tcp'][0]['HostPort']
        except:
            port = None

        if envs.get('VIRTUAL_HOST'):
            remote.url = 'http://{}'.format(envs.get('VIRTUAL_HOST'))
        else:
            remote.url = 'http://{}{}'.format(remote.docker_url, ':{}'.format(port) if port else '')

    inspect = client.inspect_container(remote.ui_name)

    return inspect['Id']


def docker_init(args, l, rc):
    """Initialize a new docker volumes and database container, and report the database DSNs"""

    from docker.errors import NotFound, NullResource
    import string
    import random
    from ambry.util import parse_url_to_dict, random_string, set_url_part
    from docker.utils import kwargs_from_env
    from ambry.cli import fatal

    client = docker_client()

    def id_generator(size=12, chars=string.ascii_lowercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    groupname = args.groupname[0]

    remote =  l.find_or_new_remote(groupname, service='docker')
    remote.message = args.message
    remote.docker_url = client.base_url
    if not remote.jwt_secret:
        remote.jwt_secret = random_string(16)

    if remote.db_dsn:
        d = parse_url_to_dict(remote.db_dsn)
        remote.tr_db_password = d['password']
        assert d['username'] == groupname

    else:

        remote.tr_db_password = id_generator()
        remote.vol_name = 'ambry_volumes_{}'.format(groupname)
        remote.db_name = 'ambry_db_{}'.format(groupname)
        remote.ui_name =  'ambry_ui_{}'.format(remote.short_name)

    remote.message = args.message

    _docker_mk_volume(rc, client,remote)
    _docker_mk_db(rc, client,remote, public_port=args.public)
    ui_id = _docker_mk_ui(rc, client,remote, hostname=make_hostname(remote.short_name, args, rc))

    # Create an account entry for the api token
    if remote.url:
        d = parse_url_to_dict(remote.url)
        acct = l.find_or_new_account(remote.url, major_type='ambry')
        acct.encrypt_secret(remote.jwt_secret)

    # Create a local user account entry for accessing the API
    account = l.find_or_new_account(set_url_part(remote.url, username='api'), major_type='api')
    if not account.access_key:
        account.url = remote.url
        account.access_key = 'api'
        secret = random_string(20)
        account.encrypt_secret(secret)
    else:
        secret = account.decrypt_secret()

    assert secret

    # Create the corresponding account in the UI's database
    ex = client.exec_create(container=ui_id,
                            cmd='ambry accounts add -v user -a api -s {} api'.format(secret))

    print client.exec_start(ex['Id'])


    l.commit()

    prt('UI Container')
    prt('   Name: {}'.format(remote.ui_name))
    prt('   URL:  {} '.format(remote.url))

    if l and l.database.dsn != remote.db_dsn:
        prt("Set the library.database configuration to this DSN:")
        prt("    " + remote.db_dsn)
    if remote.db_host == 'localhost':
        warn("No public port; you'll need to set up a tunnel for external access")



def check_ambry_image(client, image):
    from docker.errors import NotFound, NullResource
    try:
        _ = client.inspect_image(image)
    except NotFound:
        fatal(('Database image {i} not in docker. Run \'python setup.py docker {{opt}}\' or '
               ' \'docker pull {i}\'').format(i=image))

def docker_shell(args, l, rc):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from docker.errors import NotFound, NullResource
    import os

    client = docker_client()
    remote = l.remote(args.groupname[0])


    if args.docker_command:

        if args.docker_command[0] not in ('bambry', 'ambry'):
            docker_command = ['bambry'] + list(args.docker_command)
        else:
            docker_command =  list(args.docker_command)
    else:
        docker_command = None


    shell_name = 'ambry_shell_{}'.format(remote.short_name)

    # Check if the  image exists.

    image = 'civicknowledge/ambry'

    check_ambry_image(client, image)

    try:
        inspect = client.inspect_container(shell_name)
        running = inspect['State']['Running']
        exists = True
    except NotFound as e:
        running = False
        exists = False

    # If no one is using is, clear it out.
    if exists and not running:
        prt('Container {} exists but is not running; recreate it from latest image'.format(shell_name))
        client.remove_container(shell_name)
        exists = False

    if not running:

        kwargs = dict(
            name=shell_name,
            image=image,
            labels={
                'civick.ambry.group': remote.short_name,
                'civick.ambry.role': 'shell'
            },
            detach=False,
            tty=True,
            stdin_open=True,
            environment=remote_envs(rc,remote),
            host_config=client.create_host_config(
                volumes_from=[remote.vol_name],
                links={
                    remote.db_name: 'db'
                }
            ),
            command= docker_command or '/bin/bash'
        )

        prt('Starting container with image {} '.format(image))

        r = client.create_container(**kwargs)

        while True:
            try:
                inspect = client.inspect_container(r['Id'])
                break
            except NotFound:
                prt('Waiting for container to be created')

        prt('Starting {}'.format(inspect['Id']))
        os.execlp('docker', 'docker', 'start', '-a', '-i', inspect['Id'])

    else:

        prt("Exec new shell on running container")
        cmd = ['docker', 'docker', 'exec', '-t', '-i', inspect['Id'] ]
        if docker_command:
            cmd += docker_command
        else:
            cmd.append('/bin/bash')

        os.execvp('docker',cmd)


def docker_tunnel(args, l, rc):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from docker.errors import NotFound, NullResource
    from docker.utils import kwargs_from_env
    from ambry.util import parse_url_to_dict
    import os
    from ambry.cli import fatal

    args.ssh_key_file = args.ssh_key_file.pop(0)

    if not os.path.exists(args.ssh_key_file):
        fatal('The tunnel argument must be the path to a public ssh key')

    client = docker_client()
    remote = l.remote(args.groupname[0])

    shell_name = 'ambry_tunnel_{}'.format(remote.short_name)

    # Check if the  image exists.

    image = 'civicknowledge/tunnel'

    check_ambry_image(client, image)

    try:
        inspect = client.inspect_container(shell_name)
        running = inspect['State']['Running']
        exists = True
    except NotFound as e:
        running = False
        exists = False

    if args.kill and running:
        client.remove_container(shell_name, force=True)
        running = False

    if running:
        fatal('Container {} is running. Kill it with -k'.format(shell_name))

    kwargs = dict(
        name=shell_name,
        image=image,
        labels={
            'civick.ambry.group': remote.short_name,
            'civick.ambry.role': 'tunnel'
        },
        detach=False,
        tty=False,
        stdin_open=False,
        environment=remote_envs(rc, remote),
        host_config=client.create_host_config(
            links={
                remote.db_name: 'db'
            },
            port_bindings={22: ('0.0.0.0',)}
        ),
        command="/usr/sbin/sshd -D"

    )

    prt('Starting tunnel container with image {} '.format(image))

    r = client.create_container(**kwargs)

    client.start(r['Id'])

    inspect = client.inspect_container(r['Id'])

    port =  inspect['NetworkSettings']['Ports']['22/tcp'][0]['HostPort']

    host, _ = parse_url_to_dict(kwargs_from_env()['base_url'])['netloc'].split(':',1)

    # Now, insert the SSH key

    with open(args.ssh_key_file) as f:
        key = f.read()

    ex = client.exec_create(container=r['Id'],
                            cmd=['sh', '/bin/loadkey',key])

    client.exec_start(ex['Id'])

    p = start_tunnel(host, port)
    prt("Tunnel is running as pid: {}".format(p.pid))
    p.wait()


def start_tunnel(host, port):
    import subprocess

    options = ['-o','"CheckHostIP no"',
               '-o','"StrictHostKeyChecking no"',
               '-o','"UserKnownHostsFile /dev/null"']


    cmd = ['ssh','-N', '-p', port, '-L', '{}:{}:{}'.format(5432,'db',5432)] + options  + ['root@{}'.format(host)]

    prt('Running: '+' '.join(cmd))

    p = subprocess.Popen(' '.join(cmd), shell=True)
    return p


def docker_kill(args, l, rc):
    from operator import itemgetter
    from docker.utils import kwargs_from_env
    from ambry.orm.exc import  NotFoundError

    client = docker_client()

    remove_remote = False if args.ui else True

    for groupname in args.groupname:

        for c in client.containers(all=True):
            name = c['Names'][0].strip('/')
            if groupname in name:

                try:
                    role = c['Labels'].get('civick.ambry.role')
                except KeyError:
                    role = 'uknown'

                if args.ui and role != 'ui':
                    continue

                if role == 'volumes' and not args.volumes:
                    prt("Skipping {}; -v was not specified".format(name))
                    continue

                prt("Removing: {} ({})".format(name, role))

                client.remove_container(container=c['Id'], v=True, force=True)

                if remove_remote:
                    try:
                        l.delete_remote(groupname)
                    except NotFoundError:
                        pass



def make_hostname(groupname, args, rc):

    if args.host:
        if args.host.startswith('.'):
            host = groupname+args.host
        else:
            host = args.host
    else:

        config_vh_root = rc.get('docker', {}).get('ui_domain', None)
        if config_vh_root:
            host = '{}.{}'.format(groupname, config_vh_root)
        else:
            host = None

    return host


def docker_ckan(args, l, rc, attach=True):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from ambry.util import parse_url_to_dict
    from docker.errors import NotFound, NullResource
    import os

    client = docker_client()

    username, dsn, volumes_c, db_c, envs = get_docker_links(args, l, rc)

    container_name = 'ambry_ckan_{}'.format(username)

    # Check if the  image exists.

    image = 'civicknowledge/ckan'

    check_ambry_image(client, image)

    try:
        inspect = client.inspect_container(container_name)
        running = inspect['State']['Running']
        exists = True
    except NotFound as e:
        running = False
        exists = False

    # If no one is using is, clear it out.
    if exists and (not running or args.kill):
        prt('Killing container {}'.format(container_name))
        client.remove_container(container_name, force = True)
        exists = False
        running = False

    if not running:

        envs = remote_envs(rc, remote)

        vh_root = rc.get('docker', {}).get('ui_domain', None)
        if vh_root:
            envs['VIRTUAL_HOST'] = '{}.repo.{}'.format(username, vh_root)


        envs['ADMIN_USER_EMAIL'] = 'none@example.com'

        kwargs = dict(
            name=container_name,
            image=image,
            labels={
                'civick.ambry.group': username,
                'civick.ambry.role': 'ckan',
                'civick.ambry.virt_host': envs.get('VIRTUAL_HOST')
            },
            detach=False,
            tty=True,
            stdin_open=True,
            environment=envs,
            host_config=client.create_host_config(
                volumes_from=[volumes_c],
                links={
                    db_c: 'db', # Mostly to get the password, etc
                },
                port_bindings={80: ('0.0.0.0',)}
            )
        )

        r = client.create_container(**kwargs)

        while True:
            try:
                inspect = client.inspect_container(r['Id'])
                break
            except NotFound:
                prt('Waiting for container to be created')

        client.start(r['Id'])

        inspect = client.inspect_container(r['Id'])

        try:
            port = inspect['NetworkSettings']['Ports']['80/tcp'][0]['HostPort']
        except:
            port = None
            print inspect['NetworkSettings']['Ports']

        d = parse_url_to_dict(dsn)

        prt('Starting ui container')
        prt('   Name {}'.format(container_name))
        prt('   Password / key: {}'.format(d['password']))
        prt('   Virtual host http://{} '.format(envs.get('VIRTUAL_HOST')))
        prt('   Host port: {}'.format(port))

    else:
        prt('Container {} is already running'.format(container_name))

def docker_list(args, l, rc):
    from operator import itemgetter
    from docker.utils import kwargs_from_env
    from collections import defaultdict
    from ambry.util import parse_url_to_dict
    from ambry.orm.exc import NotFoundError

    client = docker_client()
    prt("Listing Ambry containers for : {}",client.base_url)

    host = parse_url_to_dict(client.base_url)['hostname']

    fields = ' '.split
    rows = []

    entries = defaultdict(dict)

    for c in client.containers(all=True):
        if 'civick.ambry.role' in c['Labels']:
            group = c['Labels'].get('civick.ambry.group')
            role = c['Labels'].get('civick.ambry.role')
            entries[group]['group'] = group

            if role == 'db':
                entries[group]['message'] = c['Labels'].get('civick.ambry.message')


            vhost = c['Labels'].get('civick.ambry.virt_host')

            entries[group][role] = {'name': c['Names'][0],
                                    'role': role,
                                    'message': c['Labels'].get('civick.ambry.message'),
                                    'vhost': "http://{}".format(vhost) if vhost else None,
                                    'id': c['Id'],
                                    'ports': None}

            if c['Ports'] and c['Ports'][0].get('PublicPort'):
                ports = c['Ports'][0]
                host = ports['IP'] if ports.get('IP') and ports.get('IP') != '0.0.0.0' else host
                entries[group][role]['ports'] = "{}:{}".format(host, ports['PublicPort'])


    rows = []
    headers = 'Group Role Name Ports Notes'.split()

    message_map = {
        'db': 'dsn',
        'ui': 'vhost'
    }

    for key in sorted(entries.keys()):
        e = entries[key]
        group = e['group']
        rows.append([group, None, None, None, e.get('message') ])

        try:
            remote = l.remote(key).dict
        except NotFoundError:
            remote  = {}

        for role in sorted([k for k,v in e.items() if isinstance(v, dict)]):
            m = e[role]
            if role in ('ui', 'ckan'):
                message = m['vhost']
            elif role == 'db' and remote:
                message = remote.get('db_dsn')
            else:
                message = None

            rows.append(['', role, m['name'], m['ports'], message])


    from tabulate import tabulate

    print tabulate(rows, headers)

def docker_info(args, l, rc):

    groupname = args.groupname.pop(0)

    if args.dsn:
        try:
            remote = l.remote(groupname)
            prt(remote.db_dsn)
        except KeyError:
            # Meant for use in shell scripts, so just return an error return code
            import sys
            sys.exit(1)



def remote_envs(rc, remote):
    from ambry.util import parse_url_to_dict, unparse_url_dict

    d = parse_url_to_dict(remote.db_dsn)

    if not 'docker' in d['query']:
        fatal("Database '{}' doesn't look like a docker database DSN; it should have 'docker' at the end"
              .format(dsn))

    # Create the new container DSN; in docker, the database is always known as 'db'
    d['hostname'] = 'db'
    d['port'] = None
    dsn = unparse_url_dict(d)

    envs = {}
    envs['AMBRY_DB'] = dsn
    envs['AMBRY_ACCOUNT_PASSWORD'] = (rc.accounts.get('password'))

    return envs

def docker_build(args, l, rc):
    from ambry_admin import docker as dckr_dir
    import os, sys, shutil
    from os.path import dirname, abspath

    base_dir = os.path.dirname(dckr_dir.__file__)

    def get_ambry_code_dir():

        import ambry

        cd = dirname(dirname(ambry.__file__))

        if not os.path.exists(os.path.join(cd, 'setup.py')):
            from ambry.dbexceptions import ConfigurationError
            raise ConfigurationError('For this docker build, ambry must be installed as development source '
                                     'Expected setup.py in {} '.format(cd))

        return abspath(cd)

    def make_dist_tar(docker_file):
        import subprocess
        from ambry._meta import __version__
        import tarfile

        cd = get_ambry_code_dir()

        tar_file = os.path.join(cd, 'dist', "ambry-{}.tar".format(__version__))

        if True or not os.path.exists(tar_file):
            prt("Building context from {}".format(cd))
            subprocess.check_call(['python', 'setup.py', 'sdist', '--formats=tar'], cwd=cd)

            assert os.path.exists(tar_file)

            with tarfile.open(tar_file, "a:") as tar:
                tar.add(docker_file, arcname='Dockerfile')
                tar.add(os.path.join(base_dir, 'ambry','ambry-init.sh'), arcname='ambry-init.sh')
                tar.add(os.path.join(cd, 'ambry', 'support', 'ambry-docker.yaml'), arcname='config.yaml')
                tar.close()

        return tar_file


    def d_build(name, context=None, tag = None):
        from ambry._meta import __version__
        import io
        docker_file_dir = os.path.join(base_dir, name)
        docker_file_in = os.path.join(docker_file_dir, 'Dockerfile')

        if context:
            context_file = make_dist_tar(docker_file_in)
            prt('Using context file: {} '.format(context_file))
            with open(context_file) as docker_f:
                fo = io.BytesIO(docker_f.read())
            df = None
            context = True
            docker_file_path = None
        else:

            #with open(docker_file_in) as docker_f:
            #    fo = io.BytesIO(docker_f.read().encode('utf-8'))
            fo = None
            df = None
            context = False
            docker_file_path = os.path.dirname(docker_file_in)

        tag = 'civicknowledge/' + (tag or name)

        client = docker_client()

        for line in client.build(path=docker_file_path, fileobj=fo,dockerfile=df,
                                 custom_context=context, rm=True, nocache=args.clean,
                                 tag=tag, decode=True):
            if 'stream' in line:
                print line['stream'],
            elif 'errorDetail' in line:
                m = line['errorDetail']['message']
                raise DockerError("Docker Error: "+m)
            else:
                raise DockerError(line)

        client.tag(tag+':latest', tag, __version__, force=True)

    if args.base:
        d_build('ambry-base', context=True)

    if args.numbers:
        d_build('numbers')

    if args.build:
        d_build('ambry', context=True)

    if args.dev:

        d_build('dev', tag='ambry', context=True)

    if args.db:
        d_build('postgres')

    if args.tunnel:
        d_build('tunnel')

    if args.ui:
        d_build('ambryui')

    if args.volumes:
        d_build('volumes')

    if args.ckan:
        d_build('ckan')



def _split_envs(env_strings):
    envs = {}

    for s in env_strings:
        k,v = s.split('=')
        envs[k.lower()] = v

    return envs

def _make_dsn(ip, port, envs):
    if port:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=envs['user'], password=envs['password'], database=envs['user'], host=ip, port=port)

    else:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=envs['user'], password=envs['password'], database=envs['user'], host='localhost', port='5432')

    return dsn

def docker_import(args, l, rc):
    from operator import itemgetter
    from docker.utils import kwargs_from_env
    from collections import defaultdict
    from ambry.util import parse_url_to_dict
    from ambry.orm.exc import NotFoundError

    client = docker_client()
    prt("Listing Ambry containers for : {}",client.base_url)

    host = parse_url_to_dict(client.base_url)['hostname']

    entries = defaultdict(dict)

    for c in client.containers(all=True):
        if 'civick.ambry.role' in c['Labels']:
            group = c['Labels'].get('civick.ambry.group')
            role = c['Labels'].get('civick.ambry.role')
            entries[group]['group'] = group

            if role == 'db':
                entries[group]['message'] = c['Labels'].get('civick.ambry.message')


            vhost = c['Labels'].get('civick.ambry.virt_host')

            entries[group][role] = {'name': c['Names'][0],
                                    'role': role,
                                    'message': c['Labels'].get('civick.ambry.message'),
                                    'vhost': "http://{}".format(vhost) if vhost else None,
                                    'id': c['Id'],
                                    'ports': None}

            if c['Ports'] and c['Ports'][0].get('PublicPort'):
                ports = c['Ports'][0]
                host = ports['IP'] if ports.get('IP') and ports.get('IP') != '0.0.0.0' else host
                entries[group][role]['ports'] = "{}:{}".format(host, ports['PublicPort'])

    for k, e in entries.items():

        remote = l.find_or_new_remote(k, service='docker')
        remote.docker_url = client.base_url

        for role in sorted([k for k,v in e.items() if isinstance(v, dict)]):
            m = e[role]

            import json

            inspect = client.inspect_container(m['name'])

            if role == 'db':

                try:
                    port = inspect['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
                except (TypeError, KeyError):
                    port = None

                remote.db_name = m['name']
                envs = _split_envs(inspect['Config']['Env'])

                remote.db_dsn =  _make_dsn(host, port, envs)

                #print json.dumps(inspect, indent=4)
            elif role == 'ui':
                remote.ui_name = m['name']
                envs = _split_envs(inspect['Config']['Env'])
                remote.jwt_secret = envs.get('ambry_jwt_secret', envs.get('ambry_api_token'))
                remote.url = envs['virtual_host']
            elif role == 'volumes':
                remote.vol_name = m['name']


            prt("Added {}".format(m['name']))

    l.commit()



