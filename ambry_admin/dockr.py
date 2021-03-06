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

    sp = asp.add_parser('library', help="Initialilze a new data volume and database")
    sp.set_defaults(subcommand='library')
    sp.add_argument('-p', '--public', default=False, action='store_true',
                    help="Map the database port to the host")
    sp.add_argument('groupname', nargs=1, type=str, help='Name of group to initialize')

    sp = asp.add_parser('host', help="Set parameters for the current docker host")
    sp.set_defaults(subcommand='host')
    sp.add_argument('-v', '--virtual', help="Set the base for virtual host names")

    sp = asp.add_parser('ui', help="Create or destroy a UI container for a group")
    sp.set_defaults(subcommand='ui')
    sp.add_argument('-k', '--kill', default=False, action='store_true', help="Kill a running UI continer")
    sp.add_argument('-r', '--restart', default=False, action='store_true', help="Start, or stop and start, a UI container")
    sp.add_argument('-v', '--virtual', help="Set the virtual hostname")
    sp.add_argument('-t', '--title', help="Set the display title")
    sp.add_argument('groupname', nargs=1, type=str, help='Name of group to initialize')

    sp = asp.add_parser('shell', help='Run a shell in a container')
    sp.set_defaults(subcommand='shell')
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running shell before starting a new one")
    sp.add_argument('-d', '--detach', default=False, action='store_true',
                    help="Detach after starting the process")

    sp.add_argument('-g','--group', type=str, help='Name of group create shell for')
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

    sp = asp.add_parser('volumes', help='RUn a container to access the volumes')
    sp.set_defaults(subcommand='volumes')
    sp.add_argument('groupname', type=str, nargs=1, help='Group name')

    sp = asp.add_parser('info', help='Print information about a docker group')
    sp.set_defaults(subcommand='info')
    sp.add_argument('-d', '--dsn', default=False, action='store_true',
                    help="Display the database DSN")
    sp.add_argument('groupname', type=str, nargs=1, help='Group name of set of containers')

    sp = asp.add_parser('build', help='Build a docker container')
    sp.set_defaults(subcommand='build')

    sp.add_argument('-C', '--clean', default=False, action='store_true',
                    help='Build without the image cache -- completely rebuild')
    sp.add_argument('-X', '--context', default=False, action='store_true',
                    help='Build only the context TAR file, written to the dist subdirectory of the source')
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
    sp.add_argument('-U', '--ui-debug', default=False, action='store_true',
                    help='Build the user debug version of the interface image, civicknowledge/ambryui')
    sp.add_argument('-v', '--volumes', default=False, action='store_true',
                    help='Build the user interface image, civicknowledge/volumes')
    sp.add_argument('-c', '--ckan', default=False, action='store_true',
                    help='Build the CKAN image, civicknowledge/ckan')
    sp.add_argument('-p', '--proxy', default=False, action='store_true',
                    help='Build the proxy image, civicknowledge/proxy')


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
                'civick.ambry.role': 'volumes'
            },
            volumes=['/var/ambry', '/var/backups'],
            host_config=client.create_host_config()
        )

        inspect = client.inspect_container(remote.vol_name)

    return inspect['Id']

def _docker_mk_db(rc, client, remote, public_port = False):
    from docker.errors import NotFound
    from ambry.util import parse_url_to_dict
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
                username=remote.short_name, password=remote.tr_db_password, database=remote.short_name,
                host=parse_url_to_dict(client.base_url)['hostname'], port=port)

        else:
            dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
                username=remote.short_name, password=remote.tr_db_password, database=remote.short_name,
                host='localhost', port='5432')

        remote.db_dsn = dsn

    return inspect['Id']

def _docker_mk_ui(rc, client, group_name=None, dsn=None, virtual_host=None):
    from docker.errors import NotFound
    from ambry.util import parse_url_to_dict, select_from_url

    image = 'civicknowledge/ambryui'

    check_ambry_image(client, image)

    assert (group_name is not None) or ( dsn is not None)

    envs = {}

    if group_name:
        vol_name = 'ambry_volumes_{}'.format(group_name)
        try:
            inspect = client.inspect_container(vol_name)
            prt('Using group volume: {}'.format(vol_name))
            volumes_from = [vol_name]
        except NotFound:
            volumes_from = None
    else:
        volumes_from = None

    if group_name and not dsn:
        db_name = 'ambry_db_{}'.format(group_name)

        inspect = client.inspect_container(db_name)

        prt('Using docker db : {}'.format(db_name))
        links = { db_name: 'db', }
        dsn = _docker_db_dsn(client, db_name)
        envs['AMBRY_DB'] = docker_local_dsn(dsn)

    else:
        envs['AMBRY_DB'] = dsn
        links = None

    if not group_name:
        group_name = select_from_url(dsn, 'username')

    docker_name = 'ambry_ui_{}'.format(group_name)

    try:
        inspect = client.inspect_container(docker_name)
        prt('Found ui container {}'.format(docker_name))

        # So the info printing at the end works
        try:
            envs['VIRTUAL_HOST'] = next( e.split('=')[1] for e in inspect['Config']['Env']
                                     if e.split('=')[0] == 'VIRTUAL_HOST' )
        except IndexError:
            pass # Probably, VIRTUAL_HOST is not in env

    except NotFound:
        prt('Creating ui container {}'.format(docker_name))

        if virtual_host:
            hostname = virtual_host
            if hostname.startswith('.'):
                hostname = group_name + hostname
        else:
            hostname = None

        envs['VIRTUAL_HOST'] = hostname

        #envs['AMBRY_UI_DEBUG'] = 'true'

        kwargs = dict(
            name=docker_name,
            image=image,
            labels={
                'civick.ambry.group': group_name,
                'civick.ambry.role': 'ui',
                'civick.ambry.virt_host': envs.get('VIRTUAL_HOST')
            },
            detach=False,
            tty=True,
            stdin_open=True,
            environment=envs,
            host_config=client.create_host_config(
                volumes_from=volumes_from,
                links=links,
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

    if envs.get('VIRTUAL_HOST'):
        remote_url = 'http://{}'.format(envs.get('VIRTUAL_HOST'))
    else:
        docker_host = select_from_url(client.base_url, 'hostname')

        try:
            port = inspect['NetworkSettings']['Ports']['80/tcp'][0]['HostPort']
        except:
            port = None

        remote_url = 'http://{}{}'.format(docker_host, ':{}'.format(port) if port else '')



    inspect = client.inspect_container(docker_name)

    return inspect['Id'], remote_url

def docker_ui(args, l, rc):
    from docker.errors import NotFound
    from ambry.exc import NotFoundError
    from ambry.util import select_from_url

    client = docker_client()

    if args.groupname[0].startswith('postgres://'):
        # A database name
        dsn = args.groupname[0]
        group_name = None
        container_name = "ambry_ui_{}".format(select_from_url(dsn, 'username'))
    else:
        group_name = args.groupname[0]
        dsn = None
        container_name = "ambry_ui_{}".format(group_name)

    try:

        if args.kill or args.restart:

            if not group_name:
                fatal("Must have a groupname to kill the UI container")

            try:
                client.remove_container(container_name, force=True)
                prt("Killed {}", container_name)
            except NotFound:
                if args.kill:
                    raise

        if args.kill:
            return

        # Try to get the base name for the virtual host from the docker host.
        virtual = args.virtual

        if not virtual:
            try:
                r = l.remote(client.base_url)
                virtual = r.virtual_host
            except NotFoundError:
                pass

        container_id, url = _docker_mk_ui(rc, client, group_name=group_name, dsn=dsn, virtual_host=virtual)

        admin_password = _init_ui(l, client, url, container_id, virtual_host=args.virtual, title=args.title)

        prt('UI Container')
        prt('   Name       : {}'.format(container_name))
        prt('   URL        : {} '.format(url))
        prt('   Credentials: {}/{} '.format('admin',admin_password))

    except NotFound as e:
        fatal("Docker error: {}".format(str(e)))


def _init_ui(library, client, remote_url,  ui_container_id, virtual_host=None, title=None):
    # Create the corresponding account in the UI's database. The database may not have been started yet, so
    # we may have to retry a bit

    from time import sleep
    from ambry.util import random_string

    last_output = []
    success = False

    for i in range(10):

        cmd = 'ambry ui init'

        if virtual_host:
            cmd += ' -v {}'.format(virtual_host)

        if title:
            cmd += ' -t {}'.format(title)

        ex = client.exec_create(container=ui_container_id, cmd=cmd)

        last_output = list(client.exec_start(ex['Id'], stream=True))

        ei = client.exec_inspect(ex['Id'])
        if ei['ExitCode'] == 0:
            success = True
            break
        else:
            prt("Database not running (yet?) Retry setting accounts ({})", last_output)
            sleep(1)

    if not success:
        warn("Failed to add api account to remote: ")
        prt('\n'.join(last_output))

    # Now that the DB is running:
    admin_password = random_string(20)
    ex = client.exec_create(container=ui_container_id,
                            cmd='ambry accounts add -v user/admin -a admin -s {} admin'.format(admin_password))
    client.exec_start(ex['Id'])

    remote = library.find_or_new_remote(remote_url, service='ambry')

    library.commit() # In case the remote is new

    remote.data['admin_pw'] = admin_password

    if not remote.secret:

        api_password = random_string(20)
        ex = client.exec_create(container=ui_container_id,
                                cmd='ambry accounts add -v api -a api -s {} api'.format(api_password))
        client.exec_start(ex['Id'])

        # Create a remote entry

        remote.access = 'api'
        remote.secret = api_password

    library.commit()

    return admin_password


def _docker_mk_proxy(client):
    from docker.errors import NotFound

    image = 'civicknowledge/proxy'

    check_ambry_image(client, image)

    container_name = 'ambry_proxy'

    try:
        inspect = client.inspect_container(container_name)
        print inspect['Id']
        prt('Found proxy container {}'.format(container_name))
    except NotFound:
        prt('Creating proxy container {}'.format(container_name))

        kwargs = dict(
            name=container_name,
            image=image,
            labels={
                'civick.ambry.role': 'proxy'
            },
            detach=False,
            tty=True,
            stdin_open=True,
            host_config=client.create_host_config(
                binds=[
                    '/var/run/docker.sock:/tmp/docker.sock:ro',
                ],
                port_bindings={80: ('0.0.0.0',80)}
            )
        )

        r = client.create_container(**kwargs)

        while True:
            try:
                inspect = client.inspect_container(r['Id'])
                break
            except NotFound:
                prt('Waiting for container to be created')

    inspect = client.inspect_container(container_name)

    if not inspect['State']['Running']:
        prt('Starting proxy container {}'.format(container_name))
        client.start(inspect['Id'])

    return inspect['Id']

def docker_volumes(args, l, rc):
    import os
    import shlex

    remote = l.remote(args.groupname[0])

    cmd = "docker run --rm -t -i --volumes-from {} ubuntu /bin/bash".format(remote.vol_name)

    os.execvp('docker', shlex.split(cmd))

def docker_library(args, l, rc):
    """Initialize a new docker volumes and database container, and report the database DSNs"""

    from ambry.util import parse_url_to_dict, random_string

    client = docker_client()

    groupname = args.groupname[0]

    remote = l.find_or_new_remote(groupname, service='docker')

    remote.docker_url = client.base_url

    if remote.db_dsn:
        d = parse_url_to_dict(remote.db_dsn)
        remote.tr_db_password = d['password']
        assert d['username'] == groupname

    else:
        remote.tr_db_password = random_string(16)

    if not remote.vol_name:
        remote.vol_name = 'ambry_volumes_{}'.format(groupname)

    if not remote.db_name:
        remote.db_name = 'ambry_db_{}'.format(groupname)


    l.commit()

    _docker_mk_proxy(client)
    _docker_mk_volume(rc, client,remote)
    db_id = _docker_mk_db(rc, client,remote, public_port=args.public)

    l.commit()

    if l and l.database.dsn != remote.db_dsn:
        prt("Set the library.database configuration to this DSN:")
        prt("    " + remote.db_dsn)

    if remote.db_host == 'localhost':
        warn("No public port; you'll need to set up a tunnel for external access")

def _docker_db_dsn(client, continer_id):
    """Return the database DSN from inspecting a db container"""
    from ambry.util import parse_url_to_dict

    inspect = client.inspect_container(continer_id)

    try:
        port = inspect['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
    except (TypeError, KeyError):
        port = None

    env = { e.split('=')[0]:e.split('=')[1] for e in  inspect['Config']['Env'] }

    if port:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=env['USER'], password=env['PASSWORD'], database=env['SCHEMA'],
            host=parse_url_to_dict(client.base_url)['hostname'], port=port)

    else:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=env['USER'], password=env['PASSWORD'], database=env['SCHEMA'],
            host='localhost', port='5432')

    return dsn


def check_ambry_image(client, image):
    from docker.errors import NotFound, NullResource


    try:
        _ = client.inspect_image(image)
    except NotFound:
        fatal(('Database image {i} not in docker. Run \'ambry docker build\' ').format(i=image))

def docker_shell(args, l, rc):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from docker.errors import NotFound, NullResource
    from ambry.util import set_url_part
    import os

    client = docker_client()

    if args.group:
        # The group was specified, so the database will be name 'db', via a docker link
        remote = l.remote(args.group)
        short_name = remote.short_name
        dsn = set_url_part(remote.db_dsn, hostname='db')
        host_config = client.create_host_config(volumes_from=[remote.vol_name],links={remote.db_name: 'db'})
    else:
        # No group was specified, so assume that the caller wants to use the DSN of the local library,
        # which must be acessible over the network.
        import hashlib
        short_name = hashlib.md5(l.dsn).hexdigest()
        dsn = l.dsn
        host_config = client.create_host_config()

    shell_name = 'ambry_shell_{}'.format(short_name)

    if args.docker_command:

        if args.docker_command[0] not in ('bambry', 'ambry'):
            docker_command = ['bambry'] + list(args.docker_command)
        else:
            docker_command =  list(args.docker_command)
    else:
        docker_command = None

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
                'civick.ambry.group': short_name,
                'civick.ambry.role': 'shell'
            },
            detach=args.detach,
            tty= not args.detach,
            stdin_open= not args.detach,
            environment={
                'AMBRY_DB': dsn
            },
            host_config=host_config,
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

        if args.detach:
            prt('Starting {} in background'.format(inspect['Id']))
            client.start(inspect['Id'])
        else:
            prt('Starting {} with exec'.format(inspect['Id']))
            # Starting with an exec to get a proper shell.
            os.execlp('docker', 'docker', 'start', '-a', '-i', inspect['Id'])

    else:

        prt("Exec new shell on running container")
        cmd = ['docker',  'exec', '-t', '-i', inspect['Id'] ]
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
        environment=remote_envs(rc, remote.db_dsn),
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

    for c in client.containers(all=True):

        try:
            groupname = c['Labels'].get('civick.ambry.group')
        except KeyError:
            groupname = 'uknown'

        if groupname not in args.groupname:
            continue

        name = c['Names'][0].strip('/')

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



def docker_ckan(args, l, rc, attach=True):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from ambry.util import parse_url_to_dict
    from docker.errors import NotFound, NullResource
    import os

    client = docker_client()

    raise NotImplementedError

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

        envs = remote_envs(rc, remote.db_dsn)

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

def docker_host(args, l, rc):

    client = docker_client()

    r = l.find_or_new_remote(client.base_url, service='docker_host')

    r.url = client.base_url
    r.service = 'docker_host'

    if args.virtual:
        r.virtual_host = '.'+args.virtual.strip('.')

    l.commit()

    prt("Docker host : {}", r.short_name)
    prt("Virtual host: {}", r.virtual_host)



def docker_local_dsn(dsn):
    from ambry.util import parse_url_to_dict, unparse_url_dict
    d = parse_url_to_dict(dsn)

    # Create the new container DSN; in docker, the database is always known as 'db'
    d['hostname'] = 'db'
    d['port'] = None

    return unparse_url_dict(d)

def remote_envs(rc, dsn):

    return {
        'AMBRY_DB' :  docker_local_dsn(dsn)
    }


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
                tar.add(os.path.join(cd, 'ambry', 'support', 'ambry-devel.yaml'), arcname='ambry/support/ambry-devel.yaml')
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

        prt('Building')

        tag = 'civicknowledge/' + (tag or name)

        client = docker_client()

        for line in client.build(path=docker_file_path, fileobj=fo,dockerfile=df,
                                 custom_context=context, rm=True, nocache=args.clean,
                                 tag=tag, decode=True):
            if 'stream' in line:
                print line['stream'],
            elif 'status' in line:
                print 'Status', line['status']

            elif 'errorDetail' in line:
                m = line['errorDetail']['message']
                raise DockerError("Docker Error: "+m)

            else:
                raise DockerError(line)

        client.tag(tag+':latest', tag, __version__, force=True)

    if args.context:

        docker_file_dir = os.path.join(base_dir, 'dev') # 'dev' select which Dockerfile is included in the context
        docker_file_in = os.path.join(docker_file_dir, 'Dockerfile')

        context_file = make_dist_tar(docker_file_in)
        prt('Built context file: {} '.format(context_file))

    if args.base or args.all:
        d_build('ambry-base', context=True)

    if args.numbers:
        d_build('numbers')

    if args.build:
        d_build('ambry', context=True)

    if args.dev or args.all:
        d_build('dev', tag='ambry', context=True)

    if args.db or args.all:
        d_build('postgres')

    if args.tunnel:
        d_build('tunnel')

    if args.ui or args.all:
        d_build('ambryui')

    if args.ui_debug:
        d_build('ambryui-debug', tag='ambryui')

    if args.volumes or args.all:
        d_build('volumes')

    if args.ckan:
        d_build('ckan')

    if args.proxy or args.all:
        d_build('proxy')



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
                remote.url = "http://"+envs['virtual_host']
            elif role == 'volumes':
                remote.vol_name = m['name']


            prt("Added {}".format(m['name']))

    l.commit()



