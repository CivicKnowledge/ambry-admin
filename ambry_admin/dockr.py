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
    sp.add_argument('-g', '--groupname', help="Set the username / group name, rather than selecting one randomly")

    sp = asp.add_parser('shell', help='Run a shell in a container')
    sp.set_defaults(subcommand='shell')
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running shell before starting a new one")
    sp.add_argument('docker_command', nargs='*', type=str, help='Command to run, instead of bash')

    sp = asp.add_parser('tunnel', help='Run an ssh tunnel to the current database container')
    sp.set_defaults(subcommand='tunnel')
    sp.add_argument('-i', '--identity', help="Specify an identity file for loggin into the docker host")
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running tunnel before starting a new one")
    sp.add_argument('ssh_key_file', type=str, nargs=1, help='Path to an ssh key file')

    sp = asp.add_parser('list', help='List docker entries in the accounts file')
    sp.set_defaults(subcommand='list')

    sp = asp.add_parser('kill', help='Destroy all of the containers associated with a username')
    sp.set_defaults(subcommand='kill')
    sp.add_argument('groupname', type=str, nargs='*', help='Group name of set of containers')

    sp = asp.add_parser('ui', help='Run the user interface container')
    sp.set_defaults(subcommand='ui')
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running shell before starting a new one")
    sp.add_argument('-s', '--shell', default=False, action='store_true',
                    help="Run a shell instead")

    sp = asp.add_parser('ckan', help='Run the ckan container')
    sp.set_defaults(subcommand='ckan')
    sp.add_argument('-k', '--kill', default=False, action='store_true',
                    help="Kill a running container before starting a new one")


    sp = asp.add_parser('info', help='Print information about a docker group')
    sp.set_defaults(subcommand='info')
    sp.add_argument('-d', '--dsn', default=False, action='store_true',
                    help="Display the database DSN")
    sp.add_argument('groupname', type=str, nargs=1, help='Group name of set of containers')

    sp = asp.add_parser('build', help='BUild a docker container')
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

    #
    # Run
    #

    command_p = asp.add_parser('run', help='Run bambry commands in a docker container')
    command_p.set_defaults(subcommand='run')
    command_p.add_argument('-i', '--id', help='Specify the id of the bundle to run')
    command_p.add_argument('-I', '--docker_id', default=False, action='store_true',
                           help='Print the id of the running container')
    command_p.add_argument('-c', '--container', help='Use a specific container id')
    command_p.add_argument('-k', '--kill', default=False, action='store_true',
                           help='Kill the running container')
    command_p.add_argument('-n', '--docker_name', default=False, action='store_true',
                           help='Print the name of the running container')
    command_p.add_argument('-l', '--logs', default=False, action='store_true',
                           help='Get the logs (stdout) from a runnings container')
    command_p.add_argument('-s', '--shell', default=False, action='store_true',
                           help='Run a shell on the currently running container')
    command_p.add_argument('-S', '--stats', default=False, action='store_true',
                           help='Report stats from the currently running container')
    command_p.add_argument('-v', '--version', default=False, action='store_true',
                           help='Select a docker version that is the same as this Ambry installation')
    command_p.add_argument('-m', '--multi', default=False, action='store_true',
                        help='Run in multiprocessing mode')
    command_p.add_argument('-L', '--limited-run', default=False, action='store_true',
                           help='Run a limited number of rows, for testing')
    command_p.add_argument('-p', '--processes', type=int,
                    help='Number of multiprocessing processors. implies -m')

    command_p.add_argument('args', nargs='*', type=str, help='additional arguments')


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

def get_docker_file(rc):
    """Get the path for a .ambry-docker file, parallel to the .ambry.yaml file"""
    from os.path import dirname, join, exists
    from ambry.util import AttrDict

    loaded = rc['loaded'][0]

    path = join(dirname(loaded),'docker.yaml')

    if not exists(path):
        with open(path, 'wb') as f:
            d = AttrDict()
            d['foo'] = dict(name='bar')
            d.dump(f)

    return path

def get_df_entry(rc,name):
    from ambry.util import AttrDict

    d = AttrDict.from_yaml(get_docker_file(rc))

    return d[name]

def set_df_entry(rc, name, entry):
    from ambry.util import AttrDict
    import os.path

    if os.path.exists(get_docker_file(rc)):
        try:
            d = AttrDict.from_yaml(get_docker_file(rc))
        except TypeError:
            # Empty file, I guess.
            d = AttrDict()
    else:
        d = AttrDict()

    d[name] = entry

    with open(get_docker_file(rc), 'wb') as f:
        d.dump(f)

def remove_df_entry(rc, name):
    from ambry.util import AttrDict
    import os.path

    if os.path.exists(get_docker_file(rc)):
        d = AttrDict.from_yaml(get_docker_file(rc))
    else:
        d = AttrDict()

    if name in d:
        del d[name]

    with open(get_docker_file(rc), 'wb') as f:
        d.dump(f)

def docker_init(args, l, rc):
    """Initialize a new docker volumes and database container, and report the database DSNs"""

    from docker.errors import NotFound, NullResource
    import string
    import random
    from ambry.util import parse_url_to_dict
    from docker.utils import kwargs_from_env
    from ambry.cli import fatal

    client = docker_client()

    def id_generator(size=12, chars=string.ascii_lowercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    # Check if the postgres image exists.

    postgres_image = 'civicknowledge/postgres'

    try:
        inspect = client.inspect_image(postgres_image)
    except NotFound:
        fatal(('Database image {i} not in docker. Run \'python setup.py docker -D\' or '
               ' \'docker pull {i}\'').format(i=postgres_image))

    volumes_image = 'civicknowledge/volumes'

    try:
        inspect = client.inspect_image(volumes_image)
    except NotFound:
        prt('Pulling image for volumns container: {}'.format(volumes_image))
        client.pull(volumes_image)


    # Assume that the database host IP is also the docker host IP. This usually be true
    # externally to the docker host, and internally, we'll alter the host:port to
    # 'db' anyway.
    db_host_ip = parse_url_to_dict(kwargs_from_env()['base_url'])['netloc'].split(':',1)[0]

    try:
        d = parse_url_to_dict(l.database.dsn)
    except AttributeError:
        d = {'query':''}

    if 'docker' not in d['query'] or args.new:
        groupname = id_generator()
        password = id_generator()
        database = groupname
    else:
        groupname = d['username']
        password = d['password']
        database = d['path'].strip('/')

    # Override the username if one was provided
    if args.groupname:
        groupname =  database = args.groupname

    volumes_c = 'ambry_volumes_{}'.format(groupname)
    db_c = 'ambry_db_{}'.format(groupname)

    #
    # Create the volume container
    #

    try:
        inspect = client.inspect_container(volumes_c)
        prt('Found volume container {}'.format(volumes_c))
    except NotFound:
        prt('Creating volume container {}'.format(volumes_c))

        r = client.create_container(
            name=volumes_c,
            image=volumes_image,
            labels={
                'civick.ambry.group': groupname,
                'civick.ambry.message': args.message,
                'civick.ambry.role': 'volumes'
            },
            volumes=['/var/ambry', '/var/backups'],
            host_config = client.create_host_config()
        )

    #
    # Create the database container
    #

    try:
        inspect = client.inspect_container(db_c)
        prt('Found db container {}'.format(db_c))
    except NotFound:
        prt('Creating db container {}'.format(db_c))

        if args.public:
            port_bindings = {5432: ('0.0.0.0',)}
        else:
            port_bindings = None

        kwargs = dict(
            name=db_c,
            image=postgres_image,
            labels={
                'civick.ambry.group': groupname,
                'civick.ambry.message': args.message,
                'civick.ambry.role': 'db'

            },
            volumes=['/var/ambry', '/var/backups'],
            ports=[5432],
            environment={
                'ENCODING': 'UTF8',
                'BACKUP_ENABLED': 'true',
                'BACKUP_FREQUENCY': 'daily',
                'BACKUP_EMAIL': 'eric@busboom.org',
                'USER': groupname,
                'PASSWORD': password,
                'SCHEMA': database,
                'POSTGIS': 'true'
            },
            host_config=client.create_host_config(
                volumes_from=[volumes_c],
                port_bindings=port_bindings
            )
        )

        r = client.create_container(**kwargs)

        client.start(r['Id'])

        inspect = client.inspect_container(r['Id'])

    try:
        port =  inspect['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
    except (TypeError, KeyError):
        port = None

    if port:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
                username=groupname, password=password, database=database, host=db_host_ip, port=port)

    else:
        dsn = 'postgres://{username}:{password}@{host}:{port}/{database}?docker'.format(
            username=groupname, password=password, database=database, host='localhost', port='5432')
        warn("No public port; you'll need to set up a tunnel for external access")

    if l and l.database.dsn != dsn:
        prt("Set the library.database configuration to this DSN:")
        prt(dsn)


    set_df_entry(rc, groupname, dict(
        username=groupname,
        password=password,
        database=database,
        db_port=int(port) if port else None,
        host=db_host_ip,
        docker_url=client.base_url,
        volumes_name=volumes_c,
        db_name=db_c,
        dsn=dsn,
        message=args.message
    ))

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

    if args.docker_command:

        if args.docker_command[0] not in ('bambry', 'ambry'):
            docker_command = ['bambry'] + list(args.docker_command)
        else:
            docker_command =  list(args.docker_command)
    else:
        docker_command = None

    client = docker_client()

    username, dsn, volumes_c, db_c, envs = get_docker_links(rc)

    shell_name = 'ambry_shell_{}'.format(username)

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
                'civick.ambry.group': username,
                'civick.ambry.role': 'shell'
            },
            detach=False,
            tty=True,
            stdin_open=True,
            environment=envs,
            host_config=client.create_host_config(
                volumes_from=[volumes_c],
                links={
                    db_c: 'db'
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

    groupname, dsn, volumes_c, db_c, envs = get_docker_links(rc)

    shell_name = 'ambry_tunnel_{}'.format(groupname)

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
            'civick.ambry.group': groupname,
            'civick.ambry.role': 'tunnel'
        },
        detach=False,
        tty=False,
        stdin_open=False,
        environment=envs,
        host_config=client.create_host_config(
            links={
                db_c: 'db'
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

    client = docker_client()

    for groupname in args.groupname:

        for c in client.containers(all=True):
            name = c['Names'][0].strip('/')
            if groupname in name:
                prt("Removing: {}".format(name))
                client.remove_container(container=c['Id'], v=True, force=True)
                try:
                    remove_df_entry(rc, groupname)
                except KeyError:
                    pass


def docker_ui(args, l, rc, attach=True):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from docker.errors import NotFound, NullResource
    import os

    client = docker_client()

    groupname, dsn, volumes_c, db_c, envs = get_docker_links(rc)

    shell_name = 'ambry_ui_{}'.format(groupname)

    # Check if the  image exists.

    image = 'civicknowledge/ambryui'

    check_ambry_image(client, image)

    try:
        inspect = client.inspect_container(shell_name)
        running = inspect['State']['Running']
        exists = True
    except NotFound as e:
        running = False
        exists = False

    # If no one is using is, clear it out.
    if exists and (not running or args.kill):
        prt('Killing container {}'.format(shell_name))
        client.remove_container(shell_name, force = True)
        exists = False
        running = False

    if not running:

        vh_root = rc.get('docker', {}).get('ui_domain', None)
        if vh_root:
            envs['VIRTUAL_HOST'] = '{}.{}'.format(groupname, vh_root)

        try:
            df = get_df_entry(rc, groupname)
            if df.get('message'):
                envs['AMBRY_UI_TITLE'] = df.get('message')
        except KeyError:
            pass

        kwargs = dict(
            name=shell_name,
            image=image,
            labels={
                'civick.ambry.group': groupname,
                'civick.ambry.role': 'ui',
                'civick.ambry.virt_host': envs.get('VIRTUAL_HOST')
            },
            detach=False,
            tty=True,
            stdin_open=True,
            environment=envs,
            host_config=client.create_host_config(
                volumes_from=[volumes_c],
                links={
                    db_c: 'db',
                },
                port_bindings={80: ('0.0.0.0',)}
            )
        )

        if args.shell:
            kwargs['command'] = '/bin/bash' # Just to turn off the call to  Gunicorn

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

        prt('Starting ui container')
        prt('   Name {}'.format(shell_name))
        prt('   Virtual host http://{} '.format(envs.get('VIRTUAL_HOST')))
        prt('   Host port: {}'.format(port))

    else:
        prt('Container {} is already running'.format(shell_name))
        inspect = client.inspect_container(shell_name)

    if args.shell:
        inspect = client.inspect_container(shell_name)
        running = inspect['State']['Running']

        if running:
            prt('Starting {}'.format(inspect['Id']))
            os.execlp('docker', 'docker', 'start', '-a', '-i', inspect['Id'])
        else:
            prt("Exec new shell on running container")
            os.execlp('docker', 'docker', 'exec', '-t', '-i', inspect['Id'], '/bin/bash')

def docker_ckan(args, l, rc, attach=True):
    """Run a shell in an Ambry builder image, on the current docker host"""

    from ambry.util import parse_url_to_dict
    from docker.errors import NotFound, NullResource
    import os

    client = docker_client()

    username, dsn, volumes_c, db_c, envs = get_docker_links(rc)

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
        rows.append([group, None, None, None, e['message'] ])

        try:
            df = get_df_entry(rc, group)
        except KeyError:
            df = {}

        for role in sorted([k for k,v in e.items() if isinstance(v, dict)]):
            m = e[role]
            if role in ('ui', 'ckan'):
                message = m['vhost']
            elif role == 'db' and df:
                message = df.get('dsn')
            else:
                message = None
            rows.append(['', role, m['name'], m['ports'], message])


    from tabulate import tabulate

    print tabulate(rows, headers)

def docker_info(args, l, rc):

    groupname = args.groupname.pop(0)

    if args.dsn:
        try:
            df = get_df_entry(rc, groupname)
            prt(df['dsn'])
        except KeyError:
            # Meant for use in shell scripts, so jsut reutrn an error return code
            import sys
            sys.exit(1)


def get_docker_links(rc):
    from ambry.util import parse_url_to_dict, unparse_url_dict
    from ambry.library.filesystem import LibraryFilesystem

    fs = LibraryFilesystem(rc)

    dsn = fs.database_dsn

    d = parse_url_to_dict(dsn)

    if not 'docker' in d['query']:
        fatal("Database '{}' doesn't look like a docker database DSN; it should have 'docker' at the end"
              .format(dsn))

    # Create the new container DSN; in docker, the database is always known as 'db'
    d['hostname'] = 'db'
    d['port'] = None
    dsn = unparse_url_dict(d)

    # The username is the unique id part of all of the docker containers, so we
    # can construct the names of the database and volumes container from it.
    groupname = d['username']
    volumes_c = 'ambry_volumes_{}'.format(groupname)
    db_c = 'ambry_db_{}'.format(groupname)

    envs = {}
    envs['AMBRY_DB'] = dsn
    envs['AMBRY_ACCOUNT_PASSWORD'] = (rc.accounts.get('password'))

    return groupname, dsn, volumes_c, db_c, envs

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


def docker_run(args, l, rc):
    import os
    import sys
    from docker.errors import NotFound, NullResource
    from ambry.cli.bundle import using_bundle

    username, dsn, volumes_c, db_c, envs = get_docker_links(rc)

    b = using_bundle(args, l, print_loc=False)
    client = docker_client()

    if args.container:
        last_container = args.container
    else:
        try:
            last_container = b.buildstate.docker.last_container
        except KeyError:
            last_container = None

    try:
        inspect = client.inspect_container(last_container)

    except NotFound:
        # OK; the last_container is dead
        b.buildstate.docker.last_container = None
        b.buildstate.commit()
        inspect  = None
    except NullResource:
        inspect = None
        pass  # OK; no container specified in the last_container value

    #
    # Command args
    #

    bambry_cmd = ' '.join(args.args).strip()

    def run_container(bambry_cmd=None):
        """Run a new docker container"""


        if bambry_cmd:

            if last_container:
                fatal("Bundle already has a running container: {}\n{}".format(inspect['Name'], inspect['Id']))

            bambry_cmd_args = []

            if args.limited_run:
                bambry_cmd_args.append('-L')

            if args.multi:
                bambry_cmd_args.append('-m')

            if args.processes:
                bambry_cmd_args.append('-p' + str(args.processes))

            envs['AMBRY_COMMAND'] = 'bambry -i {} {} {}'.format(
                                    b.identity.vid, ' '.join(bambry_cmd_args), bambry_cmd)

            detach = True
        else:
            detach = False

        if args.limited_run:
            envs['AMBRY_LIMITED_RUN'] = '1'

        try:
            image_tag = rc.docker.ambry_image
        except KeyError:
            image_tag = 'civicknowledge/ambry'

        if args.version:
            import ambry._meta
            image = '{}:{}'.format(image_tag,ambry._meta.__version__)
        else:
            image = image_tag

        try:
            volumes_from = [rc.docker.volumes_from]
        except KeyError:
            volumes_from = []

        volumes_from.append(volumes_c)

        host_config = client.create_host_config(
            volumes_from=volumes_from,
            links={
                db_c:'db'
            }
        )

        kwargs = dict(
            image=image,
            detach=detach,
            tty=not detach,
            stdin_open=not detach,
            environment=envs,
            host_config=host_config
        )

        prt('Starting container with image {} '.format(image))

        r = client.create_container(**kwargs)

        client.start(r['Id'])

        return r['Id']

    if args.kill:

        if last_container:

            if inspect and inspect['State']['Running']:
                client.kill(last_container)

            client.remove_container(last_container)

            prt('Killed {}', last_container)

            b.buildstate.docker.last_container = None
            b.buildstate.commit()
            last_container = None
        else:
            warn('No container to kill')

    if bambry_cmd:
        # If there is command, run the container first so the subsequent arguments can operate on it
        last_container = run_container(bambry_cmd)
        b.buildstate.docker.last_container = last_container
        b.buildstate.commit()

    if args.docker_id:
        if last_container:
            prt(last_container)

        return

    elif args.docker_name:

        if last_container:
            prt(inspect['Name'])

        return

    elif args.logs:

        if last_container:
            for line in client.logs(last_container, stream=True):
                print line,
        else:
            fatal('No running container')

    elif args.stats:

        for s in client.stats(last_container, decode=True):

            sys.stderr.write("\x1b[2J\x1b[H")
            prt_no_format(s.keys())
            prt_no_format(s['memory_stats'])
            prt_no_format(s['cpu_stats'])

    elif args.shell:
        # Run a shell on a container
        # This is using execlp rather than the docker API b/c we want to entirely replace the
        # current process to get a good tty.
        os.execlp('docker', 'docker', 'exec', '-t','-i', last_container, '/bin/bash')

    elif not bambry_cmd and not args.kill:
        # Run a container and then attach to it.
        cid = run_container()

        os.execlp('docker', 'docker', 'attach', cid)

