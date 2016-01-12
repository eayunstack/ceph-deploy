import os
import re
import errno
from ceph_deploy.cliutil import priority
import logging
from cStringIO import StringIO
from ceph_deploy import conf
from ceph_deploy import exc
from ceph_deploy import hosts
from ceph_deploy.lib import remoto
from ceph_deploy.new import generate_auth_key
from ceph_deploy.util import files

LOG = logging.getLogger(__name__)

RGW_CONTECT = '''<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html
    ErrorLog /var/log/httpd/rgw_error.log
    CustomLog /var/log/httpd/rgw_access.log combined
    # LogLevel debug
    RewriteEngine On
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%%{HTTP:Authorization},L]
    SetEnv proxy-nokeepalive 1
    ProxyPass / unix:///var/run/ceph/client.radosgw.%s.sock|fcgi://localhost:9000/
</VirtualHost>'''

FACTCGI_CONTECT = "<IfModule !proxy_fcgi_module>\nLoadModule proxy_fcgi_module modules/mod_proxy_fcgi.so\n</IfModule>"

REGION_CONTECT = '''{ "name": "%s",
    "api_name": "%s",
    "is_master": "true",
    "endpoints": [
          "http:\/\/%s:80\/"],
    "master_zone": "%s",
    "zones": [
        { "name": "%s",
            "endpoints": [
                "http:\/\/%s:80\/"],
            "log_meta": "true",
            "log_data": "true"}],
    "placement_targets": [
        {
            "name": "default-placement",
            "tags": []
        }
    ],
    "default_placement": "default-placement"},
    "hostnames": [%s]'''

ZONE_CONTECT = '''{ "domain_root": ".%(zone)s.domain.rgw",
      "control_pool": ".%(zone)s.rgw.control",
      "gc_pool": ".%(zone)s.rgw.gc",
      "log_pool": ".%(zone)s.log",
      "intent_log_pool": ".%(zone)s.intent-log",
      "usage_log_pool": ".%(zone)s.usage",
      "user_keys_pool": ".%(zone)s.users",
      "user_email_pool": ".%(zone)s.users.email",
      "user_swift_pool": ".%(zone)s.users.swift",
      "user_uid_pool": ".%(zone)s.users.uid",
      "system_key": { "access_key": "%(access_key)s", "secret_key": "%(secret_key)s"},
      "placement_pools": [
        { "key": "default-placement",
          "val": { "index_pool": ".%(zone)s.rgw.buckets.index",
                   "data_pool": ".%(zone)s.rgw.buckets"}
        }
      ]
    }'''


def get_exists_region(cfg):
    for sec in cfg.sections():
        if 'rgw_region' in cfg.options(sec):
            return cfg.get(sec, 'rgw_region')
    raise


def get_hosts(cfg, zone_name):
    host_list = []
    for sec in cfg.sections():
        if 'rgw_zone' in cfg.options(sec) and cfg.get(sec, 'rgw_zone') == zone_name:
            host_list.append(cfg.get(sec, 'host'))
    return host_list


def restart_serv(conn, gw_name):
    remoto.process.run(conn, ['/etc/init.d/ceph', 'restart', 'mon', ], timeout=7)
    remoto.process.run(conn,
                       ['/etc/init.d/ceph-radosgw', 'start', '-n', 'client.radosgw.%s' % gw_name],
                       timeout=7)
    remoto.process.run(conn, ['systemctl', 'enable', 'httpd', ], timeout=7)
    remoto.process.run(conn, ['systemctl', 'restart', 'httpd', ], timeout=7)


def push_admin_keyring(args):
    host_name = args.host
    keyring_path = '{name}.client.admin.keyring'.format(
        name=args.cluster,
    )
    rgw_keyring = files.read_file(keyring_path)
    admin_keyring = '/etc/ceph/{name}.client.admin.keyring'.format(
        name=args.cluster,
    )
    distro = hosts.get(host_name, username=args.username)
    distro.conn.remote_module.write_file(admin_keyring, rgw_keyring)


def new_rgw_keyring(args, gw_name, conn):
    LOG.debug('Creating a random rgw key...')
    keyring_path = '{name}.client.radosgw.keyring'.format(
        name=args.cluster,
    )
    rgw_keyring = ''
    if os.path.exists(keyring_path):
        try:
            rgw_keyring = files.read_file(keyring_path)
        except Exception:
            raise

    rgw_keyring += '''[client.radosgw.%s]
    key = %s
    caps mon = "allow rwx"
    caps osd = "allow rwx"\n''' % (gw_name, generate_auth_key())

    # Write to the local configuration file.
    LOG.debug('Writing radosgw keyring to %s...', keyring_path)
    tmp = '%s.tmp' % keyring_path
    with file(tmp, 'w') as f:
        f.write(rgw_keyring)
    try:
        os.rename(tmp, keyring_path)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise exc.ClusterExistsError(keyring_path)
        else:
            raise

    # Write to the remote configuration file.
    keypath = '/etc/ceph/{name}.client.radosgw.keyring'.format(
        name=args.cluster,
    )
    cfg = conf.ceph.load(args)
    zone_name = args.zone
    host_name = args.host
    other_hosts = get_hosts(cfg, zone_name)
    other_hosts.append(host_name)
    for host in other_hosts:
        distro = hosts.get(host, username=args.username)
        distro.conn.remote_module.write_file(keypath, rgw_keyring)

    # add each key as an entry to your Ceph Storage Cluster.
    remoto.process.run(
        conn,
        [
            'ceph',
            '-k',
            '/etc/ceph/%s.client.admin.keyring' % args.cluster,
            'auth',
            'add',
            'client.radosgw.%s' % gw_name,
            '-i',
            '/etc/ceph/%s.client.radosgw.keyring' % args.cluster,
        ],
        timeout=7
    )


def config_http(distro, conn, gw_name):
    # Create data directories for each daemon instance on their respective hosts.
    remoto.process.run(conn, ['mkdir', '-p', '/var/lib/ceph/radosgw/ceph-radosgw.%s' % gw_name, ],
                       timeout=7)
    # install httpd
    stdout, stderr, returncode = remoto.process.check(conn, ['rpm','-qa','httpd'], timeout=7)
    if not stdout:
        remoto.process.run(conn, ['yum', 'install', '-y', 'httpd', ], timeout=0)
    remoto.process.run(conn, ['chown', 'apache:apache', '/var/run/ceph', ], timeout=0)
    remoto.process.run(conn, ['mkdir', '-p', '/var/log/radosgw', ], timeout=0)
    distro.conn.remote_module.touch_file('/var/log/radosgw/client.radosgw.gateway.log')
    remoto.process.run(conn, ['chown', 'apache:apache', '/var/log/radosgw/client.radosgw.gateway.log', ],
                       timeout=0)
    httpd_path = '/etc/httpd/conf/httpd.conf'
    httpd_context = '%s\n%s' % (distro.conn.remote_module.get_file(httpd_path), FACTCGI_CONTECT)
    distro.conn.remote_module.write_file(httpd_path, httpd_context)
    gw_context = RGW_CONTECT % gw_name
    gw_path = '/etc/httpd/conf.d/rgw.conf'
    distro.conn.remote_module.write_file(gw_path, gw_context)


def create_tmp_conf(args):
    cfg = conf.ceph.load(args)
    try:
        region_name = get_exists_region(cfg)
    except Exception:
        region_name = args.region
    zone_name = args.zone
    host_name = args.host
    gw_name = '%s-%s' % (zone_name, host_name)
    section = 'client.radosgw.%s' % gw_name
    cfg.add_section(section)
    cfg.set(section, 'rgw region', region_name)
    cfg.set(section, 'rgw region root pool', '.%s.rgw.root' % region_name)
    cfg.set(section, 'rgw zone', zone_name)
    cfg.set(section, 'rgw zone root pool', '.%s.rgw.root' % zone_name)
    cfg.set(section, 'keyring', '/etc/ceph/ceph.client.radosgw.keyring')
    cfg.set(section, 'rgw dns name', host_name)
    cfg.set(section, 'rgw socket path', '/var/run/ceph/client.radosgw.%s.sock' % gw_name)
    cfg.set(section, 'log file', '/var/log/radosgw/client.radosgw.gateway.log')
    cfg.set(section, 'host', host_name)

    LOG.debug('Set configuration item and Create Configuration file...')
    path = '{name}.conf'.format(name=args.cluster)
    tmp = '%s.tmp' % path
    with file(tmp, 'w') as f:
        cfg.write(f)
    try:
        os.rename(tmp, path)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise exc.ClusterExistsError(path)
        else:
            raise

    conf_data = StringIO()
    cfg.write(conf_data)
    other_hosts = get_hosts(cfg, zone_name)
    other_hosts.append(host_name)
    for host in other_hosts:
        distro = hosts.get(host, username=args.username)
        distro.conn.remote_module.write_conf(
            args.cluster,
            conf_data.getvalue(),
            True,
        )

def eayunrgw_create(args):
    LOG.info("eayunrgw create ")

    region_name = args.region
    zone_name = args.zone
    host_name = args.host
    domain = args.domain
    if not domain:
        domain = ["obs.eayun.com"]
    gw_name = '%s-%s' % (zone_name, host_name)
    distro = hosts.get(host_name, username=args.username)
    conn = distro.conn

    create_tmp_conf(args)
    new_rgw_keyring(args, gw_name, conn)

    # Create pools.
    suffix = ['.rgw', '.rgw.root', '.rgw.control', '.rgw.gc',
              '.rgw.buckets', '.rgw.buckets.index', '.rgw.buckets.extra',
              '.log', '.intent-log', '.usage', '.users',
              '.users.email', '.users.uid']
    pools = ['.%s%s' % (zone_name, suf) for suf in suffix]
    for pool in pools:
        remoto.process.run(conn,
                           ['ceph', 'osd', 'pool', 'create', pool, '32', ],
                           timeout=7)
    # Create region root pools,Otherwise fail to update regionmap
    remoto.process.run(conn,
                   ['ceph', 'osd', 'pool', 'create', '.%s.rgw.root' % region_name, '32', ],
                   timeout=7)

    config_http(distro, conn, gw_name)

    # To configure region.
    LOG.debug('Create region configuration file and Set region...')
    region_context = REGION_CONTECT % (
        region_name,
        region_name,
        host_name,
        zone_name,
        zone_name,
        host_name,
        reduce(lambda x, y: x+','+y, domain)
    )
    region_path = '/etc/ceph/%s.json' % region_name
    distro.conn.remote_module.write_file(region_path, region_context)
    remoto.process.run(conn,
                       ['radosgw-admin', 'region', 'set', '--infile', region_path, '--name',
                        'client.radosgw.%s' % gw_name],
                       timeout=7)
    remoto.process.run(conn,
                       ['radosgw-admin', 'region', 'default', '--rgw-region=%s' % region_name, '--name',
                        'client.radosgw.%s' % gw_name],
                       timeout=7)
    remoto.process.run(conn,
                       ['radosgw-admin', 'regionmap', 'update', '--name', 'client.radosgw.%s' % gw_name],
                       timeout=7)

    # To configure zone.
    LOG.debug('Create zone configuration file and Set zone...')
    # frist configure
    zone_context = ZONE_CONTECT % {
        'zone': zone_name,
        'access_key': '',
        'secret_key': ''
    }
    zone_path = '/etc/ceph/%s.json' % zone_name
    distro.conn.remote_module.write_file(zone_path, zone_context)
    remoto.process.run(
        conn,
        [
            'radosgw-admin',
            'zone',
            'set',
            '--rgw-zone=%s' % zone_name,
            '--infile',
            zone_path,
            '--name',
            'client.radosgw.%s' % gw_name
        ],
        timeout=7
    )
    remoto.process.run(
        conn,
        [
            'radosgw-admin',
            'regionmap',
            'update',
            '--name',
            'client.radosgw.%s' % gw_name
        ],
        timeout=7
    )

    def create_zone_user(name):
        distro = hosts.get(host_name, username=args.username)
        conn = distro.conn
        stdout, stderr, returncode = remoto.process.check(
            conn,
            ['radosgw-admin',
             'user',
             'create',
             '--uid=%s' % name,
             '--display-name=user-%s' % name,
             '--name',
             'client.radosgw.%s' % name,
             '--system'],
            timeout=7)

        acc_key, sec_key = ('', '')
        if returncode != 0:
            LOG.error('Get radosgw user access_key and secret_key failure')
        else:
            m = re.search('"access_key": "(\S+)"', str(stdout))
            if hasattr(m, 'group'):
                acc_key = m.group(1)
            m = re.search('"secret_key": "(\S+)"', str(stdout))
            if hasattr(m, 'group'):
                sec_key = m.group(1)
            return acc_key, sec_key

    # second configure
    access_key, secret_key = create_zone_user(gw_name)
    zone_context = ZONE_CONTECT % {'zone': zone_name, 'access_key': access_key, 'secret_key': secret_key}
    zone_path = '/etc/ceph/%s.json' % zone_name
    distro.conn.remote_module.write_file(zone_path, zone_context)
    remoto.process.run(
        conn,
        [
            'radosgw-admin',
            'zone',
            'set',
            '--rgw-zone=%s' % zone_name,
            '--infile',
            zone_path,
            '--name',
            'client.radosgw.%s' % gw_name
        ],
        timeout=7
    )
    remoto.process.run(
        conn,
        [
            'radosgw-admin',
            'regionmap',
            'update',
            '--name',
            'client.radosgw.%s' % gw_name
        ],
        timeout=7
    )

    restart_serv(conn, gw_name)


def eayunrgw_add(args):
    LOG.info("eayunrgw add ")

    zone_name = args.zone
    host_name = args.host
    gw_name = '%s-%s' % (zone_name, host_name)
    distro = hosts.get(host_name, username=args.username)
    conn = distro.conn

    create_tmp_conf(args)
    push_admin_keyring(args)
    new_rgw_keyring(args, gw_name, conn)
    config_http(distro, conn, gw_name)
    restart_serv(conn, gw_name)


def eayunrgw(args):
    if args.subcommand == 'create':
        eayunrgw_create(args)
    elif args.subcommand == 'add':
        eayunrgw_add(args)


@priority(30)
def make(parser):
    """
    RGWEayun RGW deploy tool
    """
    eayunrgw_parser = parser.add_subparsers(dest='subcommand')
    eayunrgw_create = eayunrgw_parser.add_parser(
        'create',
        help='Create an Eayun RGW instance'
        )
    eayunrgw_create.add_argument(
        '--region',
        metavar='REGION',
        required=True,
        help='The name of logical geographic area, e.g. beijing'
        )
    eayunrgw_create.add_argument(
        '--zone',
        metavar='ZONE',
        required=True,
        help='The name of logical grouping, e.g. daxing'
        )
    eayunrgw_create.add_argument(
        '--host',
        metavar='HOST',
        required=True,
        help='The host to which deploy eayun rgw'
        )
    eayunrgw_create.add_argument(
        '--domain',
        metavar='DOMAIN',
        required=False,
        nargs='*',
        help='The domain name to which deploy eayun rgw'
        )

    eayunrgw_create = eayunrgw_parser.add_parser(
        'add',
        help='Add an eayunrgw instance to exist and zone'
        )
    eayunrgw_create.add_argument(
        '--zone',
        metavar='ZONE',
        required=True,
        help='The name of logical grouping, e.g. daxing'
        )
    eayunrgw_create.add_argument(
        '--host',
        metavar='HOST',
        required=True,
        help='The host to which deploy eayun rgw'
        )

    parser.set_defaults(
        func=eayunrgw,
        )
