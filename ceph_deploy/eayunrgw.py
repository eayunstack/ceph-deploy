import os
import time
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

RGW_CONTECT = '''<VirtualHost *:8080>
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
          "http:\/\/%s:8080\/"],
    "master_zone": "%s",
    "zones": [
        { "name": "%s",
            "endpoints": [
                "http:\/\/%s:8080\/"],
            "log_meta": "true",
            "log_data": "true"}],
    "placement_targets": [
        {
            "name": "default-placement",
            "tags": []
        }
    ],
    "default_placement": "default-placement",
    "hostnames": [%s]},'''

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

HAPROXY_CONF_COMMON = '''global
    log         127.0.0.1 local2

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon
    stats socket /var/lib/haproxy/stats

defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

listen Stats *:10000
    mode http
    stats enable
    stats uri /
    stats refresh 5s
    stats show-node
    stats show-legends
    stats hide-version

peers ceph_peers'''

HAPROXY_PEER_CONTECT='    peer %(host)s %(host)s:8060'


HAPROXY_ENDS_CONTECT='''
frontend rgw_front
    bind %s:%s
    default_backend rgw_back

backend rgw_back
    balance roundrobin
    option httpchk HEAD / HTTP/1.1\\r\\nHost:\ localhost
    cookie RADOSGWLB insert indirect nocache
    stick-table type ip size 2 nopurge peers ceph_peers
    stick on dst'''

HAPROXY_SERVER_CONTECT='    server %(host)s %(host)s:8080 check cookie %(host)s'

def get_exists_region(cfg):
    for sec in cfg.sections():
        if 'rgw_region' in cfg.options(sec):
            return cfg.get(sec, 'rgw_region')
    raise


def get_hosts(cfg, zone_name=None):
    host_list = []
    for sec in cfg.sections():
        if 'rgw_zone' in cfg.options(sec):
            if not zone_name or cfg.get(sec, 'rgw_zone') == zone_name:
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
    httpd_conf = distro.conn.remote_module.get_file(httpd_path)
    httpd_conf = httpd_conf.replace('\nListen 80\n', '\nListen 8080\n')
    httpd_context = '%s\n%s' % (httpd_conf, FACTCGI_CONTECT)
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
        ",".join("\"%s\"" % i for i in domain)
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


def create_haproxy_conf(hosts_list, vip, vport):
    haproxy_conf = HAPROXY_CONF_COMMON
    haproxy_conf_path = '/etc/haproxy/haproxy.cfg'

    haproxy_peers = ''
    haproxy_servers = HAPROXY_ENDS_CONTECT % (vip, vport)

    for host in hosts_list:
        haproxy_peers +='\n'
        haproxy_peers += HAPROXY_PEER_CONTECT % {'host': host}
        haproxy_servers += '\n'
        haproxy_servers += HAPROXY_SERVER_CONTECT % {'host': host}

    haproxy_peers += '\n'
    haproxy_servers += '\n'

    haproxy_conf += haproxy_peers + haproxy_servers

    for host in hosts_list:
        distro = hosts.get(host)
        distro.conn.remote_module.write_file(
            haproxy_conf_path,
            haproxy_conf
        )

def init_pcs_cluster(hosts_list, vip, vip_cidr, hauser, hapass):
    pcs_init_host = hosts_list[0]
    distro = hosts.get(pcs_init_host)
    conn = distro.conn

    (_, _, ret) = remoto.process.check(
        conn,
        [
            'pcs', 'cluster', 'auth',
            '-u', hauser,
            '-p', hapass
        ] + hosts_list
    )

    if ret != 0:
        raise exc.GenericError('Failed to initialize PCS cluster: auth\n')

    (_, _, ret) = remoto.process.check(
        conn,
        [
            'pcs', 'cluster', 'setup',
            '--start', '--enable',
            '--name', 'eayunobs-cluster'
        ] + hosts_list
    )

    if ret != 0:
        raise exc.GenericError('Failed to initialize PCS cluster: setup\n')

    remoto.process.run(
        conn,
        [
            'pcs', 'property', 'set',
            'stonith-enabled=false',
        ]
    )

    remoto.process.run(
        conn,
        [
            'pcs', 'property', 'set',
            'no-quorum-policy=ignore'
        ]
    )

    remoto.process.run(
        conn,
        [
            'pcs', 'resource', 'create',
            'p_haproxy', 'systemd:haproxy',
            'op', 'monitor', 'interval=5s',
            '--clone'
        ]
    )

    remoto.process.run(
        conn,
        [
            'pcs', 'resource', 'create',
            'p_ceph_rgw', 'lsb:ceph-radosgw',
            'op', 'monitor', 'interval=5s',
            '--clone'
        ]
    )

    remoto.process.run(
        conn,
        [
            'pcs', 'resource', 'create',
            'p_httpd', 'systemd:httpd',
            'op', 'monitor', 'interval=5s',
            '--clone'
        ]
    )

    remoto.process.run(
        conn,
        [
            'pcs', 'resource', 'create',
            'p_vip', 'ocf:heartbeat:IPaddr2', 'ip=%s' % vip,
            'cidr_netmask=%s' % vip_cidr,
            'op', 'monitor', 'interval=5s'
        ]
    )

    remoto.process.run(
        conn,
        [
            'pcs', 'constraint', 'colocation', 'add',
            'p_vip', 'p_haproxy-clone', 'INFINITY'
        ]
    )

def check_host_in_pcs(host, existed_hosts):
    op_host = existed_hosts[0]
    distro = hosts.get(op_host)
    conn = distro.conn
    host_in_pcs = False

    (out, _, _) = remoto.process.check(
        conn,
        ['pcs', 'status', 'nodes']
    )

    for line in out:
        if re.search(host, line):
            host_in_pcs = True
            break

    return host_in_pcs

def extend_pcs_cluster(host, existed_hosts, hauser, hapass):
    # add new host should operated on existed hosts
    op_host = existed_hosts[0]
    distro = hosts.get(op_host)
    conn = distro.conn

    (_, _, ret) = remoto.process.check(
        conn,
        [
            'pcs', 'cluster', 'auth',
            '-u', hauser,
            '-p', hapass
        ] + existed_hosts + [host]
    )

    if ret != 0:
        raise exc.GenericError('Failed to extend PCS cluster: auth\n')

    (_, _, ret) = remoto.process.check(
        conn,
        [
            'pcs', 'cluster', 'node', 'add',
            '%s' % host,
            '--start', '--enable'
        ]
    )

    if ret != 0:
        raise exc.GenericError('Failed to extend PCS cluster: node add\n')

def reload_haproxy(hosts_list):
    succeed_hosts = []

    for host in hosts_list:
        distro = hosts.get(host)
        conn = distro.conn

        LOG.info('Reloading HAProxy service on %s' % host)
        (_, _, ret) = remoto.process.check(
            conn,
            ['systemctl', 'reload', 'haproxy']
        )

        if ret != 0:
            LOG.error('Failed to reload HAProxy service on %s' % host)
        else:
            succeed_hosts.append(host)

    pending_hosts = [h for h in hosts_list if h not in succeed_hosts]
    if len(pending_hosts) > 0:
        raise exc.GenericError('HAProxy not reloaded on following node(s):'
                               ' %s\n' % (' '.join(pending_hosts)))

def parse_haproxy_listen(haproxy_cfg_list):
    in_rgw_front = 0
    haproxy_listen = None

    for line in haproxy_cfg_list:
        if line == 'frontend rgw_front':
            in_rgw_front = 1
        if in_rgw_front == 1:
            if line != '':
                m = re.match(r'    bind ([0-9\.]+:[0-9]+)', line)
                if m:
                    haproxy_listen = m.group(1)
                    break
            else:
                break

    return haproxy_listen

def get_haproxy_listen(existed_hosts):
    haproxy_listen_dict = {}

    for host in existed_hosts:
        distro = hosts.get(host)
        conn = distro.conn
        (out, _, ret) = remoto.process.check(
            conn,
            ['cat', '/etc/haproxy/haproxy.cfg']
        )

        if ret != 0:
            raise exc.GenericError('Failed to read haproxy.cfg on %s\n' % host)

        haproxy_listen_dict[host] = parse_haproxy_listen(out)

    haproxy_listen_values = haproxy_listen_dict.values()
    if len(set(haproxy_listen_values)) == 1:
        return haproxy_listen_values[0]
    else:
        return None

def eayunrgw_lb_init(args):
    cfg = conf.ceph.load(args)
    hosts_list = get_hosts(cfg)
    vip = args.vip
    vport = args.vport
    vip_cidr = args.vip_cidr
    hauser = args.hauser
    hapass = args.hapass

    if len(hosts_list) < 3:
        LOG.error('Failed to init loadbalance cluster. There should be'
                  ' 3 nodes at least!')
        raise exc.GenericError("lb-init: not enough nodes (< 3)\n")

    create_haproxy_conf(hosts_list, vip, vport)

    for host in hosts_list:
        distro = hosts.get(host, username=args.username)
        conn = distro.conn
        remoto.process.run(
            conn,
            ['systemctl', 'enable', 'haproxy']
        )
        remoto.process.run(
            conn,
            ['systemctl', 'start', 'haproxy']
        )

    init_pcs_cluster(hosts_list, vip, vip_cidr, hauser, hapass)

def eayunrgw_lb_extend(args):
    cfg = conf.ceph.load(args)
    hosts_list = get_hosts(cfg)

    new_host = args.host
    hauser = args.hauser
    hapass = args.hapass

    existed_hosts = [h for h in hosts_list if h != new_host]

    if check_host_in_pcs(new_host, existed_hosts):
        LOG.info('%s already in EayunOBS loadbalance cluster!' % new_host)
        return

    haproxy_listen = get_haproxy_listen(existed_hosts)
    if haproxy_listen == None:
        raise exc.GenericError('HAProxy listening configuration not matching'
                               ' across existing nodes\n')

    vip, vport = haproxy_listen.split(':')
    create_haproxy_conf(hosts_list, vip, vport)

    try:
        extend_pcs_cluster(new_host, existed_hosts, hauser, hapass)
    except Exception:
        LOG.error('Extend pcs cluster failed, roll back to previous HAPorxy'
                  ' configuration.')
        create_haproxy_conf(existed_hosts, vip, vport)
        raise

    haproxy_started_on_new_host = 0
    retries = 0
    while retries <= 6:
        LOG.debug('Checking HAProxy starting on new node: %s' % new_host)
        distro = hosts.get(new_host)
        conn = distro.conn
        (_, _, ret) = remoto.process.check(
            conn,
            ['systemctl', 'status', 'haproxy']
        )
        if ret == 0:
            haproxy_started_on_new_host = 1
            break
        else:
            retries += 1

        time.sleep(10)

    if haproxy_started_on_new_host == 0:
        LOG.error('HAProxy not starting in 60s on %s, you should check'
                  ' mannually. And after HAProxy is started on new node,'
                  ' you should reload HAPorxy service on all other'
                  ' nodes.' % new_host)
        raise exc.GenericError('Extend LB cluster not completed: HAProxy'
                               ' not starting on new host in time.\n')

    reload_haproxy(existed_hosts)

def eayunrgw(args):
    if args.subcommand == 'create':
        eayunrgw_create(args)
    elif args.subcommand == 'add':
        eayunrgw_add(args)
    elif args.subcommand == 'lb-init':
        eayunrgw_lb_init(args)
    elif args.subcommand == 'lb-extend':
        eayunrgw_lb_extend(args)

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

    eayunrgw_lb_init = eayunrgw_parser.add_parser(
        'lb-init',
        help='Setup EayunOBS loadbalance cluster'
        )
    eayunrgw_lb_init.add_argument(
        '--vip',
        metavar='VIP',
        required=True,
        help='Virutal IP address of EayunOBS loadbalance cluster'
        )
    eayunrgw_lb_init.add_argument(
        '--vip-cidr',
        metavar='VIP-CIDR',
        required=True,
        help=('Virutal IP cidr netmask of EayunOBS loadbalance cluster,'
              ' e.g., 24 not 255.255.255.0')
        )
    eayunrgw_lb_init.add_argument(
        '--vport',
        metavar='VPORT',
        default='80',
        help='Listening port of EayunOBS loadbalance cluster'
        )
    eayunrgw_lb_init.add_argument(
        '--hauser',
        metavar='HAUSER',
        default='hacluster',
        help='User to setup Pacemaker HA Cluster, default: hacluster'
        )
    eayunrgw_lb_init.add_argument(
        '--hapass',
        metavar='HAPASSWD',
        default='hacluster',
        help='Pacemaker HA Cluster user password, default: hacluster'
        )

    eayunrgw_lb_extend = eayunrgw_parser.add_parser(
        'lb-extend',
        help='Extend EayunOBS loadbalance cluster'
        )
    eayunrgw_lb_extend.add_argument(
        '--host',
        metavar='HOST',
        required=True,
        help='New server to be added to EayunOBS loadbalance cluster'
        )
    eayunrgw_lb_extend.add_argument(
        '--hauser',
        metavar='HAUSER',
        default='hacluster',
        help='User to setup Pacemaker HA Cluster, default: hacluster'
        )
    eayunrgw_lb_extend.add_argument(
        '--hapass',
        metavar='HAPASSWD',
        default='hacluster',
        help='Pacemaker HA Cluster user password, default: hacluster'
        )

    parser.set_defaults(
        func=eayunrgw,
        )
