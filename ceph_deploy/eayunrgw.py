from ceph_deploy.cliutil import priority
import logging

LOG = logging.getLogger(__name__)


def eayunrgw_create(args):
    LOG.info("eayunrgw create ")


def eayunrgw_add(args):
    LOG.info("eayunrgw add ")


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
        help='The name of logical geographic area, e.g. beijing'
        )
    eayunrgw_create.add_argument(
        '--zone',
        metavar='ZONE',
        help='The name of logical grouping, e.g. daxing'
        )
    eayunrgw_create.add_argument(
        '--host',
        metavar='HOST',
        help='The host to which deploy eayun rgw'
        )

    eayunrgw_create = eayunrgw_parser.add_parser(
        'add',
        help='Add an eayunrgw instance to exist and zone'
        )
    eayunrgw_create.add_argument(
        '--zone',
        metavar='ZONE',
        help='The name of logical grouping, e.g. daxing'
        )
    eayunrgw_create.add_argument(
        '--host',
        metavar='HOST',
        help='The host to which deploy eayun rgw'
        )

    parser.set_defaults(
        func=eayunrgw,
        )
