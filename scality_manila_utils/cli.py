# Copyright (c) 2015 Scality
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import grp
import logging
import logging.handlers
import os
import pwd
import sys
import traceback

import scality_manila_utils
import scality_manila_utils.helper

log = logging.getLogger(__name__)


def setup_logger():
    """
    Setup root log handler.
    """
    log_format = logging.Formatter(
        '%(name)s - %(levelname)s - %(message)s'
    )
    handler = logging.handlers.SysLogHandler('/dev/log')
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(log_format)
    logging.root.addHandler(handler)
    logging.root.setLevel(logging.INFO)


def drop_privileges():
    """
    Attempt to drop privileges.
    """
    def _try_get(f, *args, **kwargs):
        try:
            return f(*args, **kwargs)
        except KeyError:
            return None

    def get_user(name):
        return _try_get(pwd.getpwnam, name)

    def get_group(name):
        return _try_get(grp.getgrnam, name)

    # Attempt to find a proper user and group
    user_info = get_user('nobody')
    candidate_groups = ('nogroup', 'nobody')
    for group in candidate_groups:
        group_info = get_group(group)
        if group_info is not None:
            break

    # Drop privileges
    if user_info and group_info:
        log.debug('Dropping privileges to %s:%s', user_info.pw_name,
                  group_info.gr_name)
        previous_gid = os.getegid()
        os.setegid(group_info.gr_gid)
        try:
            os.seteuid(user_info.pw_uid)
        except Exception:
            log.error("Unable to drop effective uid")
            # Attempt to restore effective gid
            try:
                os.setegid(previous_gid)
            except OSError:
                # Don't mask the previous exception
                log.exception("Unable to restore effective gid")

            raise

    else:
        msg = 'Unable to find an unprivileged user/group'
        log.error(msg)
        raise RuntimeError(msg)


def main(args=None):
    setup_logger()

    if os.getuid() != 0:
        log.error('Invoked without superuser privileges')
        raise RuntimeError("This program requires superuser privileges")

    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        '--exports-file',
        help='Path to exports file',
        default='/etc/exports.conf',
    )
    pre_parser.add_argument(
        '--root-export',
        help='NFS export path to the ring NFS root volume',
        default='127.0.0.1:/'
    )
    pre_parser.add_argument(
        '--debug',
        help='Set debug log level',
        action='store_true',
        default=False
    )
    pre_parser.add_argument(
        '--version',
        action='version',
        version=scality_manila_utils.__version__
    )

    command_parser = argparse.ArgumentParser(
        parents=[pre_parser],
        description='Manila exports management',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = command_parser.add_subparsers(help='sub-command help')

    parser_create = subparsers.add_parser(
        'create',
        help='Prepare an export without any access grants'
    )
    parser_create.add_argument(
        'export_name',
        help='Export point to create'
    )

    parser_grant = subparsers.add_parser(
        'grant',
        help='Grant access to an existing filesystem, and reexport it'
    )
    parser_grant.add_argument(
        'export_name',
        help='Filesystem to grant access to'
    )
    parser_grant.add_argument(
        'host',
        help='IP address or network to grant access for'
    )
    parser_grant.add_argument(
        'options',
        help='Export options',
        nargs='*'
    )

    parser_revoke = subparsers.add_parser(
        'revoke',
        help='Revoke access from an existing filesystem, and reexport it'
    )
    parser_revoke.add_argument(
        'export_name',
        help='Filesystem to revoke access from'
    )
    parser_revoke.add_argument(
        'host',
        help='IP address or network to revoke access for'
    )

    parser_check = subparsers.add_parser(
        'check',
        help='Check for required binaries and running services'
    )

    parser_get = subparsers.add_parser(
        'get',
        help='List the addresses that a filesystem is exported to'
    )
    parser_get.add_argument(
        'export_name',
        help='Filesystem to get information about'
    )

    parser_create.set_defaults(func=scality_manila_utils.helper.add_export)
    parser_grant.set_defaults(func=scality_manila_utils.helper.grant_access)
    parser_revoke.set_defaults(func=scality_manila_utils.helper.revoke_access)
    parser_get.set_defaults(func=scality_manila_utils.helper.get_export)
    parser_check.set_defaults(
        func=scality_manila_utils.helper.verify_environment
    )

    parsed_args = command_parser.parse_args(args)

    # Set debug level if requested
    if parsed_args.debug:
        logging.root.setLevel(logging.DEBUG)

    # Drop any elevated permissions
    drop_privileges()

    command_args = dict(
        (k, v) for k, v in vars(parsed_args).items()
        if k not in ('func', 'debug')
    )

    formatted_args = ", ".join(
        "{arg:s}={val!r}".format(arg=arg, val=val)
        for arg, val in command_args.items()
    )
    log.info("Invoking %s(%s)", parsed_args.func.__name__, formatted_args)
    try:
        result = parsed_args.func(**command_args)
        if result is not None:
            print(result)
    except Exception as e:
        log.exception("Invocation failed")
        traceback.print_exc()
        exit_code = getattr(e, 'EXIT_CODE', 1)
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
