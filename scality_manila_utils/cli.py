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
import os
import pwd

from scality_manila_utils.helper import Helper


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
        previous_gid = os.getegid()
        os.setegid(group_info.gr_gid)
        try:
            os.seteuid(user_info.pw_uid)
        except Exception:
            # Attempt to restore effective gid
            try:
                os.setegid(previous_gid)
            except OSError:
                # Don't mask the previous exception
                pass

            raise

    else:
        raise RuntimeError("Unable to find an unprivilged user/group")


def main(args=None):
    if os.getuid() != 0:
        raise RuntimeError("This program requires superuser privileges")

    # Drop any elevated permissions
    drop_privileges()

    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument(
        '--exports',
        help='Path to exports file',
        default='/etc/exports.conf'
    )
    pre_parser.add_argument(
        '--root-export',
        help='NFS export path to the ring NFS root volume',
        default='127.0.0.1:/'
    )

    command_parser = argparse.ArgumentParser(
        parents=[pre_parser],
        description='Manila exports management'
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

    parser_create.set_defaults(func=Helper.add_export)
    parser_grant.set_defaults(func=Helper.grant_access)
    parser_revoke.set_defaults(func=Helper.revoke_access)
    parser_check.set_defaults(func=Helper.verify_environment)

    parsed_args = command_parser.parse_args(args)

    helper = Helper(parsed_args.root_export, parsed_args.exports)

    command_args = dict(
        (k, v) for k, v in vars(parsed_args).items()
        if k not in ('exports', 'root_export', 'func')
    )
    parsed_args.func(helper, **command_args)
