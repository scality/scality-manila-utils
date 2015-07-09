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

import grp
import mock
import pwd
import unittest2 as unittest

import scality_manila_utils.cli


class TestCli(unittest.TestCase):
    group_nobody = grp.struct_group(('nogroup', 'x', 65534, []))
    user_nobody = pwd.struct_passwd(('nobody', 'x', 99, 99,
                                     'nobody', '/', '/usr/sbin/nologin'))

    def setUp(self):
        attrs = {
            'add_export.__name__': 'add_export',
            'grant_access.__name__': 'grant_access',
            'revoke_access.__name__': 'revoke_access',
            'verify_environment.__name__': 'verify_environment',
            'get_export.__name__': 'get_export',
        }
        patcher = mock.patch('scality_manila_utils.cli.Helper', **attrs)
        self.addCleanup(patcher.stop)
        self.helper = patcher.start()

    @mock.patch('scality_manila_utils.cli.drop_privileges')
    @mock.patch('os.getuid', return_value=0)
    def test_setup(self, getuid, drop_privileges):
        exports = '/etc/exports'
        root_export = 'localhost:/'
        args = ['--exports', exports, '--root-export', root_export, 'check']

        scality_manila_utils.cli.main(args)
        drop_privileges.called_once_with()
        self.helper.assert_called_once_with(root_export, exports)

        # Non-root invocation
        getuid.return_value = 1000
        with self.assertRaises(RuntimeError):
            scality_manila_utils.cli.main(args)

    @mock.patch('scality_manila_utils.cli.drop_privileges')
    @mock.patch('os.getuid', return_value=0)
    def test_invoke_check(self, getuid, drop_privileges):
        scality_manila_utils.cli.main(['check'])
        self.helper.verify_environment.assert_called_once_with(self.helper())

    @mock.patch('scality_manila_utils.cli.drop_privileges')
    @mock.patch('os.getuid', return_value=0)
    def test_invoke_grant(self, getuid, drop_privileges):
        export_name = 'share'
        host = '192.168.0.100'
        options = ['rw', 'no_root_squash']

        scality_manila_utils.cli.main(['grant', export_name, host] + options)
        self.helper.grant_access.assert_called_once_with(
            self.helper(),
            export_name=export_name,
            host=host,
            options=options
        )

    @mock.patch('scality_manila_utils.cli.drop_privileges')
    @mock.patch('os.getuid', return_value=0)
    def test_invoke_revoke(self, getuid, drop_privileges):
        export_name = 'share'
        host = '192.168.0.100'

        scality_manila_utils.cli.main(['revoke', export_name, host])
        self.helper.revoke_access.assert_called_once_with(
            self.helper(),
            export_name=export_name,
            host=host,
        )

    @mock.patch('scality_manila_utils.cli.drop_privileges')
    @mock.patch('os.getuid', return_value=0)
    def test_invoke_create(self, getuid, drop_privileges):
        export_name = 'share'

        scality_manila_utils.cli.main(['create', export_name])
        self.helper.add_export.assert_called_once_with(
            self.helper(),
            export_name=export_name,
        )

    @mock.patch('scality_manila_utils.cli.drop_privileges')
    @mock.patch('os.getuid', return_value=0)
    def test_invoke_get(self, getuid, drop_privileges):
        export_name = 'share'

        scality_manila_utils.cli.main(['get', export_name])
        self.helper.get_export.assert_called_once_with(
            self.helper(),
            export_name=export_name,
        )

    @mock.patch('grp.getgrnam')
    @mock.patch('pwd.getpwnam')
    @mock.patch('os.setegid')
    @mock.patch('os.seteuid')
    def test_drop_privileges(self, seteuid, setegid, pwd, grp):
        # No user found
        grp.side_effect = lambda user: self.group_nobody
        pwd.side_effect = KeyError
        with self.assertRaises(RuntimeError):
            scality_manila_utils.cli.drop_privileges()

        # No group found
        grp.side_effect = KeyError
        pwd.side_effect = lambda user: self.user_nobody
        with self.assertRaises(RuntimeError):
            scality_manila_utils.cli.drop_privileges()

        # Unprivileged user and group found
        grp.side_effect = lambda user: self.group_nobody
        pwd.side_effect = lambda user: self.user_nobody

        scality_manila_utils.cli.drop_privileges()
        setegid.assert_called_once_with(self.group_nobody.gr_gid)
        seteuid.assert_called_once_with(self.user_nobody.pw_uid)
