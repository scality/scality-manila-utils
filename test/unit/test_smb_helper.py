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

import errno
import json
import os
import unittest2 as unittest

import mock

from scality_manila_utils import smb_helper
from scality_manila_utils.exceptions import (ClientExistsException,
                                             ClientNotFoundException,
                                             EnvironmentException,
                                             ExportAlreadyExists,
                                             ExportException,
                                             ExportNotFoundException,
                                             ExportHasGrantsException)


class BaseTestSMBHelper(unittest.TestCase):

    root_export = '/root/sofs'

    def setUp(self):
        elevated_privileges_patcher = mock.patch(
            'scality_manila_utils.utils.elevated_privileges'
        )
        self.addCleanup(elevated_privileges_patcher.stop)
        self.elevated_privileges_mock = elevated_privileges_patcher.start()


class TestSMBHelper(BaseTestSMBHelper):

    @mock.patch('scality_manila_utils.utils.is_stored_on_sofs',
                return_value=True)
    @mock.patch('scality_manila_utils.utils.binary_check')
    @mock.patch('scality_manila_utils.utils.process_check')
    @mock.patch('os.getenv', mock.Mock(return_value='/a:/b'))
    def test_verify_environment(self, mock_pc, mock_bc,
                                mock_is_stored_on_sofs):
        mock_open = mock.mock_open(read_data='registry shares = yes\n')

        with mock.patch('io.open', mock_open) as mock_open:
            smb_helper.verify_environment(self.root_export)

        mock_open.assert_called_once_with('/etc/samba/smb.conf')

        mock_is_stored_on_sofs.assert_called_once_with(self.root_export)

        mock_bc.assert_has_calls((
            mock.call('net', ['/a', '/b']),
            mock.call('sfused', ['/a', '/b']),
        ))

        mock_pc.assert_has_calls((
            mock.call('sfused'),
            mock.call('smbd'),
        ))

    @mock.patch('scality_manila_utils.utils.is_stored_on_sofs',
                return_value=False)
    def test_verify_environment_with_wrong_root_export(self, mock_is_sofs):
        self.assertRaises(EnvironmentException, smb_helper.verify_environment,
                          self.root_export)
        mock_is_sofs.assert_called_once_with(self.root_export)

    @mock.patch('scality_manila_utils.utils.is_stored_on_sofs',
                mock.Mock(return_value=True))
    @mock.patch('scality_manila_utils.utils.binary_check', mock.Mock())
    @mock.patch('scality_manila_utils.utils.process_check', mock.Mock())
    def test_verify_environment_with_wrong_smb_conf(self):
        for read_data in ('registry shares = no\n', ''):
            mock_open = mock.mock_open(read_data=read_data)
            with mock.patch('io.open', mock_open):
                self.assertRaises(EnvironmentException,
                                  smb_helper.verify_environment,
                                  self.root_export)

            mock_open.assert_called_once_with('/etc/samba/smb.conf')

    @mock.patch('scality_manila_utils.utils.execute')
    def test_get_defined_exports(self, mock_execute):
        output = (u'[share1]\n\tpath = share1\n\tguest ok = yes\n'
                  u'[share2]\n\tpath = share2\n\tguest ok = yes\n')
        mock_execute.return_value = output, ""

        exports = smb_helper._get_defined_exports()

        mock_execute.assert_called_once_with(['net', 'conf', 'list'], mock.ANY)

        for share in ('share1', 'share2'):
            self.assertTrue(share in exports)
            self.assertEqual(share, exports[share]['path'])

        self.elevated_privileges_mock.assert_called_with()

    @mock.patch('scality_manila_utils.utils.execute')
    def test_set_hosts_allow(self, mock_execute):
        smb_helper._set_hosts_allow('share1', ['net1', 'net2'])

        cmd = ['net', 'conf', 'setparm', 'share1',
               'hosts allow', 'net1 net2']
        mock_execute.assert_called_once_with(cmd, mock.ANY)

        self.elevated_privileges_mock.assert_called_once_with()

    def test_ensure_export_exists(self):
        export_name = 'share1'
        exports = {export_name: None}
        mock_get_exports = mock.Mock(return_value=exports)

        decorated_fn = mock.Mock(__name__='fake')
        with mock.patch('scality_manila_utils.smb_helper._get_defined_exports',
                        mock_get_exports):
            wrapped = smb_helper.ensure_export_exists(decorated_fn)
            wrapped(export_name)

        mock_get_exports.assert_called_once_with()
        decorated_fn.assert_called_once_with(export_name=export_name,
                                             exports=exports)

    def test_ensure_export_exists_with_no_export(self):
        exports = {'share1': None}
        mock_get_exports = mock.Mock(return_value=exports)

        decorated_fn = mock.Mock(__name__='fake')
        with mock.patch('scality_manila_utils.smb_helper._get_defined_exports',
                        mock_get_exports):
            wrapped = smb_helper.ensure_export_exists(decorated_fn)
            self.assertRaises(ExportNotFoundException, wrapped, 'blah')

        mock_get_exports.assert_called_once_with()
        self.assertEqual(0, decorated_fn.call_count)


class TestSMBHelperWithMockedVerifyEnv(BaseTestSMBHelper):

    def setUp(self):
        super(TestSMBHelperWithMockedVerifyEnv, self).setUp()

        verify_environment_patcher = mock.patch(
            'scality_manila_utils.smb_helper.verify_environment'
        )
        self.addCleanup(verify_environment_patcher.stop)
        self.mock_verify_environment = verify_environment_patcher.start()

    def patch_defined_exports(self, defined_exports):
        get_defined_export_patcher = mock.patch(
            'scality_manila_utils.smb_helper._get_defined_exports',
            return_value=defined_exports
        )
        self.addCleanup(get_defined_export_patcher.stop)
        return get_defined_export_patcher.start()

    def test_get_export(self):
        exports = {'share1': {'hosts allow': '127.0.0.1 10.0.0.0/8'}}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        export = smb_helper.get_export(export_name='share1',
                                       root_export=self.root_export)

        # We can't compare json strings here because the order of the
        # keys in the json object is not deterministic.
        expected = {"10.0.0.0/8": ["rw"], "127.0.0.1": ["rw"]}
        self.assertEqual(expected, json.loads(export))

        mock_get_defined_exports.assert_called_once_with()
        self.mock_verify_environment.assert_called_once_with(self.root_export)

    def test_add_export_with_wrong_export_name(self):
        self.assertRaises(ExportException, smb_helper.add_export,
                          export_name='', root_export=self.root_export)

        self.assertRaises(ExportException, smb_helper.add_export,
                          export_name='sla/sh', root_export=self.root_export)

    @mock.patch('os.mkdir')
    @mock.patch('subprocess.check_call')
    def test_add_export(self, mock_check_call, mock_mkdir):
        smb_helper.add_export(export_name='test', root_export=self.root_export)

        export_point = os.path.join(self.root_export, 'test')

        mock_mkdir.assert_called_once_with(export_point, 0o0777)
        self.assertEqual(6, mock_check_call.call_count)
        self.elevated_privileges_mock.assert_called_once_with()
        self.mock_verify_environment.assert_called_once_with(self.root_export)

    @mock.patch('os.mkdir')
    def test_add_export_when_export_already_exists(self, mock_mkdir):
        mock_mkdir.side_effect = OSError(errno.EEXIST, '')

        exports = {'share1': None}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        self.assertRaises(ExportAlreadyExists, smb_helper.add_export,
                          export_name='share1', root_export=self.root_export)

        mock_get_defined_exports.assert_called_once_with()
        self.mock_verify_environment.assert_called_once_with(self.root_export)
        self.elevated_privileges_mock.assert_called_once_with()

    def test_wipe_export_when_export_has_grants(self):
        exports = {'share1': {'hosts allow': '127.0.0.1 10.0.0.0/8'}}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        self.assertRaises(ExportHasGrantsException, smb_helper.wipe_export,
                          export_name='share1', root_export=self.root_export)
        self.mock_verify_environment.assert_called_once_with(self.root_export)
        mock_get_defined_exports.assert_called_once_with()

    @mock.patch('os.rename')
    @mock.patch('scality_manila_utils.utils.fsync_path')
    @mock.patch('scality_manila_utils.utils.execute')
    def test_wipe_export(self, mock_execute, mock_fsync, mock_rename):
        exports = {'share1': {'hosts allow': '127.0.0.1'}}
        mock_get_defined_exports = self.patch_defined_exports(exports)
        mock_rename.side_effect = OSError(errno.ENOENT, '')

        smb_helper.wipe_export(export_name='share1',
                               root_export=self.root_export)

        export_path = os.path.join(self.root_export, 'share1')

        class AnyStringWith(str):
            def __eq__(self, other):
                return self in other

        mock_rename.assert_called_once_with(export_path,
                                            AnyStringWith("TRASH-share1"))

        mock_fsync.assert_called_once_with(self.root_export)

        mock_execute.assert_called_once_with(['net', 'conf', 'delshare',
                                              'share1'], mock.ANY)

        mock_get_defined_exports.assert_called_once_with()
        self.elevated_privileges_mock.assert_called_once_with()
        self.mock_verify_environment.assert_called_once_with(self.root_export)

    def test_grant_access_when_host_already_allowed(self):
        exports = {'share1': {'hosts allow': 'net1'}}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        self.assertRaises(ClientExistsException, smb_helper.grant_access,
                          export_name='share1', host='net1',
                          root_export=self.root_export)

        self.mock_verify_environment.assert_called_once_with(self.root_export)
        mock_get_defined_exports.assert_called_once_with()

    @mock.patch('scality_manila_utils.smb_helper._set_hosts_allow')
    def test_grant_access(self, mock_set_hosts_allow):
        exports = {'share1': {'hosts allow': ''}}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        smb_helper.grant_access(export_name='share1', host='net1',
                                root_export=self.root_export)

        mock_set_hosts_allow.assert_called_once_with('share1', ['net1'])
        self.mock_verify_environment.assert_called_once_with(self.root_export)
        mock_get_defined_exports.assert_called_once_with()

    def test_revoke_access_when_client_not_found(self):
        exports = {'share1': {'hosts allow': ''}}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        self.assertRaises(ClientNotFoundException, smb_helper.revoke_access,
                          export_name='share1', host='net1',
                          root_export=self.root_export)
        mock_get_defined_exports.assert_called_once_with()

    @mock.patch('scality_manila_utils.smb_helper._set_hosts_allow')
    def test_revoke_access(self, mock_set_hosts_allow):
        exports = {'share1': {'hosts allow': 'net1'}}
        mock_get_defined_exports = self.patch_defined_exports(exports)

        smb_helper.revoke_access(export_name='share1', host='net1',
                                 root_export=self.root_export)

        mock_set_hosts_allow.assert_called_once_with('share1', [])
        self.mock_verify_environment.assert_called_once_with(self.root_export)
        mock_get_defined_exports.assert_called_once_with()
