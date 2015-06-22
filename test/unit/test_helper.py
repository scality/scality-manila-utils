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

import io
import os
import shutil
import signal
import tempfile
import unittest2 as unittest

import mock

from scality_manila_utils.helper import Helper
from scality_manila_utils.exceptions import (EnvironmentException,
                                             ExportException)


class TestHelper(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        self.exports_file = f.name
        self.root_export = '127.0.0.1:/'
        self.helper = Helper(self.root_export, self.exports_file)
        self.nfs_root = tempfile.mkdtemp()

        attrs = {'return_value.__enter__.return_value': self.nfs_root}
        nfs_mount_patcher = mock.patch('scality_manila_utils.utils.nfs_mount',
                                       **attrs)
        self.addCleanup(nfs_mount_patcher.stop)
        self.nfs_mount_mock = nfs_mount_patcher.start()

        elevated_privileges_patcher = mock.patch(
            'scality_manila_utils.utils.elevated_privileges'
        )
        self.addCleanup(elevated_privileges_patcher.stop)
        self.elevated_privileges_mock = elevated_privileges_patcher.start()

    def tearDown(self):
        os.unlink(self.exports_file)
        shutil.rmtree(self.nfs_root)

    def test_helper_instantiation(self):
        with mock.patch('os.path.exists', return_value=False):
            with self.assertRaises(EnvironmentException):
                Helper("127.0.0.1:/", "/no/exports")

    def test_verify_environment(self):
        with mock.patch('scality_manila_utils.utils.binary_check') as bc:
            with mock.patch('scality_manila_utils.utils.process_check') as pc:
                with mock.patch('os.getenv', return_value='/a:/b'):
                    self.helper.verify_environment()
                    bc.has_calls((
                        mock.call('rpcbind', ['/a', '/b']),
                        mock.call('sfused', ['/a', '/b']),
                    ))
                    pc.has_calls((
                        mock.call('rpcbind'),
                        mock.call('sfused'),
                    ))

        with mock.patch('os.getenv', return_value='/foo:/bar'):
            with self.assertRaises(EnvironmentException):
                self.helper.verify_environment()

    def test_add_export_invalid(self):
        # Invalid share name checks
        with self.assertRaises(ExportException):
            self.helper.add_export('../directory/outside/share/root')
            self.helper.add_export('directory/in/another/share')
            self.helper.add_export('')

    def test_add_export(self):
        export_name = 'test'
        absolute_export_path = os.path.join(self.nfs_root, export_name)
        self.assertFalse(os.path.exists(absolute_export_path))

        self.helper.add_export(export_name)
        self.assertTrue(os.path.exists(absolute_export_path))
        self.elevated_privileges_mock.assert_called_once_with()
        self.nfs_mount_mock.assert_called_once_with(self.root_export)

        # Assert that no permissions were created for the new share
        self.assertEqual(len(self.helper.exports.exports), 0)

    @mock.patch.object(Helper, '_reexport')
    def test_grant_access_invalid(self, reexport):
        export_name = 'grant_twice'
        host = 'hostname'
        self.helper.add_export(export_name)
        self.helper.grant_access(export_name, host, [])

        with self.assertRaises(ExportException):
            self.helper.grant_access('unadded_share', host, None)

            # Attempt granting access to the same export for a client twice
            self.helper.grant_access(export_name, host, ['rw'])

    @mock.patch.object(Helper, '_reexport')
    def test_grant_access(self, reexport):
        export_name = 'test'
        host = 'hostname'
        options = set(['rw'])

        # Add an export
        self.helper.add_export(export_name)
        self.nfs_mount_mock.reset_mock()
        self.elevated_privileges_mock.reset_mock()

        # Grant access to it
        self.helper.grant_access(export_name, host, options)
        self.nfs_mount_mock.assert_called_once_with(self.root_export)
        self.elevated_privileges_mock.assert_called_once_with()
        reexport.assert_called_once_with()

        self.nfs_mount_mock.reset_mock()
        self.elevated_privileges_mock.reset_mock()
        reexport.reset_mock()

        exports = self.helper.exports.exports
        export_point = os.path.join('/', export_name)
        self.assertIn(export_point, exports)
        self.assertIn(host, exports[export_point].clients)
        self.assertEqual(exports[export_point].clients[host], options)

        # Grant access to another client on the previously added export
        host = '10.0.0.0/16'
        self.helper.grant_access(export_name, host, None)
        self.nfs_mount_mock.assert_called_once_with(self.root_export)
        self.elevated_privileges_mock.assert_called_once_with()
        reexport.assert_called_once_with()
        self.assertIn(host, exports[export_point].clients)
        self.assertEqual(exports[export_point].clients[host], set())

    @mock.patch.object(Helper, '_reexport')
    def test_revoke_access_invalid(self, reexport):
        export_name = 'revoke_twice'
        host = 'hostname'

        self.helper.add_export(export_name)
        with self.assertRaises(ExportException):
            self.helper.revoke_access('non_existing_export', host)
            # Export added, but has no access granted to it
            self.helper.revoke_access(export_name, host)

        self.helper.grant_access(export_name, host, ['rw'])
        reexport.assert_called_once_with()
        reexport.reset_mock()
        self.helper.revoke_access(export_name, host)
        reexport.assert_called_once_with()
        with self.assertRaises(ExportException):
            self.helper.revoke_access(export_name, 'ungranted_client')
            # Test revoking access twice
            self.helper.revoke_access(export_name, host)

    @mock.patch.object(Helper, '_reexport')
    def test_revoke_access(self, reexport):
        export1 = 'export'
        export2 = 'otherexport'
        export_point1 = os.path.join('/', export1)
        export_point2 = os.path.join('/', export2)
        host1 = 'hostname'
        host2 = '192.168.0.1'
        host3 = '192.168.100.0/24'
        exports = self.helper.exports.exports

        self.helper.add_export(export1)
        self.helper.add_export(export2)

        # Grant access for three clients to export1
        for client in (host1, host2, host3):
            self.helper.grant_access(export1, client, ['rw'])

        self.helper.grant_access(export2, host2, ['rw'])
        reexport.reset_mock()

        # Ensure integrity of other grants when revoking access
        self.helper.revoke_access(export1, host3)
        reexport.assert_called_once_with()
        self.assertNotIn(host3, exports[export_point1].clients)
        self.assertIn(host2, exports[export_point1].clients)
        self.assertIn(host1, exports[export_point1].clients)
        self.assertIn(host2, exports[export_point2].clients)
        reexport.reset_mock()

        self.helper.revoke_access(export1, host2)
        reexport.assert_called_once_with()
        self.assertNotIn(host2, exports[export_point1].clients)
        self.assertIn(host1, exports[export_point1].clients)
        self.assertIn(host2, exports[export_point2].clients)
        reexport.reset_mock()

        # Check that the export is removed together with the last permission
        self.helper.revoke_access(export1, host1)
        reexport.assert_called_once_with()
        self.assertNotIn(export_point1, exports)
        self.assertIn(host2, exports[export_point2].clients)

    @mock.patch('scality_manila_utils.utils.find_pids', return_value=[100])
    @mock.patch('os.kill')
    def test_reexport(self, kill, find_pids):
        export_name = 'test_export'
        expected_exports = '/test_export                      10.0.0.1(rw)\n'

        # No pre-existing exports
        self.assertEqual(os.path.getsize(self.exports_file), 0)

        self.helper.add_export(export_name)
        self.helper.grant_access(export_name, '10.0.0.1', ['rw'])
        find_pids.assert_called_once_with('sfused')
        kill.assert_called_once_with(100, signal.SIGHUP)
        self.elevated_privileges_mock.assert_called_with()

        # Assert that the added export has been written
        with io.open(self.exports_file) as f:
            self.assertEqual(f.read(), expected_exports)
