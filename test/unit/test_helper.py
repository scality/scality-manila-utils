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

from scality_manila_utils import helper
from scality_manila_utils.export import ExportTable, Export
from scality_manila_utils.exceptions import (EnvironmentException,
                                             ExportException,
                                             ExportNotFoundException)


class TestHelper(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.close()
        self.exports_file = f.name

        self.root_export = '127.0.0.1:/'
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

    def test_verify_environment(self):
        with mock.patch('scality_manila_utils.utils.binary_check') as bc:
            with mock.patch('scality_manila_utils.utils.process_check') as pc:
                with mock.patch('os.getenv', return_value='/a:/b'):
                    helper.verify_environment(self.exports_file)
                    bc.has_calls((
                        mock.call('rpcbind', ['/a', '/b']),
                        mock.call('sfused', ['/a', '/b']),
                    ))
                    pc.has_calls((
                        mock.call('rpcbind'),
                        mock.call('sfused'),
                    ))

        with mock.patch('os.path.exists', return_value=False) as exists:
            with self.assertRaises(EnvironmentException):
                exports_file = '/no/exports'
                helper.verify_environment(exports_file)
                exists.assert_called_once_with(exports_file)

    @mock.patch('scality_manila_utils.helper.verify_environment')
    def test_add_export_invalid(self, verify_environment):
        # Invalid share name checks
        with self.assertRaises(ExportException):
            helper.add_export(self.root_export,
                              '../directory/outside/share/root',
                              exports_file=self.exports_file)
            helper.add_export(self.root_export, 'directory/in/another/share',
                              exports_file=self.exports_file)
            helper.add_export(self.root_export, '',
                              exports_file=self.exports_file)

    @mock.patch('scality_manila_utils.helper.verify_environment')
    def test_add_export(self, verify_environment):
        export_name = 'test'
        absolute_export_path = os.path.join(self.nfs_root, export_name)
        self.assertFalse(os.path.exists(absolute_export_path))

        helper.add_export(self.root_export, export_name,
                          exports_file=self.exports_file)
        self.assertTrue(os.path.exists(absolute_export_path))

        # Check that `ensure_environment` decorator is called
        verify_environment.assert_called_once_with(
            self.root_export,
            export_name,
            exports_file=self.exports_file
        )

        self.elevated_privileges_mock.assert_called_once_with()
        self.nfs_mount_mock.assert_called_once_with(self.root_export)

    @mock.patch('scality_manila_utils.helper.verify_environment')
    @mock.patch('scality_manila_utils.helper._reexport')
    def test_grant_access_invalid(self, reexport, verify_environment):
        export_name = 'grant_twice'
        export_point = os.path.join('/', export_name)
        host = 'hostname'
        exports = ExportTable([])

        helper.add_export(self.root_export, export_name,
                          exports_file=self.exports_file)
        verify_environment.reset_mock()

        with mock.patch('scality_manila_utils.helper._get_defined_exports',
                        return_value=exports):
            helper.grant_access(self.root_export, self.exports_file,
                                export_name, host, [])

            reexport.assert_called_once_with(
                self.exports_file,
                ExportTable([
                    Export(
                        export_point=export_point,
                        clients={host: frozenset([])}
                    )
                ])
            )

        with self.assertRaises(ExportException):
            helper.grant_access(self.root_export, self.exports_file,
                                'unadded_share', host, None)

            # Attempt granting access to the same export for a client twice
            self.helper.grant_access(self.root_export, self.exports_file,
                                     export_name, host, ['rw'])

    @mock.patch('scality_manila_utils.helper.verify_environment')
    @mock.patch('scality_manila_utils.helper._reexport')
    def test_grant_access(self, reexport, verify_environment):
        export_name = 'test'
        export_point = os.path.join('/', export_name)
        host = 'hostname'
        options = frozenset(['rw'])
        expected_exports = ExportTable([
            Export(
                export_point=export_point,
                clients={host: options}
            )
        ])

        # Add an export
        helper.add_export(self.root_export, export_name,
                          exports_file=self.exports_file)

        self.nfs_mount_mock.reset_mock()
        verify_environment.reset_mock()

        # Grant access to it
        helper.grant_access(self.root_export, self.exports_file,
                            export_name, host, options)

        # Check that `ensure_environment decorator` is called
        verify_environment.assert_called_once_with(self.root_export,
                                                   self.exports_file,
                                                   export_name, host, options)

        self.nfs_mount_mock.assert_called_once_with(self.root_export)
        reexport.assert_called_once_with(self.exports_file, expected_exports)

        self.nfs_mount_mock.reset_mock()
        reexport.reset_mock()

        # Grant access to another client on the previously added export
        with mock.patch('scality_manila_utils.helper._get_defined_exports',
                        return_value=expected_exports):
            host2 = '10.0.0.0/16'
            helper.grant_access(self.root_export, self.exports_file,
                                export_name, host2, None)
            self.nfs_mount_mock.assert_called_once_with(self.root_export)
            reexport.assert_called_once_with(
                self.exports_file,
                ExportTable([
                    Export(
                        export_point=export_point,
                        clients={
                            host: options,
                            host2: frozenset([])
                        }
                    )
                ])
            )

    @mock.patch('scality_manila_utils.helper.verify_environment')
    @mock.patch('scality_manila_utils.helper._reexport')
    def test_revoke_access_invalid(self, reexport, verify_environment):
        export_name = 'revoke'
        export_point = os.path.join('/', export_name)
        host = 'hostname'
        exports = ExportTable([
            Export(
                export_point=export_point,
                clients={host: frozenset(['rw'])}
            ),
        ])

        with mock.patch('scality_manila_utils.helper._get_defined_exports',
                        return_value=exports):
            with self.assertRaises(ExportException):
                helper.revoke_access(self.root_export, self.exports_file,
                                     'non_existing_export', host)

                helper.revoke_access(self.root_export, self.exports_file,
                                     export_name, 'ungranted_client')

    @mock.patch('scality_manila_utils.helper.verify_environment')
    @mock.patch('scality_manila_utils.helper._reexport')
    def test_revoke_access(self, reexport, verify_environment):
        export1 = 'export'
        export2 = 'otherexport'
        export_point1 = os.path.join('/', export1)
        export_point2 = os.path.join('/', export2)
        host1 = 'hostname'
        host2 = '192.168.0.1'
        host3 = '192.168.100.0/24'

        exports = ExportTable([
            Export(
                export_point=export_point1,
                clients={
                    host1: frozenset(['rw']),
                    host2: frozenset(['rw']),
                    host3: frozenset(['rw']),
                }
            ),
            Export(
                export_point=export_point2,
                clients={host2: frozenset(['rw'])}
            ),
        ])

        # Ensure integrity of other grants when revoking access
        with mock.patch('scality_manila_utils.helper._get_defined_exports',
                        return_value=exports):
            helper.revoke_access(self.root_export, self.exports_file,
                                 export1, host3)

            # Check that `ensure_environment` decorator is called
            verify_environment.assert_called_once_with(self.root_export,
                                                       self.exports_file,
                                                       export1, host3)
            reexport.assert_called_once_with(
                self.exports_file,
                ExportTable([
                    Export(
                        export_point=export_point1,
                        clients={
                            host1: frozenset(['rw']),
                            host2: frozenset(['rw']),
                        }
                    ),
                    Export(
                        export_point=export_point2,
                        clients={host2: frozenset(['rw'])}
                    ),
                ])
            )
            reexport.reset_mock()

            helper.revoke_access(self.root_export, self.exports_file,
                                 export1, host2)
            reexport.assert_called_once_with(
                self.exports_file,
                ExportTable([
                    Export(
                        export_point=export_point1,
                        clients={
                            host1: frozenset(['rw']),
                        }
                    ),
                    Export(
                        export_point=export_point2,
                        clients={host2: frozenset(['rw'])}
                    ),
                ])
            )
            reexport.reset_mock()

            # Check that the export is removed together with the last
            # permission
            helper.revoke_access(self.root_export, self.exports_file, export2,
                                 host2)
            reexport.assert_called_once_with(
                self.exports_file,
                ExportTable([
                    Export(
                        export_point=export_point1,
                        clients={
                            host1: frozenset(['rw']),
                        }
                    ),
                ])
            )

    @mock.patch('scality_manila_utils.utils.find_pids', return_value=[100])
    @mock.patch('os.kill')
    def test_reexport(self, kill, find_pids):
        expected_exports = '/test_export                      10.0.0.1(rw)\n'

        # No pre-existing exports
        self.assertEqual(os.path.getsize(self.exports_file), 0)

        helper._reexport(
            self.exports_file,
            ExportTable([
                Export(
                    export_point='/test_export',
                    clients={'10.0.0.1': frozenset(['rw'])},
                )
            ])
        )
        find_pids.assert_called_once_with('sfused')
        kill.assert_called_once_with(100, signal.SIGHUP)
        self.elevated_privileges_mock.assert_called_with()

        # Assert that the added export has been written
        with io.open(self.exports_file) as f:
            self.assertEqual(f.read(), expected_exports)

    @mock.patch('scality_manila_utils.helper.verify_environment')
    def test_get_export(self, verify_environment):
        export = 'export'
        export_point = os.path.join('/', export)
        host = 'host'

        with self.assertRaises(ExportNotFoundException):
            helper.get_export(
                root_export=self.root_export,
                exports_file=self.exports_file,
                export_name=export
            )

        # Check that `ensure_environment` decorator is called
        verify_environment.assert_called_once_with(
            root_export=self.root_export,
            exports_file=self.exports_file,
            export_name=export
        )

        # Getting a newly added export should have no clients associated
        helper.add_export(self.root_export, export,
                          exports_file=self.exports_file)
        get = helper.get_export(self.root_export, self.exports_file, export)
        self.assertEqual(get, '{}')

        exports = ExportTable([
            Export(
                export_point=export_point,
                clients={host: frozenset(['rw'])}
            ),
        ])
        with mock.patch('scality_manila_utils.helper._get_defined_exports',
                        return_value=exports):
            get = helper.get_export(self.root_export, self.exports_file,
                                    export)
            self.assertEqual(get, '{"host": ["rw"]}')
