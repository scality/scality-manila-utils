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

import mock
import io
import os
import shutil
import stat
import subprocess
import tempfile
import unittest2 as unittest

from scality_manila_utils import utils
from scality_manila_utils.exceptions import EnvironmentException


class TestUtils(unittest.TestCase):
    def setUp(self):
        self.test_directories = []

    def tearDown(self):
        for directory in self.test_directories:
            shutil.rmtree(directory)

    @mock.patch('os.geteuid', return_value=1000)
    @mock.patch('os.getegid', return_value=1000)
    @mock.patch('os.seteuid')
    @mock.patch('os.setegid')
    def test_elevated_privileges(self, setegid, seteuid, getegid, geteuid):
        unprivileged_uid = os.geteuid()
        unprivileged_gid = os.getegid()

        with utils.elevated_privileges():
            # Privileges should be elevated inside the context manager
            seteuid.assert_called_once_with(0)
            setegid.assert_called_once_with(0)
            seteuid.reset_mock()
            setegid.reset_mock()

        # Privileges should be reset once outside the context manager
        seteuid.assert_called_once_with(unprivileged_uid)
        setegid.assert_called_once_with(unprivileged_gid)

    def test_find_pids(self):
        # Setup a directory to serve as /proc
        proc_path = tempfile.mkdtemp()
        self.test_directories.append(proc_path)
        processes = ((10, 'p1'), (20, 'p2'), (30, 'p3'), (40, 'p4'))
        for pid, process_name in processes:
            self._create_proc_entry(proc_path, pid, process_name)

        # Add some other directories under proc
        non_processes = ('otherdir', 'noprocess', 'sys')
        for directory in non_processes:
            os.mkdir(os.path.join(proc_path, directory))

        # Mocks for `os.listdir` and `os.path.join`
        def listdir_mock(*args, **kwargs):
            proc_listing = [str(pid) for pid, _ in processes]
            proc_listing.extend(non_processes)
            return proc_listing

        def join_mock(procdir, pid, status):
            return "/{proc:s}/{pid:s}/{status:s}".format(proc=proc_path,
                                                         pid=pid,
                                                         status=status)

        with mock.patch('os.listdir', side_effect=listdir_mock):
            with mock.patch('os.path.join', side_effect=join_mock):
                for not_a_process in non_processes:
                    self.assertEqual(utils.find_pids(not_a_process), [])

                for pid, process_name in processes:
                    self.assertEqual(utils.find_pids(process_name), [pid])

    def _create_proc_entry(self, proc_path, pid, process_name):
        pid_path = os.path.join(proc_path, str(pid))
        os.mkdir(pid_path)
        with io.open(os.path.join(pid_path, 'status'), 'wt') as f:
            f.write(u'Name: {0:s}'.format(process_name))

    def test_binary_check(self):
        self.test_directories = [tempfile.mkdtemp(), tempfile.mkdtemp()]
        binary_name = 'bin'

        with self.assertRaises(EnvironmentException):
            utils.binary_check(binary_name, [])
            utils.binary_check('', self.test_directories)
            utils.binary_check(binary_name, self.test_directories)

        # Put the expected binary in a test directory
        binary_path = os.path.join(self.test_directories[-1], binary_name)
        io.open(binary_path, 'wb').close()
        # Should be ok
        utils.binary_check(binary_name, self.test_directories)

    @mock.patch('scality_manila_utils.utils.find_pids')
    def test_process_check(self, find_pids):
        find_pids.return_value = []
        process_name = 'sfused'

        with self.assertRaises(EnvironmentException):
            utils.process_check(process_name)

        find_pids.assert_called_once_with(process_name)
        find_pids.reset_mock()
        find_pids.return_value = [100]
        utils.process_check(process_name)
        find_pids.assert_called_once_with(process_name)

    def test_safe_write(self):
        testdir = tempfile.mkdtemp()
        self.test_directories.append(testdir)
        test_file = os.path.join(testdir, 'testfile')
        sometext = 'abc123'
        mode = 0o444

        utils.safe_write(sometext, test_file, mode)

        # Check for expected permission bitmask
        self.assertEqual(stat.S_IMODE(os.stat(test_file).st_mode), mode)

        # Check contents
        with io.open(test_file, 'rt') as f:
            self.assertEqual(f.read(), sometext)

    @mock.patch('subprocess.check_call')
    def test_nfs_mount(self, check_call):
        export_path = '127.0.0.1:/'
        with utils.nfs_mount(export_path) as root:
            self.assertTrue(os.path.exists(root))
            check_call.assert_called_once_with(['mount', export_path, root])
            check_call.reset_mock()

        self.assertFalse(os.path.exists(root))
        check_call.assert_called_once_with(['umount', root])

        # Check that cleanup is made when an exception is raised
        class TestException(Exception):
            """Cleanup test exception"""

        check_call.reset_mock()
        try:
            with utils.nfs_mount(export_path) as root:
                self.assertTrue(os.path.exists(root))
                check_call.assert_called_once_with(['mount', export_path,
                                                   root])
                check_call.reset_mock()
                raise TestException
        except TestException:
            self.assertFalse(os.path.exists(root))
            check_call.assert_called_once_with(['umount', root])

    def test_fsync_path(self):
        fd = 10
        path = '/'
        with mock.patch('os.open', return_value=fd) as osopen:
            with mock.patch('os.fsync') as fsync:
                with mock.patch('os.close') as osclose:
                    utils.fsync_path(path)
                    osopen.assert_called_once_with(
                        path,
                        os.O_RDONLY | os.O_DIRECTORY
                    )
                    fsync.assert_called_once_with(fd)
                    osclose.assert_called_once_with(fd)

    @mock.patch('os.seteuid', mock.Mock())
    @mock.patch('os.setegid', mock.Mock())
    def test_is_stored_on_sofs(self):
        header = (
            'Filesystem     1024-blocks    Used Available Capacity Mounted on'
        )
        fuse_line = '/dev/fuse          4088408       0   4088408       0% /r'
        bad_line = '/dev/sda1         20608636 1119716  18619320       6% /'

        on_sofs = header + '\n' + fuse_line
        with mock.patch('subprocess.check_output', return_value=on_sofs,
                        autospec=True) as df:
            path = '/r/some/share'
            self.assertTrue(utils.is_stored_on_sofs(path))
            df.assert_called_once_with(['df', '-P', path])

        no_sofs = header + '\n' + bad_line
        with mock.patch('subprocess.check_output', return_value=no_sofs,
                        autospec=True) as df:
            path = '/var/log'
            self.assertFalse(utils.is_stored_on_sofs(path))
            df.assert_called_once_with(['df', '-P', path])

        side_effect = subprocess.CalledProcessError(None, None, None)
        with mock.patch('subprocess.check_output',
                        autospec=True, side_effect=side_effect) as df:
            self.assertRaises(subprocess.CalledProcessError,
                              utils.is_stored_on_sofs, path)
            df.assert_called_once_with(['df', '-P', path])

    @mock.patch('subprocess.Popen', autospec=True, spec_set=True)
    def test_execute_when_cmd_failed(self, mock_popen):
        type(mock_popen.return_value).returncode = mock.PropertyMock(
            return_value=1)
        mock_popen.return_value.communicate.return_value = (b'out', b'err')

        cmd = ['cmd', 'arg1']
        try:
            utils.execute(cmd, "error: {stdout}, {stderr}")
        except EnvironmentError as exc:
            self.assertEqual('error: out, err', exc.args[0])
        else:
            self.fail("Should have raised an EnvironmentError")

        mock_popen.assert_called_once_with(cmd, stdout=-1, stderr=-1)

    @mock.patch('subprocess.Popen', autospec=True, spec_set=True)
    def test_execute_when_cmd_succeeded(self, mock_popen):
        type(mock_popen.return_value).returncode = mock.PropertyMock(
            return_value=0)
        mock_popen.return_value.communicate.return_value = (b'out', b'err')

        cmd = ['cmd', 'arg1']
        self.assertEqual((u'out', u'err'), utils.execute(cmd, ""))

        mock_popen.assert_called_once_with(cmd, stdout=-1, stderr=-1)
