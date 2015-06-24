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

import contextlib
import errno
import io
import logging
import os
import os.path
import subprocess
import tempfile

from scality_manila_utils.exceptions import EnvironmentException

log = logging.getLogger(__name__)


@contextlib.contextmanager
def elevated_privileges():
    """
    Obtain temporary root privileges.
    """
    previous_uid = os.geteuid()
    previous_gid = os.getegid()
    # Become root
    os.seteuid(0)
    try:
        os.setegid(0)
    except OSError:
        os.setegid(previous_gid)
        raise

    try:
        yield

    finally:
        # Drop root privileges
        try:
            os.setegid(previous_gid)
        finally:
            os.seteuid(previous_uid)


def find_pids(process):
    """
    Find pids by inspection of procfs.

    :param process: process name
    :type process: string
    :returns: list of pids
    """
    process_pids = []
    pids = filter(lambda f: f.isdigit(), os.listdir('/proc'))
    for pid in pids:
        status_path = os.path.join('/proc', pid, 'status')
        try:
            with io.open(status_path, 'rt') as f:
                line = f.readline()
                _, process_name = line.split()
                if process_name == process:
                    process_pids.append(int(pid))
        except IOError as e:
            # Pass on processes that no longer exist
            if e.errno != errno.ENOENT:
                raise

    return process_pids


def binary_check(binary, paths):
    """
    Check if a binary exists on the given paths.

    :param binary: name of binary
    :type binary: string
    :param paths: list of paths to inspect for binary
    :type paths: list of strings
    :raises: :py:class:`scality_manila_utils.exceptions.EnvironmentException`
        if the binary couldn't be found
    """
    for path in paths:
        if os.path.exists(os.path.join(path, binary)):
            return

    raise EnvironmentException("Unable to find '{0:s}', make sure it "
                               "is installed".format(binary))


def process_check(process):
    """
    Check if a process is running.

    :param process: process name
    :type process: string
    :raises: :py:class:`scality_manila_utils.exceptions.EnvironmentException`
        if the process isn't running
    """
    process_pids = find_pids(process)
    if not process_pids:
        raise EnvironmentException("Could not find '{0:s}' running, "
                                   "make sure it is "
                                   "started".format(process))


def safe_write(text, path, permissions=0o644):
    """
    Write contents to file in a safe manner.

    Write contents to a tempfile and then move it in place. This is guarenteed
    to be atomic on a POSIX filesystem.

    :param text: the content to write to file
    :type text: string
    :param path: path to write to
    :type path: string
    :param permissions: file permissions
    :type permissions: int (octal)
    """
    # Make sure that the temporary file lives on the same fs
    target_dir, _ = os.path.split(path)
    with tempfile.NamedTemporaryFile(mode='wt', dir=target_dir,
                                     delete=False) as f:
        os.chmod(f.name, permissions)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
        os.rename(f.name, path)

    # fsync the directory holding the file just written and moved
    dir_fd = None
    try:
        dir_fd = os.open(target_dir, os.O_RDONLY)
        os.fsync(dir_fd)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


@contextlib.contextmanager
def nfs_mount(export_path):
    """
    Mount an NFS filesystem, and keep it mounted while in context.

    :param export_path: exported filesystem to mount, eg. `127.0.0.1:/`
    :type export_path: string
    :returns: path to where the filesystem was mounted
    """
    try:
        mount_point = tempfile.mkdtemp()
        subprocess.check_call(['mount', export_path, mount_point])
    except (OSError, subprocess.CalledProcessError):
        log.exception('Unable to mount NFS root')
        raise

    try:
        yield mount_point

    finally:
        try:
            subprocess.check_call(['umount', mount_point])
        except subprocess.CalledProcessError:
            log.exception('Unable to umount NFS root')
            raise
        try:
            os.rmdir(mount_point)
        except OSError as e:
            log.warning("Unable to clean up temporary NFS root: %s", e)