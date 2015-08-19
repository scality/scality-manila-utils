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
    log.debug("Elevating privileges")
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
        log.debug("Dropping elevated privileges")
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
    pids = [f for f in os.listdir('/proc') if f.isdigit()]
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

    log.debug("PIDs for '%s': %r", process, process_pids)
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

    log.error("No '%s' found in PATH (%s)", binary, ', '.join(paths))
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
        log.error("'%s' is not running", process)
        raise EnvironmentException("Could not find '{0:s}' running, "
                                   "make sure it is "
                                   "started".format(process))


def fsync_path(path):
    """
    Fsync a directory.

    :param path: path to directory to fsync
    :type path: string (unicode)
    """
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(fd)
    finally:
        if fd is not None:
            os.close(fd)


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
    log.debug("Writing '%s'", path)
    target_dir, _ = os.path.split(path)
    with tempfile.NamedTemporaryFile(mode='wt', dir=target_dir,
                                     delete=False) as f:
        os.chmod(f.name, permissions)
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
        os.rename(f.name, path)

    # fsync the directory holding the file just written and moved
    fsync_path(target_dir)


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
        log.debug("Mounted nfs root '%s' at '%s'", export_path, mount_point)
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

        log.debug('Unmounted nfs root')

        try:
            os.rmdir(mount_point)
        except OSError as e:
            log.warning("Unable to clean up temporary NFS root: %s", e)


def is_stored_on_sofs(path):
    """
    Check if the given location is stored on a SOFS filesystem.

    :param path: an absolute path, e.g `/ring/fs/samba_shares`
    :type path: string
    :rtype: boolean
    """
    with io.open('/proc/mounts') as mounts:
        for mount in mounts.readlines():
            # A typical line looks line:
            # /dev/fuse on /ring/0.XX type fuse (rw,nosuid,nodev,allow_other)
            parts = mount.split()
            mnt_type = parts[0]
            mnt_point = parts[1].rstrip('/')
            if (mnt_type.endswith('fuse') and
                    path.rstrip('/').startswith(mnt_point)):
                        return True
    return False


def execute(cmd, error_msg):
    """
    Utility function to execute a command

    :param cmd: the command with arguments to execute
    :type cmd: iterable of `str` or a single `str`
    :param error_msg: the exception message in case something went wrong.
        `error_msg` must include the placeholders `{stdout}` and `{stderr}`
    :type error_msg: `str`
    :rtype: (`unicode`, `unicode`)
    """
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    # `subprocess.communicate` returns a byte stream
    stdout, stderr = process.communicate()
    stdout, stderr = stdout.decode(), stderr.decode()

    if process.returncode != 0:
        raise EnvironmentError(error_msg.format(stdout=stdout, stderr=stderr))

    return stdout, stderr
