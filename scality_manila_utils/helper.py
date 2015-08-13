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
"""
Collection of functions for
 - Addition and removal of exports
 - Management of client permissions on export locations
"""

import functools
import io
import json
import logging
import os
import os.path
import signal

from scality_manila_utils import utils
from scality_manila_utils.export import ExportTable
from scality_manila_utils.exceptions import (EnvironmentException,
                                             ExportException,
                                             ExportNotFoundException,
                                             ExportHasGrantsException)

log = logging.getLogger(__name__)


def _get_defined_exports(exports_file):
    """
    Retrieve all defined exports from the nfs exports config file.

    :param exports_file: path to nfs exports file
    :type exports_file: string (unicode)
    :returns: py:class:`scality_manila_utils.exports.ExportTable`
        with the exports read from file
    """
    with io.open(exports_file, 'rt') as exports_file:
        exports = ExportTable.deserialize(exports_file)
    return exports


def _get_export_points(root_export):
    """
    Retrieve all created export points.

    The returned exports include the ones without any access grants, and
    thus has no entry in the exports configuration file.

    :param root_export: nfs root export which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :returns: list of strings
    """
    with utils.elevated_privileges():
        with utils.nfs_mount(root_export) as root:
            return os.listdir(root)


def _reexport(exports_file, exports):
    """
    Export all defined filesystems.

    :param exports_file: path to the nfs exports file
    :type exports_file: string (unicode)
    :param exports: table of exports to re-export
    :type exports: :py:class:`scality_manila_utils.export.ExportTable`
    """
    serialized_exports = exports.serialize()
    sfused_pids = utils.find_pids('sfused')

    with utils.elevated_privileges():
        utils.safe_write(serialized_exports, exports_file)
        for pid in sfused_pids:
            log.debug('Killing sfused pid %d', pid)
            os.kill(pid, signal.SIGHUP)


def verify_environment(exports_file, *args, **kwargs):
    """
    Preliminary checks for installed binaries and running services.

    :param exports_file: path to the nfs exports file
    :type exports_file: string (unicode)
    :raises:
        :py:class:`scality_manila_utils.exceptions.EnvironmentException`
        if the environment is not ready
    """
    # Check path to nfs exports file
    if not os.path.exists(exports_file):
        raise EnvironmentException('Unable to locate exports file')

    # Ensure that expected services are installed and running
    env_path = os.getenv('PATH').split(':')
    binaries = ('rpcbind', 'sfused')
    for binary in binaries:
        utils.binary_check(binary, env_path)
        utils.process_check(binary)


def ensure_environment(f):
    """
    Decorator function which verifies that expected services are running etc.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        verify_environment(*args, **kwargs)
        return f(*args, **kwargs)

    return wrapper


@ensure_environment
def add_export(root_export, export_name, *args, **kwargs):
    """
    Add an export.

    :param root_export: nfs root export which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param export_name: name of export to add
    :type export_name: string (unicode)
    """
    if not export_name or '/' in export_name:
        raise ExportException('Invalid export name')

    with utils.elevated_privileges():
        with utils.nfs_mount(root_export) as root:
            export_point = os.path.join(root, export_name)

            # Create export directory if it does not already exist
            if not os.path.exists(export_point):
                os.mkdir(export_point)
                os.chmod(export_point, 0o0777)


@ensure_environment
def wipe_export(root_export, exports_file, export_name):
    """
    Remove an export.

    The export point is not actually removed, but renamed with the prefix
    "TRASH-".

    :param root_export: nfs root export which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param exports_file: path to the nfs exports file
    :type exports_file: string (unicode)
    :param export_name: name of export to remove
    :type export_name: string (unicode)
    """
    export_point = os.path.join('/', export_name)
    if export_point in _get_defined_exports(exports_file):
        raise ExportHasGrantsException('Unable to remove export with grants')

    if export_name not in _get_export_points(root_export):
        raise ExportNotFoundException("No export point found for "
                                      "'{0:s}'".format(export_name))

    with utils.elevated_privileges():
        with utils.nfs_mount(root_export) as root:
            tombstone = 'TRASH-{0:s}'.format(export_name)
            tombstone_path = os.path.join(root, tombstone)
            export_path = os.path.join(root, export_name)

            log.info("Renaming export '%s' to '%s'", export_name, tombstone)
            try:
                os.rename(export_path, tombstone_path)
            except OSError:
                log.error("Unable to rename '%s' for removal", export_name)
                raise

            # Persisting the parent of the moved directory is required, as
            # it keeps track of its contents.
            utils.fsync_path(root)


@ensure_environment
def grant_access(root_export, exports_file, export_name, host, options):
    """
    Grant access for a host to an export.

    :param root_export: nfs root export which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param exports_file: path to the nfs exports file
    :type exports_file: string (unicode)
    :param export_name: name of export to grant access to
    :type export_name: string (unicode)
    :param host: host to grant access for
    :type host: string (unicode)
    :param options: sequence of nfs options
    :type options: iterable of strings (unicode)
    """
    if export_name not in _get_export_points(root_export):
        raise ExportNotFoundException("No export point found for "
                                      "'{0:s}'".format(export_name))

    export_point = os.path.join('/', export_name)
    exports = _get_defined_exports(exports_file)

    exports.add_client(export_point, host, options)
    _reexport(exports_file, exports)


@ensure_environment
def revoke_access(root_export, exports_file, export_name, host):
    """
    Revoke access for a host to an export.

    :param root_export: nfs root export which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param exports_file: path to the nfs exports file
    :type exports_file: string (unicode)
    :param export_name: name of export for revocation
    :type export_name: string (unicode)
    :param host: host to revoke access for
    :type host: string (unicode)
    """
    export_point = os.path.join('/', export_name)
    exports = _get_defined_exports(exports_file)
    exports.remove_client(export_point, host)
    _reexport(exports_file, exports)


@ensure_environment
def get_export(root_export, exports_file, export_name):
    """
    Retrieve client details of an export.

    :param root_export: nfs root export which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param exports_file: path to the nfs exports file
    :type exports_file: string (unicode)
    :param export_name: name of export
    :type export_name: string (unicode)
    :returns: string with export client details in json format
    """
    export_point = os.path.join('/', export_name)
    exports = _get_defined_exports(exports_file)
    if export_point in exports:
        clients = dict(
            (host, list(permissions)) for
            host, permissions in
            exports[export_point].clients.items()
        )
    elif export_name in _get_export_points(root_export):
        # Export has been created, but without any access grants
        clients = {}
    else:
        raise ExportNotFoundException("Export '{0:s}' not found".format(
                                      export_name))

    return json.dumps(clients)
