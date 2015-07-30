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
import json
import logging
import os
import os.path
import signal

from scality_manila_utils import utils
from scality_manila_utils.export import ExportTable
from scality_manila_utils.exceptions import (EnvironmentException,
                                             ExportException,
                                             ExportNotFoundException)

log = logging.getLogger(__name__)


class Helper(object):
    """
    Handles addition, removal of exports as well as client permissions.
    """

    def __init__(self, root_volume, exports_path):
        """
        Create a new Helper instance operating on the given exports file.

        :param root_volume: root volume exported by the sfused nfs connector
        :type root_volume: string (unicode)
        :param exports_path: path to nfs exports file
        :type exports_path: string (unicode)
        """
        # Ring root volume export
        self.root_volume = root_volume

        if not os.path.exists(exports_path):
            raise EnvironmentException('Unable to locate exports file')

        # Path to nfs exports file
        self.exports_path = exports_path

        with io.open(self.exports_path, 'rt') as exports_file:
            self.exports = ExportTable.deserialize(exports_file)

    def verify_environment(self):
        """
        Preliminary checks for installed binaries and running services.

        :raises:
            :py:class:`scality_manila_utils.exceptions.EnvironmentException`
            if the environment is not ready
        """
        env_path = os.getenv('PATH').split(':')
        binaries = ('rpcbind', 'sfused')
        for binary in binaries:
            utils.binary_check(binary, env_path)
            utils.process_check(binary)

    def _reexport(self):
        """
        Export all defined filesystems.
        """
        exports_data = self.exports.serialize()
        sfused_pids = utils.find_pids('sfused')

        with utils.elevated_privileges():
            utils.safe_write(exports_data, self.exports_path)
            for pid in sfused_pids:
                log.debug('Killing sfused pid %d', pid)
                os.kill(pid, signal.SIGHUP)

    def add_export(self, export_name):
        """
        Add an export.

        :param export_name: name of export
        :type export_name: string (unicode)
        """
        if not export_name or '/' in export_name:
            raise ExportException('Invalid export name')

        with utils.elevated_privileges():
            with utils.nfs_mount(self.root_volume) as root:
                export_point = os.path.join(root, export_name)

                # Create export directory if it does not already exist
                if not os.path.exists(export_point):
                    os.mkdir(export_point)
                    os.chmod(export_point, 0o0777)

    def wipe_export(self, export_name):
        """
        Remove an export.

        :param export_name: name of export to remove
        :type export_name: string (unicode)
        """
        raise NotImplementedError

    def grant_access(self, export_name, host, options):
        """
        Grant access for a host to an export.

        :param export_name: name of export to grant access to
        :type export_name: string (unicode)
        :param host: host to grant access for
        :type host: string (unicode)
        :param options: sequence of nfs options
        :type options: iterable of strings (unicode)
        """
        if export_name not in self._get_exports():
            raise ExportNotFoundException("No export point found for "
                                          "'{0:s}'".format(export_name))

        export_point = os.path.join('/', export_name)
        self.exports.add_client(export_point, host, options)
        self._reexport()

    def revoke_access(self, export_name, host):
        """
        Revoke access for a host to an export.

        :param export_name: name of export for revocation
        :type export_name: string (unicode)
        :param host: host to revoke access for
        :type host: string (unicode)
        """
        export_point = os.path.join('/', export_name)
        self.exports.remove_client(export_point, host)
        self._reexport()

    def get_export(self, export_name):
        """
        Retrieve client details of an export.

        :param export_name: name of export
        :type export_name: string (unicode)
        :returns: string with export client details in json format
        """
        export_point = os.path.join('/', export_name)
        if export_point in self.exports:
            clients = dict(
                (host, list(permissions)) for
                host, permissions in
                self.exports[export_point].clients.items()
            )
        elif export_name in self._get_exports():
            # Export has been created, but without any access grants
            clients = {}
        else:
            raise ExportNotFoundException("Export '{0:s}' not found".format(
                                          export_name))

        return json.dumps(clients)

    def _get_exports(self):
        """
        Retrieve all created export points.

        The returned exports include the ones without any access grants, and
        thus has no entry in the exports configuration file.

        :returns: list of strings
        """
        with utils.elevated_privileges():
            with utils.nfs_mount(self.root_volume) as root:
                return os.listdir(root)