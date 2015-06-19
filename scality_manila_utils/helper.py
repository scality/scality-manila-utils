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
import os.path

from scality_manila_utils import utils
from scality_manila_utils.export import ExportTable
from scality_manila_utils.exceptions import (EnvironmentException,
                                             ExportException)


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
                    os.mkdir(export_point, 0o777)

    def wipe_export(self, export_name):
        """
        Remove an export.

        :param export_name: name of export to remove
        :type export_name: string (unicode)
        """

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

    def revoke_access(self, export_name, host):
        """
        Revoke access for a host to an export.

        :param export_name: name of export for revocation
        :type export_name: string (unicode)
        :param host: host to revoke access for
        :type host: string (unicode)
        """

    def get_export(self, export_name):
        """
        Retrieve client details of an export.

        :param export_name: name of export
        :type export_name: string (unicode)
        """
