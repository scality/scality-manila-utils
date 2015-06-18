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

    def verify_environment(self):
        """
        Preliminary checks for installed binaries and running services.
        """

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
