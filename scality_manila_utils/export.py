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

import logging
import re

from scality_manila_utils.exceptions import (ExportException,
                                             DeserializationException,
                                             ExportNotFoundException,
                                             ClientExistsException,
                                             ClientNotFoundException)

log = logging.getLogger(__name__)


class ExportTable(object):
    """
    A set of exports that can be distilled into /etc/exports.
    """
    def __init__(self, exports):
        """
        Create a new exports table from the given exports.

        :param exports: iterable of exports
        :type exports: iterable of
            :py:class:`scality_manila_utils.export.Export`
        """
        self.exports = dict(
            (export.export_point, export)
            for export in exports
        )

    def add_client(self, export_point, host, options=None):
        """
        Export a filesystem to a client.

        The export is created if it does not exist.

        :param export_point: filesystem (path) to export
        :type export_point: string (unicode)
        :param host: ip address, network or domain name
        :type host: string (unicode)
        :param options: sequence of nfs options (optional)
        :type options: iterable of strings
        """
        if options is None:
            export_options = frozenset()
        else:
            export_options = frozenset(options)

        if export_point not in self.exports:
            export = Export(export_point, {host: export_options})
            log.debug("Export created: %r", export)
        else:
            clients = self.exports[export_point].clients
            if host in clients:
                raise ClientExistsException("Client '{0:s}' is already "
                                            "defined".format(host))
            clients[host] = export_options
            export = Export(export_point, clients)
            log.debug("Export updated: %r", export)

        self.exports[export_point] = export

    def remove_client(self, export_point, host):
        """
        Remove access for a client to an export.

        The filesystem is unexported if there are no clients left.

        :param export_point: export to remove access from
        :type export_point: string (unicode)
        :param host: ip address, network or domain name for removal
        :type host: string (unicode)
        """
        if export_point not in self.exports:
            raise ExportNotFoundException("No export point found for "
                                          "'{0:s}'".format(export_point))

        export = self.exports[export_point]
        if host not in export.clients:
            raise ClientNotFoundException("'{0:s}' has no access defined for "
                                          "'{1:s}'".format(export_point, host))

        clients = export.clients
        # If there are still clients after removal,
        # replace the export with an updated version
        if len(clients) > 1:
            del clients[host]
            self.exports[export_point] = Export(export_point, clients)
        # Otherwise remove the export
        else:
            del self.exports[export_point]

        log.debug("'%s' revoked from export '%s'", host, export_point)

    @classmethod
    def deserialize(cls, export_content):
        """
        Create an `ExportTable` from the contents of an /etc/exports file.

        Each line of the exports file will be represented by a
        :py:class:`scality_manila_utils.exports.Export`. Lines consisting of
        whitespace only or that are comments will be ignored.

        :param export_content: exports file contents split into a list of
            strings
        :type export_content: list of strings
        :returns: a :py:class`scality_manila_utils.exports.ExportTable` object
            with the exported filesystems
        """
        def strip_comment(line):
            export, _, _ = line.partition('#')
            return export

        def is_blank(line):
            stripped = line.strip()
            return stripped == '' or stripped.startswith('#')

        return cls(
            Export.deserialize(strip_comment(line))
            for line in export_content
            if not is_blank(line)
        )

    def serialize(self):
        """
        Serialize the `ExportTable` to a string following /etc/exports format.

        :returns: string representation of the exports
        """
        return '\n'.join(
            export.serialize() for export in self.exports.values()
        ) + '\n'

    def __eq__(self, other):
        if not isinstance(other, ExportTable):
            return NotImplemented

        return self.exports == other.exports

    def __ne__(self, other):
        eq = self.__eq__(other)

        if isinstance(eq, bool):
            return not eq
        else:
            return NotImplemented

    def __repr__(self):
        exports = (repr(export) for export in self.exports.values())
        return "ExportTable([{0:s}])".format(", ".join(exports))

    def __getitem__(self, key):
        return self.exports[key]

    def __contains__(self, item):
        return item in self.exports


class Export(object):
    """
    Represents an exported filesystem, i.e. a single line in /etc/exports.
    """
    __slots__ = ('export_point', 'clients')

    # Naive pattern, matching anything similar to an ip, hostname with wildcard
    # combinations followed by optional mount options
    CLIENT_PATTERN = re.compile(
        r'^(?P<host>[a-z0-9*.-/]+)([(](?P<options>.+)[)])?$'
    )

    def __init__(self, export_point, clients):
        """
        :param export_point: the export point or filesystem
        :type export_point: string (unicode)
        :param clients: a mapping from hostname/network to a set of export
            options
        :type clients: dict
        """
        # Exported filesystem
        self.export_point = export_point

        # Hosts, networks allowed to mount the filesystem and corresponding
        # export options
        if not clients:
            raise ExportException('An export must have at least one client')
        self.clients = clients

    @classmethod
    def deserialize(cls, line):
        """
        Deserialize a line of an /etc/exports file.

        A line contains an export point and a whitespace-separated list of
        clients allowed to mount the file system at that point;
            <export> <host1>(<options>) <host2>(<options>)...

        :param line: a line in /etc/exports format
        :type line: string (unicode)
        :returns: :py:class:`scality_manila_utils.export.Export` instance
        """
        def client_extract(client):
            match = cls.CLIENT_PATTERN.match(client)
            if match is None:
                msg = "Unable to parse client from {0:s}".format(client)
                raise DeserializationException(msg)

            host = match.group('host')
            option_list = match.group('options')
            if option_list is None:
                options = frozenset()
            else:
                options = frozenset(option_list.split(','))
            return host, options

        export_parts = line.split()

        if len(export_parts) < 2:
            msg = "'{0:s}' is not a valid export line".format(line)
            raise DeserializationException(msg)

        export_point = export_parts[0]
        clients = dict(map(client_extract, export_parts[1:]))
        return cls(export_point, clients)

    def serialize(self):
        """
        Serialize this `Export` to an /etc/exports representation.

        :returns: a string in /etc/exports format
        """
        clients = ''
        for host, options in self.clients.items():
            clients += ' ' + host
            if options:
                clients += '({0:s})'.format(','.join(options))

        # Attempt to align clients by padding with space up to col32
        export_line = '{export_point:<32s} {clients:s}'.format(
            export_point=self.export_point,
            clients=clients,
        )
        return export_line

    def __eq__(self, other):
        if not isinstance(other, Export):
            return NotImplemented

        return (self.export_point == other.export_point and
                self.clients == other.clients)

    def __ne__(self, other):
        eq = self.__eq__(other)

        if isinstance(eq, bool):
            return not eq
        else:
            return NotImplemented

    def __repr__(self):
        return "Export(export_point='{0:s}', clients={1!s})".format(
            self.export_point, self.clients
        )
