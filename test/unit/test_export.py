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

try:
    from hypothesis import given, Settings
    from hypothesis.strategies import (builds, dictionaries, integers, lists,
                                       one_of, sampled_from, sets, text)
except ImportError:
    pass

import sys
import unittest2 as unittest

from scality_manila_utils.export import Export, ExportTable


class ExportStrategy(object):
    @classmethod
    def export_table(cls):
        """
        Strategy for :py:class:`scality_manila_utils.export.ExportTable`.
        """
        exports = lists(cls.export(), max_size=50)
        return builds(ExportTable, exports)

    @classmethod
    def export(cls):
        """
        Strategy that generates :py:class:`scality_manila_utils.export.Export`.
        """
        export_point = cls.path()
        host = cls.host()
        options = sets(cls.options(), average_size=3)
        clients = dictionaries(
            keys=host,
            values=options,
            min_size=1,
            average_size=5
        )
        return builds(Export, export_point, clients)

    @classmethod
    def export_line(cls):
        """
        Strategy that generates nfs export lines.
        """
        def format_export(path, clients):
            return '{0:s} {1:s}'.format(path, ' '.join(clients))

        path = cls.path()
        clients = lists(cls.client(), min_size=1)
        return builds(format_export, path, clients)

    @classmethod
    def client_string(cls):
        """
        Strategy for generation of nfs clients.
        """
        def format_client(host, options):
            return '{0:s}{1:s}'.format(host, options)

        host = cls.host()
        options = cls.options_string()
        return builds(format_client, host, options)

    @classmethod
    def options_string(cls):
        """
        Strategy for generation of nfs options formatted for an exports line.
        """
        def format_options(opts):
            if not opts:
                return ''
            else:
                return '({0:s})'.format(','.join(opts))

        options = cls.options()
        return builds(format_options, sets(options))

    @classmethod
    def options(cls):
        """
        Strategy for generation of nfs export options.
        """
        return sampled_from(('secure', 'rw', 'ro', 'sync', 'async',
                             'no_wdelay', 'no_wdelay', 'no_subtree_check',
                             'subtree_check', 'crossmnt', 'no_auth_nlm',
                             'fsid=num', 'fsid=root', 'fsid=uuid', 'anonuid',
                             'anongid', 'root_squash', 'no_root_squash',
                             'all_squash'))

    @classmethod
    def host(cls):
        """
        Strategy for generation of an ip, network, or hostname
        """
        return one_of(cls.ip(), cls.network(), cls.hostname())

    @classmethod
    def ip(cls):
        """
        Strategy for IP generation.
        """
        def format_ip(o1, o2, o3, o4):
            return '{:d}.{:d}.{:d}.{:d}'.format(o1, o2, o3, o4)

        octet = integers(1, 254)
        return builds(format_ip, octet, octet, octet, octet)

    @classmethod
    def network(cls):
        """
        Strategy for generation of networks in CIDR notation.
        """
        def format_network(ip, routing_prefix):
            return '{0:s}/{1:d}'.format(ip, routing_prefix)

        routing_prefix = integers(0, 32)
        return builds(format_network, cls.ip(), routing_prefix)

    @classmethod
    def hostname(cls):
        """
        Strategy for hostname generation.
        """
        return text(cls.a_z(), min_size=1, average_size=10)

    @classmethod
    def path(cls):
        """
        Strategy for path name generation.
        """
        alphabet = one_of(cls.A_Z(), cls.a_z(), cls.numbers(),
                          cls.punctuation())
        # Create an absolute path from the alphabet by prepending a '/'
        return text(alphabet, average_size=20).map(lambda s: '/' + s)

    @classmethod
    def A_Z(cls):
        """
        Strategy for generation of capital letters through 'A' to 'Z'.
        """
        return sampled_from(map(lambda c: chr(c), range(65, 91)))

    @classmethod
    def a_z(cls):
        """
        Strategy for generation of lowercase letters through 'a' to 'z'.
        """
        return sampled_from(map(lambda c: chr(c), range(97, 123)))

    @classmethod
    def numbers(cls):
        """
        Strategy for generation of digits.
        """
        return sampled_from(map(lambda n: str(n), range(10)))

    @classmethod
    def punctuation(cls):
        """
        Strategy for generation of punctuation characters.
        """
        return sampled_from(('.', '_', '/', ',', '-'))
