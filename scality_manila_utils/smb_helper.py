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

import errno
import functools
import io
import json
import logging
import os
import subprocess
import time

try:
    import ConfigParser as configparser
except ImportError:
    import configparser


from scality_manila_utils import utils
from scality_manila_utils.exceptions import (ClientExistsException,
                                             ClientNotFoundException,
                                             EnvironmentException,
                                             ExportException,
                                             ExportAlreadyExists,
                                             ExportNotFoundException,
                                             ExportHasGrantsException)

log = logging.getLogger(__name__)


# From http://prosseek.blogspot.fr/2012/10/
# reading-ini-file-into-dictionary-in.html
class SmbConfParser(configparser.ConfigParser):
    def as_dict(self):
        d = dict(self._sections)
        for k in d:
            d[k] = dict(self._defaults, **d[k])
            d[k].pop('__name__', None)
        return d


def _get_defined_exports():
    """Retrieve all defined exports from the Samba registry."""

    with utils.elevated_privileges():
        cmd = ['net', 'conf', 'list']
        msg = ("Something went wrong while dumping the Samba "
               "registry: stdout='{stdout}', stderr='{stderr}'")
        stdout, stderr = utils.execute(cmd, msg)

    config = SmbConfParser()
    output = stdout.replace('\t', '')
    config.readfp(io.StringIO(output))

    return config.as_dict()


def verify_environment(root_export):
    """
    Preliminary checks for installed binaries and running services.

    :param root_export: SOFS directory which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :raises:
        :py:class:`scality_manila_utils.exceptions.EnvironmentException`
        if the environment is not ready
    """

    if not utils.is_stored_on_sofs(root_export):
        raise EnvironmentException("%s doesn't seem to be stored on a SOFS "
                                   "filesystem" % root_export)

    env_path = os.getenv('PATH').split(':')
    for binary in ('net', 'sfused'):
        utils.binary_check(binary, env_path)

    for process in ('sfused', 'smbd'):
        utils.process_check(process)

    with io.open('/etc/samba/smb.conf') as f:
        # We can't use `for line in f` here because it seems unmockable...
        for line in f.readlines():
            if line.strip() == 'registry shares = yes':
                break
        else:
            msg = ("You must enable 'registry shares' in your Samba "
                   "configuration: add 'registry shares = yes' in the [global]"
                   " section.")
            raise EnvironmentException(msg)


def ensure_environment(f):
    """
    Decorator function which verifies that expected services are running etc.
    """
    @functools.wraps(f)
    def wrapper(root_export, *args, **kwargs):
        verify_environment(root_export)
        return f(root_export=root_export, *args, **kwargs)

    return wrapper


def ensure_export_exists(f):
    """
    Decorator function which verifies that a given export exists and pass
    the `dict` of all defined exports to the decorated function.
    """
    @functools.wraps(f)
    def wrapper(export_name, *args, **kwargs):
        exports = _get_defined_exports()
        if export_name not in exports:
            msg = "Share '{0:s}' not found in Samba registry.".format(
                  export_name)
            raise ExportNotFoundException(msg)

        return f(export_name=export_name, exports=exports, *args, **kwargs)

    return wrapper


@ensure_environment
@ensure_export_exists
def get_export(export_name, exports, *args, **kwargs):
    """
    Retrieve client details of an export.

    :param export_name: name of export
    :type export_name: string (unicode)
    :param exports: all the defined shares in the Samba registry
    :type exports: dictionary
    :returns: string with export client details in json format
    """

    export = exports[export_name]
    clients = dict((host, ["rw"]) for host in export['hosts allow'].split())

    return json.dumps(clients)


@ensure_environment
def add_export(root_export, export_name, *args, **kwargs):
    """
    Add an export.

    :param root_export: SOFS directory which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param export_name: name of export to add
    :type export_name: string (unicode)
    """

    if not export_name or '/' in export_name:
        raise ExportException('Invalid export name')

    export_point = os.path.join(root_export, export_name)

    create_cmd = [
        'net', 'conf', 'addshare', export_name, export_point,
        'writeable=y', 'guest_ok=y',
    ]
    parameters = {
        'browseable': 'yes',
        'create mask': '0755',
        'hosts deny': '0.0.0.0/0',  # deny all by default
        'hosts allow': '127.0.0.1',
        'read only': 'no',
    }

    set_of_commands = [['net', 'conf', 'setparm', export_name,
                        param, value] for param, value in parameters.items()]

    with utils.elevated_privileges():
        try:
            os.mkdir(export_point)
            # On some systems, the `mode` argument of mkdir is ignored.
            # So be safe, and do an explicit chmod.
            os.chmod(export_point, 0o0777)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            else:
                log.debug("The share/directory %s already exists on SOFS",
                          export_name)
                exports = _get_defined_exports()
                if export_name in exports:
                    msg = ("Share '{0:s}' already defined in Samba "
                           "registry.".format(export_name))
                    raise ExportAlreadyExists(msg)

        subprocess.check_call(create_cmd)
        for cmd in set_of_commands:
            subprocess.check_call(cmd)


@ensure_environment
@ensure_export_exists
def wipe_export(root_export, export_name, exports):
    """
    Remove an export.

    The export point is not actually removed, but renamed with the prefix
    "TRASH-".

    :param root_export: SOFS directory which holds the export points exposed
        through manila
    :type root_export: string (unicode)
    :param export_name: name of export to remove
    :type export_name: string (unicode)
    :param exports: all the defined shares in the Samba registry
    :type exports: dictionary
    """

    export = exports[export_name]
    export_path = os.path.join(root_export, export_name)

    # Wipe export if and only if no "external host" has access to it
    if export['hosts allow'] not in ['', '127.0.0.1']:
        raise ExportHasGrantsException('Unable to remove export with grants')

    # We need to introduce a "variable" part (i.e a date)
    # in case an export with the same name is deleted twice
    tombstone = u'TRASH-{0:s}-{1:s}'.format(export_name,
                                            time.strftime("%Y-%b-%d-%X-%Z"))
    tombstone_path = os.path.join(root_export, tombstone)

    with utils.elevated_privileges():
        log.info("Deleting the export '%s' from the Samba registry",
                 export_name)
        cmd = ['net', 'conf', 'delshare', export_name]
        msg = ("Something went wrong while deleting the export {0:s}: "
               "stdout={{stdout}}, stderr={{stderr}}").format(export_name)
        utils.execute(cmd, msg)

        log.info("Renaming export '%s' to '%s'", export_name, tombstone)
        try:
            os.rename(export_path, tombstone_path)
        except OSError as exc:
            log.error("Unable to rename '%s' for removal : %r",
                      export_name, exc)
            # Two concurrent wipe_export could happen at the same time so
            # the loser of the race could see a ENOENT.
            if exc.errno != errno.ENOENT:
                raise

        # Persisting the parent of the moved directory is required, as
        # it keeps track of its contents.
        utils.fsync_path(root_export)


def _set_hosts_allow(export_name, hosts_allow):
    """
    Set the `hosts_allow` parameter for a given share.

    :param export_name: name of export to grant access to
    :type export_name: string (unicode)
    :param hosts_allow: hosts allowed on this share
    :type hosts_allow: iterable of `str`
    """

    cmd = ['net', 'conf', 'setparm', export_name,
           'hosts allow', ' '.join(hosts_allow)]
    msg = ("Something went wrong while setting '{0!r}' as "
           "the list of 'hosts allow' for share '{1:s}': stdout={{stdout}}, "
           "stderr={{stderr}}").format(hosts_allow, export_name)

    with utils.elevated_privileges():
        utils.execute(cmd, msg)


@ensure_environment
@ensure_export_exists
def grant_access(export_name, host, exports, *args, **kwargs):
    """
    Grant access for a host to an export.

    :param export_name: name of export to grant access to
    :type export_name: string (unicode)
    :param host: host to grant access for
    :type host: string (unicode)
    :param exports: all the defined shares in the Samba registry
    :type exports: dictionary
    """

    hosts_allow = exports[export_name]['hosts allow'].split()

    if host in hosts_allow:
        msg = "Host '{0:s}' already allowed on share '{1:s}'".format(
            host, export_name)
        raise ClientExistsException(msg)

    hosts_allow.append(host)
    _set_hosts_allow(export_name, hosts_allow)


@ensure_environment
@ensure_export_exists
def revoke_access(export_name, host, exports, *args, **kwargs):
    """
    Revoke access for a host to an export.

    :param export_name: name of export for revocation
    :type export_name: string (unicode)
    :param host: host to revoke access for
    :type host: string (unicode)
    :param exports: all the defined shares in the Samba registry
    :type exports: dictionary
    """

    hosts_allow = exports[export_name]['hosts allow'].split()

    if host not in hosts_allow:
        raise ClientNotFoundException("'{0:s}' has no access defined on share "
                                      "'{1:s}'".format(host, export_name))

    hosts_allow.remove(host)
    _set_hosts_allow(export_name, hosts_allow)
