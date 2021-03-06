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


class DeserializationException(ValueError):
    """Raised on deserialization failure of an exports file."""


class ExportException(Exception):
    """Raised on errors pertaining to management of exports."""


class EnvironmentException(Exception):
    """Raised when required processes and binaries are not present."""


class ExportNotFoundException(ExportException):
    """Raised when an export is not found."""
    EXIT_CODE = 10


class ClientExistsException(ExportException):
    """Raised when a client is already granted access to an export."""
    EXIT_CODE = 11


class ClientNotFoundException(ExportException):
    """Raised when a permission is not defined for an export."""
    EXIT_CODE = 12


class ExportHasGrantsException(ExportException):
    """Raised when attempting to remove an export with existing clients."""
    EXIT_CODE = 13


class ExportAlreadyExists(ExportException):
    """Raised when an export already exists."""
    EXIT_CODE = 14
