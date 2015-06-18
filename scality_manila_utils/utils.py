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
import os


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
