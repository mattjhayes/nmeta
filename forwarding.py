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

#*** nmeta - Network Metadata - Measurement Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
It is provides methods for forwarding functions.
"""

import logging
import logging.handlers

class Forwarding(object):
    """
    This class is instantiated by nmeta.py and provides methods
    for making forwarding decisions and transformations to packets.
    """
    def __init__(self, forwarding_logging_level):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(forwarding_logging_level)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address=('localhost',
                                                      514), facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)

    def packet_in(self):
        """
        TBD
        """
        self.logger.debug("DEBUG: module=forwarding Packet in...")
        #*** UNDER CONSTRUCTION...
