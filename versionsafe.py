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

#*** nmeta - Network Metadata - Version Safe OpenFlow Calls
#
# Matt Hayes
# Victoria University, New Zealand
# Version 0.2

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata.
It contains version safe OpenFlow calls for where there are implementation
differences
"""

import logging
import logging.handlers

#*** Ryu Imports:
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3

class VersionSafe(object):
    """
    This class is instantiated by various other modules
    and provides methods for interacting with switches
    that are safe to use without need to for the calling
    program to know calls specific to the version of
    OpenFlow that the switch runs
    """
    def __init__(self):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address = ('localhost', 514),
            facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        
    def get_in_port(self, msg, datapath, ofproto):
        """
        Passed a msg, datapath and OF protocol version
        and return the port that the
        packet came in on (version specific)
        """
        #self.logger.debug("DEBUG: testing,1,2,3...!!!")
        if ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            inport = msg.match['in_port']
            return inport
        elif ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            inport = msg.in_port
            return inport
        else:
            self.logger.error("ERROR: module=versionsafe Unsupported OpenFlow version %s", datapath.ofproto.OFP_VERSION)
            return 0
