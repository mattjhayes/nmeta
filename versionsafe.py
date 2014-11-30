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

#*** This dictionary is used to check validity of flow match attributes
#*** per OpenFlow version, and provides alternates for different versions
#*** where there is complete compatibility:
OF_MATCH_COMPAT = {'dl_dst': {'1.0': 'dl_dst', '1.3': 'eth_dst'},
                 'dl_src': {'1.0': 'dl_src', '1.3': 'eth_src'},
                 'dl_type': {'1.0': 'dl_type', '1.3': 'eth_type'},
                 'dl_vlan': {'1.0': 'dl_vlan', '1.3': 'vlan_vid'},
                 'dl_vlan_pcp': {'1.0': 'dl_vlan_pcp', '1.3': 'vlan_pcp'},
                 'eth_dst': {'1.0': 'dl_dst', '1.3': 'eth_dst'},
                 'eth_src': {'1.0': 'dl_src', '1.3': 'eth_src'},
                 'eth_type': {'1.0': 'dl_type', '1.3': 'eth_type'},
                 'in_port': {'1.0': 'in_port', '1.3': 'in_port'},
                 'ip_dscp': {'1.0': 'nw_tos', '1.3': 'ip_dscp'},
                 'ip_proto': {'1.0': 'nw_proto', '1.3': 'ip_proto'},
                 'ipv4_dst': {'1.3': 'ipv4_dst'},
                 'ipv4_src': {'1.3': 'ipv4_src'},
                 'ipv6_dst': {'1.3': 'ipv6_dst'},
                 'ipv6_src': {'1.3': 'ipv6_src'},                 
                 'nw_dst': {'1.0': 'nw_dst', '1.3': 'ipv4_dst'},
                 'nw_proto': {'1.0': 'nw_proto', '1.3': 'ip_proto'},
                 'nw_src': {'1.0': 'nw_src', '1.3': 'ipv4_src'},
                 'nw_tos': {'1.0': 'nw_tos', '1.3': 'ip_dscp'},
                 'tcp_dst': {'1.3': 'tcp_dst'},
                 'tcp_src': {'1.3': 'tcp_src'},
                 'tp_dst': {'1.0': 'tp_dst'},
                 'tp_src': {'1.0': 'tp_src'},
                 'udp_dst': {'1.3': 'udp_dst'},
                 'udp_src': {'1.3': 'udp_src'},
                 'vlan_pcp': {'1.0': 'dl_vlan_pcp', '1.3': 'vlan_pcp'},
                 'vlan_vid': {'1.0': 'dl_vlan', '1.3': 'vlan_vid'},
                 }

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
        self.handler = logging.handlers.SysLogHandler(address = 
                            ('localhost', 514), facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        
    def get_in_port(self, msg, datapath, ofproto):
        """
        Passed a msg, datapath and OF protocol version
        and return the port that the
        packet came in on (version specific)
        """
        if ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            inport = msg.match['in_port']
            return inport
        elif ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            inport = msg.in_port
            return inport
        else:
            self.logger.error("ERROR: module=versionsafe Unsupported OpenFlow "
                              "version %s", datapath.ofproto.OFP_VERSION)
            return 0

    def get_flow_match(self, ofproto, **kwargs):
        """
        Passed a OF protocol version and a Flow Match keyword arguments dict 
        and return an OF match tailored for the OF version
        otherwise 0 (false) if compatibility not possible.
        TBD: validating values...
        """
        #*** Iterate through all kwargs checking attribute validity and 
        #*** substituting as appropriate or exiting with 0 if invalid 
        #*** or not not valid and not substitutable for current OF version:
        for key, value in kwargs.iteritems():
            #*** Check if key exists in OF_MATCH_COMPAT dict:
            if key in OF_MATCH_COMPAT:
                #*** Key exists, check version compatibility:
                if ofproto in OF_MATCH_COMPAT[key]:
                    kwargs[key] = 
            else:
                #*** Key doesn't exist so bomb out of this fn with a 0:
                return 0
        
