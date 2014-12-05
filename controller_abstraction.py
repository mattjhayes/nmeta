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

#*** nmeta - Network Metadata - Abstractions of Controller for OpenFlow Calls
#
# Matt Hayes
# Victoria University, New Zealand

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata.
It provides functions that abstract the details of OpenFlow calls, including
differences between OpenFlow versions where practical
"""

import logging
import logging.handlers
import sys

#*** Ryu Imports:
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3

#*** This dictionary is used to check validity of flow match attributes
#*** per OpenFlow version, and provides alternates for different versions
#*** where there is complete compatibility.
#*** Note that number 1 corresponds to OFv1.0 and number 4 to OFv1.3:
OF_MATCH_COMPAT = {'dl_dst': {'1': 'dl_dst', '4': 'eth_dst'},
                 'dl_src': {'1': 'dl_src', '4': 'eth_src'},
                 'dl_type': {'1': 'dl_type', '4': 'eth_type'},
                 'dl_vlan': {'1': 'dl_vlan', '4': 'vlan_vid'},
                 'dl_vlan_pcp': {'1': 'dl_vlan_pcp', '4': 'vlan_pcp'},
                 'eth_dst': {'1': 'dl_dst', '4': 'eth_dst'},
                 'eth_src': {'1': 'dl_src', '4': 'eth_src'},
                 'eth_type': {'1': 'dl_type', '4': 'eth_type'},
                 'in_port': {'1': 'in_port', '4': 'in_port'},
                 'ip_dscp': {'1': 'nw_tos', '4': 'ip_dscp'},
                 'ip_proto': {'1': 'nw_proto', '4': 'ip_proto'},
                 'ipv4_dst': {'4': 'ipv4_dst'},
                 'ipv4_src': {'4': 'ipv4_src'},
                 'ipv6_dst': {'4': 'ipv6_dst'},
                 'ipv6_src': {'4': 'ipv6_src'},                 
                 'nw_dst': {'1': 'nw_dst', '4': 'ipv4_dst'},
                 'nw_proto': {'1': 'nw_proto', '4': 'ip_proto'},
                 'nw_src': {'1': 'nw_src', '4': 'ipv4_src'},
                 'nw_tos': {'1': 'nw_tos', '4': 'ip_dscp'},
                 'tcp_dst': {'4': 'tcp_dst'},
                 'tcp_src': {'4': 'tcp_src'},
                 'tp_dst': {'1': 'tp_dst'},
                 'tp_src': {'1': 'tp_src'},
                 'udp_dst': {'4': 'udp_dst'},
                 'udp_src': {'4': 'udp_src'},
                 'vlan_pcp': {'1': 'dl_vlan_pcp', '4': 'vlan_pcp'},
                 'vlan_vid': {'1': 'dl_vlan', '4': 'vlan_vid'},
                 }

class ControllerAbstract(object):
    """
    This class is instantiated by various other modules
    and provides methods for interacting with switches
    that are safe to use without need to for the calling
    program to know calls specific to the version of
    OpenFlow that the switch runs (where practical...)
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
            self.logger.error("ERROR: module=CtrlAbs Unsupported OpenFlow "
                              "version %s", datapath.ofproto.OFP_VERSION)
            return 0

    def get_flow_match(self, datapath, ofproto, **kwargs):
        """
        Passed a OF protocol version and a Flow Match keyword arguments dict 
        and return an OF match tailored for the OF version
        otherwise 0 (false) if compatibility not possible.
        TBD: validating values...
        """
        #*** Iterate through all kwargs checking attribute validity and 
        #*** substituting as appropriate or exiting with 0 if invalid 
        #*** or not not valid and not substitutable for current OF version:
        results = dict()
        for key, value in kwargs.iteritems():
            #*** Check if key exists in OF_MATCH_COMPAT dict:
            if key in OF_MATCH_COMPAT:
                #*** Key exists, check version compatibility:
                if str(ofproto) in OF_MATCH_COMPAT[key]:
                    #*** Write compatible key to results (may be the original):
                    new_key = OF_MATCH_COMPAT[key][str(ofproto)]
                    #*** Only log if changing the key:
                    if key != new_key:
                        self.logger.debug("DEBUG: module=CtrlAbs match "
                                      "attr %s will be replaced with %s", 
                                      key, new_key)
                    results[new_key] = value
                else:
                    #*** No valid attribute for this OF version so log the 
                    #*** error and return 0:
                    self.logger.error("ERROR: module=CtrlAbs match failed."
                                      " No OF %s match for attr %s in %s", 
                                      ofproto, key, OF_MATCH_COMPAT[key])
                    return 0
            else:
                #*** Key doesn't exist so log the error and return 0:
                self.logger.error("ERROR: module=CtrlAbs match failed "
                                      "on attr %s", OF_MATCH_COMPAT[key])
                return 0
        #*** We now have a compatible kwargs dict build a match:
        try:
            match = datapath.ofproto_parser.OFPMatch(**results)
        except:
            #*** Log the error and return 0:
            e = sys.exc_info()[0]
            self.logger.error("ERROR: module=CtrlAbs OFPMatch error %s", e)
            return 0
        return match
        
    def add_flow(self, datapath, match, actions, priority=0, buffer_id=None):
        """
        Add a flow table entry to a switch.
        Returns 1 for success or 0 for any type of error
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            #*** OpenFlow version 1.3 specific:
            try:
                inst = [parser.OFPInstructionActions(
                                    ofproto.OFPIT_APPLY_ACTIONS, actions)]
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("ERROR: module=CtrlAbs "
                    "parser.OFPInstructionActions v1.3 Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                return 0
            
            if buffer_id:
                try:
                    mod = parser.OFPFlowMod(datapath=datapath, 
                                    buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
                except:
                    #*** Log the error and return 0:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error("ERROR: module=CtrlAbs "
                        "parser.OFPFlowMod v1.3 #1 Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                    return 0
            else:
                try:
                    mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    match=match, instructions=inst)
                except:
                    #*** Log the error and return 0:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error("ERROR: module=CtrlAbs "
                        "parser.OFPFlowMod v1.3 #2 Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                    return 0
            try:                        
                #*** Send flow to switch:
                datapath.send_msg(mod)
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("ERROR: module=CtrlAbs "
                    "datapath.send_msg v1.3 Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                return 0
            return 1
        elif ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            try:
                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_ADD, idle_timeout=5, hard_timeout=0,
                    priority=priority,
                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("ERROR: module=CtrlAbs "
                    "datapath.ofproto_parser.OFPFlowMod v1.0 Exception "
                    "%s, %s, %s",
                    exc_type, exc_value, exc_traceback)
                return 0
            try:
                datapath.send_msg(mod)
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("ERROR: module=CtrlAbs "
                    "datapath.send_msg v1.0 Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                return 0
            return 1
