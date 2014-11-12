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

#*** nmeta - Network Metadata - TC Payload Class and Methods
#
# Matt Hayes
# Victoria University, New Zealand
# Version 1.8

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import logging
import logging.handlers
import struct
import binascii
import time

#*** Ryu imports:
from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

#*** nmeta imports:
import nmisc

#============== For PEP8 this is 79 characters long... ========================
#========== For PEP8 DocStrings this is 72 characters long... ==========

class PayloadInspect(object):
    """
    This class is instantiated by tc_policy.py 
    (class: TrafficClassificationPolicy) and provides methods to 
    run payload traffic classification matches
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
        #*** Instantiate the Flow Classification In Progress (FCIP) Table:
        self._fcip_table = nmisc.AutoVivification()        
        #*** Initialise FCIP Tables unique reference number:
        self._fcip_ref = 1
        #*** Do you want really verbose debugging?
        self.extra_debugging = 0
        
    def check_payload(self, policy_attr, policy_value, pkt):
        """
        Passed a payload classification attribute, value and packet and
        return a dictionary containing attributes 'match' and
        'continue_to_inspect' with appropriate values set.
        """
        if (policy_attr == "payload_type" and policy_value == "ftp"):
            #*** call the function for this particular payload classifier
            results_dict = self._payload_ftp(pkt)
            return results_dict
        else:
            self.logger.error("ERROR: module=tc_payload Policy attribute %s and value %s"
                              " did not match", policy_attr, policy_value)
            return {'match':False, 'continue_to_inspect':False}        
            
    def _payload_ftp(self, pkt):
        """
        A payload classifier that matches FTP traffic, including
        parsing the dynamic port number and matching that flow too
        This function is passed a packet and returns a dictionary of 
        results (match and continue_to_inspect). Only works on TCP.
        """
        #*** Initialise variables
        _continue_to_inspect = False
        _match = False
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp)        
        if not _pkt_tcp:
            return {'match':False, 'continue_to_inspect':False}
        #*** It is TCP, static classification check to see if it's FTP control:
        if ((int(_pkt_tcp.src_port) == 21) or (int(_pkt_tcp.dst_port) == 21)):
            #*** Its FTP control, based on the above, ahem, static classification. But wait, there's more...
            _match = True
            _continue_to_inspect = True
            self.logger.debug("DEBUG: module=tc_payload matched FTP control packet") 
            #*** Do FCIP processing:
            _fcip_results = self._process_pkt_fcip(pkt, 'ftp')
            if _fcip_results['finalised']:
                #*** Its finalised so set continue_to_inspect to false so flow installed to switch:
                return {'match':_match, 'continue_to_inspect':False}
            if _fcip_results['viable']:
                #*** Viable for payload inspection so check it out...
                _dynamic_port = self._payload_ftp_decode_dynamic_port(_fcip_results['payload'])
                if _dynamic_port:
                    #*** Have dynamic port so can stop inspecting this flow.
                    #*** Note that this is likely to be an errant assumption.
                    #*** (i.e. will not see any subsequent control traffic)
                    self.logger.debug("DEBUG: module=tc_payload FTP dynamic TCP port number is %s", _dynamic_port)
                    _continue_to_inspect = False
                    #*** Finalise the flow:
                    self._fcip_finalise(_fcip_results['table_ref'])
                    #*** Add the dynamic flow (IP dst and src reversed
                    #*** and source port 20 and dest port the dynamic port
                    _dynamic_flow_dict = {'finalised':True, 'pkt_ip4.src':_pkt_ip4.dst, 'pkt_ip4.dst':_pkt_ip4.src,
                                          'pkt_tcp.src_port':20, 'pkt_tcp.dst_port':_dynamic_port,
                                          'classifier_type':'ftp'}
                    self._fcip_add_new2(_dynamic_flow_dict)
            else:
                pass
        else:
            #*** Not FTP control traffic but could still be FTP data traffic
            #*** Check the FCIP table for an FTP match for this packet:
            _table_ref = self._fcip_check(pkt, 'ftp')
            if _table_ref:
                _match = True
                if self._fcip_is_finalised(_table_ref):
                    _continue_to_inspect = False
                else:
                    _continue_to_inspect = True
        return {'match':_match, 'continue_to_inspect':_continue_to_inspect}

    def _payload_ftp_decode_dynamic_port(self, payload):
        """
        Packet decode for FTP control traffic. Passed a packet
        and return dynamic port number if it is present otherwise
        return 0
        """
        #*** Initialise variables
        _dynamic_port = 0
        if payload[:8] == '504f5254':
            self.logger.debug("DEBUG: module=tc_payload matched PORT command")
            #*** Now decode to get the dynamic port. It's comma separated (Hex 2c) decimal characters in hex
            _port_cmd_values_raw = payload[9:].split("2c")
            _higher_byte = _port_cmd_values_raw[4]
            _lower_byte = _port_cmd_values_raw[5]
            #*** chop off the last 4 hex (always 0d0a):
            _lower_byte = _lower_byte[:-4]
            #*** convert hex bytes into decimal:
            _dynamic_port = ((int(binascii.unhexlify(_higher_byte))*256) + int(binascii.unhexlify(_lower_byte)))
            if ((_dynamic_port > 0) and (_dynamic_port < 65537)):
                return _dynamic_port
            else:
                self.logger.warning("WARNING: module=tc_payload function=_payload_ftp dynamic port not valid: %s", 
                                            _dynamic_port)
                return 0                           
        

    def _process_pkt_fcip(self, pkt, classifier_type):
        """
        This function deals with common FCIP drudgery so that 
        it doesn't need to be repeated in each payload classifier.
        Passed a packet and classifier type then work out if 
        it should have its payload inspected.
        Return a dictionary with attributes/values:
        - viable:    Indicates that the packet has payload and is
                     not finalised
        - table_ref: Table reference (if exists) to matching flow entry
                     in the FCIP table
        - finalised: Whether or not the flow is finalised (if exists)
        - payload:   Packet payload in ASCII (if exists)
        """
        _viable = False
        _table_ref = self._fcip_check(pkt, classifier_type)
        _finalised = False
        _payload = 0
        if _table_ref:
            #*** It's a flow that we know about.
            #*** Update the last seen table time:
            self._fcip_update_time(_table_ref)
            #*** Check that the flow hasn't been finalised:
            if not self._fcip_is_finalised(_table_ref):
                #*** check if payload is present:
                if len(pkt.protocols) >= 4:
                    _viable = True
                    _payload = str(binascii.b2a_hex(pkt.protocols[-1]))
            else:
                _finalised = True
        else:
            #*** It's not a flow we're classifying so start a new entry:
            self._fcip_add_new(pkt, classifier_type)
            #*** Could still be viable, it isn't finalised so check if has payload:
            if len(pkt.protocols) >= 4:
                _viable = True
                _payload = str(binascii.b2a_hex(pkt.protocols[-1]))
        return {'viable':_viable, 'table_ref':_table_ref, 'finalised': _finalised,
                'payload':_payload} 

    def _fcip_update_time(self, table_ref):
        """
        Passed a table row (flow reference) and update the
        last seen timestamp (used for table maintenance)
        """
        self._fcip_table[table_ref]["time_last_seen"] = time.time()
                
    def _fcip_finalise(self, table_ref):
        """
        Passed a table row (flow reference) and set it as finalised
        so that no more packets will be added
        """
        self._fcip_table[table_ref]["finalised"] = 1

    def _fcip_is_finalised(self, table_ref):
        """
        Passed a table row (flow reference) and check if it has 
        finalised set. Return True (1) if it does and False (0)
        if it doesn't
        """
        if self._fcip_table[table_ref]["finalised"] == 1:
            return 1
        else:
            return 0
            
    def _fcip_check(self, pkt, classifier_type):
        """
        Checks if a packet is part of a flow in the
        Flow Classification In Progress (FCIP) table
        for the particular classifier type.
        Returns False if not in table.
        Returns a table reference if it is in the table
        """
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp) 
        _ip_A = _pkt_ip4.src
        _ip_B = _pkt_ip4.dst
        _tcp_A = _pkt_tcp.src_port
        _tcp_B = _pkt_tcp.dst_port
        for _table_ref in self._fcip_table:
            _ip_match = self._fcip_check_ip(_table_ref, _ip_A, _ip_B)
            if _ip_match:
                #*** Matched IP address pair in either direction
                #*** Now check for TCP port match (with consideration to directionality):
                _tcp_match = self._fcip_check_tcp(_table_ref, _ip_match, _tcp_A, _tcp_B)
                if _tcp_match:
                    #*** Matched IP and TCP parameters, now check classifier type:
                    if self._fcip_table[_table_ref]['classifier_type'] == classifier_type:
                        #*** Return the table reference:
                        return _table_ref
        return False

    def _fcip_check_ip(self, table_ref, ip_A, ip_B):
        """
        Checks if a source/destination IP addresses match against
        a given table entry in either order.
        Returns 'forward' for a direct match, 'reverse' for a 
        transposed match and False (0) for no match
        """
        if (ip_A == self._fcip_table[table_ref]["ip_A"]
            and ip_B == self._fcip_table[table_ref]["ip_B"]):
                return('forward')
        elif (ip_A == self._fcip_table[table_ref]["ip_B"]
            and ip_B == self._fcip_table[table_ref]["ip_A"]):
                return('reverse')
        else:
            return False

    def _fcip_check_tcp(self, table_ref, ip_match, tcp_A, tcp_B):
        """
        Checks if source/destination tcp ports match against
        a given table entry same order that IP addresses matched 
        in.
        .
        Also deduplicates for same packet passing through multiple
        switches by checking the TCP acknowledgement number
        .
        Returns True (1) for a match and False (0) for no match
        """        
        if (ip_match == 'forward' and tcp_A == self._fcip_table[table_ref]["tcp_A"]
            and tcp_B == self._fcip_table[table_ref]["tcp_B"]):
                return True
        elif (ip_match == 'reverse' and tcp_A == self._fcip_table[table_ref]["tcp_B"]
            and tcp_B == self._fcip_table[table_ref]["tcp_A"]):
                return True
        else:
            return False

    def _fcip_add_new(self, pkt, classifier_type):
        """
        Passed a packet that is a new flow and add to the
        Flow Classification In Progress (FCIP) table.
        """        
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp) 
        #*** Initial setting of variable allowing more packets being added:
        self._fcip_table[self._fcip_ref]['finalised'] = 0
        self._fcip_table[self._fcip_ref]['time_last_seen'] = time.time()
        #*** Add the standard layer-3 and 4 values:
        self._fcip_table[self._fcip_ref]['ip_A'] = _pkt_ip4.src
        self._fcip_table[self._fcip_ref]['ip_B'] = _pkt_ip4.dst
        self._fcip_table[self._fcip_ref]['tcp_A'] = _pkt_tcp.src_port
        self._fcip_table[self._fcip_ref]['tcp_B'] = _pkt_tcp.dst_port
        #*** Classifier Type:
        self._fcip_table[self._fcip_ref]['classifier_type'] = classifier_type
        if self.extra_debugging:
            self.logger.debug("DEBUG: module=tc_payload added new: %s", self._fcip_table[self._fcip_ref])
        #*** increment table ref ready for next time we use it:
        self._fcip_ref += 1

    def _fcip_add_new2(self, flow_dict):
        """
        Passed flow detail parameters as a dictionary and add to the
        Flow Classification In Progress (FCIP) table.
        """
        if self.extra_debugging:
            self.logger.debug("DEBUG: module=tc_payload add_new2: %s", flow_dict)
        #*** Initial setting of variable allowing more packets being added:
        self._fcip_table[self._fcip_ref]['finalised'] = flow_dict['finalised']
        self._fcip_table[self._fcip_ref]['time_last_seen'] = time.time()
        #*** Add the standard layer-3 and 4 values:
        self._fcip_table[self._fcip_ref]['ip_A'] = flow_dict['pkt_ip4.src']
        self._fcip_table[self._fcip_ref]['ip_B'] = flow_dict['pkt_ip4.dst']
        self._fcip_table[self._fcip_ref]['tcp_A'] = flow_dict['pkt_tcp.src_port']
        self._fcip_table[self._fcip_ref]['tcp_B'] = flow_dict['pkt_tcp.dst_port']
        #*** Classifier Type:
        self._fcip_table[self._fcip_ref]['classifier_type'] = flow_dict['classifier_type']
        if self.extra_debugging:
            self.logger.debug("DEBUG: module=tc_payload added new: %s", self._fcip_table[self._fcip_ref])
        #*** increment table ref ready for next time we use it:
        self._fcip_ref += 1
