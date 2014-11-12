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

#*** nmeta - Network Metadata - TC Statistical Class and Methods
#
# Matt Hayes
# Victoria University, New Zealand
#
# Version 2.5

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import logging
import logging.handlers
import struct
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

class StatisticalInspect(object):
    """
    This class is instantiated by tc_policy.py 
    (class: TrafficClassificationPolicy) and provides methods to 
    run statistical traffic classification matches
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
        self.extra_debugging = 1
        
    def check_statistical(self, policy_attr, policy_value, pkt):
        """
        Passed a statistical classification attribute, value and packet and
        return a dictionary containing attributes 'valid', 
        'continue_to_inspect' and 'actions' with appropriate values set.
        """
        self.logger.debug("DEBUG: module=tc_statistical check_statistical was called")
        if policy_attr == "statistical_qos_bandwidth_1":
            #*** call the function for this particular statistical classifier
            results_dict = self._statistical_qos_bandwidth_1(pkt)
            return results_dict
        else:
            self.logger.error("ERROR: module=tc_statistical Policy attribute %s "
                              "did not match", policy_attr)
            return {'valid':False, 'continue_to_inspect':False, 'actions':'none'}        
        return False

    def _statistical_qos_bandwidth_1(self, pkt):
        """
        A really basic statistical classifier to demonstrate ability
        to differentiate 'bandwidth hog' flows from ones that are 
        more interactive so that appropriate classification metadata
        can be passed to QoS for differential treatment.
        This function is passed a packet and returns a dictionary of 
        results. Only works on TCP.
        """
        #*** Maximum packets to accumulate in a flow before making a classification
        _max_packets = 5
        #*** Thresholds used in calculations:
        _max_packet_size_threshold = 1200
        _interpacket_ratio_threshold = 0.25
        #*** Initialise variables
        _continue_to_inspect = True
        _actions = 0
        _pkt_tcp = pkt.get_protocol(tcp.tcp)        
        if not _pkt_tcp:
            return {'valid':True, 'continue_to_inspect':False, 
                    'actions':_actions}
        #*** It is TCP, check if it's part of a flow we're already classifying:
        _table_ref = self._fcip_check(pkt)
        self.logger.debug("DEBUG: module=tc_statistical Table ref is %s", _table_ref)          
        if _table_ref:
            #*** It's a flow that we are classifying. Update the table and
            #*** check if we have enough data to make a classification.
            #*** Check that the flow hasn't been finalised:
            if not self._fcip_is_finalised(_table_ref):
                #*** Not finalised so add to table row:
                _flow_packet_count = self._fcip_add_to_existing(pkt, _table_ref)
                #*** Note that _flow_packet_count will be 0 if a duplicate packet
                if _flow_packet_count > (_max_packets - 1):
                    #*** Reached our maximum packet count so do some classification:
                    self.logger.debug("DEBUG: module=tc_statistical Reached max packets count")
                    #*** Set the flow to be finalised so no more packets will be added: 
                    self._fcip_finalise(_table_ref)
                    #*** Set result value to say that flow can be installed to switch now
                    #*** as we don't need to see any more packets to classify it:
                    _continue_to_inspect = False                        
                    #*** Call functions to get statistics to make decisions on:
                    _max_packet_size = self._calc_max_packet_size(_table_ref)
                    _max_interpacket_interval = self._calc_max_interpacket_interval(_table_ref)
                    _min_interpacket_interval = self._calc_min_interpacket_interval(_table_ref)
                    #*** Avoid possible divide by zero error:
                    if (_max_interpacket_interval and _min_interpacket_interval):
                        #*** Ratio between largest directional interpacket delta and smallest
                        #*** Use a ratio as it accounts for base RTT:
                        _interpacket_ratio = float(_min_interpacket_interval) / float(_max_interpacket_interval)
                    else:
                        _interpacket_ratio = 0
                    self.logger.debug("DEBUG: module=tc_statistical _max_packet_size is %s", _max_packet_size)
                    self.logger.debug("DEBUG: module=tc_statistical _interpacket_ratio is %s", _interpacket_ratio)
                    #*** Decide actions based on the statistics:
                    if (_max_packet_size > _max_packet_size_threshold and 
                            _interpacket_ratio < _interpacket_ratio_threshold):
                        #*** This traffic looks like a bandwidth hog so set to low priority:
                        _actions = { 'set_qos_tag': "QoS_treatment=low_priority" }
                    else:
                        #*** Doesn't look like bandwidth hog so default priority:
                        _actions = { 'set_qos_tag': "QoS_treatment=default_priority" }
                    self.logger.debug("DEBUG: module=tc_statistical Decided on actions %s", _actions)
                    #*** Install actions into table so that subsequent packets of same flow
                    #*** get same actions when seeing finalised entry:
                    self._fcip_table[_table_ref]["actions"] = _actions
            else:
                #*** It's a finalised flow so we don't want to touch it,
                #*** but we do want to grab the actions if there are any
                _actions = self._fcip_table[_table_ref]["actions"]
                return {'valid':True, 'continue_to_inspect':False, 
                'actions':_actions}
        else:
            #*** It's not a flow we're classifying so start a new entry:
            self._fcip_add_new(pkt)
        return {'valid':True, 'continue_to_inspect':_continue_to_inspect, 
                    'actions':_actions}
            
    def _calc_max_packet_size(self, table_ref):
        """
        Review packet sizes in a flow and return the largest one
        """
        _max_size = 0
        for _packet_number in self._fcip_table[table_ref]["ip_total_length"]:
            _size = self._fcip_table[table_ref]["ip_total_length"][_packet_number]
            if _size > _max_size:
                _max_size = _size
        return _max_size

    def _calc_max_window_growth(self, table_ref):
        """
        Review TCP window sizes and return the largest growth ratio out
        of forward and reverse window sizes when comparing intial and
        final TCP window sizes
        """
        #*** Note: this may not handle flows well that we haven't seen SYNs
        #*** for and thus the window is not scaled...
        _first_forward = 0
        _first_reverse = 0
        _max_forward = 0
        _max_reverse = 0
        for _packet_number in self._fcip_table[table_ref]["window_size"]:
            _size = self._fcip_table[table_ref]["window_size"][_packet_number]
            _direction = self._fcip_table[table_ref]["direction"][_packet_number]            
            if _direction == "forward":
                if not _first_forward:
                    _first_forward = _size
                if _size > _max_forward:
                    _max_forward = _size
            if _direction == "reverse":
                if not _first_reverse:
                    _first_reverse = _size
                if _size > _max_reverse:
                    _max_reverse = _size
        if _first_forward and _max_forward:
            _forward_ratio = float(_max_forward) / float(_first_forward)
        if _first_reverse and _max_reverse:
            _reverse_ratio = float(_max_reverse) / float(_first_reverse)
        if _forward_ratio > _reverse_ratio:
            return _forward_ratio
        elif _reverse_ratio > _forward_ratio:
            return _reverse_ratio
        else:
            #*** It's a draw!
            return _forward_ratio

    def _calc_max_interpacket_interval(self, table_ref):
        """
        Review packet arrival times for each direction in 
        a flow and return the size of the largest inter-
        packet interval (from either direction) in seconds
        """
        _max_interpacket = 0
        _previous_reverse = 0
        _previous_forward = 0
        for _packet_number in self._fcip_table[table_ref]["arrival_time"]:
            _arrival_time = self._fcip_table[table_ref]["arrival_time"][_packet_number]
            _direction = self._fcip_table[table_ref]["direction"][_packet_number]
            if _direction == 'forward' and _previous_forward:
                _interpacket_interval = _arrival_time - _previous_forward
                if not _max_interpacket:
                    _max_interpacket = _interpacket_interval
                elif _interpacket_interval > _max_interpacket:
                    _max_interpacket = _interpacket_interval
                else:
                    #*** nothing to see here, move on
                    pass
                _previous_forward = _arrival_time
            elif _direction == 'reverse' and _previous_reverse:
                _interpacket_interval = _arrival_time - _previous_reverse
                if not _max_interpacket:
                    _max_interpacket = _interpacket_interval
                elif _interpacket_interval > _max_interpacket:
                    _max_interpacket = _interpacket_interval
                else:
                    #*** nothing to see here, move on
                    pass
                _previous_reverse = _arrival_time
            elif _direction == 'forward':
                #*** First time we've seen a forward packet so set previous for next time
                _previous_forward = _arrival_time
            elif _direction == 'reverse':
                #*** First time we've seen a reverse packet so set previous for next time
                _previous_reverse = _arrival_time
            else:
                #*** should never hit this...
                self.logger.error("ERROR: module=tc_statistical Strange condition encountered")
        if not _max_interpacket:
            return 0
        else:
            return _max_interpacket

    def _calc_min_interpacket_interval(self, table_ref):
        """
        Review packet arrival times for each direction in 
        a flow and return the size of the smallest inter-
        packet interval (from either direction) in seconds
        """
        _min_interpacket = 0
        _previous_reverse = 0
        _previous_forward = 0
        for _packet_number in self._fcip_table[table_ref]["arrival_time"]:
            _arrival_time = self._fcip_table[table_ref]["arrival_time"][_packet_number]
            _direction = self._fcip_table[table_ref]["direction"][_packet_number]
            if _direction == 'forward' and _previous_forward:
                _interpacket_interval = _arrival_time - _previous_forward
                if not _min_interpacket:
                    _min_interpacket = _interpacket_interval
                elif _interpacket_interval < _min_interpacket:
                    _min_interpacket = _interpacket_interval
                else:
                    #*** nothing to see here, move on
                    pass
                _previous_forward = _arrival_time
            elif _direction == 'reverse' and _previous_reverse:
                _interpacket_interval = _arrival_time - _previous_reverse
                if not _min_interpacket:
                    _min_interpacket = _interpacket_interval
                elif _interpacket_interval < _min_interpacket:
                    _min_interpacket = _interpacket_interval
                else:
                    #*** nothing to see here, move on
                    pass
                _previous_reverse = _arrival_time
            elif _direction == 'forward':
                #*** First time we've seen a forward packet so set previous for next time
                _previous_forward = _arrival_time
            elif _direction == 'reverse':
                #*** First time we've seen a reverse packet so set previous for next time
                _previous_reverse = _arrival_time
            else:
                #*** should never hit this...
                self.logger.error("ERROR: module=tc_statistical Strange condition encountered")
        if not _min_interpacket:
            return 0
        else:
            return _min_interpacket
            
    def _calc_last_interpacket_interval(self, table_ref):
        """
        Interval from last packet arrival times for same  
        direction in flow in seconds
        """
        _previous_reverse = 0
        _previous_forward = 0
        _interpacket_interval = 0
        for _packet_number in self._fcip_table[table_ref]["arrival_time"]:
            _arrival_time = self._fcip_table[table_ref]["arrival_time"][_packet_number]
            _direction = self._fcip_table[table_ref]["direction"][_packet_number]
            if _direction == 'forward' and _previous_forward:
                _interpacket_interval = _arrival_time - _previous_forward
                _previous_forward = _arrival_time
            elif _direction == 'reverse' and _previous_reverse:
                _interpacket_interval = _arrival_time - _previous_reverse
                _previous_reverse = _arrival_time
            elif _direction == 'forward':
                #*** First time we've seen a forward packet so set previous for next time
                _previous_forward = _arrival_time
            elif _direction == 'reverse':
                #*** First time we've seen a reverse packet so set previous for next time
                _previous_reverse = _arrival_time
            else:
                #*** should never hit this...
                self.logger.error("ERROR: module=tc_statistical Strange condition encountered")
        return _interpacket_interval
            
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

    def _fcip_check(self, pkt):
        """
        Checks if a packet is part of a flow in the
        Flow Classification In Progress (FCIP) table.
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
                    #*** Matched IP and TCP parameters so return
                    #*** the table reference:
                    self.logger.debug("DEBUG: module=tc_statistical Matched a flow "
                                      "we're already classifying...")
                    return _table_ref
                
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
            
    def _fcip_add_new(self, pkt):
        """
        Passed a packet that is a new flow and add to the
        Flow Classification In Progress (FCIP) table.
        """        
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp) 
        #*** Direction for first packet is always forward:
        self._fcip_table[self._fcip_ref]["direction"][1] = "forward"
        #*** Initial setting of variable that stops more packets being added:
        self._fcip_table[self._fcip_ref]["finalised"] = 0
        #*** Allow actions to be stored for reference on finalised flows:
        self._fcip_table[self._fcip_ref]["actions"] = 0
        #*** Add the standard layer-3 and 4 values:
        self._fcip_table[self._fcip_ref]["ip_A"] = _pkt_ip4.src
        self._fcip_table[self._fcip_ref]["ip_B"] = _pkt_ip4.dst
        self._fcip_table[self._fcip_ref]["tcp_A"] = _pkt_tcp.src_port
        self._fcip_table[self._fcip_ref]["tcp_B"] = _pkt_tcp.dst_port        
        #*** This could do with improvement - would be subject to variability
        #*** due to time taken for packet to reach the controller and processing
        #*** time on the controller. But, it'll do for the moment:
        self._fcip_table[self._fcip_ref]["arrival_time"][1] = time.time()
        #*** Add packet size:
        self._fcip_table[self._fcip_ref]["ip_total_length"][1] = _pkt_ip4.total_length
        #*** Add TCP parameters like window size, ack number and bits (aka TCP flags):
        if self._tcp_syn_flag(_pkt_tcp.bits):
            #*** Packet has TCP SYN flag set:
            self._fcip_table[self._fcip_ref]["TCP_SYN"][1] = "SYN"
            #*** To calculate TCP Window size we need to know the TCP window scale shift
            #*** count as per RFC1323. Parse this from the TCP SYN:
            _tcp_window_shift =  self._tcp_window_scale(_pkt_tcp.option)
            self._fcip_table[self._fcip_ref]["window_scale"]["forward"] = _tcp_window_shift
        self._fcip_table[self._fcip_ref]["window_size"][1] = _pkt_tcp.window_size
        self._fcip_table[self._fcip_ref]["ack"][1] = _pkt_tcp.ack
        self._fcip_table[self._fcip_ref]["bits"][1] = _pkt_tcp.bits
        #*** Number of packets is 1 as this is the first packet in the flow:
        self._fcip_table[self._fcip_ref]["number_of_packets"] = 1
        if self.extra_debugging:
            self.logger.debug("DEBUG: module=tc_statistical added new: %s", self._fcip_table[self._fcip_ref])
        #*** increment table ref ready for next time we use it:
        self._fcip_ref += 1

    def _fcip_add_to_existing(self, pkt, table_ref):
        """
        Passed a packet that is in a flow that we are
        already classifying and a reference to the
        Flow Classification In Progress (FCIP) table.
        Return the packet number of this packet in
        the flow.
        """        
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp)
        _ip_A = _pkt_ip4.src
        _ip_B = _pkt_ip4.dst
        if self._fcip_check_duplicate(pkt, table_ref):
            #*** It's a packet we've already seen - either a retransmission
            #*** or the same packet from another switch along the data path
            #*** so we'll ignore it:
            if self.extra_debugging:
                self.logger.debug("DEBUG: module=tc_statistical Ignoring duplicate packet")
            return 0
        #*** Work out what packet number we are in the flow:
        _packet_number = self._fcip_table[table_ref]["number_of_packets"]
        _packet_number += 1
        self.logger.debug("DEBUG: module=tc_statistical _packet_number is %s", _packet_number)        
        #*** Update number of packets:
        self._fcip_table[table_ref]["number_of_packets"] = _packet_number
        #*** Work out directionality and add to the table:
        _direction = self._fcip_check_ip(table_ref, _ip_A, _ip_B)
        self._fcip_table[table_ref]["direction"][_packet_number] = _direction
        #*** This could do with improvement - would be subject to variability
        #*** due to time taken for packet to reach the controller and processing
        #*** time on the controller. But, it'll do for the moment:
        self._fcip_table[table_ref]["arrival_time"][_packet_number] = time.time()
        #*** Add packet size:
        self._fcip_table[table_ref]["ip_total_length"][_packet_number] = _pkt_ip4.total_length
        #*** Add TCP parameters like window size, ack number and bits (aka TCP flags):
        _tcp_window_size = _pkt_tcp.window_size
        if self._tcp_syn_flag(_pkt_tcp.bits):
            #*** Packet has TCP SYN flag set:
            self._fcip_table[table_ref]["TCP_SYN"][_packet_number] = "SYN"
            if _direction == "reverse":
                #*** Get the reverse direction TCP window scale:
                _tcp_window_shift =  self._tcp_window_scale(_pkt_tcp.option)
                self._fcip_table[table_ref]["window_scale"]["reverse"] = _tcp_window_shift
        else:
            #*** Apply TCP Window scaling if set:
            if (_direction == "forward" and self._fcip_table[table_ref]["window_scale"]["forward"]):
                _tcp_window_size = _tcp_window_size << self._fcip_table[table_ref]["window_scale"]["forward"]
            if (_direction == "reverse" and self._fcip_table[table_ref]["window_scale"]["reverse"]):
                _tcp_window_size = _tcp_window_size << self._fcip_table[table_ref]["window_scale"]["reverse"]
        self._fcip_table[table_ref]["window_size"][_packet_number] = _tcp_window_size
        self._fcip_table[table_ref]["ack"][_packet_number] = _pkt_tcp.ack
        self._fcip_table[table_ref]["bits"][_packet_number] = _pkt_tcp.bits
        if self.extra_debugging:
            self.logger.debug("DEBUG: module=tc_statistical updated with packet %s: %s", 
                              _packet_number, self._fcip_table[table_ref])
            #*** Extra data for easy recording of statistical results for analysis charts:
            _max_packet_size = self._calc_max_packet_size(table_ref)
            self._fcip_table[table_ref]["max_packet_size"][_packet_number] = _max_packet_size
            _max_window_growth_ratio = self._calc_max_window_growth(table_ref)
            self._fcip_table[table_ref]["max_window_growth_ratio"][_packet_number] = _max_window_growth_ratio
            _min_interpacket_interval = self._calc_min_interpacket_interval(table_ref)
            self._fcip_table[table_ref]["min_interpacket"][_packet_number] = _min_interpacket_interval
            _calc_last_interpacket_interval = self._calc_last_interpacket_interval(table_ref)
            self._fcip_table[table_ref]["last_interpacket"][_packet_number] = _calc_last_interpacket_interval
        return _packet_number
        
    def _fcip_check_duplicate(self, pkt, table_ref):
        """
        Passed a packet that is in a flow that we are
        already classifying and a reference to the FCIP
        table row.
        Check to see if this packet is a duplicate of
        any of the packets already included in this table
        row and if it is a duplicate return True otherwise
        False
        """        
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp)
        #*** iterate through table row checking for duplicate values
        for _packet_number in xrange(1, (self._fcip_table[table_ref]["number_of_packets"]+1)):
            if (self._fcip_table[table_ref]["window_size"][_packet_number] == _pkt_tcp.window_size
            and self._fcip_table[table_ref]["ack"][_packet_number] == _pkt_tcp.ack
            and self._fcip_table[table_ref]["bits"][_packet_number] == _pkt_tcp.bits):
                if self.extra_debugging:
                    self.logger.debug("DEBUG: module=tc_statistical DUPLICATE PACKET")
                return True
        return False
        
    def _tcp_syn_flag(self, bits):
        """
        Passed the bits field (more commonly known as TCP Flags)
        and return True if the SYN flag is set otherwise False
        """
        _tcp_syn_mask = 2
        if(bits & _tcp_syn_mask):
            return True
        else:
            return False
        
    def _tcp_window_scale(self, option):
        """
        Passed a TCP options field
        and parse through it looking for a TCP
        window scale shift count. Return this if we
        find it otherwise 0
        """
        if self.extra_debugging:
            self.logger.debug("DEBUG: module=tc_statistical SCALE: TCP Option is %s", option)
        byte_key = bytearray(option)
        _position = 0
        _max_position = len(byte_key)
        while _position <= _max_position:
            _type = byte_key[_position]
            if _type == 0:
                #*** 1 Byte End of Options so just increment position:
                _position += 1
            elif _type == 1:
                #*** 1 Byte No-Operation (NOP) so just increment position:
                _position += 1
            elif _type == 3:
                #*** Have matched the Window scale that we want, now get the value:
                _position += 2
                if self.extra_debugging:
                    self.logger.debug("DEBUG: module=tc_statistical SCALE: matched scale %s", byte_key[_position])
                return byte_key[_position]
            else:
                #*** Matched another TLV type so get the len and then increment position
                #*** to get start of next TLV:
                _position += 1
                _len = byte_key[_position]
                _position += _len - 1
        return 0
    
