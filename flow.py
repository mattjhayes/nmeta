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

#*** nmeta - Network Metadata - Flow Metadata Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import logging
import logging.handlers
import struct
import time
import json

#*** Ryu imports:
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import tcp
from ryu.lib.mac import haddr_to_bin
from ryu.lib import addrconv
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3

#*** nmeta imports:
import qos
import nmisc
import controller_abstraction

class FlowMetadata(object):
    """
    This class is instantiated by nmeta.py and provides methods to 
    add/remove/update/search flow metadata table entries
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('flow_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('flow_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _console_format = _config.get_value('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(address=(
                                                _loghost, _logport), 
                                                facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            self.console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(_console_format)
            self.console_handler.setFormatter(console_formatter)
            self.console_handler.setLevel(_logging_level_c)
            #*** Add console log handler to logger:
            self.logger.addHandler(self.console_handler)

        #*** Instantiate the Flow Metadata (FM) Table:
        self._fm_table = nmisc.AutoVivification()
        #*** Instantiate the Controller Abstraction class for calls to 
        #*** OpenFlow Switches:
        self.ca = controller_abstraction.ControllerAbstract(_config)
        #*** initialise Flow Metadata Table unique reference number:
        self._fm_ref = 1
        #*** Instantiate QoS class:
        self.qos = qos.QoS(_config)
        #*** Do you want really verbose debugging?
        self.extra_debugging = 1
        
    def update_flowmetadata(self, msg, flow_actions):
        """
        Passed a message and actions assigned by
        Traffic Classification and Forwarding modules.
        Do the following:
        1) Update Flow Metadata Table
        2) Check QoS to see if special queueing should be applied. 
           If so update the actions
        3) Return updated actions
        """
        pkt = packet.Packet(msg.data)
        #*** check if packet is part of a flow already in the FM table:
        _table_ref = self._fm_check(pkt)
        if _table_ref:
            #*** In table so update existing record:
            self._fm_add_to_existing(pkt, _table_ref, flow_actions)
        else:
            #*** Not in table, so lets add it:
            self._fm_add_new(pkt, flow_actions)
        #*** Call QoS check_policy to see if special queueing
        #***  should be applied:
        out_queue = self.qos.check_policy(flow_actions['actions'])
        self.logger.debug("out_queue=%s", out_queue)
        flow_actions['queue'] = out_queue
        #*** Return the updated flow actions:
        return flow_actions

    def update_flowmetadata_old(self, msg, out_port, flow_actions):
        """
        Passed a message, output port(s) and actions assigned by
        Traffic Classification and Forwarding, and do the following:
        1) Update Flow Metadata Table
        2) Check if flow should be installed to switch
        3) Check QoS to see if special queueing should be applied 
        4) Return a Flow Match (if required) and Actions to install to switch
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        in_port = self.ca.get_in_port(msg, datapath, ofproto)
        dpid = datapath.id
        
        #*** check if packet is part of a flow already in the FM table:
        _table_ref = self._fm_check(pkt)
        if self.extra_debugging:
            self.logger.debug("table_ref_match=%s", 
                              _table_ref)
        if _table_ref:
            self._fm_add_to_existing(pkt, _table_ref, flow_actions)
        else:
            #*** Not in table so lets add it:
            self._fm_add_new(pkt, flow_actions)
            
        #*** Check if a flow should be installed to the switch:
        if not flow_actions["continue_to_inspect"]:       
            #*** Call QoS check_policy to see if special queueing
            #*** should be applied:
            out_queue = self.qos.check_policy(flow_actions["actions"])
            #*** Debug:
            if out_queue:
                 self.logger.debug("out_queue=%s", out_queue)
            #*** Build a fine-grained flow match to install onto switch
            eth = pkt.get_protocol(ethernet.ethernet)
            pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
            pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            #*** Use Controller Abstraction module to build match statements:
            if (pkt_tcp and pkt_ip4 and 
                     ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION,
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst), nw_proto=6,
                        tp_src=pkt_tcp.src_port, tp_dst=pkt_tcp.dst_port)
                self.logger.debug("OF1.0 IPv4 TCP match "
                                  "is %s", match)
            elif (pkt_tcp and pkt_ip6 and 
                       ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800, nw_src=self._ipv6_t2i(pkt_ip6.src),
                        nw_dst=self._ipv6_t2i(pkt_ip6.dst), nw_proto=6,
                        tp_src=pkt_tcp.src_port, tp_dst=pkt_tcp.dst_port)
                self.logger.debug("OF1.0 IPv6 TCP match "
                                  "is %s", match)
            elif (pkt_tcp and pkt_ip4 and 
                       ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
                #*** Note OF1.3 needs eth src and dest in ascii not bin
                #*** and tcp vs udp protocol specific attributes: 
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst), nw_proto=6,
                        tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
                self.logger.debug("OF1.3 IPv4 TCP match "
                                  "is %s", match)
            elif (pkt_tcp and pkt_ip6 and 
                       ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
                #*** Note OF1.3 needs eth src and dest in ascii not bin
                #*** and tcp vs udp protocol specific attributes: 
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv6_t2i(pkt_ip6.src),
                        nw_dst=self._ipv6_t2i(pkt_ip6.dst), nw_proto=6,
                        tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
                self.logger.debug("OF1.3 IPv6 TCP match "
                                  "is %s", match)
            elif (pkt_ip4 and ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst),
                        nw_proto=pkt_ip4.proto)
                self.logger.debug("IPv4 match "
                                  "is %s", match)
            elif (pkt_ip4 and ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst),
                        ip_proto=pkt_ip4.proto)
                self.logger.debug("IPv4 match "
                                  "is %s", match)
            elif (eth.ethertype != 0x0800 and 
                   ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst))
                self.logger.debug("Non-IP match"
                                  " is %s", match)
            elif (eth.ethertype != 0x0800 and 
                   ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
                match = self.ca.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst)
                self.logger.debug("Non-IP match"
                                  " is %s", match)
            else:
                #*** possibly strange weirdness happened so log this event as
                #*** a warning and don't install flow match:
                self.logger.warning("Packet observed "
                                    "that is not IPv4 but has dl_type=0x0800")
                match = 0
            if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                #*** Only do Enqueue action if not flooding:
                if out_port != ofproto.OFPP_FLOOD:
                    actions = [datapath.ofproto_parser.OFPActionEnqueue \
                                     (out_port, out_queue)]
                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput \
                                     (out_port)]
            elif ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
                #*** Note: out_port must come last!
                actions = [
                    datapath.ofproto_parser.OFPActionSetQueue(out_queue),
                    datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
            else:
                self.logger.error("error=E1000006 Unhandled"
                    " OF version %s means no action will be installed", 
                    ofproto.OFP_VERSION)
                actions = 0
            return (match, actions, out_queue)
        else:
            self.logger.debug("Not installing flow to "
                              "switch as continue_to_inspect is True")
            match = 0
            actions = 0
            return (match, actions, out_queue)

    def maintain_fm_table(self, max_age):
        """
        Deletes old entries from FM table.
        This function is passed a maximum age
        and deletes any entries in the FM
        table that have a time_last that is
        older than that when compared to
        current time
        """
        _time = time.time()
        _for_deletion = []
        for _table_ref in self._fm_table:
            if self._fm_table[_table_ref]["time_last"]:
                _last = self._fm_table[_table_ref]["time_last"]
                if (_time - _last > max_age):
                    self.logger.debug("event=delete_FM_table_row"
                                        "id=%s", _table_ref)
                    #*** Can't delete while iterating dictionary so just note
                    #***  the table ref:
                    _for_deletion.append(_table_ref)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            del self._fm_table[_del_ref]

    def get_fm_table(self):
        """
        Return the flow metadata table
        """
        return self._fm_table

    def get_fm_table_size_rows(self):
        """
        Return the number of rows (items) in the flow metadata table
        """
        return len(self._fm_table)

    def _fm_check(self, pkt):
        """
        Checks if a packet is part of a flow in the
        Flow Metadata (FM) table.
        Returns False if not in table.
        Returns a table reference if it is in the table
        """
        _pkt_eth = pkt.get_protocol(ethernet.ethernet)
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp)
        #*** Iterate through the Flow Metadata (FM) table:
        for _table_ref in self._fm_table:
            if _pkt_ip4:
                _ip_match = self._fm_check_ip(_table_ref, pkt)
                if _ip_match:
                    #*** Matched IP address pair in either direction
                    #*** Now check for TCP port match (with consideration 
                    #*** to directionality):
                    if _pkt_tcp:
                        _tcp_match = self._fm_check_tcp(_table_ref, 
                                                         _ip_match, pkt)
                        if _tcp_match:
                            #*** Matched IP and TCP parameters so return
                            #*** the table reference:
                            self.logger.debug("Matched a flow "
                                              "we're already classifying...")
                            return _table_ref
                    else:
                        #*** It's IP but not TCP:
                        #*** return the table ref, but needs work in future....
                        return _table_ref
            elif _pkt_eth:
                #*** Non-IP packet, check if it matches on src and dest MAC 
                #*** and ethertype
                _eth_match = self._fm_check_eth(_table_ref, pkt)
                if _eth_match:
                    return _table_ref
            else:
                #*** We shouldn't ever hit this condition. Just log that
                #*** some weirdness went on
                self.logger.warning("observed non-ethernet packet")  
                return False
        #*** No match iterating through FM table so return false:
        return False
                
    def _fm_check_eth(self, table_ref, pkt):
        """
        Checks if packet source/destination MAC addresses match against
        a given table entry in either order as well as the ethertype
        Returns 'forward' for a direct match, 'reverse' for a 
        transposed match and False (0) for no match
        """
        _pkt_eth = pkt.get_protocol(ethernet.ethernet) 
        _eth_A = _pkt_eth.src
        _eth_B = _pkt_eth.dst
        _ethertype = _pkt_eth.ethertype        
        if (_eth_A == self._fm_table[table_ref]["eth_A"]
            and _eth_B == self._fm_table[table_ref]["eth_B"]
            and _ethertype == self._fm_table[table_ref]["ethertype"]):
                return('forward')
        elif (_eth_B == self._fm_table[table_ref]["eth_A"]
            and _eth_A == self._fm_table[table_ref]["eth_B"]
            and _ethertype == self._fm_table[table_ref]["ethertype"]):
                return('reverse')
        else:
            return False

    def _fm_check_ip(self, table_ref, pkt):
        """
        Checks if a source/destination IP addresses match against
        a given table entry in either order.
        Returns 'forward' for a direct match, 'reverse' for a 
        transposed match and False (0) for no match
        """
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _ip_A = _pkt_ip4.src
        _ip_B = _pkt_ip4.dst
        if (_ip_A == self._fm_table[table_ref]["ip_A"]
            and _ip_B == self._fm_table[table_ref]["ip_B"]):
                return('forward')
        elif (_ip_A == self._fm_table[table_ref]["ip_B"]
            and _ip_B == self._fm_table[table_ref]["ip_A"]):
                return('reverse')
        else:
            return False

    def _fm_check_tcp(self, table_ref, ip_match, pkt):
        """
        Checks if source/destination tcp ports match against
        a given table entry same order that IP addresses matched 
        in.
        .
        Returns True (1) for a match and False (0) for no match
        """ 
        _pkt_tcp = pkt.get_protocol(tcp.tcp)
        _tcp_A = _pkt_tcp.src_port
        _tcp_B = _pkt_tcp.dst_port
        if (ip_match == 'forward' and
                    _tcp_A == self._fm_table[table_ref]["tcp_A"]
                    and _tcp_B == self._fm_table[table_ref]["tcp_B"]):
            return True
        elif (ip_match == 'reverse' and
                    _tcp_A == self._fm_table[table_ref]["tcp_B"]
                    and _tcp_B == self._fm_table[table_ref]["tcp_A"]):
            return True
        else:
            return False
            
    def _fm_add_new(self, pkt, flow_actions):
        """
        Passed a packet that is a new flow 
        along with flow actions and add to the
        Flow Metadata (FM) table.
        """
        self.logger.debug("Adding new record to flow metadata table")
        _pkt_eth = pkt.get_protocol(ethernet.ethernet)
        _pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        _pkt_tcp = pkt.get_protocol(tcp.tcp)
        #*** Add timestamp:
        self._fm_table[self._fm_ref]["time_first"] = time.time()
        self._fm_table[self._fm_ref]["time_last"] = time.time()
        if _pkt_ip4:
            #*** Add IP info:
            self._fm_table[self._fm_ref]["ip_A"] = _pkt_ip4.src
            self._fm_table[self._fm_ref]["ip_B"] = _pkt_ip4.dst
            self._fm_table[self._fm_ref]["ip_proto"] = _pkt_ip4.proto
            if _pkt_tcp:
                #*** Add TCP info:
                self._fm_table[self._fm_ref]["tcp_A"] = _pkt_tcp.src_port
                self._fm_table[self._fm_ref]["tcp_B"] = _pkt_tcp.dst_port
            #*** Need to add other attribute/values here for different 
            #***  protocol types: <TBD>
        elif _pkt_eth:
            #*** Add layer-2 as non-IP traffic so local to a subnet 
            #*** and therefore it is significant:
            self._fm_table[self._fm_ref]["eth_A"] = _pkt_eth.src
            self._fm_table[self._fm_ref]["eth_B"] = _pkt_eth.dst
            self._fm_table[self._fm_ref]["ethertype"] = _pkt_eth.ethertype
        else:
            #*** We shouldn't ever hit this condition. Just log that
            #*** some weirdness went on
            self.logger.warning("observed non ethernet packet")
        #*** Need to add in what (if any) classification has been made:
        if flow_actions:
            self._fm_table[self._fm_ref]["flow_actions"] = flow_actions 
        #*** Number of packets seen by controller is 1 as this is the first 
        #***  packet in the flow:
        self._fm_table[self._fm_ref]["number_of_packets_to_controller"] = 1
        if self.extra_debugging:
            self.logger.debug("added new: %s", self._fm_table[self._fm_ref])
        #*** increment table ref ready for next time we use it:
        self._fm_ref += 1

    def _fm_add_to_existing(self, pkt, table_ref, flow_actions):
        """
        Passed a packet that is in a flow that we are
        already classifying and a reference to the
        Flow Metadata (FM) table.
        """
        self.logger.debug("Updating existing record in flow metadata table")
        #*** Update last seen timestamp:
        self._fm_table[table_ref]["time_last"] = time.time()
        #*** Update the count of Packet-In events for this flow:
        _packet_in_count = \
                   self._fm_table[table_ref]['number_of_packets_to_controller']
        if _packet_in_count:
            self._fm_table[table_ref]["number_of_packets_to_controller"] = _packet_in_count + 1
        else:
            self._fm_table[table_ref]["number_of_packets_to_controller"] = 1
        #*** Want to add any extra parameters to the flow record here:
        #*** <TBD>

    def _ipv4_t2i(self, ip_text):
        """
        Turns an IPv4 address in text format into an integer.
        Borrowed from rest_router.py code
        """
        if ip_text == 0:
            return ip_text
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]      

    def _ipv6_t2i(self, ip_text):
        """
        Turns an IPv6 address in text format into an integer.
        """
        if ip_text == 0:
            return ip_text
        assert isinstance(ip_text, str)
        return struct.unpack('!I', addrconv.ipv6.text_to_bin(ip_text))[0]  
