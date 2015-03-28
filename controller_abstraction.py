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

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata.
It provides functions that abstract the details of OpenFlow calls, including
differences between OpenFlow versions where practical
"""

import logging
import logging.handlers
import sys
import struct

#*** Ryu Imports:
from ryu.lib.mac import haddr_to_bin
from ryu.lib import addrconv
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import tcp

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
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('ca_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('ca_logging_level_c')
        _syslog_enabled = _config.get_value ('syslog_enabled')
        _loghost = _config.get_value ('loghost')
        _logport = _config.get_value ('logport')
        _logfacility = _config.get_value ('logfacility')
        _syslog_format = _config.get_value ('syslog_format')
        _console_log_enabled = _config.get_value ('console_log_enabled')
        _console_format = _config.get_value ('console_format')
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

    def add_flow_tcp(self, datapath, msg, flow_actions, **kwargs):
        """
        Add a TCP flow table entry to a switch.
        Returns 1 for success or 0 for any type of error
        Required kwargs are:
            priority (0)
            buffer_id (None)
            idle_timeout (5)
            hard_timeout (0)
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        in_port=flow_actions['in_port']
        idle_timeout=kwargs['idle_timeout']
        hard_timeout=kwargs['hard_timeout']
        buffer_id=kwargs['buffer_id']
        priority=kwargs['priority']
        #*** Build a match that is dependant on the IP and OpenFlow versions:
        if (pkt_tcp and pkt_ip4 and 
                     ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
            #*** Build a full match to get maximum performance from
            #*** software switches by allowing them to install into
            #*** a hash instead of linear table
            #*** TBD: need to dynamically set values for dl_vlan,
            #***  dl_vlan_pcp, nw_tos and dl_type
            #print "packet is %s" % pkt
            #print "packet eth is %s" % eth
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION,
                        in_port=in_port,
                        dl_vlan=0xffff,
                        dl_vlan_pcp=0x00,
                        nw_tos=0x00,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800,
                        nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst), 
                        nw_proto=6,
                        tp_src=pkt_tcp.src_port, 
                        tp_dst=pkt_tcp.dst_port)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv4-TCP "
                                  "match=%s", ofproto.OFP_VERSION, match)
        elif (pkt_tcp and pkt_ip6 and 
                       ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800, nw_src=self._ipv6_t2i(pkt_ip6.src),
                        nw_dst=self._ipv6_t2i(pkt_ip6.dst), nw_proto=6,
                        tp_src=pkt_tcp.src_port, tp_dst=pkt_tcp.dst_port)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv6-TCP "
                                 "match=%s", ofproto.OFP_VERSION, match)
        elif (pkt_tcp and pkt_ip4 and 
                       ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
            #*** Note OF1.3 needs eth src and dest in ascii not bin
            #*** and tcp vs udp protocol specific attributes: 
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst), nw_proto=6,
                        tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv4-TCP "
                                 "match=%s", ofproto.OFP_VERSION, match)
        elif (pkt_tcp and pkt_ip6 and 
                       ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
            #*** Note OF1.3 needs eth src and dest in ascii not bin
            #*** and tcp vs udp protocol specific attributes: 
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv6_t2i(pkt_ip6.src),
                        nw_dst=self._ipv6_t2i(pkt_ip6.dst), nw_proto=6,
                        tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv6-TCP "
                                   "match=%s", ofproto.OFP_VERSION, match)
        else:
            #*** Possibly an unsupported OF version. Log and return 0:
            self.logger.error("event=add_flow error=E1000027 Did not compute. "
                                "ofv=%s pkt=%s", ofproto.OFP_VERSION, pkt)
            return 0
        #*** Get the actions to install for the match:
        actions = self.get_actions(datapath, ofproto.OFP_VERSION,
                        flow_actions['out_port'], flow_actions['out_queue'])
        self.logger.debug("actions=%s", actions)
        #*** Now have a match and actions so call add_flow to instantiate it:
        _result = self.add_flow(datapath, match, actions,
                                 priority=priority, buffer_id=buffer_id,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
        self.logger.debug("result is %s", _result)
        return _result

    def add_flow_ip(self, datapath, msg, flow_actions, **kwargs):
        """
        Add an IP (v4 or v6) flow table entry to a switch.
        Returns 1 for success or 0 for any type of error
        Required kwargs are:
            priority (0)
            buffer_id (None)
            idle_timeout (5)
            hard_timeout (0)
        Uses IP protocol number to prevent matching on TCP flows
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
        in_port=flow_actions['in_port']
        idle_timeout=kwargs['idle_timeout']
        hard_timeout=kwargs['hard_timeout']
        buffer_id=kwargs['buffer_id']
        priority=kwargs['priority']
        #*** Build a match that is dependant on the IP and OpenFlow versions:
        if (pkt_ip4 and ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst),
                        nw_proto=pkt_ip4.proto)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv4 match=%s",
                                  ofproto.OFP_VERSION, match)
        elif (pkt_ip6 and ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst), 
                        dl_type=0x0800, nw_src=self._ipv6_t2i(pkt_ip6.src),
                        nw_dst=self._ipv6_t2i(pkt_ip6.dst),
                        nw_proto=pkt_ip4.proto)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv6 match=%s",
                                  ofproto.OFP_VERSION, match)
        elif (pkt_ip4 and ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv4_t2i(pkt_ip4.src),
                        nw_dst=self._ipv4_t2i(pkt_ip4.dst),
                        ip_proto=pkt_ip4.proto)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv4 match=%s",
                                  ofproto.OFP_VERSION, match)
        elif (pkt_ip6 and ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst, 
                        dl_type=0x0800, nw_src=self._ipv6_t2i(pkt_ip6.src),
                        nw_dst=self._ipv6_t2i(pkt_ip6.dst),
                        ip_proto=pkt_ip4.proto)
            self.logger.debug("event=add_flow ofv=%s match_type=IPv6 match=%s",
                                  ofproto.OFP_VERSION, match)
        else:
            #*** Possibly an unsupported OF version. Log and return 0:
            self.logger.error("event=add_flow error=E1000028 Did not compute. "
                                "ofv=%s pkt=%s", ofproto.OFP_VERSION, pkt)
            return 0
        #*** Get the actions to install for the match:
        actions = self.get_actions(datapath, ofproto.OFP_VERSION,
                        flow_actions['out_port'], flow_actions['out_queue'])
        self.logger.debug("actions=%s", actions)
        #*** Now have a match and actions so call add_flow to instantiate it:
        _result = self.add_flow(datapath, match, actions,
                                 priority=priority, buffer_id=buffer_id,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
        self.logger.debug("result is %s", _result)
        return _result

    def add_flow_eth(self, datapath, msg, flow_actions, **kwargs):
        """
        Add an ethernet (non-IP) flow table entry to a switch.
        Returns 1 for success or 0 for any type of error
        Required kwargs are:
            priority (0)
            buffer_id (None)
            idle_timeout (5)
            hard_timeout (0)
        Uses Ethertype in match to prevent matching against IPv4 
        or IPv6 flows
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        in_port=flow_actions['in_port']
        idle_timeout=kwargs['idle_timeout']
        hard_timeout=kwargs['hard_timeout']
        buffer_id=kwargs['buffer_id']
        priority=kwargs['priority']
        #*** Build a match that is dependant on the IP and OpenFlow versions:
        if (eth.ethertype != 0x0800 and 
                   ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=haddr_to_bin(eth.src),
                        dl_dst=haddr_to_bin(eth.dst),
                        dl_type=eth.ethertype)
            self.logger.debug("event=add_flow ofv=%s match_type=Non-IP "
                                  "match=%s", ofproto.OFP_VERSION, match)
        elif (eth.ethertype != 0x0800 and 
                   ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION):
            match = self.get_flow_match(datapath, ofproto.OFP_VERSION, 
                        in_port=in_port,
                        dl_src=eth.src,
                        dl_dst=eth.dst,
                        dl_type=eth.ethertype)
            self.logger.debug("event=add_flow ofv=%s match_type=Non-IP "
                                  "match=%s", ofproto.OFP_VERSION, match)
        else:
            #*** Possibly an unsupported OF version. Log and return 0:
            self.logger.error("event=add_flow error=E1000028 Did not compute. "
                                "ofv=%s pkt=%s", ofproto.OFP_VERSION, pkt)
            return 0
        #*** Get the actions to install for the match:
        actions = self.get_actions(datapath, ofproto.OFP_VERSION,
                        flow_actions['out_port'], flow_actions['out_queue'])
        self.logger.debug("actions=%s", actions)
        #*** Now have a match and actions so call add_flow to instantiate it:
        _result = self.add_flow(datapath, match, actions,
                                 priority=priority, buffer_id=buffer_id,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
        self.logger.debug("result is %s", _result)
        return _result

    def add_flow(self, datapath, match, actions, **kwargs):
        """
        Add a flow table entry to a switch.
        Returns 1 for success or 0 for any type of error

        Required kwargs are:
            priority (0)
            buffer_id (None)
            idle_timeout (5)
            hard_timeout (0)
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
                self.logger.error("parser.OFPInstructionActions v1.3 "
                            "Exception %s, %s, %s",
                             exc_type, exc_value, exc_traceback)
                return 0
            if kwargs['buffer_id']:
                try:
                    mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=kwargs['idle_timeout'],
                                    hard_timeout=kwargs['hard_timeout'],
                                    buffer_id=kwargs['buffer_id'],
                                    priority=kwargs['priority'],
                                    match=match,
                                    instructions=inst)
                except:
                    #*** Log the error and return 0:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error("parser.OFPFlowMod v1.3 #1 Exception "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                    return 0
            else:
                try:
                    mod = parser.OFPFlowMod(datapath=datapath,
                                    idle_timeout=kwargs['idle_timeout'],
                                    hard_timeout=kwargs['hard_timeout'],
                                    priority=kwargs['priority'],
                                    match=match, instructions=inst)
                except:
                    #*** Log the error and return 0:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    self.logger.error("parser.OFPFlowMod v1.3 #2 Exception "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                    return 0
            try:
                #*** Send flow to switch:
                datapath.send_msg(mod)
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("datapath.send_msg v1.3 Exception "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                return 0
            return 1
        elif ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            try:
                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath,
                    idle_timeout=kwargs['idle_timeout'],
                    hard_timeout=kwargs['hard_timeout'],
                    priority=kwargs['priority'],
                    match=match, cookie=0,
                    command=ofproto.OFPFC_ADD,
                    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("datapath.ofproto_parser.OFPFlowMod "
                     "v1.0 Exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
                return 0
            try:
                datapath.send_msg(mod)
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("datapath.send_msg v1.0 Exception "
                            "%s, %s, %s",
                            exc_type, exc_value, exc_traceback)
                return 0
            return 1

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
                        self.logger.debug("match_attr=%s will be replaced "
                                 "with %s", key, new_key)
                    results[new_key] = value
                else:
                    #*** No valid attribute for this OF version so log the
                    #*** error and return 0:
                    self.logger.error("event=match_failed No OF %s match for "
                                    "attr=%s in OF_MATCH_COMPAT=%s",
                                      ofproto, key, OF_MATCH_COMPAT[key])
                    return 0
            else:
                #*** Key doesn't exist so log the error and return 0:
                self.logger.error("event=match_failed attr=%s", 
                                       OF_MATCH_COMPAT[key])
                return 0
        #*** We now have a compatible kwargs dict build a match:
        try:
            match = datapath.ofproto_parser.OFPMatch(**results)
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("event=ofproto_parser.OFPMatch_error %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        return match

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
            self.logger.error("Unsupported_OpenFlow_Version=%s", 
                                      datapath.ofproto.OFP_VERSION)
            return 0

    def get_actions(self, datapath, ofv, out_port, out_queue):
        """
        Passed a datapath, an OpenFlow version an out port,
        an out queue and flood port # and build and return an
        appropriate set of actions for this
        """
        ofproto = datapath.ofproto
        if ofv == ofproto_v1_0.OFP_VERSION:
            #*** Only do Enqueue action if not flooding:
            if out_port != ofproto.OFPP_FLOOD:
                actions = [datapath.ofproto_parser.OFPActionEnqueue \
                                     (out_port, out_queue)]
            else:
                actions = [datapath.ofproto_parser.OFPActionOutput \
                                     (out_port)]
        elif ofv == ofproto_v1_3.OFP_VERSION:
            #*** Note: out_port must come last!
            actions = [
                    datapath.ofproto_parser.OFPActionSetQueue(out_queue),
                    datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        else:
            self.logger.error("error=E1000006 Unhandled"
                    " OF version ofv=%s means no action will be installed", 
                    ofv)
            actions = 0
        return actions

    def packet_out(self, datapath, msg, in_port, out_port, out_queue):
        """
        Sends a supplied packet out switch port(s) in specific queue 
        """
        ofproto = datapath.ofproto
        #*** First build OF version specific list of actions:
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            try:
                #*** Note that QoS seems broken for packet out on OF1.0 with
                #*** OVS (or more probably the writer of this code failed to
                #*** properly understand the standard). The OFPActionEnqueue
                #*** action does not result in the packet being sent, i.e.:
                #actions = [datapath.ofproto_parser.OFPActionEnqueue(out_port, 
                #            out_queue)]
                #*** This works, but doesn't specify a queue:
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port, )]
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("error=E1000001 "
                   "actions v01 Exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
                return 0 
        elif ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            try:
                #*** Note: out_port must come last!
                actions = [
                    datapath.ofproto_parser.OFPActionSetQueue(out_queue),
                    datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("error=E1000002 "
                   "actions v03 Exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
                return 0 
        else:
            self.logger.error("error=E1000003 "
                                "Unsupported OpenFlow version %s",
                                ofproto.OFP_VERSION)
            return 0
        #*** Now have we have actions, build the packet out message:
        try:
            #*** Assemble the switch/packet/actions ready to push:
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions)
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("error=E1000004 "
               "datapath.ofproto_parser.OFPPacketOut Exception %s, %s, %s",
                exc_type, exc_value, exc_traceback)
            return 0 
        try:
            #*** Tell the switch to send the packet:
            datapath.send_msg(out)
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("error=E1000005 "
               "datapath.send_msg Exception %s, %s, %s",
                exc_type, exc_value, exc_traceback)
            return 0 
        return 1

    def packet_out_nq(self, datapath, msg, in_port, out_port):
        """
        Sends a supplied packet out switch port(s) (nq = no queueing)
        """
        ofproto = datapath.ofproto
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            try:
                actions = [datapath.ofproto_parser.OFPActionOutput \
                             (out_port, )]
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("error=E1000022 "
                    "actions exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
                return 0
        elif ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            try:
                actions = [datapath.ofproto_parser.OFPActionOutput \
                             (out_port, 0)]
            except:
                #*** Log the error and return 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("error=E1000025 "
                    "actions exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
                return 0
        else:
            self.logger.error("error=E1000026 "
                                "Unsupported OpenFlow version %s",
                                ofproto.OFP_VERSION)
            return 0
                
        #*** Now have we have actions, build the packet out message:
        try:
            #*** Assemble the switch/packet/actions ready to push:
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions)
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("error=E1000023 "
               "datapath.ofproto_parser.OFPPacketOut Exception %s, %s, %s",
                exc_type, exc_value, exc_traceback)
            return 0 
        try:
            #*** Tell the switch to send the packet:
            datapath.send_msg(out)
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("error=E1000024 "
               "datapath.send_msg Exception %s, %s, %s",
                exc_type, exc_value, exc_traceback)
            return 0 
        return 1

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
