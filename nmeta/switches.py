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

#*** nmeta - Network Metadata - Abstractions of Switches for OpenFlow Calls

"""
This module is part of the nmeta suite running on top of Ryu SDN controller.

It provides classes that abstract the details of OpenFlow switches
"""

#*** General Imports:
import sys
import struct

#*** Ryu Imports:
from ryu.lib import addrconv
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import tcp

#*** For logging configuration:
from baseclass import BaseClass

#*** mongodb Database Import:
import pymongo
from pymongo import MongoClient

#*** Constant to use for a port not found value:
PORT_NOT_FOUND = 999999999

#*** Supports OpenFlow version 1.3:
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

class Switches(BaseClass):
    """
    This class provides an abstraction for a set of OpenFlow
    Switches.

    It stores instances of the Switch class in a dictionary keyed
    by DPID. The switch instances are accessible externally.

    A standard (not capped) MongoDB database collection is used to
    record switch details so that they can be accessed via the
    external API.
    """
    def __init__(self, config):
        #*** Required for BaseClass:
        self.config = config
        #*** Run the BaseClass init to set things up:
        super(Switches, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("switches_logging_level_s",
                                       "switches_logging_level_c")

        #*** Set up database collections:
        #*** Get parameters from config:
        mongo_addr = config.get_value("mongo_addr")
        mongo_port = config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")

        #*** Start mongodb:
        self.logger.info("Connecting to MongoDB database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB nmeta database:
        db_nmeta = mongo_client[mongo_dbname]

        #*** Delete (drop) previous switches collection if it exists:
        self.logger.debug("Deleting previous switches MongoDB collection...")
        db_nmeta.switches.drop()

        #*** Create the switches collection:
        self.switches = db_nmeta.create_collection('switches')

        #*** Index dpid key to improve look-up performance:
        self.switches.create_index([('dpid', pymongo.TEXT)], unique=False)

        #*** Get max bytes of new flow packets to send to controller from
        #*** config file:
        self.miss_send_len = self.config.get_value("miss_send_len")
        if self.miss_send_len < 1500:
            self.logger.info("Be aware that setting "
                             "miss_send_len to less than a full size packet "
                             "may result in errors due to truncation. "
                             "Configured value is %s bytes",
                             self.miss_send_len)
        #*** Tell switch how to handle fragments (see OpenFlow spec):
        self.ofpc_frag = self.config.get_value("ofpc_frag")

        #*** Dictionary of the instances of the Switch class,
        #***  key is the switch DPID which is assumed to be unique:
        self.switches = {}

    def add(self, datapath):
        """
        Add a switch to the Switches class
        """
        dpid = datapath.id
        self.logger.info("Adding switch dpid=%s", dpid)
        switch = Switch(self.logger, self.config, datapath)
        switch.dpid = dpid
        #*** Record class instance into dictionary to make it accessible:
        self.switches[datapath.id] = switch
        #*** Record switch in database collection:
        # TBD

        #*** Set the switch up for operation:
        switch.set_switch_config(self.ofpc_frag, self.miss_send_len)
        switch.request_switch_desc()
        switch.set_switch_table_miss(self.miss_send_len)
        return 1

    def stats_reply(self, msg):
        """
        Read in a switch stats reply
        """
        body = msg.body
        dpid = msg.datapath.id
        #*** Look up the switch:
        if dpid in self.switches:
            self.logger.info('event=DescStats Switch dpid=%s is mfr_desc="%s" '
                      'hw_desc="%s" sw_desc="%s" serial_num="%s" dp_desc="%s"',
                      dpid, body.mfr_desc, body.hw_desc, body.sw_desc,
                      body.serial_num, body.dp_desc)
            switch = self.switches[dpid]
            switch.mfr_desc = body.mfr_desc
            switch.hw_desc = body.hw_desc
            switch.sw_desc = body.sw_desc
            switch.serial_num = body.serial_num
            switch.dp_desc = body.dp_desc

            #*** Update switch details in database collection:
            # TBD

        else:
            self.logger.warning("Ignoring DescStats reply from unknown switch"
                                                              " dpid=%s", dpid)
            return 0

    def __getitem__(self, key):
        """
        Passed a dpid key and return corresponding switch
        object, or 0 if it doesn't exist.
        Example:
            switch = switches[dpid]
        """
        if key in self.switches:
            return self.switches[key]
        else:
            return 0

class Switch(object):
    """
    This class provides an abstraction for an OpenFlow
    Switch
    """
    def __init__(self, logger, config, datapath):
        #*** Initialise switch variables:
        self.logger = logger
        self.config = config
        self.datapath = datapath
        self.switch_hash = ""
        self.dpid = 0
        self.ip_address = ""
        self.time = ""
        self.cxn_status = ""
        self.cxn_ver = ""
        self.mfr_desc = ""
        self.hw_desc = ""
        self.sw_desc = ""
        self.serial_num = ""
        self.dp_desc = ""
        #*** Instantiate a class that represents flow tables:
        self.flowtables = FlowTables(self.logger, config, datapath)

    def dbdict(self):
        """
        Return a dictionary object of switch
        parameters for storing in the database
        """
        return self.__dict__

    def request_switch_desc(self):
        """
        Send an OpenFlow request to the switch asking it to
        send us it's description data
        """
        parser = self.datapath.ofproto_parser
        req = parser.OFPDescStatsRequest(self.datapath, 0)
        self.logger.debug("Sending description request to dpid=%s",
                            self.datapath.id)
        self.datapath.send_msg(req)

    def set_switch_config(self, config_flags, miss_send_len):
        """
        Set config on a switch including config flags that
        instruct fragment handling behaviour and miss_send_len
        which controls the number of bytes sent to the controller
        when the output port is specified as the controller.
        """
        parser = self.datapath.ofproto_parser
        self.logger.info("Setting config on switch "
                         "dpid=%s to config_flags flag=%s and "
                         "miss_send_len=%s bytes",
                          self.dpid, config_flags, miss_send_len)
        try:
            self.datapath.send_msg(parser.OFPSetConfig(
                                     self.datapath,
                                     config_flags,
                                     miss_send_len))
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("Failed to set switch config. "
                   "Exception %s, %s, %s",
                    exc_type, exc_value, exc_traceback)
            return 0
        return 1

    def packet_out(self, data, in_port, out_port, out_queue, no_queue=0):
        """
        Sends a supplied packet out switch port(s) in specific queue.

        Set no_queue=1 if want no queueing specified (i.e. for a flooded
        packet). Also use for Zodiac FX compatibility.

        Does not use Buffer IDs as they are unreliable resource.
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        dpid = self.datapath.id
        #*** First build OF version specific list of actions:
        if no_queue:
            #*** Packet out with no queue:
            actions = [self.datapath.ofproto_parser.OFPActionOutput \
                             (out_port, 0)]

        else:
            #*** Note: out_port must come last!
            actions = [
                    parser.OFPActionSetQueue(out_queue),
                    parser.OFPActionOutput(out_port, 0)]

        #*** Now have we have actions, build the packet out message:
        out = parser.OFPPacketOut(
                    datapath=self.datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=data)

        self.logger.debug("Sending Packet-Out message dpid=%s port=%s",
                                    dpid, out_port)
        #*** Tell the switch to send the packet:
        self.datapath.send_msg(out)

    def set_switch_table_miss(self, miss_send_len):
        """
        Set a table miss rule on table 0 to send packets to
        the controller. This is required for OF versions higher
        than v1.0
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        dpid = self.datapath.id
        self.logger.info("Setting table-miss flow entry on switch dpid=%s with"
                                       "miss_send_len=%s", dpid, miss_send_len)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                                miss_send_len)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath, priority=0,
                                                match=match, instructions=inst)
        self.datapath.send_msg(mod)

class FlowTables(object):
    """
    This class provides an abstraction for the flow tables on
    an OpenFlow Switch
    """
    def __init__(self, logger, config, datapath):
        self.logger = logger
        self.config = config
        self.datapath = datapath
        self.dpid = datapath.id
        self.parser = datapath.ofproto_parser
        self.suppress_idle_timeout = config.get_value('suppress_idle_timeout')
        self.suppress_hard_timeout = config.get_value('suppress_hard_timeout')
        self.suppress_priority = config.get_value('suppress_priority')

    def suppress_flow(self, msg, in_port, out_port, out_queue):
        """
        Add flow entries to a switch to suppress further packet-in
        events while the flow is active.
        Prefer to do fine-grained match where possible.
        Install reverse matches as well for TCP flows.
        """
        #*** Extract parameters:
        pkt = packet.Packet(msg.data)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        idle_timeout = self.suppress_idle_timeout
        hard_timeout = self.suppress_hard_timeout
        priority = self.suppress_priority
        self.logger.debug("event=add_flow out_queue=%s", out_queue)
        #*** Install flow entry(ies) based on type of flow:
        if pkt_tcp:
            #*** Install two flow entries for TCP so that return traffic
            #*** is also suppressed:
            if pkt_ip4:
                forward_match = self.match_ipv4_tcp(pkt_ip4.src, pkt_ip4.dst,
                                            pkt_tcp.src_port, pkt_tcp.dst_port)
                reverse_match = self.match_ipv4_tcp(pkt_ip4.dst, pkt_ip4.src,
                                            pkt_tcp.dst_port, pkt_tcp.src_port)
            elif pkt_ip6:
                forward_match = self.match_ipv6_tcp(pkt_ip6.src, pkt_ip6.dst,
                                            pkt_tcp.src_port, pkt_tcp.dst_port)
                reverse_match = self.match_ipv6_tcp(pkt_ip6.dst, pkt_ip6.src,
                                            pkt_tcp.dst_port, pkt_tcp.src_port)
            else:
                #*** Unknown protocol so warn and exit:
                self.logger.warning("Unknown protocol, not installing flow "
                                    "suppression entries")
                return 0
            #*** Actions:
            forward_actions = self.actions(out_port, out_queue)
            #*** Note, not setting QoS on reverse:
            reverse_actions = self.actions(in_port, 0)
            #*** Now have matches and actions. Install to switch:
            self.add_flow(forward_match, forward_actions,
                                 priority=priority,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
            self.add_flow(reverse_match, reverse_actions,
                                 priority=priority,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
            return 1
        else:
            if pkt_ip4:
                #*** Match IPv4 packet
                match = self.match_ipv4(pkt_ip4.src, pkt_ip4.dst)
            elif pkt_ip6:
                #*** Match IPv6 packet
                match = self.match_ipv6(pkt_ip6.src, pkt_ip6.dst)
            else:
                #*** Non-IP packet, ignore:
                return 1
            #*** Actions:
            actions = self.actions(out_port, out_queue)
            #*** Now have matches and actions. Install to switch:
            self.add_flow(match, actions,
                                 priority=priority,
                                 idle_timeout=idle_timeout,
                                 hard_timeout=hard_timeout)
            return 1

    def add_flow(self, match, actions, priority, idle_timeout, hard_timeout):
        """
        Add a flow entry to a switch
        """
        ofproto = self.datapath.ofproto
        parser = self.datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                                      actions)]
        mod = parser.OFPFlowMod(datapath=self.datapath,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                priority=priority,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                match=match,
                                instructions=inst)
        self.logger.debug("Installing Flow Entry to dpid=%s", self.dpid)
        self.datapath.send_msg(mod)

    def actions(self, out_port, out_queue, no_queue=0):
        """
        Create actions for a switch flow entry. Specify the out port
        and QoS queue, and set no_queue=1 if don't want QoS set.
        Returns a list of action objects
        """
        if no_queue:
            #*** Set flow entry action without queueing specified:
            return [self.datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        else:
            return [self.datapath.ofproto_parser.OFPActionSetQueue(out_queue),
                    self.datapath.ofproto_parser.OFPActionOutput(out_port, 0)]


    def match_ipv4_tcp(self, ipv4_src, ipv4_dst, tcp_src, tcp_dst):
        """
        Match an IPv4 TCP flow on a switch.
        Passed IPv4 and TCP parameters and return
        an OpenFlow match object for this flow
        """
        return self.parser.OFPMatch(eth_type=0x0800,
                    ipv4_src=_ipv4_t2i(str(ipv4_src)),
                    ipv4_dst=_ipv4_t2i(str(ipv4_dst)),
                    ip_proto=6,
                    tcp_src=tcp_src,
                    tcp_dst=tcp_dst)

    def match_ipv6_tcp(self, ipv6_src, ipv6_dst, tcp_src, tcp_dst):
        """
        Match an IPv6 TCP flow on a switch.
        Passed IPv6 and TCP parameters and return
        an OpenFlow match object for this flow
        """
        return self.parser.OFPMatch(eth_type=0x86DD,
                    ipv6_src=ipv6_src,
                    ipv6_dst=ipv6_dst,
                    ip_proto=6,
                    tcp_src=tcp_src,
                    tcp_dst=tcp_dst)

    def match_ipv4(self, ipv4_src, ipv4_dst):
        """
        Match an IPv4 flow on a switch.
        Passed IPv4 parameters and return
        an OpenFlow match object for this flow
        """
        return self.parser.OFPMatch(eth_type=0x0800,
                    ipv4_src=_ipv4_t2i(str(ipv4_src)),
                    ipv4_dst=_ipv4_t2i(str(ipv4_dst)))

    def match_ipv6(self, ipv6_src, ipv6_dst):
        """
        Match an IPv6 flow on a switch.
        Passed IPv6 parameters and return
        an OpenFlow match object for this flow
        """
        return self.parser.OFPMatch(eth_type=0x86DD,
                    ipv6_src=ipv6_src,
                    ipv6_dst=ipv6_dst)

#=============== Private functions:

def _ipv4_t2i(ip_text):
    """
    Turns an IPv4 address in text format into an integer.
    Borrowed from rest_router.py code
    """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
