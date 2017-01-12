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
It provides methods for forwarding functions.
"""

#*** Ryu Imports:
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

#*** For logging configuration:
from baseclass import BaseClass

class Forwarding(BaseClass):
    """
    This class is instantiated by nmeta.py and provides methods
    for making forwarding decisions and transformations to packets.
    """
    def __init__(self, config):
        #*** Required for BaseClass:
        self.config = config
        #*** Run the BaseClass init to set things up:
        super(Forwarding, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("forwarding_logging_level_s",
                                       "forwarding_logging_level_c")
        #*** Initiate the mac_to_port dictionary for switching:
        self.mac_to_port = {}

    def basic_switch(self, event, in_port):
        """
        Passed a packet in event and return an output port
        """
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        dpid = datapath.id
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth.src
        eth_dst = eth.dst
        #*** If the dpid doesn't exist in mac_to_port dictionary, create it:
        self.mac_to_port.setdefault(dpid, {})
        #*** If the source MAC doesn't exist, create it:
        self.mac_to_port[dpid].setdefault(eth_src, {})
        #*** Learn the MAC address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth_src] = in_port
        #*** Check to see if dst MAC is in learned MAC table:
        if eth_dst in self.mac_to_port[dpid]:
            #*** Found dst MAC so return the output port:
            self.logger.debug("Forwarding eth_dst=%s "
                    "via dpid=%s port=%s", eth_dst,
                    dpid, self.mac_to_port[dpid][eth_dst])
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            #*** We haven't learned the dst MAC so flood it:
            self.logger.debug("Flooding eth_src=%s"
                                 " eth_dst=%s via dpid=%s flood port=%s",
                                   eth_src, eth_dst, dpid, ofproto.OFPP_FLOOD)
            out_port = ofproto.OFPP_FLOOD
        return out_port
