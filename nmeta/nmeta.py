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

#*** nmeta - Network Metadata

"""
This is the main module of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
.
Do not use this code for production deployments - it is proof of concept code
and carries no warrantee whatsoever. You have been warned.
"""

#*** Note: see api_external.py module for REST API calls

#*** General Imports:
import struct
import datetime

#*** Ryu Imports:
from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib import addrconv
from ryu.lib.packet import ethernet

#*** nmeta imports:
import tc_policy
import config
import switches
import forwarding
import flows
import identities
import of_error_decode

#*** For logging configuration:
from baseclass import BaseClass

#*** Number of preceding seconds that events are averaged over:
EVENT_RATE_INTERVAL = 60

class NMeta(app_manager.RyuApp, BaseClass):
    """
    This is the main class used to run nmeta
    """
    #*** Supports OpenFlow version 1.3:
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NMeta, self).__init__(*args, **kwargs)
        #*** Instantiate config class which imports configuration file
        #*** config.yaml and provides access to keys/values:
        self.config = config.Config()

        #*** Now set config module to log properly:
        self.config.inherit_logging(self.config)

        #*** Run the BaseClass init to set things up:
        super(NMeta, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("nmeta_logging_level_s",
                                       "nmeta_logging_level_c")

        #*** Instantiate Module Classes:
        self.tc_policy = tc_policy.TrafficClassificationPolicy(self.config)
        self.switches = switches.Switches(self.config)
        self.forwarding = forwarding.Forwarding(self.config)

        #*** Instantiate a flow object for conversation metadata:
        self.flow = flows.Flow(self.config)
        #*** Instantiate an identity object for participant metadata:
        self.ident = identities.Identities(self.config)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connection_handler(self, ev):
        """
        A switch has connected to the SDN controller.
        We need to do some tasks to set the switch up properly
        such as setting it's config for fragment handling
        and table miss packet length and requesting the
        switch description
        """
        self.switches.add(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        """
        Receive a reply from a switch to a description
        statistics request
        """
        self.switches.stats_reply(ev.msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        """
        This method is called for every Packet-In event from a Switch.
        We receive a copy of the Packet-In event, pass it to the
        traffic classification area for analysis, work out the forwarding,
        update flow metadata, then add a flow entry to the switch (when
        appropriate) to suppress receiving further packets on this flow.
        Finally, we send the packet out the switch port(s) via a
        Packet-Out message, with appropriate QoS queue set.
        """
        #*** Extract parameters:
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        switch = self.switches[dpid]
        flowtables = switch.flowtables
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        #*** Get the in port (OpenFlow version dependant call):
        in_port = msg.match['in_port']

        #*** Read packet into flow object for classifiers to work with:
        self.flow.ingest_packet(dpid, in_port, msg.data,
                                                       datetime.datetime.now())

        #*** Harvest identity metadata:
        self.ident.harvest(msg.data, self.flow.packet)

        #*** Traffic Classification if not already classified.
        #*** Check traffic classification policy to see if packet matches
        #*** against policy and if it does update flow.classified.*:
        if not self.flow.classification.classified:
            self.tc_policy.check_policy(self.flow, self.ident)
            self.logger.debug("classification=%s",
                                             self.flow.classification.dbdict())
            #*** Write classification result to classifications collection:
            self.flow.classification.commit()

        #*** Call Forwarding module to determine output port:
        out_port = self.forwarding.basic_switch(ev, in_port)

        #*** Set QoS queue based on any QoS actions:
        actions = self.flow.classification.actions
        if 'qos_treatment' in actions:
            out_queue = self.tc_policy.qos(actions['qos_treatment'])
            self.logger.debug("QoS output_queue=%s", out_queue)
        else:
            out_queue = 0

        if out_port != ofproto.OFPP_FLOOD:
            #*** Do some add flow magic, but only if not a flooded packet and
            #*** has been classified.
            #*** Prefer to do fine-grained match where possible:
            if self.flow.classification.classified:
                suppress_result = flowtables.suppress_flow(msg, in_port,
                                                           out_port, out_queue)
                self.logger.debug("event=suppress_flow flow_hash=%s dpid=%s "
                                    "suppress_result=%s",
                                    self.flow.flow_hash, dpid, suppress_result)
            else:
                self.logger.debug("Flow entry for flow_hash=%s not added as "
                                     "not classified yet", self.flow.flow_hash)
            #*** Send Packet Out:
            switch.packet_out(msg.data, in_port, out_port, out_queue)
        else:
            #*** It's a packet that's flooded, so send without specific queue
            #*** and with no queue option set:
            switch.packet_out(msg.data, in_port, out_port, out_queue=0,
                                                                    no_queue=1)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """
        A switch has sent an event to us because it has removed
        a flow from a flow table
        """
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
        elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            reason = 'HARD TIMEOUT'
        elif msg.reason == ofp.OFPRR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPRR_GROUP_DELETE:
            reason = 'GROUP DELETE'
        else:
            reason = 'unknown'
        self.logger.info('Idle Flow removed dpid=%s '
                              'cookie=%d priority=%d reason=%s table_id=%d '
                              'duration_sec=%d '
                              'idle_timeout=%d hard_timeout=%d '
                              'packets=%d bytes=%d match=%s',
                              datapath.id, msg.cookie, msg.priority, reason,
                              msg.table_id, msg.duration_sec,
                              msg.idle_timeout, msg.hard_timeout,
                              msg.packet_count, msg.byte_count, msg.match)
        if reason == 'IDLE TIMEOUT':
            #*** Record flow removal into the flow_rems database collection:
            self.flow.record_removal(msg)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
            [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        """
        A switch has sent us an error event
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        self.logger.error('event=OFPErrorMsg_received: dpid=%s '
                      'type=%s code=%s message=%s',
                      dpid, msg.type, msg.code, utils.hex_array(msg.data))
        #*** Log human-friendly decodes for the error type and code:
        type1, type2, code1, code2 = of_error_decode.decode(msg.type, msg.code)
        self.logger.error('error_type=%s %s error_code=%s %s', type1, type2,
                                    code1, code2)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
        Switch Port Status event
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)

#*** Borrowed from rest_router.py code:
def ipv4_text_to_int(ip_text):
    """
    Takes an IP address string and translates it
    to an unsigned integer
    """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
