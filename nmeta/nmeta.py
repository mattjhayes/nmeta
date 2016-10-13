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

#*** Note: see api.py module for REST API calls

#*** General Imports:
import logging
import struct
import time

#*** Ryu Imports:
from ryu import utils
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib import addrconv
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import tcp

#*** Required for api module context:
from ryu.app.wsgi import WSGIApplication

#*** nmeta imports:
import flow
import tc_policy
import config
import switch_abstraction
import measure
import forwarding
import api

import flows

#*** Number of preceding seconds that events are averaged over:
EVENT_RATE_INTERVAL = 60

class NMeta(app_manager.RyuApp):
    """
    This is the main class used to run nmeta
    """
    #*** Supports OpenFlow versions 1.0 and 1.3:
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    #*** Used to call api module:
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(NMeta, self).__init__(*args, **kwargs)
        #*** Instantiate config class which imports configuration file
        #*** config.yaml and provides access to keys/values:
        self.config = config.Config()

        #*** Get logging config values from config class:
        _logging_level_s = self.config.get_value \
                                    ('nmeta_logging_level_s')
        _logging_level_c = self.config.get_value \
                                    ('nmeta_logging_level_c')
        _syslog_enabled = self.config.get_value('syslog_enabled')
        _loghost = self.config.get_value('loghost')
        _logport = self.config.get_value('logport')
        _logfacility = self.config.get_value('logfacility')
        _syslog_format = self.config.get_value('syslog_format')
        _console_log_enabled = self.config.get_value('console_log_enabled')
        _console_format = self.config.get_value('console_format')
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
        #*** Set a variable to indicate if either or both levels are at debug:
        if _logging_level_s == 'DEBUG' or _logging_level_c == 'DEBUG':
            self.debug_on = True
        else:
            self.debug_on = False
        #*** Set up variables:
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

        #*** Table maintenance settings from config.yaml file:
        self.fm_table_max_age = self.config.get_value('fm_table_max_age')
        self.fm_table_tidyup_interval = self.config.\
                                          get_value('fm_table_tidyup_interval')
        self.identity_table_tidyup_interval = self.config.\
                                    get_value('identity_table_tidyup_interval')
        self.statistical_fcip_table_max_age = self.config.\
                            get_value('statistical_fcip_table_max_age')
        self.statistical_fcip_table_tidyup_interval = self.config.\
                            get_value('statistical_fcip_table_tidyup_interval')
        self.payload_fcip_table_max_age = self.config.\
                            get_value('payload_fcip_table_max_age')
        self.payload_fcip_table_tidyup_interval = self.config.\
                            get_value('payload_fcip_table_tidyup_interval')
        self.measure_buckets_max_age = self.config.\
                            get_value('measure_buckets_max_age')
        self.measure_buckets_tidyup_interval = self.config.\
                            get_value('measure_buckets_tidyup_interval')
        #*** Set initial value of the variable that holds last time
        #*** for tidy-ups:
        self.fm_table_last_tidyup_time = time.time()
        self.identity_table_last_tidyup_time = time.time()
        self.statistical_fcip_table_last_tidyup_time = time.time()
        self.payload_fcip_table_last_tidyup_time = time.time()
        self.measure_buckets_last_tidyup_time = time.time()

        #*** Instantiate Module Classes:
        self.flowmetadata = flow.FlowMetadata(self, self.config)
        self.tc_policy = tc_policy.TrafficClassificationPolicy(self.config)
        self.sa = switch_abstraction.SwitchAbstract(self.config)
        self.measure = measure.Measurement(self.config)
        self.forwarding = forwarding.Forwarding(self.config)
        wsgi = kwargs['wsgi']
        self.api = api.Api(self, self.config, wsgi)

        #*** Retrieve config values for Flows class MongoDB connection:
        _mongo_addr = self.config.get_value("mongo_addr")
        _mongo_port = self.config.get_value("mongo_port")
        #*** Instantiate a flow object for classifiers to work with:
        self.flow = flows.Flow(self.logger, _mongo_addr, _mongo_port)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connection_handler(self, ev):
        """
        A switch has connected to the SDN controller.
        We need to do some tasks to set the switch up properly
        such as setting it's config for fragment handling
        and table miss packet length and requesting the
        switch description
        """
        datapath = ev.msg.datapath
        self.logger.info("In switch_connection_handler")
        #*** Set config on the switch:
        self.sa.set_switch_config(datapath, self.ofpc_frag, self.miss_send_len)

        #*** Request the switch send us it's description:
        self.sa.request_switch_desc(datapath)

    @set_ev_cls(ofp_event.EventOFPDescStatsReply, MAIN_DISPATCHER)
    def desc_stats_reply_handler(self, ev):
        """
        Receive a reply from a switch to a description
        statistics request
        """
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.logger.info('event=DescStats Switch dpid=%s is mfr_desc="%s" '
                      'hw_desc="%s" sw_desc="%s" serial_num="%s" dp_desc="%s"',
                      dpid, body.mfr_desc, body.hw_desc, body.sw_desc,
                      body.serial_num, body.dp_desc)
        #*** Some switches need a table miss flow entry installed to buffer
        #*** packet and send a packet-in message to the controller:
        self.sa.set_switch_table_miss(datapath, self.miss_send_len,
                                                    body.hw_desc, body.sw_desc)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        This method is called for every Packet-In event from a Switch.
        We receive a copy of the Packet-In event, pass it to the
        traffic classification area for analysis, work out the forwarding,
        update flow metadata, then add a flow entry to the switch (when
        appropriate) to suppress receiving further packets on this flow.
        Finally, we send the packet out the switch port(s) via a
        Packet-Out message, with appropriate QoS queue set.
        """
        #*** Record the time for later delta measurement:
        pi_start_time = time.time()

        #*** Record the event for measurements:
        self.measure.record_rate_event('packet_in')



        #*** Extract parameters:
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # TEST USE OF DATABASE FOR FLOW CONVERSATIONS:
        #*** The following is TCP specific but shouldn't be... TBD...
        if pkt.get_protocol(tcp.tcp):
            #*** Read packet into flow object for classifiers to work with:
            self.flow.ingest_packet(msg.data, time.time())

        #*** Get the in port (OpenFlow version dependant call):
        in_port = self.sa.get_in_port(msg, datapath, ofproto)

        #*** Extra debug if syslog or console logging set to DEBUG:
        if self.debug_on:
            self._packet_in_debug(ev, in_port)

        #*** Traffic Classification:
        #*** Check traffic classification policy to see if packet matches
        #*** against policy and if it does return a dictionary of actions:
        flow_actions = self.tc_policy.check_policy(pkt, dpid, in_port)
        self.logger.debug("flow_actions=%s", flow_actions)

        #*** Call Forwarding module to carry out forwarding functions:
        out_port = self.forwarding.basic_switch(ev, in_port)

        #*** Accumulate extra information in the flow_actions dictionary:
        flow_actions.setdefault('datapath', {})
        flow_actions['datapath'].setdefault(dpid, {})
        flow_actions['datapath'][dpid]['in_port'] = in_port
        flow_actions['datapath'][dpid]['out_port'] = out_port

        #*** Update Flow Metadata Table and add QoS queue:
        flow_actions = self.flowmetadata.update_flowmetadata(msg, flow_actions)
        self.logger.debug("revised flow_actions=%s", flow_actions)
        out_queue = flow_actions['datapath'][dpid].setdefault('out_queue', 0)

        if out_port != ofproto.OFPP_FLOOD:
            #*** Do some add flow magic, but only if not a flooded packet:
            #*** Prefer to do fine-grained match where possible:
            _add_flow_result = self._add_flow(ev, in_port, out_port, out_queue)
            self.logger.debug("event=add_flow result=%s", _add_flow_result)
            #*** Record the event for measurements:
            self.measure.record_rate_event('add_flow')
            #*** Send Packet Out:
            self.sa.packet_out(datapath, msg, in_port, out_port, out_queue, 0)
        else:
            #*** It's a packet that's flooded, so send without specific queue
            #*** and with no queue option set:
            self.sa.packet_out(datapath, msg, in_port, out_port, 0, 1)

        #*** Record Measurements:
        self.measure.record_rate_event('packet_out')
        pi_delta_time = time.time() - pi_start_time
        self.measure.record_metric('packet_delta', pi_delta_time)

        #*** Now check if table maintenance is needed:
        #*** Flow Metadata (FM) table maintenance:
        _time = time.time()
        if (_time - self.fm_table_last_tidyup_time) > \
                                 self.fm_table_tidyup_interval:
            #*** Call function to do tidy-up on the Flow Metadata (FM) table:
            self.logger.debug("event=tidy-up table=fm_table")
            self.flowmetadata.maintain_fm_table(self.fm_table_max_age)
            self.fm_table_last_tidyup_time = _time
        #*** Identity NIC and System table maintenance:
        _time = time.time()
        if (_time - self.identity_table_last_tidyup_time) \
                              > self.identity_table_tidyup_interval:
            #*** Call function to do tidy-up on the Identity NIC
            #***  and System tables:
            self.logger.debug("event=tidy-up table=identity*")
            self.tc_policy.identity.maintain_identity_tables()
            self.identity_table_last_tidyup_time = _time
        #*** Statistical FCIP table maintenance:
        _time = time.time()
        if (_time - self.statistical_fcip_table_last_tidyup_time) > \
                                 self.statistical_fcip_table_tidyup_interval:
            #*** Call function to do tidy-up on the FCIP table:
            self.logger.debug("event=tidy-up table=statistical_fcip_table")
            self.tc_policy.statistical.maintain_fcip_table(
                                     self.statistical_fcip_table_max_age)
            self.statistical_fcip_table_last_tidyup_time = _time
        #*** Payload FCIP table maintenance:
        _time = time.time()
        if (_time - self.payload_fcip_table_last_tidyup_time) > \
                                 self.payload_fcip_table_tidyup_interval:
            #*** Call function to do tidy-up on the FCIP table:
            self.logger.debug("event=tidy-up table=payload_fcip_table")
            self.tc_policy.payload.maintain_fcip_table(
                                     self.payload_fcip_table_max_age)
            self.payload_fcip_table_last_tidyup_time = _time
        #*** Measure bucket maintenance:
        _time = time.time()
        if (_time - self.measure_buckets_last_tidyup_time) > \
                                 self.measure_buckets_tidyup_interval:
            #*** Call function to do tidy-up on the measure buckets:
            self.logger.debug("event=tidy-up table=measure_buckets")
            self.measure.kick_the_rate_buckets(
                                     self.measure_buckets_max_age)
            self.measure.kick_the_metric_buckets(
                                     self.measure_buckets_max_age)
            self.measure_buckets_last_tidyup_time = _time

    def _add_flow(self, ev, in_port, out_port, out_queue):
        """
        Add a flow entry to a switch
        Prefer to do fine-grained match where possible
        """
        #*** Extract parameters:
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth.src
        eth_dst = eth.dst
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        self.logger.debug("event=add_flow out_queue=%s", out_queue)
        #*** Install a flow entry based on type of flow:
        if pkt_tcp and pkt_ip4:
            #*** Call abstraction layer to add TCP flow record:
            self.logger.debug("event=add_flow match_type=tcp ip_src=%s "
                              "ip_dst=%s ip_ver=4 tcp_src=%s tcp_dst=%s",
                              pkt_ip4.src, pkt_ip4.dst,
                              pkt_tcp.src_port, pkt_tcp.dst_port)
            _result = self.sa.add_flow_tcp(datapath, msg, in_port=in_port,
                              out_port=out_port, out_queue=out_queue,
                              priority=1, buffer_id=None,
                              idle_timeout=5, hard_timeout=0)
        elif pkt_tcp and pkt_ip6:
            #*** Call abstraction layer to add TCP flow record:
            self.logger.debug("event=add_flow match_type=tcp ip_src=%s "
                              "ip_dst=%s ip_ver=6 tcp_src=%s tcp_dst=%s",
                              pkt_ip6.src, pkt_ip6.dst,
                              pkt_tcp.src_port, pkt_tcp.dst_port)
            _result = self.sa.add_flow_tcp(datapath, msg, in_port=in_port,
                              out_port=out_port, out_queue=out_queue,
                              priority=1, buffer_id=None,
                              idle_timeout=5, hard_timeout=0)
        elif pkt_ip4:
            #*** Call abstraction layer to add IP flow record:
            self.logger.debug("event=add_flow match_type=ip ip_src=%s "
                              "ip_dst=%s ip_proto=%s ip_ver=4",
                              pkt_ip4.src, pkt_ip4.dst, pkt_ip4.proto)
            _result = self.sa.add_flow_ip(datapath, msg, in_port=in_port,
                              out_port=out_port, out_queue=out_queue,
                              priority=1, buffer_id=None,
                              idle_timeout=5, hard_timeout=0)
        elif pkt_ip6:
            #*** Call abstraction layer to add IP flow record:
            self.logger.debug("event=add_flow match_type=ip ip_src=%s "
                              "ip_dst=%s ip_proto=%s ip_ver=6",
                              pkt_ip6.src, pkt_ip6.dst, pkt_ip6.nxt)
            _result = self.sa.add_flow_ip(datapath, msg, in_port=in_port,
                              out_port=out_port, out_queue=out_queue,
                              priority=1, buffer_id=None,
                              idle_timeout=5, hard_timeout=0)
        else:
            #*** Call abstraction layer to add Ethernet flow record:
            self.logger.debug("event=add_flow match_type=eth eth_src=%s "
                              "eth_dst=%s eth_type=%s",
                              eth_src, eth_dst, eth.ethertype)
            _result = self.sa.add_flow_eth(datapath, msg, in_port=in_port,
                              out_port=out_port, out_queue=out_queue,
                              priority=1, buffer_id=None,
                              idle_timeout=5, hard_timeout=0)
        return _result


    def _packet_in_debug(self, ev, in_port):
        """
        Generate a debug message describing the packet
        in event
        """
        #*** Extract parameters:
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src = eth.src
        eth_dst = eth.dst
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        #*** Some debug about the Packet In:
        if pkt_ip4 and pkt_tcp:
            self.logger.debug("event=pi_ipv4_tcp dpid=%s "
                                  "in_port=%s ip_src=%s ip_dst=%s tcp_src=%s "
                                  "tcp_dst=%s",
                                  dpid, in_port, pkt_ip4.src, pkt_ip4.dst,
                                  pkt_tcp.src_port, pkt_tcp.dst_port)
        elif pkt_ip6 and pkt_tcp:
            self.logger.debug("event=pi_ipv6_tcp dpid=%s "
                                  "in_port=%s ip_src=%s ip_dst=%s tcp_src=%s "
                                  "tcp_dst=%s",
                                  dpid, in_port, pkt_ip6.src, pkt_ip6.dst,
                                  pkt_tcp.src_port, pkt_tcp.dst_port)
        elif pkt_ip4:
            self.logger.debug("event=pi_ipv4 dpid="
                                  "%s in_port=%s ip_src=%s ip_dst=%s proto=%s",
                                  dpid, in_port,
                                  pkt_ip4.src, pkt_ip4.dst, pkt_ip4.proto)
        elif pkt_ip6:
            self.logger.debug("event=pi_ipv6 dpid=%s "
                                  "in_port=%s ip_src=%s ip_dst=%s",
                                  dpid, in_port,
                                  pkt_ip6.src, pkt_ip6.dst)
        else:
            self.logger.debug("event=pi_other dpid=%s "
                                "in_port=%s eth_src=%s eth_dst=%s eth_type=%s",
                                dpid, in_port, eth_src, eth_dst, eth.ethertype)


    @set_ev_cls(ofp_event.EventOFPErrorMsg,
            [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        """
        A switch has sent us an error event
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        if msg.type == 0x03 and msg.code == 0x00:
            self.logger.error('event=OFPErrorMsg_received: dpid=%s '
                      'type=Flow_Table_Full(0x03) code=0x%02x message=%s',
                      dpid, msg.code, utils.hex_array(msg.data))
        else:
            self.logger.error('event=OFPErrorMsg_received: dpid=%s '
                      'type=0x%02x code=0x%02x message=%s',
                      dpid, msg.type, msg.code, utils.hex_array(msg.data))

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
