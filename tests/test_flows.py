"""
nmeta flows.py Unit Tests

Note: no testing of max_interpacket_interval and
min_interpacket_interval as they become imprecise due
to floating point and when tried using decimal module
found that would not serialise into Pymongo db.

Note that packets + metadata are imported from local packets_* modules

TBD duplicate packets (retx / diff switch)
TBD: test flow.tcp_urg(), flow.tcp_ece(), flow.tcp_cwr()
TBD: IPv6 tests
TBD: ARP
TBD: ICMP
TBD: UDP

"""

#*** Handle tests being in different directory branch to app code:
import sys
import struct

sys.path.insert(0, '../nmeta')

import logging

#*** JSON imports:
import json
from json import JSONEncoder

import binascii

#*** For timestamps:
import datetime

#*** Import dpkt for packet parsing:
import dpkt

#*** Testing imports:
import mock
import unittest

#*** Ryu imports:
from ryu.base import app_manager  # To suppress cyclic import
from ryu.controller import controller
from ryu.controller import handler
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_parser
from ryu.lib import addrconv

#*** nmeta imports:
import nmeta
import config
import flows as flow_class
import tc_policy
import identities
import nethash

#*** nmeta test packet imports:
import packets_ipv4_http as pkts
import packets_ipv4_http2 as pkts2
import packets_ipv4_tcp_reset as pkts3
import packets_lldp as pkts_lldp
import packets_ipv4_ARP_2 as pkts_ARP_2

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#*** Test DPIDs and in ports:
DPID1 = 1
DPID2 = 2
INPORT1 = 1
INPORT2 = 2

#======================== flows.py Unit Tests ============================

def test_flow_ipv4_http():
    """
    Test ingesting packets from an IPv4 HTTP flow, with a packet
    from a different flow ingested mid-stream.
    This flow is not torn down.
    """
    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(pkts.RAW[0])
    eth_src = mac_addr(eth.src)
    assert eth_src == '08:00:27:2a:d6:dd'

    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    pkt_test(flow, pkts, 1, 1)

    #*** Test Flow 1 Packet 2 (Server TCP SYN ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[1], datetime.datetime.now())
    pkt_test(flow, pkts, 2, 2)

    #*** Test Flow 1 Packet 3 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[2], datetime.datetime.now())
    pkt_test(flow, pkts, 3, 3)

    #*** Random packet to ensure it doesn't count against flow 1:
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[1], datetime.datetime.now())

    #*** Test Flow 1 Packet 4 (Client to Server HTTP GET):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[3], datetime.datetime.now())
    pkt_test(flow, pkts, 4, 4)

    #*** Test Flow 1 Packet 5 (Server ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[4], datetime.datetime.now())
    pkt_test(flow, pkts, 5, 5)

    #*** Test Flow 1 Packet 6 (Server to Client HTTP 400 Bad Request):
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[5], datetime.datetime.now())
    pkt_test(flow, pkts, 6, 6)

    #*** Test Flow 1 Packet 7 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[6], datetime.datetime.now())
    pkt_test(flow, pkts, 7, 7)

def test_flow_ipv4_http2():
    """
    Test ingesting packets from an IPv4 HTTP flow, with a packet
    from a different flow ingested mid-stream. This flow is a
    successful retrieval of an HTTP object with connection close
    so TCP session nicely torn down with FINs
    """
    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)

    #*** Test Flow 2 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[0], datetime.datetime.now())
    pkt_test(flow, pkts2, 1, 1)

    #*** Test Flow 2 Packet 2 (Server TCP SYN ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[1], datetime.datetime.now())
    pkt_test(flow, pkts2, 2, 2)

    #*** Test Flow 2 Packet 3 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[2], datetime.datetime.now())
    pkt_test(flow, pkts2, 3, 3)

    #*** Random packet to ensure it doesn't count against flow 2:
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[1], datetime.datetime.now())

    #*** Test Flow 2 Packet 4 (Client HTTP GET):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[3], datetime.datetime.now())
    pkt_test(flow, pkts2, 4, 4)

    #*** Test Flow 2 Packet 5 (Server ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[4], datetime.datetime.now())
    pkt_test(flow, pkts2, 5, 5)

    #*** Test Flow 2 Packet 6 (Server HTTP 200 OK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[5], datetime.datetime.now())
    pkt_test(flow, pkts2, 6, 6)

    #*** Test Flow 2 Packet 7 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[6], datetime.datetime.now())
    pkt_test(flow, pkts2, 7, 7)

    #*** Test Flow 2 Packet 8 (Server sends HTML Page to Client):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[7], datetime.datetime.now())
    pkt_test(flow, pkts2, 8, 8)

    #*** Test Flow 2 Packet 9 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[8], datetime.datetime.now())
    pkt_test(flow, pkts2, 9, 9)

    #*** Test Flow 2 Packet 10 (Server FIN ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[9], datetime.datetime.now())
    pkt_test(flow, pkts2, 10, 10)

    #*** Test Flow 2 Packet 11 (Client FIN ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[10], datetime.datetime.now())
    pkt_test(flow, pkts2, 11, 11)

    #*** Test Flow 2 Packet 12 (Final ACK from Server):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[11], datetime.datetime.now())
    pkt_test(flow, pkts2, 12, 12)

def test_flow_ipv4_tcp_reset():
    """
    Test ingesting packets from an IPv4 TCP flow that is immediately
    shutdown with a TCP RST
    """
    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)

    #*** Test Flow 2 Packet 1 (Client SYN on TCP-81):
    flow.ingest_packet(DPID1, INPORT1, pkts3.RAW[0], datetime.datetime.now())
    pkt_test(flow, pkts3, 1, 1)

    #*** Test Flow 2 Packet 2 (Server RST):
    flow.ingest_packet(DPID1, INPORT2, pkts3.RAW[1], datetime.datetime.now())
    pkt_test(flow, pkts3, 2, 2)


def test_flow_LLDP():
    """
    Test ingesting LLDP (non-IP) packets
    """

    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)

    #*** Test LLDP ingestion:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0],
                                                     datetime.datetime.now())
    assert flow.packet_count() == 1
    assert flow.packet.length == pkts_lldp.LEN[0]
    assert flow.packet.eth_src == pkts_lldp.ETH_SRC[0]
    assert flow.packet.eth_dst == pkts_lldp.ETH_DST[0]

    #*** Ingest same packet again, shouldn't increase flow count as isn't flow:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0],
                                                     datetime.datetime.now())
    assert flow.packet_count() == 1
    assert flow.packet.length == pkts_lldp.LEN[0]
    assert flow.packet.eth_src == pkts_lldp.ETH_SRC[0]
    assert flow.packet.eth_dst == pkts_lldp.ETH_DST[0]

def test_classification_static():
    """
    Test that classification returns correct information for a static
    classification.
    Create a classification object, record it to DB then check
    that classification can be retrieved
    """
    #*** Instantiate classes:
    flow = flow_class.Flow(config)
    ident = identities.Identities(config)
    #*** Initial main_policy won't match as looking for tcp-1234:
    tc = tc_policy.TrafficClassificationPolicy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/foo",
                            pol_filename="main_policy_regression_static.yaml")

    #*** Ingest Flow 2 Packet 0 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[0], datetime.datetime.now())

    #*** Retrieve a classification object for this particular flow:
    clasfn = flow.Classification(flow.packet.flow_hash,
                                    flow.classifications,
                                    flow.classification_time_limit,
                                    logger)

    #*** Base classification state:
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 0
    assert flow.classification.classification_tag == ""
    assert flow.classification.classification_time == 0
    assert flow.classification.actions == {}

    #*** Classify the packet:
    tc.check_policy(flow, ident)

    #*** Unmatched classification state:
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == ""
    assert flow.classification.classification_time == 0
    assert flow.classification.actions == {}

    #*** Initial main_policy that matches tcp-80:
    tc = tc_policy.TrafficClassificationPolicy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/foo",
                            pol_filename="main_policy_regression_static_3.yaml")

    #*** Classify the packet:
    tc.check_policy(flow, ident)

    #*** Matched classification state:
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == "Constrained Bandwidth Traffic"
    assert flow.classification.actions == {'qos_treatment': 'constrained_bw',
                                   'set_desc': 'Constrained Bandwidth Traffic'}

    #*** Now test that classification remains after ingesting more packets
    #***  on same flow.
    #*** Load main_policy that matches dst tcp-80:
    tc = tc_policy.TrafficClassificationPolicy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/foo",
                            pol_filename="main_policy_regression_static_4.yaml")

    #*** Ingest Flow 1 Packet 0 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Classify the packet:
    tc.check_policy(flow, ident)

    logger.debug("pkt0 flow classification is %s", flow.classification.dbdict())

    #*** Matched classification state:
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == "Constrained Bandwidth Traffic"
    assert flow.classification.actions == {'qos_treatment': 'constrained_bw',
                                   'set_desc': 'Constrained Bandwidth Traffic'}

    #*** Write classification result to classifications collection:
    flow.classification.commit()

    #*** Ingest Flow 1 Packet 1 (Client TCP SYN+ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[1], datetime.datetime.now())

    logger.debug("pkt1a flow classification is %s", flow.classification.dbdict())

    assert flow.classification.classified == 1

    #*** We would never run this as otherwise above test would have failed.
    #*** Left it in here to make the point that you shouldn't classify if
    #*** classified is set.
    if not flow.classification.classified:
        #*** Classify the packet:
        tc.check_policy(flow, ident)

    logger.debug("pkt1b flow classification is %s", flow.classification.dbdict())

    #*** Matched classification state (shouldn't be changed by second packet):
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == "Constrained Bandwidth Traffic"
    assert flow.classification.actions == {'qos_treatment': 'constrained_bw',
                                   'set_desc': 'Constrained Bandwidth Traffic'}

def test_record_removal():
    """
    Test the recording of an idle-timeout flow removal message
    sent by a switch into the flow_rems database collection

    Synthesise flow removal messages to test with.
    """
    #*** Supports OpenFlow version 1.3:
    OFP_VERSION = ofproto_v1_3.OFP_VERSION

    #*** Instantiate Flow class:
    flow = flow_class.Flow(config)

    #*** Load JSON representations of flow removed messages:
    with open('OFPMsgs/OFPFlowRemoved_1.json', 'r') as json_file:
        json_str_tx = json_file.read()
        json_dict_tx = json.loads(json_str_tx)
    with open('OFPMsgs/OFPFlowRemoved_2.json', 'r') as json_file:
        json_str_rx = json_file.read()
        json_dict_rx = json.loads(json_str_rx)

    #*** Set up fake datapath and synthesise messages:
    datapath = ofproto_protocol.ProtocolDesc(version=OFP_VERSION)
    datapath.id = 1
    msg_tx = ofproto_parser.ofp_msg_from_jsondict(datapath, json_dict_tx)
    msg_rx = ofproto_parser.ofp_msg_from_jsondict(datapath, json_dict_rx)

    logger.debug("msg_tx=%s", msg_tx)

    #*** Call our method that we're testing with the synthesised flow rems:
    flow.record_removal(msg_tx)
    flow.record_removal(msg_rx)

    #*** Check that messages recorded correctly in database collection:
    db_data_tx = {'ip_A': '10.1.0.1', 'tp_B': 80}
    result = flow.flow_rems.find(db_data_tx).sort('$natural', -1).limit(1)
    result_tx = list(result)[0]
    logger.debug("result=%s", result_tx)
    assert result_tx['table_id'] == 1
    assert result_tx['ip_B'] == '10.1.0.2'
    assert result_tx['tp_A'] == 43297
    assert result_tx['packet_count'] == 10
    assert result_tx['flow_hash'] == nethash.hash_flow(('10.1.0.1',
                                                     '10.1.0.2', 43297, 80, 6))

    #*** Return leg of flow:
    db_data_tx = {'ip_B': '10.1.0.1', 'tp_A': 80}
    result = flow.flow_rems.find(db_data_tx).sort('$natural', -1).limit(1)
    result_tx = list(result)[0]
    logger.debug("result=%s", result_tx)
    assert result_tx['table_id'] == 1
    assert result_tx['ip_A'] == '10.1.0.2'
    assert result_tx['tp_B'] == 43297
    assert result_tx['packet_count'] == 9
    assert result_tx['flow_hash'] == nethash.hash_flow(('10.1.0.2',
                                                     '10.1.0.1', 80, 43297, 6))

def test_classification_identity():
    """
    Test that classification returns correct information for an identity
    classification.
    Create a classification object, record it to DB then check
    that classification can be retrieved
    """
    #*** Instantiate classes:
    flow = flow_class.Flow(config)
    ident = identities.Identities(config)
    #*** Load main_policy that matches identity pc1
    #*** and has action to constrain it's bandwidth:
    tc = tc_policy.TrafficClassificationPolicy(config,
                        pol_dir_default="config/tests/regression",
                        pol_dir_user="config/tests/foo",
                        pol_filename="main_policy_regression_identity_2.yaml")

    #*** Ingest and harvest LLDP Packet 2 (lg1) that shouldn't match:
    # 206 08:00:27:21:4f:ea 01:80:c2:00:00:0e LLDP NoS = 08:00:27:21:4f:ea
    # TTL = 120 System Name = lg1.example.com
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[2], datetime.datetime.now())
    ident.harvest(pkts_lldp.RAW[2], flow.packet)

    #*** Ingest a packet from pc1:
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    #*** Classify the packet:
    tc.check_policy(flow, ident)

    #*** Retrieve a classification object for this particular flow:
    clasfn = flow.Classification(flow.packet.flow_hash,
                                    flow.classifications,
                                    flow.classification_time_limit,
                                    logger)

    #*** Unmatched classification state:
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == ""
    assert flow.classification.actions == {}

    #*** Ingest ARP response for pc1 so we know MAC to IP mapping:
    flow.ingest_packet(DPID1, INPORT1, pkts_ARP_2.RAW[1], datetime.datetime.now())
    ident.harvest(pkts_ARP_2.RAW[1], flow.packet)

    #*** Ingest and harvest LLDP Packet 0 (pc1) that should match:
    # 206 08:00:27:2a:d6:dd 01:80:c2:00:00:0e LLDP NoS = 08:00:27:2a:d6:dd
    # TTL = 120 System Name = pc1.example.com
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    ident.harvest(pkts_lldp.RAW[0], flow.packet)

    #*** Ingest a packet from pc1:
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    #*** Classify the packet:
    tc.check_policy(flow, ident)

    #*** Retrieve a classification object for this particular flow:
    clasfn = flow.Classification(flow.packet.flow_hash,
                                    flow.classifications,
                                    flow.classification_time_limit,
                                    logger)

    #*** Matched classification state:
    assert flow.classification.flow_hash == flow.packet.flow_hash
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == "Constrained Bandwidth Traffic"
    assert flow.classification.actions == {'qos_treatment': 'constrained_bw',
                                   'set_desc': 'Constrained Bandwidth Traffic'}

#================= HELPER FUNCTIONS ===========================================

def pkt_test(flow, pkts, pkt_num, flow_packet_count):
    """
    Passed a flow object, packets object, packet number
    from the packets object and the number of unique packets
    in the flow and check parameters match
    """
    assert flow.packet_count() == flow_packet_count
    assert flow.packet.length == pkts.LEN[pkt_num - 1]
    assert flow.packet.eth_src == pkts.ETH_SRC[pkt_num - 1]
    assert flow.packet.eth_dst == pkts.ETH_DST[pkt_num - 1]
    assert flow.packet.eth_type == pkts.ETH_TYPE[pkt_num - 1]
    assert flow.packet.ip_src == pkts.IP_SRC[pkt_num - 1]
    assert flow.packet.ip_dst == pkts.IP_DST[pkt_num - 1]
    assert flow.packet.proto == pkts.PROTO[pkt_num - 1]
    assert flow.packet.tp_src == pkts.TP_SRC[pkt_num - 1]
    assert flow.packet.tp_dst == pkts.TP_DST[pkt_num - 1]
    assert flow.packet.tp_seq_src == pkts.TP_SEQ_SRC[pkt_num - 1]
    assert flow.packet.tp_seq_dst == pkts.TP_SEQ_DST[pkt_num - 1]
    assert flow.packet.tcp_syn() == pkts.TCP_SYN[pkt_num - 1]
    assert flow.packet.tcp_fin() == pkts.TCP_FIN[pkt_num - 1]
    assert flow.packet.tcp_rst() == pkts.TCP_RST[pkt_num - 1]
    assert flow.packet.tcp_psh() == pkts.TCP_PSH[pkt_num - 1]
    assert flow.packet.tcp_ack() == pkts.TCP_ACK[pkt_num - 1]
    assert flow.packet.payload.encode("hex") == pkts.PAYLOAD[pkt_num - 1]
    assert flow.client() == pkts.FLOW_IP_CLIENT
    assert flow.server() == pkts.FLOW_IP_SERVER
    assert flow.packet_direction() == pkts.DIRECTION[pkt_num - 1]
    assert flow.max_packet_size() == max(pkts.LEN[0:pkt_num])

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)

def _ipv4_t2i(ip_text):
    """
    Turns an IPv4 address in text format into an integer.
    Borrowed from rest_router.py code
    """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
