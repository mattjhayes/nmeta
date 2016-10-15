"""
nmeta flows.py Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test -vs

Note: no testing of max_interpacket_interval and
min_interpacket_interval as they become imprecise due
to floating point and when tried using decimal module
found that would not serialise into Pymongo db.

Note that packets + metadata are imported from packets_for_testing module

TBD duplicate packets (retx / diff switch)
TBD: test flow.tcp_urg(), flow.tcp_ece(), flow.tcp_cwr()
TBD: IPv6 tests
TBD: ARP
TBD: ICMP
TBD: UDP

"""

#*** Handle tests being in different directory branch to app code:
import sys

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

#*** nmeta imports:
import nmeta
import config
import flows as flow_class

#*** nmeta test imports:
import packets_ipv4_http as pkts
import packets_ipv4_http2 as pkts2
import packets_ipv4_tcp_reset as pkts3

#*** Instantiate Config class:
_config = config.Config()

#======================== flow.py Unit Tests ============================
#*** Retrieve values for db connection for flow class to use:
_mongo_addr = _config.get_value("mongo_addr")
_mongo_port = _config.get_value("mongo_port")

logger = logging.getLogger(__name__)

def test_flow_ipv4_http():
    """
    Test ingesting packets from an IPv4 HTTP flow, with a packet
    from a different flow ingested mid-stream.
    This flow is not torn down.
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(pkts.RAW[0])
    eth_src = mac_addr(eth.src)
    assert eth_src == '08:00:27:2a:d6:dd'

    #*** Instantiate a flow object:
    flow = flow_class.Flow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    pkt_test(flow, pkts, 1)

    #*** Test Flow 1 Packet 2 (Server TCP SYN ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[1], datetime.datetime.now())
    pkt_test(flow, pkts, 2)

    #*** Test Flow 1 Packet 3 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[2], datetime.datetime.now())
    pkt_test(flow, pkts, 3)

    #*** Random packet to ensure it doesn't count against flow 1:
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[1], datetime.datetime.now())

    #*** Test Flow 1 Packet 4 (Client to Server HTTP GET):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[3], datetime.datetime.now())
    pkt_test(flow, pkts, 4)

    #*** Test Flow 1 Packet 5 (Server ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[4], datetime.datetime.now())
    pkt_test(flow, pkts, 5)

    #*** Test Flow 1 Packet 6 (Server to Client HTTP 400 Bad Request):
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[5], datetime.datetime.now())
    pkt_test(flow, pkts, 6)

    #*** Test Flow 1 Packet 7 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[6], datetime.datetime.now())
    pkt_test(flow, pkts, 7)

def test_flow_ipv4_http2():
    """
    Test ingesting packets from an IPv4 HTTP flow, with a packet
    from a different flow ingested mid-stream. This flow is a
    successful retrieval of an HTTP object with connection close
    so TCP session nicely torn down with FINs
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Instantiate a flow object:
    flow = flow_class.Flow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 2 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[0], datetime.datetime.now())
    pkt_test(flow, pkts2, 1)

    #*** Test Flow 2 Packet 2 (Server TCP SYN ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[1], datetime.datetime.now())
    pkt_test(flow, pkts2, 2)

    #*** Test Flow 2 Packet 3 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[2], datetime.datetime.now())
    pkt_test(flow, pkts2, 3)

    #*** Random packet to ensure it doesn't count against flow 2:
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[1], datetime.datetime.now())

    #*** Test Flow 2 Packet 4 (Client HTTP GET):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[3], datetime.datetime.now())
    pkt_test(flow, pkts2, 4)

    #*** Test Flow 2 Packet 5 (Server ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[4], datetime.datetime.now())
    pkt_test(flow, pkts2, 5)

    #*** Test Flow 2 Packet 6 (Server HTTP 200 OK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[5], datetime.datetime.now())
    pkt_test(flow, pkts2, 6)

    #*** Test Flow 2 Packet 7 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[6], datetime.datetime.now())
    pkt_test(flow, pkts2, 7)

    #*** Test Flow 2 Packet 8 (Server sends HTML Page to Client):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[7], datetime.datetime.now())
    pkt_test(flow, pkts2, 8)

    #*** Test Flow 2 Packet 9 (Client ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[8], datetime.datetime.now())
    pkt_test(flow, pkts2, 9)

    #*** Test Flow 2 Packet 10 (Server FIN ACK):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[9], datetime.datetime.now())
    pkt_test(flow, pkts2, 10)

    #*** Test Flow 2 Packet 11 (Client FIN ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[10], datetime.datetime.now())
    pkt_test(flow, pkts2, 11)

    #*** Test Flow 2 Packet 12 (Final ACK from Server):
    flow.ingest_packet(DPID1, INPORT2, pkts2.RAW[11], datetime.datetime.now())
    pkt_test(flow, pkts2, 12)

def test_flow_ipv4_tcp_reset():
    """
    Test ingesting packets from an IPv4 TCP flow that is immediately
    shutdown with a TCP RST
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Instantiate a flow object:
    flow = flow_class.Flow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 2 Packet 1 (Client SYN on TCP-81):
    flow.ingest_packet(DPID1, INPORT1, pkts3.RAW[0], datetime.datetime.now())
    pkt_test(flow, pkts3, 1)

    #*** Test Flow 2 Packet 2 (Server RST):
    flow.ingest_packet(DPID1, INPORT2, pkts3.RAW[1], datetime.datetime.now())
    pkt_test(flow, pkts3, 2)


#================= HELPER FUNCTIONS ===========================================

def pkt_test(flow, pkts, pkt_num):
    """
    Passed a flow object, packets object and a packet number
    from the packets object and check parameters match
    """
    assert flow.packet_count() == pkt_num
    assert flow.packet['length'] == pkts.LEN[pkt_num - 1]
    assert flow.packet['ip_src'] == pkts.IP_SRC[pkt_num - 1]
    assert flow.packet['ip_dst'] == pkts.IP_DST[pkt_num - 1]
    assert flow.client() == pkts.FLOW_IP_CLIENT
    assert flow.server() == pkts.FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.PROTO[pkt_num - 1]
    assert flow.packet['tp_src'] == pkts.TP_SRC[pkt_num - 1]
    assert flow.packet['tp_dst'] == pkts.TP_DST[pkt_num - 1]
    assert flow.packet['tp_seq_src'] == pkts.TP_SEQ_SRC[pkt_num - 1]
    assert flow.packet['tp_seq_dst'] == pkts.TP_SEQ_DST[pkt_num - 1]
    assert flow.tcp_syn() == pkts.TCP_SYN[pkt_num - 1]
    assert flow.tcp_fin() == pkts.TCP_FIN[pkt_num - 1]
    assert flow.tcp_rst() == pkts.TCP_RST[pkt_num - 1]
    assert flow.tcp_psh() == pkts.TCP_PSH[pkt_num - 1]
    assert flow.tcp_ack() == pkts.TCP_ACK[pkt_num - 1]
    assert flow.payload.encode("hex") == pkts.PAYLOAD[pkt_num - 1]
    assert flow.packet_direction() == pkts.DIRECTION[pkt_num - 1]
    assert flow.max_packet_size() == max(pkts.LEN[0:pkt_num])

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
