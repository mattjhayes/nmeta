"""
nmeta identities.py Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test -vs

Note that packets + metadata are imported from local packets_* modules

TBD: everything

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
import identities as identities_class

#*** nmeta test packet imports:
import packets_ipv4_ARP as pkts_arp

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#======================== identities.py Unit Tests ============================

def test_harvest_ARP():
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

    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts_arp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_arp.RAW[0], flow)

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
