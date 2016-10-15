"""
nmeta flows.py Unit Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test -vs

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
import packets_for_testing as pkts

#*** Instantiate Config class:
_config = config.Config()

#======================== flow.py Unit Tests ============================
#*** Retrieve values for db connection for flow class to use:
_mongo_addr = _config.get_value("mongo_addr")
_mongo_port = _config.get_value("mongo_port")

logger = logging.getLogger(__name__)

#*** Test Switches and Switch classes that abstract OpenFlow switches:
def test_flow_ipv4_http():
    """
    Test ingesting packets from an IPv4 HTTP flow, with a packet
    from a different flow ingested mid-stream.

    Note: no testing of max_interpacket_interval and
    min_interpacket_interval as they become imprecise due
    to floating point and when tried using decimal module
    found that would not serialise into Pymongo db.

    Note that packets + metadata are imported from packets_for_testing module
    """

    #*** Flow 2 TCP SYN used to test flow separation:
    # 10.1.0.1 10.1.0.2 TCP 74 43300 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=7498808 TSecr=0 WS=64
    flow2_pkt1 = binascii.unhexlify("080027c8db910800272ad6dd08004510003c23df4000400602c90a0100010a010002a9240050ab094fe700000000a002721014330000020405b40402080a00726c380000000001030306")
    flow2_pkt1_timestamp = datetime.datetime.now()

    #*** Flow 3 TCP FIN + ACK used to test flags:
    # 10.1.0.2 10.1.0.1 TCP 66 http > 43302 [FIN, ACK] Seq=733 Ack=20 Win=28992 Len=0 TSval=9412661 TSecr=9417590
    flow3_pkt1 = binascii.unhexlify("0800272ad6dd080027c8db910800450000349e9a4000400688250a0100020a0100010050a92674c00c0659c96b07801101c51d1b00000101080a008fa035008fb376")
    flow3_pkt1_timestamp = datetime.datetime.now()

    #*** Flow 4 TCP RST + ACK used to test flags:
    # 10.1.0.2 10.1.0.1 TCP 60 81 > 38331 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
    flow4_pkt1 = binascii.unhexlify("0800272ad6dd080027c8db91080045100028f819400040062ea20a0100020a010001005195bb0000000051a9e82350140000cbf20000000000000000")
    flow4_pkt1_timestamp = datetime.datetime.now()

    #*** Packet lengths for flow 1 on the wire (null value for index 0):
    pkt_len = [0, 74, 74, 66, 71, 66, 162, 66]

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    IN_PORT1 = 1
    IN_PORT2 = 2

    #*** Sanity check can read into dpkt:
    eth = dpkt.ethernet.Ethernet(pkts.IPv4_HTTP[0])
    eth_src = mac_addr(eth.src)
    assert eth_src == '08:00:27:2a:d6:dd'

    #*** Instantiate a flow object:
    flow = flow_class.Flow(logger, _mongo_addr, _mongo_port)

    #*** Test Flow 1 Packet 1:
    flow.ingest_packet(DPID1, IN_PORT1, pkts.IPv4_HTTP[0], datetime.datetime.now())
    assert flow.packet_count() == 1
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[0]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[0]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[0]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[0]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[0]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[0]
    assert flow.packet['tp_seq_src'] == 3279048914
    assert flow.packet['tp_seq_dst'] == 0
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[0]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[0]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[0]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[0]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[0]
    assert flow.payload == ""
    assert flow.packet_direction() == 'c2s'
    assert flow.max_packet_size() == max(pkt_len[0:2])

    #*** Test Flow 1 Packet 2:
    flow.ingest_packet(DPID1, IN_PORT2, pkts.IPv4_HTTP[1],
                                                    datetime.datetime.now())
    assert flow.packet_count() == 2
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[1]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[1]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[1]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[1]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[1]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[1]
    assert flow.packet['tp_seq_src'] == 2656869785
    assert flow.packet['tp_seq_dst'] == 3279048915
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[1]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[1]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[1]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[1]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[1]
    assert flow.payload == ""
    assert flow.packet_direction() == 's2c'
    assert flow.max_packet_size() == max(pkt_len[0:3])

    #*** Test Flow 1 Packet 3:
    flow.ingest_packet(DPID1, IN_PORT1, pkts.IPv4_HTTP[2],
                                                    datetime.datetime.now())
    assert flow.packet_count() == 3
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[2]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[2]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[2]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[2]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[2]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[2]
    assert flow.packet['tp_seq_src'] == 3279048915
    assert flow.packet['tp_seq_dst'] == 2656869786
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[2]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[2]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[2]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[2]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[2]
    assert flow.payload == ""
    assert flow.packet_direction() == 'c2s'
    assert flow.max_packet_size() == max(pkt_len[0:4])

    #*** Random packet to ensure it doesn't count against flow 1:
    flow.ingest_packet(DPID1, IN_PORT1, flow2_pkt1, flow2_pkt1_timestamp)

    #*** Test Flow 1 Packet 4:
    flow.ingest_packet(DPID1, IN_PORT1, pkts.IPv4_HTTP[3],
                                                    datetime.datetime.now())
    assert flow.packet_count() == 4
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[3]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[3]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[3]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[3]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[3]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[3]
    assert flow.packet['tp_seq_src'] == 3279048915
    assert flow.packet['tp_seq_dst'] == 2656869786
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[3]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[3]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[3]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[3]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[3]
    assert flow.payload == "GET\r\n"
    assert flow.packet_direction() == 'c2s'
    assert flow.max_packet_size() == max(pkt_len[0:5])

    #*** Test Flow 1 Packet 5:
    flow.ingest_packet(DPID1, IN_PORT1, pkts.IPv4_HTTP[4],
                                                    datetime.datetime.now())
    assert flow.packet_count() == 5
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[4]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[4]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[4]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[4]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[4]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[4]
    assert flow.packet['tp_seq_src'] == 2656869786
    assert flow.packet['tp_seq_dst'] == 3279048920
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[4]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[4]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[4]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[4]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[4]
    assert flow.payload == ""
    assert flow.packet_direction() == 's2c'
    assert flow.max_packet_size() == max(pkt_len[0:6])

    #*** Test Flow 1 Packet 6:
    flow.ingest_packet(DPID1, IN_PORT1, pkts.IPv4_HTTP[5],
                                                    datetime.datetime.now())
    assert flow.packet_count() == 6
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[5]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[5]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[5]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[5]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[5]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[5]
    assert flow.packet['tp_seq_src'] == 2656869786
    assert flow.packet['tp_seq_dst'] == 3279048920
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[5]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[5]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[5]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[5]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[5]
    assert flow.payload.encode("hex") == "485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65"
    assert flow.packet_direction() == 's2c'
    assert flow.max_packet_size() == max(pkt_len[0:7])

    #*** Test Flow 1 Packet 7:
    flow.ingest_packet(DPID1, IN_PORT1, pkts.IPv4_HTTP[6],
                                                    datetime.datetime.now())
    assert flow.packet_count() == 7
    assert flow.packet['length'] == pkts.IPv4_HTTP_LEN[6]
    assert flow.packet['ip_src'] == pkts.IPv4_HTTP_IP_SRC[6]
    assert flow.packet['ip_dst'] == pkts.IPv4_HTTP_IP_DST[6]
    assert flow.client() == pkts.IPv4_HTTP_FLOW_IP_CLIENT
    assert flow.server() == pkts.IPv4_HTTP_FLOW_IP_SERVER
    assert flow.packet['proto'] == pkts.IPv4_HTTP_PROTO[6]
    assert flow.packet['tp_src'] == pkts.IPv4_HTTP_TP_SRC[6]
    assert flow.packet['tp_dst'] == pkts.IPv4_HTTP_TP_DST[6]
    assert flow.packet['tp_seq_src'] == 3279048920
    assert flow.packet['tp_seq_dst'] == 2656869882
    assert flow.tcp_syn() == pkts.IPv4_HTTP_TCP_SYN[6]
    assert flow.tcp_fin() == pkts.IPv4_HTTP_TCP_FIN[6]
    assert flow.tcp_rst() == pkts.IPv4_HTTP_TCP_RST[6]
    assert flow.tcp_psh() == pkts.IPv4_HTTP_TCP_PSH[6]
    assert flow.tcp_ack() == pkts.IPv4_HTTP_TCP_ACK[6]
    assert flow.payload == ""
    assert flow.packet_direction() == 'c2s'
    assert flow.max_packet_size() == max(pkt_len)

    #*** Test Flow 3 packet for TCP FIN flag:
    flow.ingest_packet(DPID1, IN_PORT1, flow3_pkt1, flow3_pkt1_timestamp)
    assert flow.tcp_fin() == 1
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 0
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 1

    #*** Test Flow 4 packet for TCP RST flag:
    flow.ingest_packet(DPID1, IN_PORT1, flow4_pkt1, flow4_pkt1_timestamp)
    assert flow.tcp_fin() == 0
    assert flow.tcp_syn() == 0
    assert flow.tcp_rst() == 1
    assert flow.tcp_psh() == 0
    assert flow.tcp_ack() == 1
    assert flow.client() == '10.1.0.2'
    assert flow.server() == '10.1.0.1'
    assert flow.packet_direction() == 'c2s'

    #*** TBD: test flow.tcp_urg(), flow.tcp_ece(), flow.tcp_cwr()
    #*** TBD: IPv6 tests
    #*** TBD: ARP
    #*** TBD: ICMP
    #*** TBD: UDP

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
