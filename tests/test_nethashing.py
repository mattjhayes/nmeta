"""
nmeta nethash.py Unit Tests
"""

#*** Handle tests being in different directory branch to app code:
import sys
import struct

sys.path.insert(0, '../nmeta')

#*** For timestamps:
import datetime

import logging

#*** nmeta imports:
import config
import flows
import nethash

#*** nmeta test packet imports:
import packets_ipv4_http as pkts

logger = logging.getLogger(__name__)

#*** Instantiate Config class:
config = config.Config()

#*** Test 5-Tuple:
IP_A = '192.168.0.1'
IP_B = '192.168.0.2'
TP_A = 12345
TP_B = 443
TCP = 6

#*** Test DPIDs and in ports:
DPID1 = 1
DPID2 = 2
INPORT1 = 1
INPORT2 = 2

#======================== nethash.py Unit Tests ============================
def test_hash_flow():
    """
    Test flow counts for packet retransmissions. For flow packets
    (i.e. TCP), all retx should be counted (if from same DPID)

    For non-flow packets, the flow packet count should always be 1
    """
    #*** Test that TCP tuples of packets in both directions on
    #*** a flow generate the same hash:
    hash1 = nethash.hash_flow((IP_A, IP_B, TP_A, TP_B, TCP))
    hash2 = nethash.hash_flow((IP_B, IP_A, TP_B, TP_A, TCP))
    assert hash1 == hash2

def test_hash_packet():
    """
    Test that same flow packet (i.e. TCP) retx adds to count whereas
    retx of non-flow packet has count of 1
    """
    #*** Create a flows packet object:
    flow = flows.Flow(config)
    #*** Ingest Flow 1 Packet 0 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    packet0_hash = nethash.hash_packet(flow.packet)
    #*** Ingest Flow 1 Packet 2 (Client TCP ACK):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[2], datetime.datetime.now())
    packet1_hash = nethash.hash_packet(flow.packet)

    #*** The two packet hashes must be different even though have same 5-tuple:
    assert packet0_hash != packet1_hash



