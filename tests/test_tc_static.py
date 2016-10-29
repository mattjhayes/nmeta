"""
nmeta tc_static.py Tests

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
import tc_static as tc_static_module

#*** nmeta test packet imports:
import packets_ipv4_http as pkts

#*** Instantiate Config class:
config = config.Config()

#*** Instantiate StaticInspect class:
tc_static = tc_static_module.StaticInspect(config)

logger = logging.getLogger(__name__)

#======================== tc_identity.py Tests ================================

def test_check_static():
    """
    Test check_static method
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    INPORT1 = 1

    #*** Instantiate class object:
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    assert tc_static.check_static('eth_src', pkts.ETH_SRC[0], flow.packet) == True
    assert tc_static.check_static('eth_src', pkts.ETH_DST[0], flow.packet) == False
    assert tc_static.check_static('eth_dst', pkts.ETH_DST[0], flow.packet) == True
    assert tc_static.check_static('eth_dst', pkts.ETH_SRC[0], flow.packet) == False
    assert tc_static.check_static('eth_type', pkts.ETH_TYPE[0], flow.packet) == True
    assert tc_static.check_static('eth_type', 2054, flow.packet) == False
    assert tc_static.check_static('ip_src', pkts.IP_SRC[0], flow.packet) == True
    assert tc_static.check_static('ip_src', pkts.IP_DST[0], flow.packet) == False
    assert tc_static.check_static('ip_dst', pkts.IP_DST[0], flow.packet) == True
    assert tc_static.check_static('ip_dst', pkts.IP_SRC[0], flow.packet) == False
    assert tc_static.check_static('tcp_src', pkts.TP_SRC[0], flow.packet) == True
    assert tc_static.check_static('tcp_src', pkts.TP_DST[0], flow.packet) == False
    assert tc_static.check_static('tcp_dst', pkts.TP_DST[0], flow.packet) == True
    assert tc_static.check_static('tcp_dst', pkts.TP_SRC[0], flow.packet) == False

    # TBD check UDP

#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
