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
import packets_ipv4_DHCP_firsttime as pkts_dhcp

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#======================== identities.py Unit Tests ============================

def test_harvest_ARP():
    """
    Test harvesting identity metadata from an IPv4 ARP reply.
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Server ARP Reply:
    flow.ingest_packet(DPID1, INPORT1, pkts_arp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_arp.RAW[1], flow.packet)
    result_identity = identities.findbymac(pkts_arp.ETH_SRC[1])

    assert result_identity['mac_address'] == pkts_arp.ETH_SRC[1]
    assert result_identity['ip_address'] == '10.1.0.2'

def test_harvest_DHCP():
    """
    Test harvesting identity metadata from an IPv4 DHCP request
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Server DHCP ACK:
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[2], flow.packet)
    result_identity = identities.findbynode('pc1')

    assert result_identity['host_name'] == 'pc1'

#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
