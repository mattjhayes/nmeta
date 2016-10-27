"""
nmeta tc_identity.py Unit Tests

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
import tc_identity

#*** nmeta test packet imports:
import packets_ipv4_ARP as pkts_arp
import packets_ipv4_DHCP_firsttime as pkts_dhcp
import packets_lldp as pkts_lldp
import packets_dns as pkts_dns

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#======================== tc_identity.py Tests ================================

def test_LLDP_identity():
    """
    Test harvesting identity metadata from LLDP packets and then
    using this to validate an identity
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    INPORT1 = 1

    #*** Instantiate class objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)
    tc_ident = tc_identity.IdentityInspect(config)

    #*** LLDP packet 0:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)
    result_identity = identities.findbynode(pkts_lldp.LLDP_SYSTEM_NAME[0])
    assert result_identity['host_name'] == pkts_lldp.LLDP_SYSTEM_NAME[0]
    assert result_identity['host_desc'] == pkts_lldp.LLDP_SYSTEM_DESC[0]
    assert result_identity['dpid'] == DPID1
    assert result_identity['in_port'] == INPORT1
    assert result_identity['mac_address'] == pkts_lldp.ETH_SRC[0]
    assert result_identity['harvest_type'] == 'LLDP'
    #*** Test tc_identity (foo should fail)
    assert tc_ident.check_identity("identity_lldp_systemname", "foo", flow.packet,
                        identities) == False
    #*** Test tc_identity (pc1.example.com should match)
    assert tc_ident.check_identity("identity_lldp_systemname", "pc1.example.com",
                        flow.packet, identities) == True
    #*** Test tc_identity regular expression (*.example.com should match)
    assert tc_ident.check_identity("identity_lldp_systemname_re", "^.*\.example\.com",
                        flow.packet, identities) == True
    #*** Test tc_identity regular expression (pc1.* should match)
    assert tc_ident.check_identity("identity_lldp_systemname_re", "^pc1\.*",
                        flow.packet, identities) == True
    #*** Test tc_identity regular expression (*.example.org should fail)
    assert tc_ident.check_identity("identity_lldp_systemname_re", "^.*\.example\.org",
                        flow.packet, identities) == False
#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
