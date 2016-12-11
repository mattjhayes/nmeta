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
import packets_lldp as pkts_lldp
import packets_ipv4_dns as pkts_dns

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
    INPORT1 = 1

    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Client to Server DHCP Discover:
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[0], flow.packet)

    # BREAK
    assert 1 == 0

    #*** Set ingest time so we can check validity based on lease
    ingest_time = datetime.datetime.now()

    #*** Server DHCP ACK:
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[3], ingest_time)
    identities.harvest(pkts_dhcp.RAW[3], flow.packet)
    result_identity = identities.findbynode('pc1')

    assert result_identity['host_name'] == 'pc1'

    #assert result_identity['valid_to'] == ingest_time + \
    #                               datetime.timedelta(0, identities.)

def test_harvest_LLDP():
    """
    Test harvesting identity metadata from LLDP packets
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Test no result found by checking before LLDP ingestion:
    result_identity = identities.findbynode(pkts_lldp.LLDP_SYSTEM_NAME[0])
    assert result_identity == 0

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

    #*** LLDP packet 1:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[1], flow.packet)
    result_identity = identities.findbynode(pkts_lldp.LLDP_SYSTEM_NAME[1])
    assert result_identity['host_name'] == pkts_lldp.LLDP_SYSTEM_NAME[1]
    assert result_identity['host_desc'] == pkts_lldp.LLDP_SYSTEM_DESC[1]
    assert result_identity['dpid'] == DPID1
    assert result_identity['in_port'] == INPORT1
    assert result_identity['mac_address'] == pkts_lldp.ETH_SRC[1]
    assert result_identity['harvest_type'] == 'LLDP'

    #*** LLDP packet 2:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[2], flow.packet)
    result_identity = identities.findbynode(pkts_lldp.LLDP_SYSTEM_NAME[2])
    assert result_identity['host_name'] == pkts_lldp.LLDP_SYSTEM_NAME[2]
    assert result_identity['host_desc'] == pkts_lldp.LLDP_SYSTEM_DESC[2]
    assert result_identity['dpid'] == DPID1
    assert result_identity['in_port'] == INPORT1
    assert result_identity['mac_address'] == pkts_lldp.ETH_SRC[2]
    assert result_identity['harvest_type'] == 'LLDP'

def test_harvest_DNS():
    """
    Test harvesting identity metadata from DNS packets
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    DPID2 = 2
    INPORT1 = 1
    INPORT2 = 2

    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** DNS packet 1 (NAME to CNAME, then second answer with IP for CNAME):
    flow.ingest_packet(DPID1, INPORT1, pkts_dns.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_dns.RAW[1], flow.packet)
    result_identity = identities.findbyservice(pkts_dns.DNS_NAME[1])
    assert result_identity['service_name'] == pkts_dns.DNS_NAME[1]
    assert result_identity['service_alias'] == pkts_dns.DNS_CNAME[1]
    result_identity = identities.findbyservice(pkts_dns.DNS_CNAME[1])
    assert result_identity['service_name'] == pkts_dns.DNS_CNAME[1]
    assert result_identity['ip_address'] == pkts_dns.DNS_IP[1]

#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
