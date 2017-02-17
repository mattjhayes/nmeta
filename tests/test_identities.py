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
import packets_ipv4_http as pkts
import packets_ipv4_http2 as pkts2

#*** Test DPIDs and in ports:
DPID1 = 1
DPID2 = 2
INPORT1 = 1
INPORT2 = 2

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#======================== identities.py Unit Tests ============================

def test_harvest_ARP():
    """
    Test harvesting identity metadata from an IPv4 ARP reply.
    """
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
    Note: this test is very basic and does not cover much...
    TBD: cover more scenarios and DHCP message types
    """
    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Client to Server DHCP Request:
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[2], flow.packet)
    flow_pkt = flow.packet

    assert identities.dhcp_msg.dpid == DPID1
    assert identities.dhcp_msg.in_port == INPORT1
    assert identities.dhcp_msg.eth_src == flow_pkt.eth_src
    assert identities.dhcp_msg.eth_dst == flow_pkt.eth_dst
    assert identities.dhcp_msg.ip_src == flow_pkt.ip_src
    assert identities.dhcp_msg.ip_dst == flow_pkt.ip_dst
    assert identities.dhcp_msg.tp_src == flow_pkt.tp_src
    assert identities.dhcp_msg.tp_dst == flow_pkt.tp_dst
    assert identities.dhcp_msg.transaction_id == '0xabc5667f'
    assert identities.dhcp_msg.host_name == 'pc1'
    assert identities.dhcp_msg.message_type == 'DHCPREQUEST'

    #*** Server to Client DHCP ACK:
    #*** Set ingest time so we can check validity based on lease
    ingest_time = datetime.datetime.now()
    flow.ingest_packet(DPID1, INPORT2, pkts_dhcp.RAW[3], ingest_time)
    identities.harvest(pkts_dhcp.RAW[3], flow.packet)
    flow_pkt = flow.packet

    assert identities.dhcp_msg.dpid == DPID1
    assert identities.dhcp_msg.in_port == INPORT2
    assert identities.dhcp_msg.eth_src == flow_pkt.eth_src
    assert identities.dhcp_msg.eth_dst == flow_pkt.eth_dst
    assert identities.dhcp_msg.ip_src == flow_pkt.ip_src
    assert identities.dhcp_msg.ip_dst == flow_pkt.ip_dst
    assert identities.dhcp_msg.tp_src == flow_pkt.tp_src
    assert identities.dhcp_msg.tp_dst == flow_pkt.tp_dst
    assert identities.dhcp_msg.transaction_id == '0xabc5667f'
    assert identities.dhcp_msg.host_name == ''
    assert identities.dhcp_msg.ip_assigned == '10.1.0.1'
    assert identities.dhcp_msg.message_type == 'DHCPACK'
    assert identities.dhcp_msg.lease_time == 300

    result_identity = identities.findbynode('pc1')
    logger.debug("result_identity=%s", result_identity)
    assert result_identity['mac_address'] == pkts_dhcp.ETH_SRC[2]
    assert result_identity['ip_address'] == '10.1.0.1'


def test_harvest_LLDP():
    """
    Test harvesting identity metadata from LLDP packets
    """
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

def test_indexing():
    """
    Test indexing of identities collection

    Ensure database indexing is working efficiently by harvesting
    various bits of identity metadata into identities collection
    then test how well queries perform against it to

    """
    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    flow.ingest_packet(DPID1, INPORT2, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)

    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[1], flow.packet)

    flow.ingest_packet(DPID1, INPORT1, pkts_arp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_arp.RAW[1], flow.packet)

    flow.ingest_packet(DPID1, INPORT1, pkts_arp.RAW[3], datetime.datetime.now())
    identities.harvest(pkts_arp.RAW[3], flow.packet)

    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[2], flow.packet)

    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[3], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[3], flow.packet)

    flow.ingest_packet(DPID1, INPORT1, pkts_dns.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_dns.RAW[1], flow.packet)

    #*** Test identities collection indexing...
    #*** Check correct number of documents in packet_ins collection:
    assert identities.identities.count() == 7

    #*** Get findbymac query execution statistics:
    #*** Retrieve an explain of identities findbymac database query:
    explain = identities.findbymac(pkts2.ETH_SRC[1], test=1)
    #*** Check an index is used:
    assert explain['queryPlanner']['winningPlan']['inputStage']['stage'] == 'FETCH'
    #*** Check how query ran:
    assert explain['executionStats']['executionSuccess'] == True
    assert explain['executionStats']['nReturned'] == 1
    assert explain['executionStats']['totalKeysExamined'] == 1
    assert explain['executionStats']['totalDocsExamined'] == 1

    #*** Get findbynode query execution statistics:
    #*** Retrieve an explain of identities findbynode database query:
    explain = identities.findbynode('pc1', test=1)
    #*** Check an index is used:
    assert explain['queryPlanner']['winningPlan']['inputStage']['stage'] == 'FETCH'
    #*** Check how query ran:
    assert explain['executionStats']['executionSuccess'] == True
    assert explain['executionStats']['nReturned'] == 1
    assert explain['executionStats']['totalKeysExamined'] == 1
    assert explain['executionStats']['totalDocsExamined'] == 1

    #*** Retrieve an explain of identities findbynode database query with
    #*** harvest_type option set:
    explain = identities.findbynode('pc1', harvest_type='DHCP', test=1)
    #*** Check an index is used:
    assert explain['queryPlanner']['winningPlan']['inputStage']['stage'] == 'FETCH'
    #*** Check how query ran:
    assert explain['executionStats']['executionSuccess'] == True
    assert explain['executionStats']['nReturned'] == 1
    assert explain['executionStats']['totalKeysExamined'] == 1
    assert explain['executionStats']['totalDocsExamined'] == 1

    #*** Get findbyservice query execution statistics:
    #*** Retrieve an explain of identities findbyservice database query:
    explain = identities.findbyservice(pkts_dns.DNS_NAME[1], test=1)
    #*** Check an index is used:
    assert explain['queryPlanner']['winningPlan']['inputStage']['stage'] == 'FETCH'
    #*** Check how query ran:
    assert explain['executionStats']['executionSuccess'] == True
    assert explain['executionStats']['nReturned'] == 1
    assert explain['executionStats']['totalKeysExamined'] == 1
    assert explain['executionStats']['totalDocsExamined'] == 1

#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
