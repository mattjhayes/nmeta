"""
nmeta tc_identity.py Tests

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
import flows as flows_module
import identities as identities_module
import policy as policy_module
import tc_identity

#*** nmeta test packet imports:
import packets_ipv4_ARP as pkts_arp
import packets_ipv4_DHCP_firsttime as pkts_dhcp
import packets_lldp as pkts_lldp
import packets_ipv4_dns as pkts_dns
import packets_ipv4_dns_4 as pkts_dns4
import packets_ipv4_tcp_facebook as pkts_facebook
import packets_ipv4_http as pkts_http_pc1
import packets_ipv4_http_lg1 as pkts_http_lg1

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#*** Test DPIDs and in ports:
DPID1 = 1
INPORT1 = 1
INPORT2 = 2

#======================== tc_identity.py Tests ================================

def test_LLDP_identity():
    """
    Test harvesting identity metadata from LLDP packets and then
    using this to validate an identity
    """
    #*** Instantiate class objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)
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
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname'
    classifier_result.policy_value = 'foo'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** Test tc_identity (pc1.example.com should match)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname'
    classifier_result.policy_value = 'pc1.example.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Test tc_identity regular expression (*.example.com should match)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname_re'
    classifier_result.policy_value = '^.*\.example\.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Test tc_identity regular expression (pc1.* should match)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname_re'
    classifier_result.policy_value = '^pc1\.*'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Test tc_identity regular expression (*.example.org should fail)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname_re'
    classifier_result.policy_value = '^.*\.example\.org'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** LLDP packet 1 - test time-based invalidity of stale data
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[1], datetime.datetime.now() - datetime.timedelta(seconds=125))
    identities.harvest(pkts_lldp.RAW[1], flow.packet)

    #*** Test tc_identity (sw1.example.com shouldn't match as data is stale as past LLDP TTL)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname'
    classifier_result.policy_value = 'sw1.example.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** Reingest with current time to check it does work
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[1], flow.packet)

    #*** Test tc_identity (sw1.example.com should match as data is no longer stale)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_lldp_systemname'
    classifier_result.policy_value = 'sw1.example.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

def test_DHCP_identity():
    """
    Test harvesting identity metadata from DHCP packets and then
    using this to validate an identities against the learnt DHCP hostname
    """
    #*** Instantiate class objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)
    tc_ident = tc_identity.IdentityInspect(config)

    #*** Ingest packet from pc1:
    flow.ingest_packet(DPID1, INPORT1, pkts_http_pc1.RAW[0], datetime.datetime.now())

    #*** Test tc_identity (pc1 should fail as haven't harvested DHCP yet)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_dhcp_hostname'
    classifier_result.policy_value = 'pc1'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** Harvesting DHCP host name for pc1 against IP 10.1.0.1
    #*** Client to Server DHCP Request (DHCP Option 12 host name is pc1):
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[2], flow.packet)
    #*** Server to Client DHCP ACK:
    flow.ingest_packet(DPID1, INPORT2, pkts_dhcp.RAW[3], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[3], flow.packet)

    #*** Ingest packet from pc1:
    flow.ingest_packet(DPID1, INPORT1, pkts_http_pc1.RAW[0], datetime.datetime.now())

    #*** Test tc_identity (pc1 should pass)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_dhcp_hostname'
    classifier_result.policy_value = 'pc1'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Ingest packet *to* pc1:
    flow.ingest_packet(DPID1, INPORT2, pkts_http_pc1.RAW[1], datetime.datetime.now())

    #*** Test tc_identity (pc1 should pass)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_dhcp_hostname'
    classifier_result.policy_value = 'pc1'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Ingest packet from lg1:
    flow.ingest_packet(DPID1, INPORT1, pkts_http_lg1.RAW[0], datetime.datetime.now())

    #*** Test tc_identity (pc1 should fail, as packet is from lg1)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_dhcp_hostname'
    classifier_result.policy_value = 'pc1'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** Ingest packet from pc1:
    flow.ingest_packet(DPID1, INPORT1, pkts_http_pc1.RAW[0], datetime.datetime.now())

    #*** Test tc_identity (Regex pc.* should pass)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_dhcp_hostname_re'
    classifier_result.policy_value = 'pc.*'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Test tc_identity (Regex ac.* should fail)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_dhcp_hostname_re'
    classifier_result.policy_value = 'ac.*'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

def test_DNS_identity():
    """
    Test harvesting identity metadata from DNS packets and then
    using this to validate an identity
    """
    #*** Instantiate class objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)
    tc_ident = tc_identity.IdentityInspect(config)
    #*** DNS packet 1 (NAME to CNAME, then second answer with IP for CNAME):
    flow.ingest_packet(DPID1, INPORT1, pkts_dns.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_dns.RAW[1], flow.packet)
    result_identity = identities.findbyservice(pkts_dns.DNS_NAME[1])
    assert result_identity['service_name'] == pkts_dns.DNS_NAME[1]
    assert result_identity['service_alias'] == pkts_dns.DNS_CNAME[1]
    result_identity = identities.findbyservice(pkts_dns.DNS_CNAME[1])
    assert result_identity['service_name'] == pkts_dns.DNS_CNAME[1]
    assert result_identity['ip_address'] == pkts_dns.DNS_IP[1]

    #*** Ingest TCP SYN to www.facebook.com (CNAME star-mini.c10r.facebook.com,
    #*** IP 179.60.193.36)
    flow.ingest_packet(DPID1, INPORT1, pkts_facebook.RAW[0], datetime.datetime.now())

    #*** Test tc_identity (foo should fail)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_service_dns'
    classifier_result.policy_value = 'foo'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** Test tc_identity (www.facebook.com should pass)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_service_dns'
    classifier_result.policy_value = 'www.facebook.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Now, harvest another DNS packet with different A record for
    #*** www.facebook.com (CNAME star-mini.c10r.facebook.com A 31.13.95.36):
    flow.ingest_packet(DPID1, INPORT1, pkts_dns4.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_dns4.RAW[1], flow.packet)

    #*** Ingest TCP SYN to www.facebook.com (CNAME star-mini.c10r.facebook.com,
    #*** IP 179.60.193.36)
    flow.ingest_packet(DPID1, INPORT1, pkts_facebook.RAW[0], datetime.datetime.now())

    #*** Test tc_identity (www.facebook.com, should pass even though there's
    #*** another A record against the CNAME, i.e. should handle one to many)
    #*** Test tc_identity (www.facebook.com should pass)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_service_dns'
    classifier_result.policy_value = 'www.facebook.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Test regular expression match of previous test:
    #*** Test tc_identity (www.facebook.com should pass)
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_service_dns_re'
    classifier_result.policy_value = '^.*\.facebook\.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

    #*** Test regular expression that shouldn't match:
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_service_dns_re'
    classifier_result.policy_value = '^.*\.facebook\.org'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == False

    #*** Ingest TCP SYN+ACK from www.facebook.com (CNAME star-mini.c10r.facebook.com,
    #*** IP 179.60.193.36) to test matching on source IP address:
    flow.ingest_packet(DPID1, INPORT1, pkts_facebook.RAW[1], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'identity_service_dns'
    classifier_result.policy_value = 'www.facebook.com'
    tc_ident.check_identity(classifier_result, flow.packet, identities)
    assert classifier_result.match == True

#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
