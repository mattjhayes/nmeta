"""
nmeta api_external.py Unit Tests

Note that packets + metadata are imported from local packets_* modules

Tests are written for particular Eve Domains (i.e. REST API resources)

TBD: Everything...

"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta')

import logging

import time

#*** JSON imports:
import json
from json import JSONEncoder

import binascii

#*** For timestamps:
import datetime

#*** nmeta imports:
import config
import flows as flow_class
import identities as identities_class
import api_external
import tc_policy
import tc_identity

#*** nmeta test packet imports:
import packets_ipv4_http as pkts
import packets_lldp as pkts_lldp
import packets_ipv4_ARP as pkts_arp
import packets_ipv4_DHCP_firsttime as pkts_dhcp
import packets_ipv4_dns as pkts_dns

#*** Ryu imports:
from ryu.base import app_manager  # To suppress cyclic import
from ryu.controller import controller
from ryu.controller import handler
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_protocol
from ryu.ofproto import ofproto_parser
from ryu.lib import addrconv

#*** Import library to do HTTP GET requests:
import requests

#*** Multiprocessing:
import multiprocessing

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

URL_TEST_I_C_PI_RATE = \
                 'http://localhost:8081/v1/infrastructure/controllers/pi_rate/'

URL_TEST_IDENTITIES = 'http://localhost:8081/v1/identities/'

URL_TEST_IDENTITIES_UI = 'http://localhost:8081/v1/identities/ui/'

#*** Test DPIDs and in ports:
DPID1 = 1
INPORT1 = 1
INPORT2 = 2

#*** Instantiate the ExternalAPI class:
api = api_external.ExternalAPI(config)

#======================== api_external.py Unit Tests ==========================

def test_response_pi_rate():
    """
    Test ingesting packets from an IPv4 HTTP flow, and check packet-in rate
    is as expected at various points
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()

    #*** Sleep to allow api_external to start fully:
    time.sleep(.5)

    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_I_C_PI_RATE)

    #*** Assumes pi_rate calculated as 10 second average rate:
    assert api_result['pi_rate'] == 0.1

    #*** Ingest two more packets:
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[1], datetime.datetime.now())
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[2], datetime.datetime.now())

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_I_C_PI_RATE)

    #*** Assumes pi_rate calculated as 10 second average rate:
    assert api_result['pi_rate'] == 0.3

    #*** Stop api_external sub-process:
    api_ps.terminate()

def test_identities():
    """
    Harvest identity data and test that the identities API resource
    returns the correct information
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()

    #*** Sleep to allow api_external to start fully:
    time.sleep(.5)

    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Ingest LLDP from pc1
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_IDENTITIES)

    logger.debug("api_result=%s", api_result)

    #*** Test identity results for first LDAP packet:
    assert api_result['_items'][0]['host_name'] == 'pc1.example.com'
    assert api_result['_items'][0]['harvest_type'] == 'LLDP'
    assert api_result['_items'][0]['mac_address'] == '08:00:27:2a:d6:dd'
    assert len(api_result['_items']) == 1

    #*** Ingest LLDP from sw1:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[1], flow.packet)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_IDENTITIES)

    logger.debug("api_result=%s", api_result)

    #*** Test identity results for second LDAP packet:
    assert api_result['_items'][0]['host_name'] == 'sw1.example.com'
    assert api_result['_items'][0]['harvest_type'] == 'LLDP'
    assert api_result['_items'][0]['mac_address'] == '08:00:27:f7:25:13'
    assert len(api_result['_items']) == 2

    #*** Ingest LLDP from pc1 (again, to test deduplication):
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_IDENTITIES)

    logger.debug("api_result=%s", api_result)

    #*** Test identity results for first LDAP packet:
    assert api_result['_items'][0]['host_name'] == 'pc1.example.com'
    assert api_result['_items'][0]['harvest_type'] == 'LLDP'
    assert api_result['_items'][0]['mac_address'] == '08:00:27:2a:d6:dd'
    #*** Should be 3 as no deduplication of the pc1 identities:
    assert len(api_result['_items']) == 3

    #*** Stop api_external sub-process:
    api_ps.terminate()

def test_identities_ui():
    """
    Harvest identity data and test that the identities/ui API resource
    returns the correct information.
    The identities/ui resource does deduplication, so test that this
    works correctly
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()

    #*** Sleep to allow api_external to start fully:
    time.sleep(.5)

    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Ingest LLDP from pc1
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_IDENTITIES_UI)

    logger.debug("api_result=%s", api_result)

    #*** Test identity results for first LDAP packet:
    assert api_result['_items'][0]['host_name'] == 'pc1.example.com'
    assert api_result['_items'][0]['harvest_type'] == 'LLDP'
    assert api_result['_items'][0]['mac_address'] == '08:00:27:2a:d6:dd'
    assert len(api_result['_items']) == 1

    #*** Ingest LLDP from sw1:
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[1], flow.packet)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_IDENTITIES_UI)

    logger.debug("api_result=%s", api_result)

    #*** Test identity results for second LDAP packet:
    assert api_result['_items'][0]['host_name'] == 'sw1.example.com'
    assert api_result['_items'][0]['harvest_type'] == 'LLDP'
    assert api_result['_items'][0]['mac_address'] == '08:00:27:f7:25:13'
    assert len(api_result['_items']) == 2

    #*** Ingest LLDP from pc1 (again, to test deduplication):
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_IDENTITIES_UI)

    logger.debug("api_result=%s", api_result)

    #*** Test identity results for first LDAP packet:
    assert api_result['_items'][0]['host_name'] == 'pc1.example.com'
    assert api_result['_items'][0]['harvest_type'] == 'LLDP'
    assert api_result['_items'][0]['mac_address'] == '08:00:27:2a:d6:dd'
    #*** Should be 2, not 3, as has deduplicated the pc1 identities:
    assert len(api_result['_items']) == 2

    #*** Stop api_external sub-process:
    api_ps.terminate()

def test_flow_normalise_direction():
    """
    Test normalising direction of flow.
    Pass a dictionary of an identity record check return a similar
    dictionary that has sources and destinations normalised to the
    direction of the first observed packet in the flow
    """
    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 0 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    original_record = flow.packet.dbdict()
    assert original_record['ip_src'] == pkts.IP_SRC[0]
    assert original_record['ip_dst'] == pkts.IP_DST[0]
    assert original_record['tp_src'] == pkts.TP_SRC[0]
    assert original_record['tp_dst'] == pkts.TP_DST[0]
    normalised_record = api.flow_normalise_direction(original_record)
    assert normalised_record['ip_src'] == pkts.IP_SRC[0]
    assert normalised_record['ip_dst'] == pkts.IP_DST[0]
    assert normalised_record['tp_src'] == pkts.TP_SRC[0]
    assert normalised_record['tp_dst'] == pkts.TP_DST[0]

    #*** Test Flow 1 Packet 1 (Server TCP SYN ACK). This should be transposed:
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[1], datetime.datetime.now())
    original_record = flow.packet.dbdict()
    assert original_record['ip_src'] == pkts.IP_SRC[1]
    assert original_record['ip_dst'] == pkts.IP_DST[1]
    assert original_record['tp_src'] == pkts.TP_SRC[1]
    assert original_record['tp_dst'] == pkts.TP_DST[1]
    normalised_record = api.flow_normalise_direction(original_record)
    assert normalised_record['ip_src'] == pkts.IP_DST[1]
    assert normalised_record['ip_dst'] == pkts.IP_SRC[1]
    assert normalised_record['tp_src'] == pkts.TP_DST[1]
    assert normalised_record['tp_dst'] == pkts.TP_SRC[1]


def test_get_flow_data_xfer():
    """
    Test the get_flow_data_xfer method.

    Synthesise flow removal messages to test with.
    """
    #*** Supports OpenFlow version 1.3:
    OFP_VERSION = ofproto_v1_3.OFP_VERSION

    #*** Instantiate Flow class:
    flow = flow_class.Flow(config)
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    flow.ingest_packet(DPID1, INPORT2, pkts.RAW[1], datetime.datetime.now())

    #*** Load JSON representations of flow removed messages:
    with open('OFPMsgs/OFPFlowRemoved_1.json', 'r') as json_file:
        json_str_tx = json_file.read()
        json_dict_tx = json.loads(json_str_tx)
    with open('OFPMsgs/OFPFlowRemoved_2.json', 'r') as json_file:
        json_str_rx = json_file.read()
        json_dict_rx = json.loads(json_str_rx)

    #*** Set up fake datapath and synthesise messages:
    datapath = ofproto_protocol.ProtocolDesc(version=OFP_VERSION)
    datapath.id = 1
    msg_tx = ofproto_parser.ofp_msg_from_jsondict(datapath, json_dict_tx)
    msg_rx = ofproto_parser.ofp_msg_from_jsondict(datapath, json_dict_rx)

    logger.debug("msg_tx=%s", msg_tx)

    #*** Record flow removals to flow_rems database collection:
    flow.record_removal(msg_tx)
    flow.record_removal(msg_rx)

    #*** Now, test the get_flow_data_xfer method:

    record = {'ip_src': '10.1.0.1',
              'ip_dst': '10.1.0.2',
              'tp_src': 43297,
              'tp_dst': 80,
              'proto': 6,
              'flow_hash': '9822b2867652ee0957892482b9f004c3'}
    xfer = api.get_flow_data_xfer(record)
    logger.debug("xfer=%s", xfer)

    assert xfer['tx_found'] == 1
    assert xfer['tx_bytes'] == 744
    assert xfer['tx_pkts'] == 10
    assert xfer['rx_found'] == 1
    assert xfer['rx_bytes'] == 6644
    assert xfer['rx_pkts'] == 9

def test_get_dns_ip():
    """
    Test looking up a DNS CNAME to get an IP address
    """
    #*** Instantiate flow and identities objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** DNS packet 1 (NAME to CNAME, then second answer with IP for CNAME):
    flow.ingest_packet(DPID1, INPORT1, pkts_dns.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_dns.RAW[1], flow.packet)

    logger.debug("Testing lookup of CNAME=%s", pkts_dns.DNS_CNAME[1])
    result_ip = api.get_dns_ip(pkts_dns.DNS_CNAME[1])
    assert result_ip == pkts_dns.DNS_IP[1]

def test_get_host_by_ip():
    """
    Test get_host_by_ip
    """
    #*** Instantiate a flow object:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)

    #*** Ingest ARP reply for MAC of pc1 so can ref later:
    flow.ingest_packet(DPID1, INPORT1, pkts_arp.RAW[3], datetime.datetime.now())
    identities.harvest(pkts_arp.RAW[3], flow.packet)

    #*** Ingest LLDP from pc1
    flow.ingest_packet(DPID1, INPORT1, pkts_lldp.RAW[0], datetime.datetime.now())
    identities.harvest(pkts_lldp.RAW[0], flow.packet)

    #*** Call the get_host_by_ip:
    get_host_by_ip_result = api.get_host_by_ip('10.1.0.1')

    logger.debug("get_host_by_ip_result=%s", get_host_by_ip_result)

    assert get_host_by_ip_result == 'pc1.example.com'

    #*** Test DHCP to host by IP

    #*** Client to Server DHCP Request:
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[2], flow.packet)

    #*** Server to Client DHCP ACK:
    flow.ingest_packet(DPID1, INPORT2, pkts_dhcp.RAW[3], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[3], flow.packet)

    #*** Call the get_host_by_ip:
    get_host_by_ip_result = api.get_host_by_ip('10.1.0.1')

    logger.debug("get_host_by_ip_result=%s", get_host_by_ip_result)

    assert get_host_by_ip_result == 'pc1'

def test_get_service_by_ip():
    """
    Test ability of get_service_by_ip to resolve
    IPs to service names
    """
    #*** Instantiate class objects:
    flow = flow_class.Flow(config)
    identities = identities_class.Identities(config)
    tc_ident = tc_identity.IdentityInspect(config)
    #*** DNS packet 1 (NAME to CNAME, then second answer with IP for CNAME):
    # A www.facebook.com CNAME star-mini.c10r.facebook.com A 179.60.193.36
    flow.ingest_packet(DPID1, INPORT1, pkts_dns.RAW[1], datetime.datetime.now())
    identities.harvest(pkts_dns.RAW[1], flow.packet)

    #*** Call the get_service_by_ip:
    get_service_by_ip_result = api.get_service_by_ip('179.60.193.36')
    logger.debug("get_service_by_ip_result=%s", get_service_by_ip_result)

    assert get_service_by_ip_result == 'www.facebook.com'

def test_get_classification():
    """
    Test get_classification which takes a flow_hash
    and return a dictionary of a classification object
    for the flow_hash (if found), otherwise
    a dictionary of an empty classification object.
    """
    #*** Instantiate classes:
    flow = flow_class.Flow(config)
    ident = identities_class.Identities(config)

    #*** Initial main_policy that matches tcp-80:
    tc = tc_policy.TrafficClassificationPolicy(config,
                        pol_dir_default="config/tests/regression",
                        pol_dir_user="config/tests/foo",
                        pol_filename="main_policy_regression_static_3.yaml")

    #*** Ingest Flow 1 Packet 0 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Classify the packet:
    tc.check_policy(flow, ident)

    logger.debug("pkt0 flow classification is %s", flow.classification.dbdict())

    #*** Write classification result to classifications collection:
    flow.classification.commit()

    #*** Retrieve classification via get_classification and check results:
    clasfn_result = api.get_classification(flow.classification.flow_hash)
    assert clasfn_result['classified'] ==  1
    assert clasfn_result['classification_tag'] ==  "Constrained Bandwidth Traffic"

def test_enumerate_eth_type():
    """
    Test eth_type enumeration
    """
    assert api_external.enumerate_eth_type(2054) == 'ARP'

def test_enumerate_ip_proto():
    """
    Test eth_type enumeration
    """
    assert api_external.enumerate_ip_proto(17) == 'UDP'

def get_api_result(url):
    """
    Retrieve JSON data from API via a supplied URL
    """
    s = requests.Session()
    r = s.get(url)
    return r.json()



