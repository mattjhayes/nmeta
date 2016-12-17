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

#*** nmeta test packet imports:
import packets_ipv4_http as pkts
import packets_lldp as pkts_lldp
import packets_ipv4_ARP as pkts_arp
import packets_ipv4_DHCP_firsttime as pkts_dhcp
import packets_ipv4_dns as pkts_dns

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

def test_i_c_pi_rate():
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



