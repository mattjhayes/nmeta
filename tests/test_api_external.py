"""
nmeta api_external.py Unit Tests

Note that packets + metadata are imported from local packets_* modules

Tests are written for particular Eve Domains (i.e. REST API resources)

TBD: Everything...

"""

#*** Handle tests being in different directory branch to app code:
import sys
import struct

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
import flows as flows_module
import identities as identities_module
import api_external
import policy as policy_module
import tc_identity

#*** nmeta test packet imports:
import packets_ipv4_http as pkts
import packets_lldp as pkts_lldp
import packets_ipv4_ARP as pkts_arp
import packets_ipv4_DHCP_firsttime as pkts_dhcp
import packets_ipv4_dns as pkts_dns
import packets_ipv4_ARP_2 as pkts_ARP_2

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

URL_FLOW_MODS = 'http://localhost:8081/v1/flow_mods/'

URL_TEST_FLOWS_REMOVED = 'http://localhost:8081/v1/flows_removed/'

URL_TEST_FLOWS_REMOVED_STATS_COUNT = 'http://localhost:8081/v1/flows_removed/stats/count'

URL_TEST_FLOWS_REMOVED_SRC_BYTES_SENT = 'http://localhost:8081/v1/flows_removed/stats/src_bytes_sent'

URL_TEST_FLOWS_REMOVED_SRC_BYTES_RECEIVED = 'http://localhost:8081/v1/flows_removed/stats/src_bytes_received'

URL_TEST_FLOWS_REMOVED_DST_BYTES_SENT = 'http://localhost:8081/v1/flows_removed/stats/dst_bytes_sent'

URL_TEST_FLOWS_REMOVED_DST_BYTES_RECEIVED = 'http://localhost:8081/v1/flows_removed/stats/dst_bytes_received'


#*** Test DPIDs and in ports:
DPID1 = 1
INPORT1 = 1
INPORT2 = 2

#*** Instantiate the ExternalAPI class:
api = api_external.ExternalAPI(config)

#======================== api_external.py Unit Tests ==========================

def test_flows_removed():
    """
    Test the flows_removed API by ingesting flow removal messages
    then checking that the API response correctly lists them
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()
    
    #*** Supports OpenFlow version 1.3:
    OFP_VERSION = ofproto_v1_3.OFP_VERSION

    #*** Instantiate Flow class:
    flow = flows_module.Flow(config)

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

    #*** Record flow removals to flow_rems database collection:
    flow.record_removal(msg_tx)
    flow.record_removal(msg_rx)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['_items'][0]['dpid'] == 1
    #*** Note: can't easily test 'removal_time' as is dynamic, so skipping...
    assert api_result['_items'][0]['cookie'] == 23
    assert api_result['_items'][0]['priority'] == 1
    assert api_result['_items'][0]['reason'] == 0
    assert api_result['_items'][0]['table_id'] == 1
    assert api_result['_items'][0]['duration_sec'] == 5
    assert api_result['_items'][0]['idle_timeout'] == 5
    assert api_result['_items'][0]['hard_timeout'] == 0
    assert api_result['_items'][0]['packet_count'] == 10
    assert api_result['_items'][0]['byte_count'] == 744
    assert api_result['_items'][0]['eth_A'] == ''
    assert api_result['_items'][0]['eth_B'] == ''
    assert api_result['_items'][0]['eth_type'] == 2048
    assert api_result['_items'][0]['ip_A'] == '10.1.0.1'
    assert api_result['_items'][0]['ip_B'] == '10.1.0.2'
    assert api_result['_items'][0]['ip_proto'] == 6
    assert api_result['_items'][0]['tp_A'] == 43297
    assert api_result['_items'][0]['tp_B'] == 80
    assert api_result['_items'][0]['flow_hash'] == '9822b2867652ee0957892482b9f004c3'
    assert api_result['_items'][0]['direction'] == 'forward'

    #*** Validate API Response parameters for second flow removal:
    assert api_result['_items'][1]['dpid'] == 1
    #*** Note: can't easily test 'removal_time' as is dynamic, so skipping...
    assert api_result['_items'][1]['cookie'] == 1000000023
    assert api_result['_items'][1]['priority'] == 1
    assert api_result['_items'][1]['reason'] == 0
    assert api_result['_items'][1]['table_id'] == 1
    assert api_result['_items'][1]['duration_sec'] == 5
    assert api_result['_items'][1]['idle_timeout'] == 5
    assert api_result['_items'][1]['hard_timeout'] == 0
    assert api_result['_items'][1]['packet_count'] == 9
    assert api_result['_items'][1]['byte_count'] == 6644
    assert api_result['_items'][1]['eth_A'] == ''
    assert api_result['_items'][1]['eth_B'] == ''
    assert api_result['_items'][1]['eth_type'] == 2048
    assert api_result['_items'][1]['ip_A'] == '10.1.0.2'
    assert api_result['_items'][1]['ip_B'] == '10.1.0.1'
    assert api_result['_items'][1]['ip_proto'] == 6
    assert api_result['_items'][1]['tp_A'] == 80
    assert api_result['_items'][1]['tp_B'] == 43297
    assert api_result['_items'][1]['flow_hash'] == '9822b2867652ee0957892482b9f004c3'
    assert api_result['_items'][1]['direction'] == 'reverse'

    #*** Stop api_external sub-process:
    api_ps.terminate()

def test_flows_removed_stats_count():
    """
    Test the flows_removed API stats count by ingesting flow removal messages
    then checking that the API response correctly specifies message count
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()
    
    #*** Supports OpenFlow version 1.3:
    OFP_VERSION = ofproto_v1_3.OFP_VERSION

    #*** Instantiate Flow class:
    flow = flows_module.Flow(config)

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

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_STATS_COUNT)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['flows_removed'] == 0

    #*** Record flow removal to flow_rems database collection:
    flow.record_removal(msg_tx)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_STATS_COUNT)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['flows_removed'] == 1

    #*** Record flow removal to flow_rems database collection:
    flow.record_removal(msg_rx)

    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_STATS_COUNT)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['flows_removed'] == 2

    #*** Stop api_external sub-process:
    api_ps.terminate()

def test_response_flows_removed_FLOWDIR_bytes_TXRX():
    """
    Test the flows_removed API various flavours of src/dst bytes
    sent/received by ingesting flow removal messages then checking
    that the API response correctly specifies appropriate
    stats for bytes sent, including identity enrichment
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()
    
    #*** Supports OpenFlow version 1.3:
    OFP_VERSION = ofproto_v1_3.OFP_VERSION

    #*** Instantiate supporting classes:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

    #*** Client to Server DHCP Request:
    flow.ingest_packet(DPID1, INPORT1, pkts_dhcp.RAW[2], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[2], flow.packet)

    #*** Server to Client DHCP ACK:
    flow.ingest_packet(DPID1, INPORT2, pkts_dhcp.RAW[3], datetime.datetime.now())
    identities.harvest(pkts_dhcp.RAW[3], flow.packet)

    #*** Load JSON representations of flow removed messages:
    with open('OFPMsgs/OFPFlowRemoved_1.json', 'r') as json_file:
        json_str_tx_1 = json_file.read()
        json_dict_tx_1 = json.loads(json_str_tx_1)
    with open('OFPMsgs/OFPFlowRemoved_2.json', 'r') as json_file:
        json_str_rx_1 = json_file.read()
        json_dict_rx_1 = json.loads(json_str_rx_1)
    with open('OFPMsgs/OFPFlowRemoved_3.json', 'r') as json_file:
        json_str_tx_2 = json_file.read()
        json_dict_tx_2 = json.loads(json_str_tx_2)
    with open('OFPMsgs/OFPFlowRemoved_4.json', 'r') as json_file:
        json_str_rx_2 = json_file.read()
        json_dict_rx_2 = json.loads(json_str_rx_2)
    with open('OFPMsgs/OFPFlowRemoved_5.json', 'r') as json_file:
        json_str_tx_3 = json_file.read()
        json_dict_tx_3 = json.loads(json_str_tx_3)
    with open('OFPMsgs/OFPFlowRemoved_6.json', 'r') as json_file:
        json_str_rx_3 = json_file.read()
        json_dict_rx_3 = json.loads(json_str_rx_3)

    #*** Switch 1:
    #*** Set up fake datapaths and synthesise messages:
    datapath1 = ofproto_protocol.ProtocolDesc(version=OFP_VERSION)
    datapath1.id = 1
    msg_tx_1_sw1 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_tx_1)
    msg_rx_1_sw1 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_rx_1)
    msg_tx_2_sw1 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_tx_2)
    msg_rx_2_sw1 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_rx_2)
    msg_tx_3_sw1 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_tx_3)
    msg_rx_3_sw1 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_rx_3)
    #*** Record flow removals to flow_rems database collection:
    flow.record_removal(msg_tx_1_sw1)
    flow.record_removal(msg_rx_1_sw1)
    flow.record_removal(msg_tx_2_sw1)
    flow.record_removal(msg_rx_2_sw1)
    flow.record_removal(msg_tx_3_sw1)
    flow.record_removal(msg_rx_3_sw1)

    #*** Switch 2 (same flows to check dedup for multiple switches works):
    #*** Set up fake datapaths and synthesise messages:
    datapath2 = ofproto_protocol.ProtocolDesc(version=OFP_VERSION)
    datapath2.id = 2
    msg_tx_1_sw2 = ofproto_parser.ofp_msg_from_jsondict(datapath2, json_dict_tx_1)
    msg_rx_1_sw2 = ofproto_parser.ofp_msg_from_jsondict(datapath2, json_dict_rx_1)
    msg_tx_2_sw2 = ofproto_parser.ofp_msg_from_jsondict(datapath2, json_dict_tx_2)
    msg_rx_2_sw2 = ofproto_parser.ofp_msg_from_jsondict(datapath2, json_dict_rx_2)
    msg_tx_3_sw2 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_tx_3)
    msg_rx_3_sw2 = ofproto_parser.ofp_msg_from_jsondict(datapath1, json_dict_rx_3)
    #*** Record flow removals to flow_rems database collection:
    flow.record_removal(msg_tx_1_sw2)
    flow.record_removal(msg_rx_1_sw2)
    flow.record_removal(msg_tx_2_sw2)
    flow.record_removal(msg_rx_2_sw2)
    flow.record_removal(msg_tx_3_sw2)
    flow.record_removal(msg_rx_3_sw2)

    #*** Test flows_removed_src_bytes_sent API:
    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_SRC_BYTES_SENT)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['_items'][0]['_id'] == '10.1.0.2'
    assert api_result['_items'][0]['total_bytes_sent'] == 12345
    assert api_result['_items'][0]['identity'] == '10.1.0.2'
    assert api_result['_items'][1]['_id'] == '10.1.0.1'
    assert api_result['_items'][1]['total_bytes_sent'] == 5533
    assert api_result['_items'][1]['identity'] == 'pc1'

    #*** Test flows_removed_src_bytes_received API:
    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_SRC_BYTES_RECEIVED)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['_items'][0]['_id'] == '10.1.0.1'
    assert api_result['_items'][0]['total_bytes_received'] == 8628
    assert api_result['_items'][0]['identity'] == 'pc1'
    assert api_result['_items'][1]['_id'] == '10.1.0.2'
    assert api_result['_items'][1]['total_bytes_received'] == 543
    assert api_result['_items'][1]['identity'] == '10.1.0.2'

    #*** Test flows_removed_dst_bytes_sent API:
    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_DST_BYTES_SENT)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['_items'][0]['_id'] == '10.1.0.2'
    assert api_result['_items'][0]['total_bytes_sent'] == 8628
    assert api_result['_items'][0]['identity'] == '10.1.0.2'
    assert api_result['_items'][1]['_id'] == '10.1.0.1'
    assert api_result['_items'][1]['total_bytes_sent'] == 543
    assert api_result['_items'][1]['identity'] == 'pc1'

    #*** Test flows_removed_src_bytes_received API:
    #*** Call the external API:
    api_result = get_api_result(URL_TEST_FLOWS_REMOVED_DST_BYTES_RECEIVED)
    logger.debug("api_result=%s", api_result)

    #*** Validate API Response parameters:
    assert api_result['_items'][0]['_id'] == '10.1.0.1'
    assert api_result['_items'][0]['total_bytes_received'] == 12345
    assert api_result['_items'][0]['identity'] == 'pc1'
    assert api_result['_items'][1]['_id'] == '10.1.0.2'
    assert api_result['_items'][1]['total_bytes_received'] == 5533
    assert api_result['_items'][1]['identity'] == '10.1.0.2'

    #*** Stop api_external sub-process:
    api_ps.terminate()

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
    flow = flows_module.Flow(config)

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

    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

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

    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

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
    flow = flows_module.Flow(config)

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
    flow = flows_module.Flow(config)
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
    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

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
    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

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
    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

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
    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    ident = identities_module.Identities(config, policy)

    #*** Initial main_policy that matches tcp-80:
    policy = policy_module.Policy(config,
                        pol_dir_default="config/tests/regression",
                        pol_dir_user="config/tests/foo",
                        pol_filename="main_policy_regression_static_3.yaml")

    #*** Ingest Flow 1 Packet 0 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Classify the packet:
    policy.check_policy(flow, ident)

    logger.debug("pkt0 flow classification is %s", flow.classification.dbdict())

    #*** Write classification result to classifications collection:
    flow.classification.commit()

    #*** Retrieve classification via get_classification and check results:
    clasfn_result = api.get_classification(flow.classification.flow_hash)
    assert clasfn_result['classified'] ==  1
    assert clasfn_result['classification_tag'] ==  "Constrained Bandwidth Traffic"
    assert clasfn_result['actions']['set_desc'] == "Constrained Bandwidth Traffic"
    assert clasfn_result['actions']['qos_treatment'] == "constrained_bw"

def test_indexing_get_pi_rate():
    """
    Test indexing of database collections for api queries
    to ensure that they run efficiently
    """
    #*** Instantiate classes:
    flow = flows_module.Flow(config)

    #*** Ingest packets older than flow timeout:
    flow.ingest_packet(DPID1, INPORT1, pkts_ARP_2.RAW[0], datetime.datetime.now() - datetime.timedelta \
                                (seconds=config.get_value("flow_time_limit")+1))
    flow.ingest_packet(DPID1, INPORT1, pkts_ARP_2.RAW[1], datetime.datetime.now() - datetime.timedelta \
                                (seconds=config.get_value("flow_time_limit")+1))

    #*** Ingest packets:
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[1], datetime.datetime.now())
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[2], datetime.datetime.now())

    #*** Test packet_ins collection indexing...
    #*** Should be 5 documents in packet_ins collection:
    assert flow.packet_ins.count() == 5
    #*** Get query execution statistics:
    explain = api.get_pi_rate(test=1)

    #*** Check an index is used:
    assert explain['queryPlanner']['winningPlan']['inputStage']['stage'] == 'IXSCAN'
    #*** Check how query ran:
    assert explain['executionStats']['executionSuccess'] == True
    assert explain['executionStats']['nReturned'] == 3
    assert explain['executionStats']['totalKeysExamined'] == 3
    assert explain['executionStats']['totalDocsExamined'] == 3

def test_flow_match():
    """
    Test flow_match

    TBD UNDER CONSTRUCTION

    """
    flow = api.FlowUI()
    flow.src = 'pc1.example.com'
    flow.dst = 'sv1.example.com'
    flow.proto = 81
    flows_filterlogicselector_includes1 = ''
    flows_filterlogicselector_includes2 = 'includes'
    flows_filterlogicselector_excludes = 'excludes'
    flows_filtertypeselector = ''
    filter_string_pc1 = 'pc1'
    filter_string_sv1 = 'sv1'

    assert api.flow_match(flow, flows_filterlogicselector_includes1,
                                flows_filtertypeselector, filter_string_pc1) == 1

    assert api.flow_match(flow, flows_filterlogicselector_includes2,
                                flows_filtertypeselector, filter_string_pc1) == 1

    assert api.flow_match(flow, flows_filterlogicselector_excludes,
                                flows_filtertypeselector, filter_string_pc1) == 0

    assert api.flow_match(flow, flows_filterlogicselector_includes1,
                                flows_filtertypeselector, filter_string_sv1) == 1

    assert api.flow_match(flow, flows_filterlogicselector_includes1,
                                flows_filtertypeselector, filter_string_sv1) == 1

    assert api.flow_match(flow, flows_filterlogicselector_excludes,
                                flows_filtertypeselector, filter_string_sv1) == 0

def test_flow_mods():
    """
    Test flow_mods API
    """
    #*** Start api_external as separate process:
    logger.info("Starting api_external")
    api_ps = multiprocessing.Process(
                        target=api.run,
                        args=())
    api_ps.start()

    #*** Sleep to allow api_external to start fully:
    time.sleep(.5)

    #*** Instantiate flow, policy and identities objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    identities = identities_module.Identities(config, policy)

    #*** Create a sample result to use:
    ipv4_src='10.1.0.1'
    ipv4_dst='10.1.0.2'
    result = {'match_type': 'single', 'forward_cookie': 1,
                 'forward_match': {'eth_type': 0x0800,
                    'ipv4_src': ipv4_src, 'ipv4_dst': ipv4_dst,
                    'ip_proto': 6}, 'reverse_cookie': 0, 'reverse_match': {},
                    'client_ip': ipv4_src}

    #*** Record flow mod:
    #*** Ingest a packet from pc1:
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    #*** Record suppressing this flow:
    flow.record_suppression(DPID1, 'suppress', result)

    #*** Call the external API:
    api_result = get_api_result(URL_FLOW_MODS)

    logger.debug("api_result=%s", api_result)

    #*** Check that API has returned expected results:
    assert api_result['_items'][0]['flow_hash'] == flow.packet.flow_hash
    assert api_result['_items'][0]['dpid'] == DPID1
    assert api_result['_items'][0]['suppress_type'] == 'suppress'
    assert api_result['_items'][0]['standdown'] == 0
    assert api_result['_items'][0]['match_type'] == 'single'
    assert api_result['_items'][0]['forward_cookie'] == 1
    assert api_result['_items'][0]['forward_match'] == {'eth_type': 0x0800,
                    'ipv4_src': ipv4_src, 'ipv4_dst': ipv4_dst,
                    'ip_proto': 6}
    assert api_result['_items'][0]['reverse_cookie'] == 0
    assert api_result['_items'][0]['reverse_match'] == {}
    assert api_result['_items'][0]['client_ip'] == ipv4_src
    assert len(api_result['_items']) == 1

    #*** Record suppressing the same flow again, setting standdown:
    flow.record_suppression(DPID1, 'suppress', result, standdown=1)

    #*** Call the external API:
    api_result = get_api_result(URL_FLOW_MODS)

    logger.debug("api_result=%s", api_result)

    #*** Check that API has returned expected results for new record
    #***  (note that result items are defaulted due to standdown):
    assert api_result['_items'][1]['flow_hash'] == flow.packet.flow_hash
    assert api_result['_items'][1]['dpid'] == DPID1
    assert api_result['_items'][1]['suppress_type'] == 'suppress'
    assert api_result['_items'][1]['standdown'] == 1
    assert api_result['_items'][1]['match_type'] == ''
    assert api_result['_items'][1]['forward_cookie'] == 0
    assert api_result['_items'][1]['forward_match'] == {}
    assert api_result['_items'][1]['reverse_cookie'] == 0
    assert api_result['_items'][1]['reverse_match'] == {}
    assert len(api_result['_items']) == 2

    #*** Stop api_external sub-process:
    api_ps.terminate()

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

#================= HELPER FUNCTIONS ===========================================

def get_api_result(url):
    """
    Retrieve JSON data from API via a supplied URL
    """
    s = requests.Session()
    r = s.get(url)
    return r.json()

def _ipv4_t2i(ip_text):
    """
    Turns an IPv4 address in text format into an integer.
    Borrowed from rest_router.py code
    """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


