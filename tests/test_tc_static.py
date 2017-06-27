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
import policy as policy_module

#*** nmeta test packet imports:
import packets_ipv4_http as pkts
import packets_ipv4_dns as pkts_udp

#*** Instantiate Config class:
config = config.Config()

#*** Instantiate Policy class:
policy = policy_module.Policy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/foo",
                            pol_filename="main_policy_regression_static.yaml")

#*** Instantiate StaticInspect class:
tc_static = tc_static_module.StaticInspect(config, policy)

logger = logging.getLogger(__name__)

#======================== tc_static.py Tests ================================

def test_check_static():
    """
    Test check_static method
    """

    #*** Test DPIDs and in ports:
    DPID1 = 123456
    INPORT1 = 1
    DPID2 = 1
    INPORT2 = 6
    DPID3 = 255
    INPORT3 = 3

    #*** Instantiate match object:
    classifier_result = policy_module.TCClassifierResult("", "")

    #*** Instantiate class object:
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    #*** Should match, even though dpid/port don't, as default match is unknown:
    classifier_result.policy_attr = 'location_src'
    classifier_result.policy_value = 'unknown'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    #*** Test Flow 1 Packet 1 (Client TCP SYN) with DPID/port set to external:
    flow.ingest_packet(DPID2, INPORT2, pkts.RAW[0], datetime.datetime.now())

    #*** Should match as DPID/port belong to location external:
    classifier_result.policy_attr = 'location_src'
    classifier_result.policy_value = 'external'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    #*** Test Flow 1 Packet 1 (Client TCP SYN) with DPID/port set to internal:
    flow.ingest_packet(DPID3, INPORT3, pkts.RAW[0], datetime.datetime.now())

    #*** Should not match as DPID/port belong to location internal:
    classifier_result.policy_attr = 'location_src'
    classifier_result.policy_value = 'external'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Should match as DPID/port belong to location internal:
    classifier_result.policy_attr = 'location_src'
    classifier_result.policy_value = 'internal'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())

    classifier_result.policy_attr = 'eth_src'
    classifier_result.policy_value = pkts.ETH_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'eth_src'
    classifier_result.policy_value = pkts.ETH_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    classifier_result.policy_attr = 'eth_dst'
    classifier_result.policy_value = pkts.ETH_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'eth_dst'
    classifier_result.policy_value = pkts.ETH_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Eth type tests:
    classifier_result.policy_attr = 'eth_type'
    classifier_result.policy_value = pkts.ETH_TYPE[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'eth_type'
    classifier_result.policy_value = 2054
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Eth type Hex tests:
    classifier_result.policy_attr = 'eth_type'
    classifier_result.policy_value = 0x800
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'eth_type'
    classifier_result.policy_value = 0x808
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Simple IP src tests:
    classifier_result.policy_attr = 'ip_src'
    classifier_result.policy_value = pkts.IP_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'ip_src'
    classifier_result.policy_value = pkts.IP_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Test IP src space matching:
    classifier_result.policy_attr = 'ip_src'
    classifier_result.policy_value = '10.1.0.0/24'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'ip_src'
    classifier_result.policy_value = '10.2.0.0/24'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    classifier_result.policy_attr = 'ip_src'
    classifier_result.policy_value = '10.1.0.1-10.1.0.15'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'ip_src'
    classifier_result.policy_value = '10.1.0.2-10.1.0.15'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Simple IP dst tests:
    classifier_result.policy_attr = 'ip_dst'
    classifier_result.policy_value = pkts.IP_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'ip_dst'
    classifier_result.policy_value = pkts.IP_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Test IP dst space matching:
    classifier_result.policy_attr = 'ip_dst'
    classifier_result.policy_value = '10.1.0.0/24'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'ip_dst'
    classifier_result.policy_value = '10.2.0.0/24'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    classifier_result.policy_attr = 'ip_dst'
    classifier_result.policy_value = '10.1.0.1-10.1.0.15'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'ip_dst'
    classifier_result.policy_value = '10.1.0.3-10.1.0.15'
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False


    classifier_result.policy_attr = 'tcp_src'
    classifier_result.policy_value = pkts.TP_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'tcp_src'
    classifier_result.policy_value = pkts.TP_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    classifier_result.policy_attr = 'tcp_dst'
    classifier_result.policy_value = pkts.TP_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'tcp_dst'
    classifier_result.policy_value = pkts.TP_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    #*** Ingest UDP:
    flow.ingest_packet(DPID1, INPORT1, pkts_udp.RAW[0], datetime.datetime.now())

    classifier_result.policy_attr = 'udp_src'
    classifier_result.policy_value = pkts_udp.TP_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'udp_src'
    classifier_result.policy_value = pkts_udp.TP_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

    classifier_result.policy_attr = 'udp_dst'
    classifier_result.policy_value = pkts_udp.TP_DST[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == True

    classifier_result.policy_attr = 'udp_dst'
    classifier_result.policy_value = pkts_udp.TP_SRC[0]
    tc_static.check_static(classifier_result, flow.packet)
    assert classifier_result.match == False

#*** MAC Address Validity Tests:
def test_is_valid_macaddress():
    assert tc_static.is_valid_macaddress('192.168.3.4') == 0
    assert tc_static.is_valid_macaddress('fe80:dead:beef') == 1
    assert tc_static.is_valid_macaddress('fe80deadbeef') == 1
    assert tc_static.is_valid_macaddress('fe:80:de:ad:be:ef') == 1
    assert tc_static.is_valid_macaddress('foo 123') == 0

#*** EtherType Validity Tests:
def test_is_valid_ethertype():
    assert tc_static.is_valid_ethertype('0x0800') == 1
    assert tc_static.is_valid_ethertype('foo') == 0
    assert tc_static.is_valid_ethertype('0x08001') == 1
    assert tc_static.is_valid_ethertype('0x18001') == 0
    assert tc_static.is_valid_ethertype('35020') == 1
    assert tc_static.is_valid_ethertype('350201') == 0

#*** IP Address Space Validity Tests:
def test_is_valid_ip_space():
    assert tc_static.is_valid_ip_space('192.168.3.4') == 1
    assert tc_static.is_valid_ip_space('192.168.3.0/24') == 1
    assert tc_static.is_valid_ip_space('192.168.322.0/24') == 0
    assert tc_static.is_valid_ip_space('foo') == 0
    assert tc_static.is_valid_ip_space('10.168.3.15/24') == 1
    assert tc_static.is_valid_ip_space('192.168.3.25-192.168.4.58') == 1
    assert tc_static.is_valid_ip_space('192.168.4.25-192.168.3.58') == 0
    assert tc_static.is_valid_ip_space('192.168.3.25-43') == 0
    assert tc_static.is_valid_ip_space('fe80::dead:beef') == 1
    assert tc_static.is_valid_ip_space('10.1.2.2-10.1.2.3') == 1
    assert tc_static.is_valid_ip_space('10.1.2.3-fe80::dead:beef') == 0
    assert tc_static.is_valid_ip_space('10.1.2.3-10.1.2.5-10.1.2.8') == 0
    assert tc_static.is_valid_ip_space('fe80::dead:beef-fe80::dead:beff') == 1

#*** Transport Port Validity Tests:
def test_is_valid_transport_port_abc123():
    assert tc_static.is_valid_transport_port('abc123') == 0
    assert tc_static.is_valid_transport_port('1') == 1
    assert tc_static.is_valid_transport_port('65535') == 1
    assert tc_static.is_valid_transport_port('65536') == 0

#*** MAC Address Match Tests:
def test_is_match_macaddress():
    assert tc_static.is_match_macaddress('fe80:dead:beef', '0000:0000:0002') \
                                                    == 0
    assert tc_static.is_match_macaddress('0000:0000:0002', '0000:0000:0002') \
                                                    == 1
    assert tc_static.is_match_macaddress('fe80:dead:beef', 'fe80deadbeef') \
                                                    == 1
    assert tc_static.is_match_macaddress('0000:0000:0002', '2') \
                                                    == 1
    assert tc_static.is_match_macaddress('0000:0000:0002', 'f00') \
                                                    == 0

#*** EtherType Match Tests:
def test_is_match_ethertype():
    assert tc_static.is_match_ethertype('35020', '35020') == 1
    assert tc_static.is_match_ethertype('35020', '0x88cc') == 1
    assert tc_static.is_match_ethertype('foo', '0x88cc') == 0
    assert tc_static.is_match_ethertype('35020', 'foo') == 0
    assert tc_static.is_match_ethertype('0xfoo', '35020') == 0
    assert tc_static.is_match_ethertype('35020', '0xfoo') == 0

#*** IP Address Match Tests:
def test_is_match_ip_space():
    assert tc_static.is_match_ip_space('192.168.56.12', '192.168.56.12') == 1
    assert tc_static.is_match_ip_space('192.168.56.11', '192.168.56.12') == 0
    assert tc_static.is_match_ip_space('192.168.56.12', '192.168.56.0/24') == 1
    assert tc_static.is_match_ip_space('192.168.56.12', '192.168.57.0/24') == 0
    assert tc_static.is_match_ip_space('192.168.56.12', \
                                            '192.168.56.10-192.168.56.42') == 1
    assert tc_static.is_match_ip_space('192.168.56.12', \
                                            '192.168.57.10-192.168.57.42') == 0
    
    #*** Non-IP packet has first field empty:
    assert tc_static.is_match_ip_space('', '192.168.57.10-192.168.57.42') == 0

    #*** Check response to unexpected conditions:
    assert tc_static.is_match_ip_space('foo', \
                                            '192.168.57.10-192.168.57.42') == 0
    

#================= HELPER FUNCTIONS ===========================================

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
