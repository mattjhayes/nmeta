"""
Nmeta Integration Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, in this directory type in:
    py.test -v
"""


import sys
#*** Handle tests being in different directory branch to app code:
sys.path.insert(0, '../nmeta')

from ryu.ofproto import ether
from ryu.lib.packet import ethernet, arp, packet, ipv4, tcp

#*** nmeta imports:
import tc_policy
import measure
import config

#*** Set up Policy Integration Tests:
#*** Instantiate classes:
_config = config.Config()
tc = tc_policy.TrafficClassificationPolicy \
                    (_config)
#*** Test values for policy_conditions:
conditions_any_openflow = {'match_type': 'any',
                             'tcp_src': 6633, 'tcp_dst': 6633}
conditions_all_openflow = {'match_type': 'all',
                             'tcp_src': 6633, 'tcp_dst': 6633}
conditions_any_mac = {'match_type': 'any', 'eth_src': '08:60:6e:7f:74:e7',
                         'eth_dst': '08:60:6e:7f:74:e8'}
conditions_all_mac = {'match_type': 'all', 'eth_src': '08:60:6e:7f:74:e7',
                         'eth_dst': '08:60:6e:7f:74:e8'}
conditions_any_ip = {'match_type': 'any', 'ip_dst': '192.168.57.12',
                         'ip_src': '192.168.56.32'}
conditions_any_ssh = {'match_type': 'any', 'tcp_src': 22, 'tcp_dst': 22}

conditions_rule_nested_1 = {'comment': 'Audit Division SSH traffic',
    'conditions_list': [{'match_type': 'any', 'tcp_src': 22, 'tcp_dst': 22},
    {'match_type': 'any', 'ip_src': '10.0.0.1'}], 'match_type': 'all',
    'actions': {'set_qos_tag': 'QoS_treatment=high_priority',
    'set_desc_tag': 'description="High Priority Audit Division SSH Traffic"'}}

conditions_rule_nested_2 = {'comment': 'Audit Division SSH traffic',
    'conditions_list': [{'match_type': 'any', 'tcp_src': 22, 'tcp_dst': 22},
    {'match_type': 'any', 'ip_src': '192.168.2.3'}], 'match_type': 'all',
    'actions': {'set_qos_tag': 'QoS_treatment=high_priority',
    'set_desc_tag': 'description="High Priority Audit Division SSH Traffic"'}}

results_dict_no_match = {'actions': False, 'match': False,
                     'continue_to_inspect': False}

results_dict_match = {'actions': False, 'match': True,
                     'continue_to_inspect': False}

#*** Set up Measurement Integration Tests:
#*** Instantiate class:
measure = measure.Measurement(_config)

#*** EXPERIMENTAL AND UNDER CONSTRUCTION...
#*** context is future-proofing for when the system will support
#*** multiple contexts. For now just set to 'default':
ctx = 'default'

#*** Check TC packet match against a conditions stanza:
def test_tc_check_conditions():
    #*** Test Packets:
    pkt_arp = build_packet_ARP()
    pkt_tcp_22 = build_packet_tcp_22()
    #*** Call _check_conditions with a packet and a conditions stanza and
    #***  validate the result is expected boolean:
    assert tc._check_conditions(pkt_arp, conditions_any_openflow, ctx) == \
                             results_dict_no_match
    assert tc._check_conditions(pkt_arp, conditions_all_openflow, ctx) == \
                             results_dict_no_match
    assert tc._check_conditions(pkt_arp, conditions_any_mac, ctx) == \
                             results_dict_match
    assert tc._check_conditions(pkt_arp, conditions_all_mac, ctx) == \
                             results_dict_no_match

#*** Test TC packet match against a rule stanza:
def test_tc_check_rule():
    #*** Test Packets:
    pkt_arp = build_packet_ARP()
    pkt_tcp_22 = build_packet_tcp_22()
    #*** Rule checks:
    assert tc._check_rule(pkt_arp, conditions_rule_nested_1, ctx) == \
                             results_dict_no_match
    assert tc._check_rule(pkt_tcp_22, conditions_rule_nested_1, ctx) == \
                             results_dict_match
    assert tc._check_rule(pkt_tcp_22, conditions_rule_nested_2, ctx) == \
                             results_dict_no_match

#*** Test Rate Measure Functions:
def test_measure_rate():
    measure.record_rate_event('rate_test')
    measure.record_rate_event('rate_test')
    measure.record_rate_event('rate_test')
    assert measure.get_event_rate('rate_test') == 3

#*** Test Metric Measure Functions:
def test_measure_metric():
    measure.record_metric('metric_test', 5)
    measure.record_metric('metric_test', 18)
    measure.record_metric('metric_test', 19)
    results_dict = measure.get_event_metric_stats ('metric_test')
    assert results_dict['metric_test']['max_max'] == 19
    assert results_dict['metric_test']['min_min'] == 5
    assert results_dict['metric_test']['avg'] == 14

#=========== Misc Functions to Generate Data for Unit Tests ===================
def build_packet_ARP():
    """
    Build an ARP packet for use in tests.
    Based on code from
    http://ryu.readthedocs.org/en/latest/library_packet.html
    """
    e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                      src='08:60:6e:7f:74:e7',
                      ethertype=ether.ETH_TYPE_ARP)
    a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
            src_mac='08:60:6e:7f:74:e7', src_ip='192.0.2.1',
            dst_mac='00:00:00:00:00:00', dst_ip='192.0.2.2')
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    print repr(p.data)  # the on-wire packet
    return p

def build_packet_tcp_22():
    """
    Build an SSH-like packet for use in tests.
    """
    #ethernet(dst='08:00:27:1e:98:88',ethertype=2048,src='00:00:00:00:00:02')
    #ipv4(csum=25158,dst='192.168.57.40',flags=2,header_length=5,
    # identification=58864,offset=0,option=None,proto=6,src='192.168.56.12',
    # tos=0,total_length=60,ttl=64,version=4)
    #tcp(ack=0,bits=2,csum=60347,dst_port=22,offset=10,
    # option='\x02\x04\x05\xb4\x04\x02\x08\n\x00\x08\x16\x0f\x00\x00\x00\x00\
    # x01\x03\x03\x06'
    # ,seq=533918719,src_port=52656,urgent=0,window_size=29200)

    e = ethernet.ethernet(dst='00:00:00:00:00:02',
                      src='00:00:00:00:00:01',
                      ethertype=2048)
    i = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=0,
                    identification=0, flags=0, offset=0, ttl=255, proto=0,
                    csum=0, src='10.0.0.1', dst='10.0.0.2', option=None)
    t = tcp.tcp(src_port=52656, dst_port=22, seq=533918719, ack=0, offset=10,
                      bits=2, window_size=29200, csum=0, urgent=0, option=None)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(i)
    p.add_protocol(t)
    p.serialize()
    print repr(p.data)  # the on-wire packet
    return p
