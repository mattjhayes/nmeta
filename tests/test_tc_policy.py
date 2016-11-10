"""
Nmeta tc_policy.py Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, in this directory type in:
    py.test -v
"""

import sys
#*** Handle tests being in different directory branch to app code:
sys.path.insert(0, '../nmeta')

import logging

#*** nmeta imports:
import tc_policy
import config
import flows as flow_class

#*** nmeta test packet imports:
import packets_ipv4_http as pkts

#*** For timestamps:
import datetime

#*** Instantiate config class:
config = config.Config()

#*** Test DPIDs and in ports:
DPID1 = 1
DPID2 = 2
INPORT1 = 1
INPORT2 = 2

#*** Test values for policy_conditions:
conditions_any_opf = {'match_type': 'any',
                             'tcp_src': 6633, 'tcp_dst': 6633}
conditions_all_opf = {'match_type': 'all',
                             'tcp_src': 6633, 'tcp_dst': 6633}
conditions_any_http = {'match_type': 'any',
                             'tcp_src': 80, 'tcp_dst': 80}
conditions_all_http = {'match_type': 'all',
                             'tcp_src': 80, 'tcp_dst': 80}
conditions_all_http2 = {'match_type': 'all',
                             'tcp_src': 43297, 'tcp_dst': 80}
conditions_any_mac = {'match_type': 'any', 'eth_src': '08:00:27:2a:d6:dd',
                         'eth_dst': '08:00:27:c8:db:91'}
conditions_all_mac = {'match_type': 'all', 'eth_src': '08:00:27:2a:d6:dd',
                         'eth_dst': '08:00:27:c8:db:91'}
conditions_any_mac2 = {'match_type': 'any', 'eth_src': '00:00:00:01:02:03',
                         'eth_dst': '08:00:27:01:02:03'}
conditions_any_ip = {'match_type': 'any', 'ip_dst': '192.168.57.12',
                         'ip_src': '192.168.56.32'}
conditions_any_ssh = {'match_type': 'any', 'tcp_src': 22, 'tcp_dst': 22}

conditions_rule_nested_1 = {
            'comment': 'Audit Division SSH traffic',
            'conditions_list':
                [
                    {
                    'match_type': 'any',
                    'tcp_src': 22,
                    'tcp_dst': 22
                },
                    {
                    'match_type': 'any',
                    'ip_src': '10.0.0.1'
                }
            ],
            'match_type': 'all',
            'actions':
                {
                'set_qos_tag': 'QoS_treatment=high_priority',
                'set_desc_tag': 'description="High Priority Audit Division SSH Traffic"'
            }
        }

conditions_rule_nested_2 = {'comment': 'Audit Division SSH traffic',
    'conditions_list': [{'match_type': 'any', 'tcp_src': 22, 'tcp_dst': 22},
    {'match_type': 'any', 'ip_src': '192.168.2.3'}], 'match_type': 'all',
    'actions': {'set_qos_tag': 'QoS_treatment=high_priority',
    'set_desc_tag': 'description="High Priority Audit Division SSH Traffic"'}}

results_dict_no_match = {'actions': False, 'match': False,
                     'continue_to_inspect': False}

results_dict_match = {'actions': False, 'match': True,
                     'continue_to_inspect': False}

logger = logging.getLogger(__name__)

#*** Check TC packet match against a conditions stanza:
def test_tc_check_conditions():
    #*** Instantiate classes:
    tc = tc_policy.TrafficClassificationPolicy(config)
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    tc.pkt = flow.packet
    #*** HTTP is not OpenFlow so shouldn't match!
    logger.debug("conditions_any_opf should not match")
    assert tc._check_conditions(conditions_any_opf) == results_dict_no_match
    #*** HTTP is HTTP so should match:
    logger.debug("conditions_any_http should match")
    assert tc._check_conditions(conditions_any_http) == results_dict_match
    #*** Source AND Dest aren't both HTTP so should not match:
    logger.debug("conditions_all_http should not match")
    assert tc._check_conditions(conditions_all_http) == results_dict_no_match
    #*** This should match (HTTP src and dst ports correct):
    logger.debug("conditions_all_http2 should match")
    assert tc._check_conditions(conditions_all_http2) == results_dict_match
    #*** MAC should match:
    assert tc._check_conditions(conditions_any_mac) == results_dict_match
    assert tc._check_conditions(conditions_all_mac) == results_dict_match
    #*** Different MAC shouldn't match:
    assert tc._check_conditions(conditions_any_mac2) == results_dict_no_match

#*** Test TC packet match against a rule stanza:
def test_tc_check_rule():
    #*** Rule checks:
    #assert tc._check_rule(pkt_arp, conditions_rule_nested_1, ctx) == \
    #                         results_dict_no_match
    #assert tc._check_rule(pkt_tcp_22, conditions_rule_nested_1, ctx) == \
    #                         results_dict_match
    #assert tc._check_rule(pkt_tcp_22, conditions_rule_nested_2, ctx) == \
    #                         results_dict_no_match
    pass


#=========== Misc Functions to Generate Data for Unit Tests ===================


