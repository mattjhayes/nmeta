"""
Nmeta tc_policy.py Tests
"""

import sys
#*** Handle tests being in different directory branch to app code:
sys.path.insert(0, '../nmeta')

import logging

#*** nmeta imports:
import tc_policy
import config
import flows as flow_class
import identities

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

rule_1 = {
            'comment': 'HTTP traffic',
            'conditions_list':
                [
                    {
                    'match_type': 'any',
                    'tcp_src': 80,
                    'tcp_dst': 80
                },
                    {
                    'match_type': 'any',
                    'ip_src': '10.1.0.1',
                    'ip_dst': '10.1.0.1'
                }
            ],
            'match_type': 'all',
            'actions':
                {
                'set_qos_tag': 'QoS_treatment=high_priority',
                'set_desc_tag': 'description="High Priority HTTP Traffic"'
            }
        }

rule_2 = {
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
                    'ip_src': '192.168.2.3'
                }
            ],
            'match_type': 'all',
            'actions':
                {
                'set_qos_tag': 'QoS_treatment=high_priority',
                'set_desc_tag': 'description="High Priority Audit Division SSHd Traffic"'
            }
        }

logger = logging.getLogger(__name__)

def test_check_policy():
    """
    Test that packet match against policy works correctly
    """
    #*** Instantiate tc_policy, flows and identities classes, specifying
    #*** a particular main_policy file to use:
    tc = tc_policy.TrafficClassificationPolicy(config,
                                pol_dir="config/tests/regression",
                                pol_file="main_policy_regression_static.yaml")
    flow = flow_class.Flow(config)
    ident = identities.Identities(config)

    #*** Note: cannot query a classification until a packet has been
    #*** ingested - will throw error

    #*** Ingest a packet:
    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Check policy:
    tc.check_policy(flow, ident)
    #*** Should not match any rules in that policy:
    logger.debug("flow.classification.classified=%s", flow.classification.classified)
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == ""
    assert flow.classification.actions == {}

    #*** Re-instantiate tc_policy with different policy that should classify:
    tc = tc_policy.TrafficClassificationPolicy(config,
                               pol_dir="config/tests/regression",
                               pol_file="main_policy_regression_static_3.yaml")

    #*** Re-ingest packet:
    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Check policy:
    tc.check_policy(flow, ident)
    #*** Should match policy:
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == "Constrained Bandwidth Traffic"
    logger.debug("flow.classification.actions=%s", flow.classification.actions)
    assert flow.classification.actions == {'set_desc': 'Constrained Bandwidth Traffic',
                                           'qos_treatment': 'constrained_bw'}

def test_check_rules():
    #*** Instantiate classes:
    tc = tc_policy.TrafficClassificationPolicy(config)
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Set tc.pkt as work around for not calling parent method that sets it:
    tc.pkt = flow.packet
    #*** Should match:
    rule = tc._check_rule(rule_1)
    logger.debug("rule=%s", rule.to_dict())
    assert rule.match == True

    # TBD - more


def test_check_conditions():
    """
    Check TC packet match against a conditions stanza
    """
    #*** Instantiate classes:
    tc = tc_policy.TrafficClassificationPolicy(config)
    flow = flow_class.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Set tc.pkt as work around for not calling parent method that sets it:
    tc.pkt = flow.packet
    #*** HTTP is not OpenFlow so shouldn't match!
    logger.debug("conditions_any_opf should not match")
    conditions = tc._check_conditions(conditions_any_opf)
    assert not conditions.condition[0].match

    #*** HTTP is HTTP so should match:
    logger.debug("conditions_any_http should match")
    conditions = tc._check_conditions(conditions_any_http)
    assert conditions.condition[0].match

    #*** Source AND Dest aren't both HTTP so should not match:
    logger.debug("conditions_all_http should not match")
    conditions = tc._check_conditions(conditions_all_http)
    assert not conditions.condition[0].match

    #*** This should match (HTTP src and dst ports correct):
    logger.debug("conditions_all_http2 should match")
    conditions = tc._check_conditions(conditions_all_http2)
    assert conditions.condition[0].match

    #*** MAC should match:
    conditions = tc._check_conditions(conditions_any_mac)
    assert conditions.condition[0].match

    conditions = tc._check_conditions(conditions_all_mac)
    assert conditions.condition[0].match

    #*** Different MAC shouldn't match:
    conditions = tc._check_conditions(conditions_any_mac2)
    assert not conditions.condition[0].match

def test_custom_classifiers():
    """
    Check deduplicated list of custom classifiers works
    """
    #*** Instantiate tc_policy, specifying
    #*** a particular main_policy file to use that has no custom classifiers:
    tc = tc_policy.TrafficClassificationPolicy(config,
                            pol_dir="config/tests/regression",
                            pol_file="main_policy_regression_static.yaml")
    assert tc.custom_classifiers == []

    #*** Instantiate tc_policy, specifying
    #*** a custom statistical main_policy file to use that has a
    #*** custom classifier:
    tc = tc_policy.TrafficClassificationPolicy(config,
                            pol_dir="config/tests/regression",
                            pol_file="main_policy_regression_statistical.yaml")
    assert tc.custom_classifiers == ['statistical_qos_bandwidth_1']

def test_qos():
    """
    Test the assignment of QoS queues based on a qos_treatment action
    """
    #*** Instantiate tc_policy, specifying
    #*** a particular main_policy file to use that has no custom classifiers:
    tc = tc_policy.TrafficClassificationPolicy(config,
                            pol_dir="config/tests/regression",
                            pol_file="main_policy_regression_static.yaml")
    assert tc.qos('default_priority') == 0
    assert tc.qos('constrained_bw') == 1
    assert tc.qos('high_priority') == 2
    assert tc.qos('low_priority') == 3
    assert tc.qos('foo') == 0



