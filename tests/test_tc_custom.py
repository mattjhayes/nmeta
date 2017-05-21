"""
nmeta tc_custom.py Tests

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

#*** For timestamps:
import datetime

#*** nmeta imports:
import nmeta
import config
import flows as flows_module
import identities as identities_module
import policy as policy_module
import tc_custom

#*** nmeta test packet imports:
import packets_ipv4_http2 as pkts2

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#===== tc_custom.py and statistical_qos_bandwidth_1.py Tests ==================

def test_statistical_classifier():
    """
    Test instantiating custom classifiers and use of
    supplied sample statistical classifier
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    INPORT1 = 1

    #*** Instantiate class object:
    flow = flows_module.Flow(config)    #*** Test DPIDs and in ports:
    DPID1 = 1
    INPORT1 = 1

    #*** Instantiate class objects:
    flow = flows_module.Flow(config)
    policy = policy_module.Policy(config)
    ident = identities_module.Identities(config, policy)

    #*** Instantiate custom classifiers
    tc_cust = tc_custom.CustomInspect(config)
    tc_cust.instantiate_classifiers(['statistical_qos_bandwidth_1'])

    #*** Instantiate match object:
    classifier_result = policy_module.TCClassifierResult("", "")

    #*** Ingest sufficient packets to complete statistical classification (7):

    #*** Ingest packet 10.1.0.1 10.1.0.2 TCP 38435 80 [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[0], datetime.datetime.now())

    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == True
    assert classifier_result.classification_tag == ""
    assert classifier_result.actions == {}

    #*** Ingest packet 10.1.0.2 10.1.0.1 TCP 80 38435 [SYN, ACK]
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[1], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == True
    assert classifier_result.classification_tag == ""
    assert classifier_result.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[2], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == True
    assert classifier_result.classification_tag == ""
    assert classifier_result.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[3], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == True
    assert classifier_result.classification_tag == ""
    assert classifier_result.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[4], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == True
    assert classifier_result.classification_tag == ""
    assert classifier_result.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[5], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == True
    assert classifier_result.classification_tag == ""
    assert classifier_result.actions == {}

    #*** Ingest packet
    #*** This should conclude the statistical classification for this flow
    #*** and conclude action is default priority
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[6], datetime.datetime.now())
    classifier_result = policy_module.TCClassifierResult("", "")
    classifier_result.policy_attr = 'custom'
    classifier_result.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(classifier_result, flow, ident)
    assert classifier_result.match == True
    assert classifier_result.continue_to_inspect == False
    assert classifier_result.classification_tag == "Normal flow"
    assert classifier_result.actions == {'qos_treatment': 'default_priority'}

