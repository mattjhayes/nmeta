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
import flows as flow_class
import identities as identities_class
import tc_policy
import tc_custom

#*** nmeta test packet imports:
import packets_ipv4_http2 as pkts2

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#======================== tc_identity.py Tests ================================

def test_statistical_classifier():
    """
    Test instantiating custom classifiers and use of
    supplied sample statistical classifier
    """

    #*** Test DPIDs and in ports:
    DPID1 = 1
    INPORT1 = 1

    #*** Instantiate class object:
    flow = flow_class.Flow(config)    #*** Test DPIDs and in ports:
    DPID1 = 1
    INPORT1 = 1

    #*** Instantiate class objects:
    flow = flow_class.Flow(config)
    ident = identities_class.Identities(config)

    #*** Instantiate custom classifiers
    tc_cust = tc_custom.CustomInspect(config)
    tc_cust.instantiate_classifiers(['statistical_qos_bandwidth_1'])

    #*** Instantiate match object:
    condition = tc_policy.TrafficClassificationPolicy.Condition()

    #*** Ingest sufficient packets to complete statistical classification (7):

    #*** Ingest packet 10.1.0.1 10.1.0.2 TCP 38435 80 [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[0], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == True
    assert condition.classification_tag == ""
    assert condition.actions == {}

    #*** Ingest packet 10.1.0.2 10.1.0.1 TCP 80 38435 [SYN, ACK]
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[1], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == True
    assert condition.classification_tag == ""
    assert condition.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[2], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == True
    assert condition.classification_tag == ""
    assert condition.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[3], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == True
    assert condition.classification_tag == ""
    assert condition.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[4], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == True
    assert condition.classification_tag == ""
    assert condition.actions == {}

    #*** Ingest packet
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[5], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == True
    assert condition.classification_tag == ""
    assert condition.actions == {}

    #*** Ingest packet
    #*** This should conclude the statistical classification for this flow
    #*** and conclude action is default priority
    flow.ingest_packet(DPID1, INPORT1, pkts2.RAW[6], datetime.datetime.now())

    condition.policy_attr = 'custom'
    condition.policy_value = 'statistical_qos_bandwidth_1'
    tc_cust.check_custom(condition, flow, ident)
    assert condition.match == True
    assert condition.continue_to_inspect == False
    assert condition.classification_tag == ""
    assert condition.actions == {'qos_treatment': 'default_priority'}

