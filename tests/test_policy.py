"""
Nmeta policy.py Tests
"""
import pytest

#*** Use copy to create copies not linked to originals (with copy.deepcopy):
import copy

from voluptuous import Invalid, MultipleInvalid

import sys
#*** Handle tests being in different directory branch to app code:
sys.path.insert(0, '../nmeta')

import logging

#*** nmeta imports:
import policy as policy_module
import config
import flows as flows_module
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

#*** Test values for tc policy_conditions:
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
                'qos_treatment': 'QoS_treatment=high_priority',
                'set_desc': 'description="High Priority HTTP Traffic"'
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
                'qos_treatment': 'QoS_treatment=high_priority',
                'set_desc': 'description="High Priority Audit Division SSHd Traffic"'
            }
        }

#*** Same as 2a, but has 'set_desc' action removed:
rule_2b = {
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
                'qos_treatment': 'QoS_treatment=high_priority',
            }
        }

logger = logging.getLogger(__name__)

def test_check_policy():
    """
    Test that packet match against policy works correctly
    """
    #*** Instantiate tc, flows and identities classes, specifying
    #*** a particular main_policy file to use:
    policy = policy_module.Policy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/foo",
                            pol_filename="main_policy_regression_static.yaml")
    flow = flows_module.Flow(config)
    ident = identities.Identities(config, policy)

    #*** Note: cannot query a classification until a packet has been
    #*** ingested - will throw error

    #*** Ingest a packet:
    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Check policy:
    policy.check_policy(flow, ident)
    #*** Should not match any rules in that policy:
    logger.debug("flow.classification.classified=%s", flow.classification.classified)
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == ""
    assert flow.classification.actions == {}

    #*** Re-instantiate tc_policy with different policy that should classify:
    policy = policy_module.Policy(config,
                        pol_dir_default="config/tests/regression",
                        pol_dir_user="config/tests/foo",
                        pol_filename="main_policy_regression_static_3.yaml")

    #*** Re-ingest packet:
    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Check policy:
    policy.check_policy(flow, ident)
    #*** Should match policy:
    assert flow.classification.classified == 1
    assert flow.classification.classification_tag == "Constrained Bandwidth Traffic"
    logger.debug("flow.classification.actions=%s", flow.classification.actions)
    assert flow.classification.actions == {'set_desc': 'Constrained Bandwidth Traffic',
                                           'qos_treatment': 'constrained_bw'}

def test_check_tc_rules():
    #*** Instantiate classes:
    policy = policy_module.Policy(config)
    flow = flows_module.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Set policy.pkt as work around for not calling parent method that sets it:
    policy.pkt = flow.packet
    #*** Should match:
    rule = policy._check_rule(rule_1)
    logger.debug("rule=%s", rule.to_dict())
    assert rule.match == True

    #*** Should not match:
    rule = policy._check_rule(rule_2b)
    logger.debug("rule=%s", rule.to_dict())
    assert rule.match == False

    # TBD - more

def test_check_tc_conditions():
    """
    Check TC packet match against a conditions stanza
    """
    #*** Instantiate classes:
    policy = policy_module.Policy(config)
    flow = flows_module.Flow(config)

    #*** Test Flow 1 Packet 1 (Client TCP SYN):
    # 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN]
    flow.ingest_packet(DPID1, INPORT1, pkts.RAW[0], datetime.datetime.now())
    #*** Set policy.pkt as work around for not calling parent method that sets it:
    policy.pkt = flow.packet
    #*** HTTP is not OpenFlow so shouldn't match!
    logger.debug("conditions_any_opf should not match")
    conditions = policy._check_conditions(conditions_any_opf)
    assert not conditions.condition[0].match

    #*** HTTP is HTTP so should match:
    logger.debug("conditions_any_http should match")
    conditions = policy._check_conditions(conditions_any_http)
    assert conditions.condition[0].match

    #*** Source AND Dest aren't both HTTP so should not match:
    logger.debug("conditions_all_http should not match")
    conditions = policy._check_conditions(conditions_all_http)
    assert not conditions.condition[0].match

    #*** This should match (HTTP src and dst ports correct):
    logger.debug("conditions_all_http2 should match")
    conditions = policy._check_conditions(conditions_all_http2)
    assert conditions.condition[0].match

    #*** MAC should match:
    conditions = policy._check_conditions(conditions_any_mac)
    assert conditions.condition[0].match

    conditions = policy._check_conditions(conditions_all_mac)
    assert conditions.condition[0].match

    #*** Different MAC shouldn't match:
    conditions = policy._check_conditions(conditions_any_mac2)
    assert not conditions.condition[0].match

def test_custom_classifiers():
    """
    Check deduplicated list of custom classifiers works
    """
    #*** Instantiate tc_policy, specifying
    #*** a particular main_policy file to use that has no custom classifiers:
    policy = policy_module.Policy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/regression",
                            pol_filename="main_policy_regression_static.yaml")
    assert policy.tc_rules.custom_classifiers == []

    #*** Instantiate tc_policy, specifying
    #*** a custom statistical main_policy file to use that has a
    #*** custom classifier:
    policy = policy_module.Policy(config,
                        pol_dir_default="config/tests/regression",
                        pol_dir_user="config/tests/foo",
                        pol_filename="main_policy_regression_statistical.yaml")
    assert policy.tc_rules.custom_classifiers == ['statistical_qos_bandwidth_1']

def test_qos():
    """
    Test the assignment of QoS queues based on a qos_treatment action
    """
    #*** Instantiate tc_policy, specifying
    #*** a particular main_policy file to use that has no custom classifiers:
    policy = policy_module.Policy(config,
                            pol_dir_default="config/tests/regression",
                            pol_dir_user="config/tests/foo",
                            pol_filename="main_policy_regression_static.yaml")
    assert policy.qos('default_priority') == 0
    assert policy.qos('constrained_bw') == 1
    assert policy.qos('high_priority') == 2
    assert policy.qos('low_priority') == 3
    assert policy.qos('foo') == 0

def test_portsets_get_port_set():
    """
    Test that get_port_set returns correct port_set name
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #*** Positive matches:
    assert policy.port_sets.get_port_set(255, 5, 0) == "port_set_location_internal"
    assert policy.port_sets.get_port_set(8796748549206, 6, 0) == "port_set_location_external"

    #*** Shouldn't match:
    assert policy.port_sets.get_port_set(1234, 5, 0) == ""

def test_portset_is_member():
    """
    Test that the PortSet class method is_member works correctly
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #*** Members:
    assert policy.port_sets.port_sets_list[0].is_member(255, 5, 0) == 1
    assert policy.port_sets.port_sets_list[0].is_member(8796748549206, 2, 0) == 1
    #*** Not members:
    assert policy.port_sets.port_sets_list[0].is_member(255, 4, 0) == 0
    assert policy.port_sets.port_sets_list[0].is_member(256, 5, 0) == 0
    assert policy.port_sets.port_sets_list[0].is_member(255, 5, 1) == 0

def test_validate():
    """
    Test the validate function of policy.py module against various
    good and bad policy scenarios to ensure correct results produced
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #=================== Top level:

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)

    #*** Check the correctness of the top level of main policy:
    assert policy_module.validate(logger, main_policy, policy_module.TOP_LEVEL_SCHEMA, 'top') == 1

    #*** Knock out a required key from top level of main policy and check that it raises exception:
    del main_policy['tc_rules']
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, main_policy, policy_module.TOP_LEVEL_SCHEMA, 'top')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)

    #*** Add an invalid key to top level of main policy and check that it raises exception:
    main_policy['foo'] = 1
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, main_policy, policy_module.TOP_LEVEL_SCHEMA, 'top')

    #=================== TC Rules branch

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_policy = main_policy['tc_rules']['tc_ruleset_1'][0]
    assert policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule') == 1

    #*** Knock comment out of rule, should still validate as comment is optional:
    del tc_rule_policy['comment']
    assert policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule') == 1

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_policy = main_policy['tc_rules']['tc_ruleset_1'][0]
    assert policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule') == 1

    #*** Knock match_type out of rule, should fail:
    del tc_rule_policy['match_type']
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_policy = main_policy['tc_rules']['tc_ruleset_1'][0]
    assert policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule') == 1

    #*** Change match_type to something that isn't supported, should fail:
    tc_rule_policy['match_type'] = 'foo'
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_policy = main_policy['tc_rules']['tc_ruleset_1'][0]
    assert policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule') == 1

    #*** Knock conditions_list out of rule, should fail:
    del tc_rule_policy['conditions_list']
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_policy = main_policy['tc_rules']['tc_ruleset_1'][0]
    assert policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule') == 1

    #*** Knock actions out of rule, should fail:
    del tc_rule_policy['actions']
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, tc_rule_policy, policy_module.TC_RULE_SCHEMA, 'tc_rule')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_actions = main_policy['tc_rules']['tc_ruleset_1'][0]['actions']
    assert policy_module.validate(logger, tc_rule_actions, policy_module.TC_ACTIONS_SCHEMA, 'tc_rule_actions') == 1

    #*** Add invalid action:
    tc_rule_actions['foo'] = 'bar'
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, tc_rule_actions, policy_module.TC_ACTIONS_SCHEMA, 'tc_rule_actions')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    tc_rule_actions = main_policy['tc_rules']['tc_ruleset_1'][0]['actions']
    assert policy_module.validate(logger, tc_rule_actions, policy_module.TC_ACTIONS_SCHEMA, 'tc_rule_actions') == 1

    #*** Add a valid action key with valid value:
    tc_rule_actions['drop'] = 'at_controller_and_switch'
    assert policy_module.validate(logger, tc_rule_actions, policy_module.TC_ACTIONS_SCHEMA, 'tc_rule_actions') == 1

    #*** Add a valid action key with invalid value:
    tc_rule_actions['drop'] = 'controller'
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, tc_rule_actions, policy_module.TC_ACTIONS_SCHEMA, 'tc_rule_actions')


    #=================== Locations branch

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    locations_policy = main_policy['locations']

    #*** Check the correctness of the locations branch of main policy:
    assert policy_module.validate(logger, locations_policy, policy_module.LOCATIONS_SCHEMA, 'locations') == 1

    #*** Knock out a required key from locations branch of main policy and check that it raises exception:
    del locations_policy['default_match']
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, locations_policy, policy_module.LOCATIONS_SCHEMA, 'locations')

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)
    locations_policy = main_policy['locations']

    #*** Add an invalid key to locations branch of main policy and check that it raises exception:
    locations_policy['foo'] = 1
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate(logger, locations_policy, policy_module.LOCATIONS_SCHEMA, 'locations')

def test_validate_locations():
    """
    Test the validate_locations function of policy.py module against various
    good and bad policy scenarios to ensure correct results produced
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)

    #*** Check the correctness of the locations branch of main policy:
    assert policy_module.validate_locations(logger, main_policy) == 1

def test_validate_port_set_list():
    """
    Test the validate_port_set_list function of policy.py module against
    various good and bad policy scenarios to ensure correct results produced
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #*** Get a copy of the main policy YAML:
    main_policy = copy.deepcopy(policy.main_policy)

    port_set_list = main_policy['locations']['locations_list'][0]['port_set_list']
    assert policy_module.validate_port_set_list(logger, port_set_list, policy) == 1

    #*** Add a bad port_set:
    bad_port_set = {'port_set': 'foobar'}
    port_set_list.append(bad_port_set)
    with pytest.raises(SystemExit) as exit_info:
        policy_module.validate_port_set_list(logger, port_set_list, policy)

def test_validate_ports():
    """
    Test the validate_ports function of policy.py module against various
    good and bad ports specifications

    Example:
    1-3,5,66
    """
    ports_good1 = "1-3,5,66"
    ports_good2 = "99"
    ports_good3 = "1-3,5,66-99"
    ports_good4 = "1-3, 5, 66-99"

    #*** Non-integer values:
    ports_bad1 = "1-3,foo,66"
    ports_bad2 = "1-b,5,66"
    #*** Invalid range:
    ports_bad3 = "1-3,5,66-65"

    assert policy_module.validate_ports(ports_good1) == ports_good1

    assert policy_module.validate_ports(ports_good2) == ports_good2

    assert policy_module.validate_ports(ports_good3) == ports_good3

    assert policy_module.validate_ports(ports_good4) == ports_good4

    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ports(ports_bad1)

    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ports(ports_bad2)

    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ports(ports_bad3)

def test_validate_macaddress():
    """
    Test the validate_macaddress function of policy.py module against various
    good and bad MAC addresses
    """
    #*** Valid MAC Addresses:
    assert policy_module.validate_macaddress('fe80:dead:beef') == 'fe80:dead:beef'
    assert policy_module.validate_macaddress('fe80deadbeef') == 'fe80deadbeef'
    assert policy_module.validate_macaddress('fe:80:de:ad:be:ef') == 'fe:80:de:ad:be:ef'

    #*** Invalid MAC Addresses:
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_macaddress('192.168.3.4')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_macaddress('foo 123')

def test_validate_ipaddress():
    """
    Test the validate_ipaddress function of policy.py module against various
    good and bad IP addresses
    """
    #*** Valid IP Addresses:
    assert policy_module.validate_ip_space('192.168.3.4') == '192.168.3.4'
    assert policy_module.validate_ip_space('192.168.3.0/24') == '192.168.3.0/24'
    assert policy_module.validate_ip_space('192.168.3.25-192.168.4.58') == '192.168.3.25-192.168.4.58'
    assert policy_module.validate_ip_space('fe80::dead:beef') == 'fe80::dead:beef'
    assert policy_module.validate_ip_space('10.1.2.2-10.1.2.3') == '10.1.2.2-10.1.2.3'
    assert policy_module.validate_ip_space('fe80::dead:beef-fe80::dead:beff') == 'fe80::dead:beef-fe80::dead:beff'

    #*** Invalid IP Addresses:
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ip_space('192.168.322.0/24')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ip_space('foo')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ip_space('192.168.4.25-192.168.3.58')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ip_space('192.168.3.25-43')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ip_space('10.1.2.3-fe80::dead:beef')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ip_space('10.1.2.3-10.1.2.5-10.1.2.8')

def test_validate_ethertype():
    """
    Test the validate_ethertype function of policy.py module against various
    good and bad ethertypes
    """
    #*** Valid EtherTypes:
    assert policy_module.validate_ethertype('0x0800') == '0x0800'
    assert policy_module.validate_ethertype('0x08001') == '0x08001'
    assert policy_module.validate_ethertype('35020') == '35020'

    #*** Invalid EtherTypes:
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ethertype('foo')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ethertype('0x18001')
    with pytest.raises(Invalid) as exit_info:
        policy_module.validate_ethertype('350201')

def test_transform_ports():
    """
    Test the transform_ports function of policy.py module against various
    ports specifications

    Example:
    Ports specification "1-3,5,66" should become list [1,2,3,5,66]
    """
    ports1 = "1-3,5,66"
    ports_list1 = [1,2,3,5,66]

    ports2 = "10-15, 19-26"
    ports_list2 = [10,11,12,13,14,15,19,20,21,22,23,24,25,26]

    assert policy_module.transform_ports(ports1) == ports_list1

    assert policy_module.transform_ports(ports2) == ports_list2

def test_location_check():
    """
    Test the check method of the Location class
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #*** Test against 'internal' location:
    assert policy.locations.locations_list[0].check(8796748549206, 1) == 'internal'
    assert policy.locations.locations_list[0].check(8796748549206, 6) == ''
    assert policy.locations.locations_list[0].check(56, 1) == ''
    assert policy.locations.locations_list[0].check(255, 3) == 'internal'

    #*** Test against 'external' location:
    assert policy.locations.locations_list[1].check(8796748549206, 6) == 'external'
    assert policy.locations.locations_list[1].check(8796748549206, 1) == ''

def test_locations_get_location():
    """
    Test the get_location method of the Locations class
    """
    #*** Instantiate Policy class instance:
    policy = policy_module.Policy(config)

    #*** Test against 'internal' location:
    assert policy.locations.get_location(8796748549206, 1) == 'internal'
    assert policy.locations.get_location(255, 3) == 'internal'
    assert policy.locations.get_location(8796748549206, 66) == 'internal'

    #*** Test against 'external' location:
    assert policy.locations.get_location(8796748549206, 6) == 'external'
    assert policy.locations.get_location(255, 4) == 'external'

    #*** Test against no match to default 'unknown' location:
    assert policy.locations.get_location(8796748549206, 7) == 'unknown'
    assert policy.locations.get_location(1234, 5) == 'unknown'
