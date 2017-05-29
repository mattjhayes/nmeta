# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#*** nmeta - Network Metadata - Policy Interpretation Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN controller.
It provides a policy class as an interface to policy configuration and
classification of packets against policy.

See Policy class docstring for more information.
"""

import sys
import os
import datetime

#*** nmeta imports:
import tc_static
import tc_identity
import tc_custom

#*** Voluptuous to verify inputs against schema:
from voluptuous import Schema, Optional, Any, All, Required, Extra
from voluptuous import Invalid, MultipleInvalid, Range

#*** Import netaddr for MAC and IP address checking:
from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import EUI

#*** YAML for config and policy file parsing:
import yaml

#*** Regular Expressions:
import re

#*** For logging configuration:
from baseclass import BaseClass

#================== Functions (need to come first):

def validate(logger, data, schema, where):
    """
    Generic validation of a data structure against schema
    using Voluptuous data validation library
    Parameters:
     - logger: valid logger reference
     - data: structure to validate
     - schema: a valid Voluptuous schema
     - where: string for debugging purposes to identity the policy location
    """
    logger.debug("validating data=%s", data)
    try:
        #*** Check correctness of data against schema with Voluptuous:
        schema(data)
    except MultipleInvalid as exc:
        #*** There was a problem with the data:
        logger.critical("Voluptuous detected a problem where=%s, exception=%s",
                                                                    where, exc)
        sys.exit("Exiting nmeta. Please fix error in main_policy.yaml")
    return 1

def validate_port_set_list(logger, port_set_list, policy):
    """
    Validate that a list of dictionaries [{'port_set': str}]
    reference valid port_sets. Return Boolean 1 if good otherwise
    exit with exception
    """
    for port_set_dict in port_set_list:
        found = 0
        for port_set in policy.port_sets.port_sets_list:
            if port_set.name == port_set_dict['port_set']:
                found = 1
        if not found:
            logger.critical("Undefined port_set=%s", port_set_dict['port_set'])
            sys.exit("Exiting nmeta. Please fix error in main_policy.yaml")
    return 1

def validate_location(logger, location, policy):
    """
    Validator for location compliance (i.e. check that the supplied
    location string exists as a location defined in policy)
    Return Boolean True if good, otherwise exit with exception
    """
    for policy_location in policy.locations.locations_list:
        if policy_location.name == location:
            return True
    logger.critical("Undefined location=%s", location)
    sys.exit("Exiting nmeta. Please fix error in main_policy.yaml")

def validate_type(type, value, msg):
    """
    Used for Voluptuous schema validation.
    Check a value is correct type, otherwise raise Invalid exception,
    including elaborated version of msg
    """
    try:
        return type(value)
    except ValueError:
        msg = msg + ", value=" + value + ", expected type=" + type.__name__
        raise Invalid(msg)

def transform_ports(ports):
    """
    Passed a ports specification and return a list of
    port numbers for easy searching.
    Example:
    Ports specification "1-3,5,66" becomes list [1,2,3,5,66]
    """
    result = []
    ports = str(ports)
    for part in ports.split(','):
        if '-' in part:
            part_a, part_b = part.split('-')
            part_a, part_b = int(part_a), int(part_b)
            result.extend(range(part_a, part_b + 1))
        else:
            part_a = int(part)
            result.append(part_a)
    return result

def validate_ports(ports):
    """
    Custom Voluptuous validator for a list of ports.
    Example good ports specification:
        1-3,5,66
    Will raise Voluptuous Invalid exception if types or
    ranges are not correct
    """
    msg = 'Ports specification contains non-integer value'
    msg2 = 'Ports specification contains invalid range'
    #*** Cast to String:
    ports = str(ports)
    #*** Split into components separated by commas:
    for part in ports.split(','):
        #*** Handle ranges:
        if '-' in part:
            part_a, part_b = part.split('-')
            #*** can they be cast to integer?:
            validate_type(int, part_a, msg)
            validate_type(int, part_b, msg)
            #*** In a port range, part_b must be larger than part_a:
            if not int(part_b) > int(part_a):
                raise Invalid(msg2)
        else:
            #*** can it be cast to integer?:
            validate_type(int, part, msg)
    return ports

def validate_macaddress(mac_addr):
    """
    Custom Voluptuous validator for MAC address compliance.
    Returns original MAC address if compliant, otherwise
    raises Voluptuous Invalid exception
    """
    msg = 'Invalid MAC address'
    try:
        result = EUI(mac_addr)
        if result.version != 48:
            raise Invalid(msg)
    except:
        raise Invalid(msg)
    return mac_addr

def validate_macaddress_OLD(mac_addr):
    """
    Custom Voluptuous validator for MAC address compliance.
    Returns original MAC address if compliant, otherwise
    raises Voluptuous Invalid exception
    """
    msg = 'Invalid MAC address'
    try:
        if not re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_addr.lower()):
            raise Invalid(msg)
    except:
        raise Invalid(msg)
    return mac_addr

def validate_ip_space(ip_addr):
    """
    Custom Voluptuous validator for IP address compliance.
    Can be IPv4 or IPv6 and can be range or have CIDR mask.
    Returns original IP address if compliant, otherwise
    raises Voluptuous Invalid exception
    """
    msg = 'Invalid IP address'
    #*** Does it look like a CIDR network?:
    if "/" in ip_addr:
        try:
            if not IPNetwork(ip_addr):
                raise Invalid(msg)
        except:
            raise Invalid(msg)
        return ip_addr
    #*** Does it look like an IP range?:
    elif "-" in ip_addr:
        ip_range = ip_addr.split("-")
        if len(ip_range) != 2:
            raise Invalid(msg)
        try:
            if not (IPAddress(ip_range[0]) and IPAddress(ip_range[1])):
                raise Invalid(msg)
        except:
            raise Invalid(msg)
        #*** Check second value in range greater than first value:
        if IPAddress(ip_range[0]).value >= IPAddress(ip_range[1]).value:
            raise Invalid(msg)
        #*** Check both IP addresses are the same version:
        if IPAddress(ip_range[0]).version != \
                                 IPAddress(ip_range[1]).version:
            raise Invalid(msg)
        return ip_addr
    else:
        #*** Or is it just a plain simple IP address?:
        try:
            if not IPAddress(ip_addr):
                raise Invalid(msg)
        except:
            raise Invalid(msg)
    return ip_addr

def validate_ethertype(ethertype):
    """
    Custom Voluptuous validator for ethertype compliance.
    Can be in hex (starting with 0x) or decimal.
    Returns ethertype if compliant, otherwise
    raises Voluptuous Invalid exception
    """
    msg = 'Invalid EtherType'
    if ethertype[:2] == '0x':
        #*** Looks like hex:
        try:
            if not (int(ethertype, 16) > 0 and \
                               int(ethertype, 16) < 65536):
                raise Invalid(msg)
        except:
            raise Invalid(msg)
    else:
        #*** Perhaps it's decimal?
        try:
            if not (int(ethertype) > 0 and \
                                  int(ethertype) < 65536):
                raise Invalid(msg)
        except:
            raise Invalid(msg)
    return ethertype

#================= Voluptuous Schema for Validating Policy

#*** Voluptuous schema for top level keys in the main policy:
TOP_LEVEL_SCHEMA = Schema({
                        Required('tc_rules'):
                            {Extra: object},
                        Required('qos_treatment'):
                            {Extra: object},
                        Required('port_sets'):
                            {Extra: object},
                        Required('locations'):
                            {Extra: object}
                        })
#*** Voluptuous schema for tc_rules branch of main policy:
TC_RULES_SCHEMA = Schema([{Extra: object}])
#*** Voluptuous schema for a tc_rule:
TC_RULE_SCHEMA = Schema({
                        Optional('comment'):
                            str,
                        Required('match_type'):
                            Required(Any('any', 'all', 'none')),
                        Required('conditions_list'):
                            [{Extra: object}],
                        Required('actions'):
                            {Extra: object}
                        })
#*** Voluptuous schema for a tc condition:
TC_CONDITION_SCHEMA = Schema({
                        Required('match_type'):
                            Required(Any('any', 'all', 'none')),
                        Required('classifiers_list'):
                            [{Extra: object}]
                        })
#*** Voluptuous schema for a tc classifier:
TC_CLASSIFIER_SCHEMA = Schema({
                        Optional('location_src'): str,
                        Optional('eth_src'): validate_macaddress,
                        Optional('eth_dst'): validate_macaddress,
                        Optional('ip_src'): validate_ip_space,
                        Optional('ip_dst'): validate_ip_space,
                        Optional('tcp_src'): All(int, Range(min=0, max=65535)),
                        Optional('tcp_dst'): All(int, Range(min=0, max=65535)),
                        Optional('udp_src'): All(int, Range(min=0, max=65535)),
                        Optional('udp_dst'): All(int, Range(min=0, max=65535)),
                        Optional('eth_type'): validate_ethertype,
                        Optional('identity_lldp_systemname'): str,
                        Optional('identity_lldp_systemname_re'): str,
                        Optional('identity_service_dns'): str,
                        Optional('identity_service_dns_re'): str,
                        Optional('custom'): str
                        })
#*** Voluptuous schema for tc actions:
TC_ACTIONS_SCHEMA = Schema({
                        Optional('drop'): Any('at_controller',
                                              'at_controller_and_switch'),
                        Optional('qos_treatment'): Any('default_priority',
                                                       'constrained_bw',
                                                       'high_priority',
                                                       'low_priority',
                                                       'classifier_return'),
                        Required('set_desc'): str
                        })
#*** Voluptuous schema for qos_treatment branch of main policy:
QOS_TREATMENT_SCHEMA = Schema({str: int})
#*** Voluptuous schema for port_sets branch of main policy:
PORT_SETS_SCHEMA = Schema({
                        Required('port_set_list'):
                            [{Extra: object}]
                        })
#*** Voluptuous schema for a port set node in main policy:
PORT_SET_SCHEMA = Schema({
                        Required('name'): str,
                        Required('port_list'):
                            [
                                {
                                'name': str,
                                'DPID': int,
                                'ports': validate_ports,
                                'vlan_id': int
                                }
                            ]
                        })
#*** Voluptuous schema for locations branch of main policy:
LOCATIONS_SCHEMA = Schema({
                        Required('locations_list'):
                            [{Extra: object}],
                        Required('default_match'): str
                        })
#*** Voluptuous schema for a location node in main policy:
LOCATION_SCHEMA = Schema({
                        Required('name'): str,
                        Required('port_set_list'):
                            [{'port_set': str}],
                        })

#*** Default policy file location parameters:
POL_DIR_DEFAULT = "config"
POL_DIR_USER = "config/user"
POL_FILENAME = "main_policy.yaml"

class Policy(BaseClass):
    """
    This policy class serves 4 main purposes:
    - Ingest policy (main_policy.yaml) from file
    - Validate correctness of policy against schema
    - Classify packets against policy, passing through to static,
      identity and custom classifiers, as required
    - Other methods and functions to check various parameters
      against policy

    Note: Class definitions are not nested as not considered Pythonic

    Main Methods and Variables:
    - check_policy(flow, ident)   # Check a packet against policy
    - qos(qos_treatment)          # Map qos_treatment string to queue number
    - main_policy                 # main policy YAML object. Read-only,
                                      no verbs. Use methods instead where
                                      possible.

    TC Methods and Variables:
    - tc_rules.rules_list         # List of TC rules
    - tc_rules.custom_classifiers # dedup list of custom classifier names


    """
    def __init__(self, config, pol_dir_default=POL_DIR_DEFAULT,
                    pol_dir_user=POL_DIR_USER,
                    pol_filename=POL_FILENAME):
        """ Initialise the Policy Class """
        #*** Required for BaseClass:
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "policy_logging_level_s",
                                       "policy_logging_level_c")
        self.policy_dir_default = pol_dir_default
        self.policy_dir_user = pol_dir_user
        self.policy_filename = pol_filename
        #*** Get working directory:
        self.working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the user policy file:
        self.fullpathname = os.path.join(self.working_directory,
                                         self.policy_dir_user,
                                         self.policy_filename)
        if os.path.isfile(self.fullpathname):
            self.logger.info("Opening user policy file=%s", self.fullpathname)
        else:
            self.logger.info("User policy file=%s not found",
                                                            self.fullpathname)
            self.fullpathname = os.path.join(self.working_directory,
                                         self.policy_dir_default,
                                         self.policy_filename)
            self.logger.info("Opening default policy file=%s",
                                                            self.fullpathname)
        #*** Ingest the policy file:
        try:
            with open(self.fullpathname, 'r') as filename:
                self.main_policy = yaml.safe_load(filename)
        except (IOError, OSError) as exception:
            self.logger.error("Failed to open policy "
                              "file=%s exception=%s",
                              self.fullpathname, exception)
            sys.exit("Exiting nmeta. Please create policy file")

        #*** Instantiate Classes:
        self.static = tc_static.StaticInspect(config, self)
        self.identity = tc_identity.IdentityInspect(config)
        self.custom = tc_custom.CustomInspect(config)

        #*** Check the correctness of the top level of main policy:
        validate(self.logger, self.main_policy, TOP_LEVEL_SCHEMA, 'top')

        #*** Instantiate classes for the second levels of policy:
        self.tc_rules = TCRules(self)
        self.qos_treatment = QoSTreatment(self)
        self.port_sets = PortSets(self)
        self.locations = Locations(self)

        #*** Instantiate any custom classifiers:
        self.custom.instantiate_classifiers(self.tc_rules.custom_classifiers)

    def check_policy(self, flow, ident):
        """
        Passed a flows object, set in context of current packet-in event,
        and an identities object.
        Check if packet matches against any policy
        rules and if it does, update the classifications portion of
        the flows object to reflect details of the classification.
        """
        #*** Check against TC policy:
        for tc_rule in self.tc_rules.rules_list:
            #*** Check the rule:
            tc_rule_result = tc_rule.check_tc_rule(flow, ident)
            if tc_rule_result.match:
                self.logger.debug("Matched policy rule=%s", tc_rule.__dict__)
                #*** Only set 'classified' if continue_to_inspect not set:
                if not tc_rule_result.continue_to_inspect:
                    flow.classification.classified = True
                else:
                    flow.classification.classified = False
                flow.classification.classification_tag = \
                                              tc_rule_result.classification_tag
                flow.classification.classification_time = \
                                                        datetime.datetime.now()
                #*** Accumulate any actions:
                flow.classification.actions.update(tc_rule_result.actions)
                return 1

        #*** No matches. Mark as classified so we don't process again:
        flow.classification.classified = True
        return 0

    def qos(self, qos_treatment):
        """
        Passed a QoS treatment string and return the relevant
        QoS queue number to use, otherwise 0. Works by lookup
        on qos_treatment section of main_policy
        """
        qos_policy = self.main_policy['qos_treatment']
        if qos_treatment in qos_policy:
            return qos_policy[qos_treatment]
        elif qos_treatment == 'classifier_return':
            #*** This happens:
            self.logger.debug("custom classifier did not return "
                                                               "qos_treatment")
            return 0
        else:
            self.logger.error("qos_treatment=%s not found in main_policy",
                                                                 qos_treatment)
            return 0

class TCRules(object):
    """
    An object that represents the tc_rules root branch of
    the main policy
    """
    def __init__(self, policy):
        """ Initialise the TCRules Class """
        #*** Extract logger and policy YAML branch:
        self.logger = policy.logger
        #*** TBD: fix arbitrary single ruleset...
        self.yaml = policy.main_policy['tc_rules']['tc_ruleset_1']

        #*** List to be populated with names of any custom classifiers:
        self.custom_classifiers = []

        #*** Check the correctness of the tc_rules branch of main policy:
        validate(self.logger, self.yaml, TC_RULES_SCHEMA, 'tc_rules')

        #*** Read in rules:
        self.rules_list = []
        for idx, key in enumerate(self.yaml):
            self.rules_list.append(TCRule(self, policy, idx))

class TCRule(object):
    """
    An object that represents a single traffic classification
    (TC) rule.
    """
    def __init__(self, tc_rules, policy, idx):
        """
        Initialise the TCRule Class
        Passed a TCRules class instance, a Policy class instance
        and an index integer for the index of the tc rule in policy
        """
        #*** Extract logger and policy YAML:
        self.logger = policy.logger
        #*** TBD: fix arbitrary single ruleset...
        self.yaml = policy.main_policy['tc_rules']['tc_ruleset_1'][idx]

        #*** Check the correctness of the tc rule, including actions:
        validate(self.logger, self.yaml, TC_RULE_SCHEMA, 'tc_rule')
        validate(self.logger, self.yaml['actions'], TC_ACTIONS_SCHEMA,
                                                     'tc_rule_actions')
        self.match_type = self.yaml['match_type']
        self.actions = self.yaml['actions']
        #*** Read in conditions_list:
        self.conditions_list = []
        for condition in self.yaml['conditions_list']:
            self.conditions_list.append(TCCondition(tc_rules,
                            policy, condition))

    def check_tc_rule(self, flow, ident):
        """
        Passed Packet and Identity class objects.
        Check to see if packet matches conditions as per the
        TC rule. Return a TCRuleResult object
        """
        #*** Instantiate object to hold results for checks:
        result = TCRuleResult(self.actions)
        #*** Iterate through the conditions list:
        for condition in self.conditions_list:
            condition_result = condition.check_tc_condition(flow, ident)
            self.logger.debug("condition=%s result=%s", condition.__dict__,
                                                     condition_result.__dict__)
            #*** Decide what to do based on match result and type:
            if condition_result.match and self.match_type == "any":
                result.match = True
                result.accumulate(condition_result)
                result.add_rule_actions()
                return result
            elif not result.match and self.match_type == "all":
                result.match = False
                return result
            elif result.match and self.match_type == "all":
                #*** Just accumulate the results:
                result.accumulate(condition_result)
            elif result.match and self.match_type == "none":
                result.match = False
                return result
            else:
                #*** Not a condition we take action on so keep going:
                pass
        #*** We've finished loop through all conditions and haven't
        #***  returned. Work out what action to take:
        if not condition_result.match and self.match_type == "any":
            result.match = False
            return result
        elif condition_result.match and self.match_type == "all":
            result.match = True
            result.accumulate(condition_result)
            result.add_rule_actions()
            return result
        elif not condition_result.match and self.match_type == "none":
            result.match = True
            result.add_rule_actions()
            return result
        else:
            #*** Unexpected result:
            self.logger.error("Unexpected result at "
                "end of loop through rule=%s", self.yaml)
            result.match = False
            return result

class TCRuleResult(object):
    """
    An object that represents a traffic classification
    result, including any decision collateral
    on matches and actions.
    Use __dict__ to dump to data to dictionary
    """
    def __init__(self, rule_actions):
        """ Initialise the TCRuleResult Class """
        self.match = 0
        self.continue_to_inspect = 0
        self.classification_tag = ""
        self.actions = {}
        #*** Actions defined in policy for this rule:
        self.rule_actions = rule_actions

    def accumulate(self, condition_result):
        """
        Passed a TCConditionResult object and
        accumulate values into our object
        """
        if condition_result.match:
            self.match = True
            if condition_result.continue_to_inspect:
                self.continue_to_inspect = True
            if self.rule_actions['set_desc'] == 'classifier_return':
                self.classification_tag = condition_result.classification_tag
            else:
                self.classification_tag = self.rule_actions['set_desc']
            self.actions.update(condition_result.actions)

    def add_rule_actions(self):
        """
        Add rule actions from policy to the actions of this class
        """
        self.actions.update(self.rule_actions)

class TCCondition(object):
    """
    An object that represents a single traffic classification
    (TC) rule condition from a conditions list
    (contains a match type and a list of one or more classifiers)
    """
    def __init__(self, tc_rules, policy, policy_snippet):
        """
        Initialise the TCCondition Class
        Passed a TCRules class instance, a Policy class instance
        and a snippet of tc policy for a condition
        """
        self.policy = policy
        self.logger = policy.logger
        self.yaml = policy_snippet
        self.classifiers = []

        #*** Check the correctness of the tc condition:
        validate(self.logger, self.yaml, TC_CONDITION_SCHEMA,
                                               'tc_rule_condition')

        for classifier in self.yaml['classifiers_list']:
            #*** Validate classifier:
            validate(self.logger, classifier, TC_CLASSIFIER_SCHEMA,
                                                               'tc_classifier')
            #*** Extra validation for location_src:
            policy_attr = next(iter(classifier))
            policy_value = classifier[policy_attr]
            if policy_attr == 'location_src':
                validate_location(self.logger, policy_value, policy)

            self.classifiers.append(classifier)
            #*** Accumulate deduplicated custom classifier names:
            if 'custom' in classifier:
                custlist = tc_rules.custom_classifiers
                if classifier['custom'] not in custlist:
                    custlist.append(classifier['custom'])

        self.match_type = self.yaml['match_type']

    def check_tc_condition(self, flow, ident):
        """
        Passed a Flow and Identity class objects. Check to see if
        flow.packet matches condition (a set of classifiers)
        as per the match type.
        Return a TCConditionResult object with match information.
        """
        pkt = flow.packet
        result = TCConditionResult()
        self.logger.debug("self.classifiers=%s", self.classifiers)
        #*** Iterate through classifiers (example: tcp_src: 123):
        for classifier in self.classifiers:
            policy_attr = next(iter(classifier))
            policy_value = classifier[policy_attr]
            #*** Instantiate data structure for classifier result:
            classifier_result = TCClassifierResult(policy_attr, policy_value)
            self.logger.debug("Iterating classifiers, policy_attr=%s "
                        "policy_value=%s, policy_attr_type=%s", policy_attr,
                        policy_value, classifier_result.policy_attr_type)
            #*** Main check on classifier attribute type:
            if classifier_result.policy_attr_type == "identity":
                self.policy.identity.check_identity(classifier_result, pkt,
                                                                         ident)
            elif policy_attr == "custom":
                self.policy.custom.check_custom(classifier_result, flow, ident)
                self.logger.debug("custom match condition=%s",
                                                    classifier_result.__dict__)
            else:
                #*** default to static classifier:
                self.policy.static.check_static(classifier_result, pkt)
                self.logger.debug("static match=%s",
                                                    classifier_result.__dict__)
            #*** Decide what to do based on match result and type:
            if classifier_result.match and self.match_type == "any":
                result.accumulate(classifier_result)
                return result
            elif not classifier_result.match and self.match_type == "all":
                result.match = False
                return result
            elif classifier_result.match and self.match_type == "none":
                result.match = False
                return result
            else:
                #*** Not a condition we take action on, keep going:
                pass
        #*** Finished loop through all conditions without return.
        #***  Work out what action to take:
        if not classifier_result.match and self.match_type == "any":
            result.match = False
            return result
        elif classifier_result.match and self.match_type == "all":
            result.accumulate(classifier_result)
            return result
        elif not classifier_result.match and self.match_type == "none":
            result.match = True
            return result
        else:
            #*** Unexpected result:
            self.logger.error("Unexpected result at end of loop"
                                        "classifier_result=%s",
                                        classifier_result.__dict__)
            result.match = False
            return result

class TCConditionResult(object):
    """
    An object that represents a traffic classification condition
    result. Custom classifiers can return additional parameters
    beyond a Boolean match, so cater for these too.
    Use __dict__ to dump to data to dictionary
    """
    def __init__(self):
        """ Initialise the TCConditionResult Class """
        self.match = False
        self.continue_to_inspect = False
        self.classification_tag = ""
        self.actions = {}

    def accumulate(self, classifier_result):
        """
        Passed a TCClassifierResult object and
        accumulate values into our object
        """
        if classifier_result.match:
            self.match = True
            if classifier_result.continue_to_inspect:
                self.continue_to_inspect = True
            self.actions.update(classifier_result.actions)
            self.classification_tag += classifier_result.classification_tag

class TCClassifierResult(object):
    """
    An object that represents a traffic classification classifier
    result. Custom classifiers can return additional parameters
    beyond a Boolean match, so cater for these too.
    Use __dict__ to dump to data to dictionary
    """
    def __init__(self, policy_attr, policy_value):
        """ Initialise the TCClassifierResult Class """
        self.match = False
        self.continue_to_inspect = 0
        self.policy_attr = policy_attr
        #*** Policy Attribute Type is for identity classifiers
        self.policy_attr_type = policy_attr.split("_")[0]
        self.policy_value = policy_value
        self.classification_tag = ""
        self.actions = {}

class QoSTreatment(object):
    """
    An object that represents the qos_treatment root branch of
    the main policy
    """
    def __init__(self, policy):
        """ Initialise the QoSTreatment Class """
        #*** Extract logger and policy YAML branch:
        self.logger = policy.logger
        self.yaml = policy.main_policy['qos_treatment']

        #*** Check the correctness of the qos_treatment branch of main policy:
        validate(self.logger, self.yaml, QOS_TREATMENT_SCHEMA, 'qos_treatment')

class PortSets(object):
    """
    An object that represents the port_sets root branch of
    the main policy
    """
    def __init__(self, policy):
        """ Initialise the PortSets Class """
        #*** Extract logger and policy YAML branch:
        self.logger = policy.logger
        self.yaml = policy.main_policy['port_sets']

        #*** Check the correctness of the port_sets branch of main policy:
        validate(self.logger, self.yaml, PORT_SETS_SCHEMA, 'port_sets')
        #*** Read in port_sets:
        self.port_sets_list = []
        for idx, key in enumerate(self.yaml['port_set_list']):
            self.port_sets_list.append(PortSet(policy, idx))

    def get_port_set(self, dpid, port, vlan_id=0):
        """
        Check if supplied dpid/port/vlan_id is member of
        a port set and if so, return the port_set name. If no
        match return empty string.
        """
        for idx in self.port_sets_list:
            if idx.is_member(dpid, port, vlan_id):
                return idx.name
        return ""

class PortSet(object):
    """
    An object that represents a single port set
    """

    def __init__(self, policy, idx):
        """ Initialise the PortSet Class """
        #*** Extract logger and policy YAML:
        self.logger = policy.logger
        self.yaml = \
                policy.main_policy['port_sets']['port_set_list'][idx]
        self.name = self.yaml['name']

        #*** Check the correctness of the location policy:
        validate(self.logger, self.yaml, PORT_SET_SCHEMA, 'port_set')

        #*** Build searchable lists of ports
        #***  (ranges turned into multiple single values):
        port_list = self.yaml['port_list']
        for ports in port_list:
            ports['ports_xform'] = transform_ports(ports['ports'])

    def is_member(self, dpid, port, vlan_id=0):
        """
        Check to see supplied dpid/port/vlan_id is member of
        this port set. Returns a Boolean
        """
        #*** Validate dpid is an integer (and coerce if required):
        msg = 'dpid must be integer'
        dpid = validate_type(int, dpid, msg)

        #*** Validate port is an integer (and coerce if required):
        msg = 'Port must be integer'
        port = validate_type(int, port, msg)

        #*** Validate vlan_id is an integer (and coerce if required):
        msg = 'vlan_id must be integer'
        vlan_id = validate_type(int, vlan_id, msg)

        #*** Iterate through port list looking for a match:
        port_list = self.yaml['port_list']
        for ports in port_list:
            if not ports['DPID'] == dpid:
                self.logger.debug("did not match dpid")
                continue
            if not ports['vlan_id'] == vlan_id:
                self.logger.debug("did not match vlan_id")
                continue
            if port in ports['ports_xform']:
                return True
        self.logger.debug("no match, returning False")
        return False

class Locations(object):
    """
    An object that represents the locations root branch of
    the main policy
    """
    def __init__(self, policy):
        """ Initialise the Locations Class """
        #*** Extract logger and policy YAML branch:
        self.logger = policy.logger
        self.yaml = policy.main_policy['locations']

        #*** Check the correctness of the locations branch of main policy:
        validate(self.logger, self.yaml, LOCATIONS_SCHEMA, 'locations')

        #*** Read in locations etc:
        self.locations_list = []
        for idx, key in enumerate(self.yaml['locations_list']):
            self.locations_list.append(Location(policy, idx))
        #*** Default location to use if no match:
        self.default_match = self.yaml['default_match']

    def get_location(self, dpid, port):
        """
        Passed a DPID and port and return a logical location
        name, as per policy configuration.
        """
        result = ""
        for location in self.locations_list:
            result = location.check(dpid, port)
            if result:
                return result
        return self.default_match

class Location(object):
    """
    An object that represents a single location
    """
    def __init__(self, policy, idx):
        """ Initialise the Location Class """
        #*** Extract logger and policy YAML:
        self.logger = policy.logger
        self.policy = policy
        self.yaml = \
                policy.main_policy['locations']['locations_list'][idx]

        #*** Check the correctness of the location policy:
        validate(self.logger, self.yaml, LOCATION_SCHEMA, 'location')

        #*** Check that port sets exist:
        validate_port_set_list(self.logger, self.yaml['port_set_list'],
                                                                policy)

        #*** Store data from YAML into this class:
        self.name = self.yaml['name']
        self.port_set_list = self.yaml['port_set_list']

    def check(self, dpid, port):
        """
        Check a dpid/port to see if it is part of this location
        and if so return the string name of the location otherwise
        return empty string
        """
        port_set_membership = \
                         self.policy.port_sets.get_port_set(dpid, port)
        for port_set in self.port_set_list:
            if port_set['port_set'] == port_set_membership:
                return self.name
        return ""
