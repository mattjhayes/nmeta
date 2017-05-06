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
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (Traffic Classification - TC) metadata.
It expects a file called "main_policy.yaml" to be in the config subdirectory
containing properly formed YAML that conforms the the particular specifications
that this program expects. See constant tuples at start of program for valid
attributes to use.
"""

import sys
import os
import datetime

#*** nmeta imports:
import tc_static
import tc_identity
import tc_custom

#*** Voluptuous to verify inputs against schema:
from voluptuous import Schema, Optional, Any, Required, Extra
from voluptuous import Invalid, MultipleInvalid

#*** YAML for config and policy file parsing:
import yaml

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
    try:
        #*** Check correctness of data against schema with Voluptuous:
        schema(data)
    except MultipleInvalid as exc:
        #*** There was a problem with the data:
        logger.critical("Voluptuous detected a problem where=%s, exception=%s",
                                                                    where, exc)
        sys.exit("Exiting nmeta. Please fix error in main_policy.yaml")
    return 1

def validate_locations(logger, main_policy):
    """
    Extra policy validation (in addition to Voluptuous-based validation)
    of the locations branch of main policy
    Parameters:
     - logger: valid logger reference
     - main_policy: The main policy in YAML
    """
    locations = main_policy['locations']
    #*** Check the default_match value exists as a key in locations_list dicts:
    location_list_keys = []
    for location_list_dict in locations['locations_list']:
        location_list_keys.append(location_list_dict['name'])
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
            a, b = part.split('-')
            a, b = int(a), int(b)
            result.extend(range(a, b + 1))
        else:
            a = int(part)
            result.append(a)
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
            a, b = part.split('-')
            #*** can they be cast to integer?:
            validate_type(int, a, msg)
            validate_type(int, b, msg)
            #*** In a port range, b must be larger than a:
            if not int(b) > int(a):
                raise Invalid(msg2)
        else:
            #*** can it be cast to integer?:
            validate_type(int, part, msg)
    return ports

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

#================= Legacy Schema

#*** Describe supported syntax in main_policy.yaml so that it can be tested
#*** for validity. Here are valid policy rule attributes:
TC_CONFIG_POLICYRULE_ATTRIBUTES = ('comment',
                                   'match_type',
                                   'conditions_list',
                                   'actions')
#*** Dictionary of valid conditions stanza attributes with type:
TC_CONFIG_CONDITIONS = {'eth_src': 'MACAddress',
                               'eth_dst': 'MACAddress',
                               'ip_src': 'IPAddressSpace',
                               'ip_dst': 'IPAddressSpace',
                               'tcp_src': 'PortNumber',
                               'tcp_dst': 'PortNumber',
                               'udp_src': 'PortNumber',
                               'udp_dst': 'PortNumber',
                               'eth_type': 'EtherType',
                               'identity_lldp_systemname': 'String',
                               'identity_lldp_systemname_re': 'String',
                               'identity_service_dns': 'String',
                               'identity_service_dns_re': 'String',
                               'custom': 'String',
                               'match_type': 'MatchType',
                               'conditions_list': 'PolicyConditions'}
TC_CONFIG_ACTIONS = ('qos_treatment',
                     'set_desc',
                     'drop')
TC_CONFIG_MATCH_TYPES = ('any',
                         'all')

#*** Default policy file location parameters:
POL_DIR_DEFAULT = "config"
POL_DIR_USER = "config/user"
POL_FILENAME = "main_policy.yaml"

class Policy(BaseClass):
    """
    This class is instantiated by nmeta.py and provides methods
    to ingest the policy file main_policy.yaml and check flows
    against policy to see if actions exist.

    Directly accessible values to read:
    main_policy         # main policy YAML object

    TBD

    """
    def __init__(self, config, pol_dir_default=POL_DIR_DEFAULT,
                    pol_dir_user=POL_DIR_USER,
                    pol_filename=POL_FILENAME):
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
        #*** List to be populated with names of any custom classifiers:
        self.custom_classifiers = []
        #*** Instantiate Classes:
        self.static = tc_static.StaticInspect(config)
        self.identity = tc_identity.IdentityInspect(config)
        self.custom = tc_custom.CustomInspect(config)

        #*** Check the correctness of the top level of main policy:
        validate(self.logger, self.main_policy, TOP_LEVEL_SCHEMA, 'top')

        #*** Instantiate classes for the second levels of policy:
        self.port_sets = self.PortSets(self)
        self.locations = self.Locations(self)

        #*** Instantiate any custom classifiers:
        self.custom.instantiate_classifiers(self.custom_classifiers)

        # LEGACY:
        #*** Run a test on the ingested traffic classification policy to ensure
        #*** that it is good:
        self.validate_policy()

    class Rule(object):
        """
        An object that represents a traffic classification rule
        (a set of conditions), including any decision collateral
        on matches and actions
        """
        def __init__(self):
            """
            Initialise variables
            """
            self.match = 0
            self.continue_to_inspect = 0
            self.match_type = ""
            self.classification_tag = ""
            self.actions = {}
            #*** List for conditions objects:
            self.conditions = []

        def to_dict(self):
            """
            Return a dictionary object of the condition object
            """
            return self.__dict__

    class Conditions(object):
        """
        An object that represents traffic classification conditions,
        including any decision collateral on matches and actions
        """
        def __init__(self):
            """
            Initialise variables
            """
            self.match = 0
            self.continue_to_inspect = 0
            self.match_type = ""
            self.classification_tag = ""
            self.actions = {}
            #*** List for condition objects:
            self.condition = []

        def to_dict(self):
            """
            Return a dictionary object of the condition object
            """
            return self.__dict__

    class Condition(object):
        """
        An object that represents a traffic classification condition,
        including any decision collateral on match test
        """
        def __init__(self):
            """
            Initialise variables
            """
            self.match = 0
            self.continue_to_inspect = 0
            self.policy_attr = ""
            self.policy_attr_type = ""
            self.policy_value = ""
            self.classification_tag = ""
            self.actions = {}

        def to_dict(self):
            """
            Return a dictionary object of the condition object
            """
            return self.__dict__

    class PortSets(object):
        """
        An object that represents the port_sets root branch of
        the main policy
        """
        def __init__(self, policy):
            #*** Extract logger and policy YAML branch:
            self.logger = policy.logger
            self.yaml = policy.main_policy['port_sets']

            #*** Check the correctness of the port_sets branch of main policy:
            validate(self.logger, self.yaml, PORT_SETS_SCHEMA, 'port_sets')
            #*** Read in port_sets:
            self.port_sets_list = []
            for idx, key in enumerate(self.yaml['port_set_list']):
                self.port_sets_list.append(self.PortSet(policy, idx))

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
                this port set.

                Returns a Boolean
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
                        return 1
                self.logger.debug("no match, returning 0")
                return 0

    class Locations(object):
        """
        An object that represents the locations root branch of
        the main policy
        """
        def __init__(self, policy):
            #*** Extract logger and policy YAML branch:
            self.logger = policy.logger
            self.yaml = policy.main_policy['locations']

            #*** Check the correctness of the locations branch of main policy:
            validate(self.logger, self.yaml, LOCATIONS_SCHEMA, 'locations')

            #*** Extra validation of locations policy:
            validate_locations(self.logger, policy.main_policy)

            #*** Read in locations etc:
            self.locations_list = []
            for idx, key in enumerate(self.yaml['locations_list']):
                self.locations_list.append(self.Location(policy, idx))
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

    def validate_policy(self):
        """
        Check main policy to ensure that it is in
        correct format so that it won't cause unexpected errors during
        packet checks.
        """
        self.logger.debug("Validating main policy...")
        #*** Validate that policy has a 'tc_rules' key off the root:
        if not 'tc_rules' in self.main_policy:
            #*** No 'tc_rules' key off the root, so log and exit:
            self.logger.critical("Missing tc_rules"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Get the tc ruleset name, only one ruleset supported at this stage:
        tc_rules_keys = list(self.main_policy['tc_rules'].keys())
        if not len(tc_rules_keys) == 1:
            #*** Unsupported number of rulesets so log and exit:
            self.logger.critical("Unsupported "
                                    "number of tc rulesets. Should be 1 but "
                                    "is %s", len(tc_rules_keys))
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        tc_ruleset_name = tc_rules_keys[0]
        self.logger.debug("tc_ruleset_name=%s",
                              tc_ruleset_name)
        #*** Create new variable to reference tc ruleset directly:
        self.tc_ruleset = self.main_policy['tc_rules'][tc_ruleset_name]
        for idx, policy_rule in enumerate(self.tc_ruleset):
            tc_rule = self.tc_ruleset[idx]
            self.logger.debug("Validating PolicyRule "
                              "number=%s rule=%s", idx, tc_rule)
            #*** Test for unsupported PolicyRule attributes:
            for policy_rule_parameter in tc_rule.keys():
                if not policy_rule_parameter in \
                        TC_CONFIG_POLICYRULE_ATTRIBUTES:
                    self.logger.critical("The "
                                         "following PolicyRule attribute is "
                                         "invalid: %s ", policy_rule_parameter)
                    sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
                if policy_rule_parameter == 'conditions_list':
                    for conditions in tc_rule[policy_rule_parameter]:
                        #*** Call function to validate the policy condition and
                        #*** any nested policy conditions that it may contain:
                        self._validate_conditions(conditions)
                if policy_rule_parameter == 'actions':
                    #*** Check actions are valid:
                    for action in tc_rule[policy_rule_parameter].keys():
                        if not action in TC_CONFIG_ACTIONS:
                            self.logger.critical("The following action "
                                                 "attribute is invalid: %s",
                                                 action)
                            sys.exit("Exiting nmeta. Please fix error in "
                                     "main_policy.yaml file")

    def _validate_conditions(self, policy_conditions):
        """
        Check Traffic Classification (TC) conditions stanza to ensure
        that it is in the correct format so that it won't cause unexpected
        errors during packet checks. Can recurse for nested policy conditions.
        """
        #*** Use this to check if there is a match_type in stanza. Note can't
        #*** check for more than one occurrence as dictionary will just
        #*** keep attribute and overwrite value. Also note that recursive
        #*** instances use same variable due to scoping:
        self.has_match_type = 0
        #*** Check conditions are valid:
        for policy_condition in policy_conditions.keys():
            #*** Check policy condition attribute is valid:
            if not (policy_condition in TC_CONFIG_CONDITIONS or
                     policy_condition[0:10] == 'conditions'):
                self.logger.critical("The following PolicyCondition attribute"
                " is invalid: %s", policy_condition)
                sys.exit("Exiting nmeta. Please fix error in "
                         "main_policy.yaml file")
            #*** Accumulate names of any custom classifiers for later loading:
            if policy_condition == 'custom':
                custom_name = policy_conditions[policy_condition]
                self.logger.debug("custom_classifier=%s", custom_name)
                if custom_name not in self.custom_classifiers:
                    self.custom_classifiers.append(custom_name)
            #*** Check policy condition value is valid:
            if not policy_condition[0:10] == 'conditions':
                pc_value_type = TC_CONFIG_CONDITIONS[policy_condition]
            else:
                pc_value_type = policy_condition
            pc_value = policy_conditions[policy_condition]
            if pc_value_type == 'String':
                #*** Can't think of a way it couldn't be a valid
                #*** string???
                pass
            elif pc_value_type == 'PortNumber':
                #*** Check is int 0 < x < 65536:
                if not \
                     self.static.is_valid_transport_port(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'MACAddress':
                #*** Check is valid MAC address:
                if not self.static.is_valid_macaddress(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'EtherType':
                #*** Check is valid EtherType - must be two bytes
                #*** as Hex (i.e. 0x0800 is IPv4):
                if not self.static.is_valid_ethertype(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'IPAddressSpace':
                #*** Check is valid IP address, IPv4 or IPv6, can
                #*** include range or CIDR mask:
                if not self.static.is_valid_ip_space(pc_value):
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
            elif pc_value_type == 'MatchType':
                #*** Check is valid match type:
                if not pc_value in TC_CONFIG_MATCH_TYPES:
                    self.logger.critical("The following "
                          "PolicyCondition value is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
                else:
                    #*** Flag that we've seen a match_type so all is good:
                    self.has_match_type = 1
            elif pc_value_type == 'conditions_list':
                #*** Check value is list:
                if not isinstance(pc_value, list):
                    self.logger.critical("A conditions_list clause "
                          "specified but is invalid: %s "
                          "as %s", policy_condition, pc_value)
                    sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
                #*** Now, iterate through conditions list:
                self.logger.debug("Iterating on "
                                    "conditions_list=%s", pc_value)
                for list_item in pc_value:
                    keys = list_item.keys()
                    name = keys[0]
                    self._validate_conditions(list_item[name])
            else:
                #*** Whoops! We have a data type in the policy
                #*** that we've forgot to code a check for...
                self.logger.critical("The following "
                          "PolicyCondition value does not have "
                          "a check: %s, %s", policy_condition, pc_value)
                sys.exit("Exiting nmeta. Coding error "
                                        "in main_policy.yaml file")
        #*** Check match_type attribute present:
        if not self.has_match_type == 1:
            #*** No match_type attribute in stanza:
            self.logger.critical("Missing match_type attribute"
                     " in stanza: %s ", policy_conditions)
            sys.exit("Exiting nmeta. Please fix error "
                                        "in main_policy.yaml file")
        else:
            #*** Reset to zero as otherwise can break parent evaluations:
            self.has_match_type = 0

    def check_policy(self, flow, ident):
        """
        Passed a flows object, set in context of current packet-in event,
        and an identities object.
        Check if packet matches against any policy
        rules and if it does, update the classifications portion of
        the flows object to reflect details of the classification.
        """
        self.flow = flow
        self.pkt = flow.packet
        self.ident = ident
        #*** Check against TC policy:
        for tc_rule in self.tc_ruleset:
            #*** Check the rule:
            rule = self._check_rule(tc_rule)
            if rule.match:
                self.logger.debug("Matched policy rule=%s", rule.to_dict())
                #*** Only set 'classified' if continue_to_inspect not set:
                if not rule.continue_to_inspect:
                    flow.classification.classified = True
                else:
                    flow.classification.classified = False
                flow.classification.classification_tag = \
                                                        rule.classification_tag
                flow.classification.classification_time = \
                                                        datetime.datetime.now()
                #*** Accumulate any actions. (will overwrite with rule action)
                #*** Firstly, any actions on the rule:
                flow.classification.actions.update(tc_rule['actions'])
                #*** Secondly, any actions returned from custom classifiers:
                flow.classification.actions.update(rule.actions)
                return 1

        #*** No matches. Mark as classified so we don't process again:
        flow.classification.classified = True
        return 0

    def _check_rule(self, rule_stanza):
        """
        Passed a main_policy.yaml tc_rule stanza.
        Check to see if packet matches conditions as per the
        rule. Return a rule object
        """
        #*** Instantiate a Rule class for results:
        rule = self.Rule()
        rule.match_type = rule_stanza['match_type']
        #*** Iterate through the conditions list:
        for condition_stanza in rule_stanza['conditions_list']:
            conditions = self._check_conditions(condition_stanza)
            self.logger.debug("condition_stanza=%s, conditions=%s",
                                        condition_stanza, conditions.to_dict())
            #*** Decide what to do based on match result and match type:
            if conditions.match and rule.match_type == "any":
                rule.match = True
                rule.actions.update(conditions.actions)

                if rule_stanza['actions']['set_desc'] == 'classifier_return':
                    #*** Tagged by a custom classifier:
                    rule.classification_tag = conditions.classification_tag
                else:
                    rule.classification_tag = rule_stanza['actions']['set_desc']

                if conditions.continue_to_inspect:
                    rule.continue_to_inspect = 1
                return rule
            elif not conditions.match and rule.match_type == "all":
                rule.match = False
                return rule
            else:
                #*** Not a condition that we take action on so keep going:
                pass
        #*** We've finished loop through all conditions and haven't returned.
        #***  Work out what action to take:
        if not conditions.match and rule.match_type == "any":
            rule.match = False
            return rule
        elif conditions.match and rule.match_type == "all":
            rule.match = True
            rule.actions.update(conditions.actions)

            if rule_stanza['actions']['set_desc'] == 'classifier_return':
                #*** Tagged by a custom classifier:
                rule.classification_tag = conditions.classification_tag
            else:
                rule.classification_tag = rule_stanza['actions']['set_desc']

            if conditions.continue_to_inspect:
                rule.continue_to_inspect = 1
            return rule
        else:
            #*** Unexpected result:
            self.logger.error("Unexpected result at "
                "end of loop through rule=%s", rule.to_dict())
            rule.match = False
            return rule

    def _check_conditions(self, conditions_stanza):
        """
        Passed a conditions stanza
        Check to see if self.packet matches conditions as per the
        match type.
        Return a condition object with match information.
        """
        self.logger.debug("conditions_stanza=%s", conditions_stanza)
        #*** Instantiate a conditions class for results:
        conditions = self.Conditions()
        conditions.match_type = conditions_stanza['match_type']
        #*** Loop through conditions_stanza checking match:
        for policy_attr in conditions_stanza.keys():
            if policy_attr == "match_type":
                #*** Nothing to do:
                continue
            #*** Instantiate a condition class for result:
            condition = self.Condition()
            condition.policy_attr = policy_attr
            condition.policy_value = conditions_stanza[policy_attr]
            self.logger.debug("looping checking policy_attr=%s "
                                  "policy_value=%s", condition.policy_attr,
                                  condition.policy_value)
            #*** Policy Attribute Type is for identity classifiers
            #*** Exclude nested conditions dictionaries from this check:
            if condition.policy_attr[0:10] == 'conditions':
                condition.policy_attr_type = "conditions"
            else:
                condition.policy_attr_type = policy_attr.split("_")[0]
            #*** Main if/elif/else check on condition attribute type:
            if condition.policy_attr_type == "identity":
                self.identity.check_identity(condition, self.pkt, self.ident)
            elif condition.policy_attr == "custom":
                self.custom.check_custom(condition, self.flow, self.ident)
                self.logger.debug("custom match condition=%s",
                                                           condition.to_dict())
            #elif condition.policy_attr_type == "conditions_list":
                # TBD: Do a recursive call on nested conditions
            else:
                #*** default to doing a Static Classification match:
                self.static.check_static(condition, self.pkt)
                self.logger.debug("static match=%s", condition.to_dict())
            #*** Decide what to do based on match result and match type:
            if condition.match and conditions.match_type == "any":
                conditions.condition.append(condition)
                #*** Accumulate actions:
                for condn in conditions.condition:
                    self.logger.debug("appending actions=%s", condn.actions)
                    conditions.actions.update(condn.actions)
                    conditions.classification_tag += condn.classification_tag
                    if condn.continue_to_inspect:
                        conditions.continue_to_inspect = 1
                conditions.match = True
                return conditions
            elif not condition.match and not condition.policy_attr == \
                            "match_type" and conditions.match_type == "all":
                conditions.condition.append(condition)
                conditions.match = False
                return conditions
            else:
                #*** Not a condition that we take action on so keep going:
                pass
        #*** We've finished loop through all conditions and haven't returned.
        #***  Work out what action to take:
        if not condition.match and conditions.match_type == "any":
            conditions.condition.append(condition)
            conditions.match = False
            return conditions
        elif condition.match and conditions.match_type == "all":
            conditions.condition.append(condition)
            #*** Accumulate actions:
            for condn in conditions.condition:
                conditions.actions.update(condn.actions)
                if condn.continue_to_inspect:
                    conditions.continue_to_inspect = 1
            conditions.match = True
            return conditions
        else:
            #*** Unexpected result:
            self.logger.error("Unexpected result at end of loop through "
                                        "attributes. condition=%s, ",
                                        condition.to_dict())
            conditions.match = False
            return conditions

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
