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

#*** Import dpkt for DNS extraction, as not native to Ryu:
#import dpkt

#*** YAML for config and policy file parsing:
import yaml

#*** For logging configuration:
from baseclass import BaseClass

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
#*** Keys that must exist under 'identity' in the policy:
IDENTITY_KEYS = ('arp',
                 'lldp',
                 'dns',
                 'dhcp')

#*** Default policy file location parameters:
POL_DIR_DEFAULT = "config"
POL_DIR_USER = "config/user"
POL_FILENAME = "main_policy.yaml"

class TrafficClassificationPolicy(BaseClass):
    """
    This class is instantiated by nmeta.py and provides methods
    to ingest the policy file main_policy.yaml and check flows
    against policy to see if actions exist
    """
    def __init__(self, config, pol_dir_default=POL_DIR_DEFAULT,
                    pol_dir_user=POL_DIR_USER,
                    pol_filename=POL_FILENAME):
        #*** Required for BaseClass:
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "tc_policy_logging_level_s",
                                       "tc_policy_logging_level_c")
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
                self._main_policy = yaml.load(filename)
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
        #*** Run a test on the ingested traffic classification policy to ensure
        #*** that it is good:
        self.validate_policy()
        #*** Instantiate any custom classifiers:
        self.custom.instantiate_classifiers(self.custom_classifiers)

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


    def validate_policy(self):
        """
        Check main policy to ensure that it is in
        correct format so that it won't cause unexpected errors during
        packet checks.
        """
        self.logger.debug("Validating main policy...")
        #*** Validate that policy has a 'tc_rules' key off the root:
        if not 'tc_rules' in self._main_policy:
            #*** No 'tc_rules' key off the root, so log and exit:
            self.logger.critical("Missing tc_rules"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Get the tc ruleset name, only one ruleset supported at this stage:
        tc_rules_keys = list(self._main_policy['tc_rules'].keys())
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
        self.tc_ruleset = self._main_policy['tc_rules'][tc_ruleset_name]
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

        #*** Validate that policy has a 'identity' key off the root:
        if not 'identity' in self._main_policy:
            #*** No 'identity' key off the root, so log and exit:
            self.logger.critical("Missing identity"
                                    "key in root of main policy")
            sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Get the identity keys and validate that they all exist in policy:
        for _id_key in IDENTITY_KEYS:
            if not _id_key in self._main_policy['identity'].keys():
                self.logger.critical("Missing identity "
                                    "key in main policy: %s", _id_key)
                sys.exit("Exiting nmeta. Please fix error in "
                             "main_policy.yaml file")
        #*** Conversely, check all identity keys in the policy are valid:
        for _id_pol_key in self._main_policy['identity'].keys():
            if not _id_pol_key in IDENTITY_KEYS:
                self.logger.critical("Invalid identity "
                                    "key in main policy: %s", _id_pol_key)
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
        qos_policy = self._main_policy['qos_treatment']
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
