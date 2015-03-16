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

import logging
import logging.handlers

import sys
import os

#*** Packet-related imports:
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

#*** nmeta imports:
import tc_static
import tc_identity
import tc_statistical
import tc_payload

#*** YAML for config and policy file parsing:
import yaml

#*** Describe supported syntax in main_policy.yaml so that it can be tested
#*** for validity. Here are valid policy rule attributes:
TC_CONFIG_POLICYRULE_ATTRIBUTES = ('comment', 'match_type', 'conditions_list', 
                                       'actions')
#*** Dictionary of valid conditions stanza attributes with type:
TC_CONFIG_CONDITIONS = {'eth_src': 'MACAddress',
                               'eth_dst': 'MACAddress', 
                               'ip_src': 'IPAddressSpace', 
                               'ip_dst': 'IPAddressSpace',
                               'tcp_src': 'PortNumber', 
                               'tcp_dst': 'PortNumber', 
                               'eth_type': 'EtherType',
                               'identity_lldp_systemname': 'String',
                               'identity_lldp_systemname_re': 'String',
                               'payload_type': 'String',
                               'statistical_qos_bandwidth_1': 'String',
                               'match_type': 'MatchType',
                               'conditions_list': 'PolicyConditions'}
TC_CONFIG_ACTIONS = ('set_qos_tag', 'set_desc_tag', 'pass_return_tags')
TC_CONFIG_MATCH_TYPES = ('any', 'all', 'statistical')

class TrafficClassificationPolicy(object):
    """
    This class is instantiated by nmeta.py and provides methods
    to ingest the policy file main_policy.yaml and check flows
    against policy to see if actions exist
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('tc_policy_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('tc_policy_logging_level_c')
        _syslog_enabled = _config.get_value ('syslog_enabled')
        _loghost = _config.get_value ('loghost')
        _logport = _config.get_value ('logport')
        _logfacility = _config.get_value ('logfacility')
        _syslog_format = _config.get_value ('syslog_format')
        _console_log_enabled = _config.get_value ('console_log_enabled')
        _console_format = _config.get_value ('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(address=(
                                                _loghost, _logport), 
                                                facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            self.console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(_console_format)
            self.console_handler.setFormatter(console_formatter)
            self.console_handler.setLevel(_logging_level_c)
            #*** Add console log handler to logger:
            self.logger.addHandler(self.console_handler)

        #*** Name of the config file:
        self.policy_filename = "main_policy.yaml"
        self.config_directory = "config"
        #*** Get working directory:
        self.working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        self.fullpathname = os.path.join(self.working_directory,
                                         self.config_directory,
                                         self.policy_filename)
        self.logger.info("About to open config file=%s", self.fullpathname)
        #*** Ingest the policy file:
        try:
            with open(self.fullpathname, 'r') as filename:
                self._main_policy = yaml.load(filename)
        except (IOError, OSError) as exception:
            self.logger.error("Failed to open policy "
                              "file=%s exception=%s",
                              self.fullpathname, exception)
            sys.exit("Exiting nmeta. Please create traffic classification "
                             "policy file")
        #*** Instantiate Classes:
        self.static = tc_static.StaticInspect(_config)
        self.identity = tc_identity.IdentityInspect(_config)
        self.payload = tc_payload.PayloadInspect(_config)
        self.statistical = tc_statistical.StatisticalInspect \
                                (_config)
        #*** Run a test on the ingested traffic classification policy to ensure
        #*** that it is good:
        self.validate_policy()

    def validate_policy(self):
        """
        Check Traffic Classification (TC) policy to ensure that it is in
        correct format so that it won't cause unexpected errors during
        packet checks.
        """
        self.logger.debug("Validating TC Policy...")
        #*** Validate that policy has a 'tc_rules' key off the root:
        if not 'tc_rules' in self._main_policy:
            #*** No 'tc_rules' key off the root so log and exit:
            self.logger.critical("Missing tc_rules"
                                    "key in root of policy")
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
                if policy_rule_parameter == 'conditions':
                    #*** Call function to validate the policy condition and
                    #*** any nested policy conditions that it may contain:
                    self._validate_conditions(tc_rule[policy_rule_parameter])
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

    def check_policy(self, pkt, dpid, inport):
        """
        Passed a packet-in packet, a Data Path ID (dpid) and an in port.
        Check if packet matches against any policy
        rules and if it does return the associated actions.
        This function is written for efficiency as it will be called for
        every packet-in event and delays will slow down the transmission
        of these packets. For efficiency, it assumes that the TC policy
        is valid as it has been checked after ingestion or update.
        It performs an additional function of sending any packets that
        contain identity information (i.e. LLDP) to the Identity module
        """
        #*** Check to see if it is an LLDP packet
        #*** and if so pass to the identity module to process:
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if pkt_eth.ethertype == 35020:
            self.identity.lldp_in(pkt, dpid, inport)
        #*** Check to see if it is an IPv4 packet
        #*** and if so pass to the identity module to process:
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip4:
            self.identity.ip4_in(pkt)
        #*** Check against TC policy:
        for tc_rule in self.tc_ruleset:
            #*** Check the rule:
            _result_dict = self._check_rule(pkt, tc_rule)
            if _result_dict['match']:
                self.logger.debug("Matched policy rule")
                #*** Need to merge the actions configured on the rule
                #*** with those returned by the classifiers
                #*** Do type inspection to ensure only dealing with non-Null
                #*** items. There has to be a better way...!!!?
                if (isinstance(tc_rule['actions'], dict) and 
                        isinstance(_result_dict['actions'], dict)):
                    _merged_actions = dict(tc_rule['actions'].items() 
                                        + _result_dict['actions'].items())
                elif isinstance(tc_rule['actions'], dict):
                    _merged_actions = tc_rule['actions']
                elif isinstance(_result_dict['actions'], dict):
                    _merged_actions = _result_dict['actions']
                else:
                    _merged_actions = False
                _result_dict['actions'] = _merged_actions
                self.logger.debug("returning result=%s", _result_dict)
                return _result_dict
        #*** No hits so return false on everything:
        _result_dict = {'match':False, 'continue_to_inspect':False,
                    'actions': False}
        return _result_dict

    def _check_rule(self, pkt, rule):
        """
        Passed a main_policy.yaml tc_rule.
        Check to see if packet matches conditions as per the
        rule.
        Return a results dictionary
        """
        _result_dict = {'match':True, 'continue_to_inspect':False,
                    'actions': False}
        self.rule_match_type = rule['match_type']
        #*** Iterate through the conditions list:
        for condition_stanza in rule['conditions_list']:
            _result = self._check_conditions(pkt, condition_stanza)
            _match = _result['match']
            #*** Decide what to do based on match result and match type:
            if _match and self.rule_match_type == "any":
                _result_dict['match'] = True
                return _result_dict
            elif not _match and self.rule_match_type == "all":
                _result_dict['match'] = False
                return _result_dict
            else:
                #*** Not a condition that we take action on so keep going:
                pass
        #*** We've finished loop through all conditions and haven't returned.
        #***  Work out what action to take:
        if not _match and self.rule_match_type == "any":
            _result_dict['match'] = False
            return _result_dict
        elif _match and self.rule_match_type == "all":
            _result_dict['match'] = True
            return _result_dict
        else:
            #*** Unexpected result:
            self.logger.error("Unexpected result at "
                "end of loop through attributes. policy_attr=%s, _match=%s, "
                "self.match_type=%s", policy_attr, _match, 
                 self.rule_match_type)
            _result_dict['match'] = False
            return _result_dict

    def _check_conditions(self, pkt, conditions):
        """
        Passed a packet-in packet and a conditions stanza (part of a 
        conditions list).
        Check to see if packet matches conditions as per the
        match type, and if so return in the dictionary attribute "match" with
        the boolean value True otherwise boolean False.
        A match_type of 'any' will return true as soon as a valid
        match is made and false if end of matching is reached.
        A match_type of 'all' will return false as soon as an invalid
        match is made and true if end of matching is reached.
        """
        #*** initial settings for results dictionary:
        _result_dict = {'match':True, 'continue_to_inspect':False,
                    'actions': False}
        self.match_type = conditions['match_type']
        #*** Loop through conditions checking match:
        for policy_attr in conditions.keys():
            policy_value = conditions[policy_attr]
            #*** Policy Attribute Type is for non-static classifiers to
            #*** hold the attribute prefix (i.e. identity).
            #*** Exclude nested conditions dictionaries from this check:
            if policy_attr[0:10] == 'conditions':
                policy_attr_type = "conditions"
            else:
                policy_attr_type = policy_attr.split("_")
                policy_attr_type = policy_attr_type[0]
            _match = False
            #*** Main if/elif/else check on condition attribute type:
            if policy_attr_type == "identity":
                _match = self.identity.check_identity(policy_attr, 
                                             policy_value, pkt)
            elif policy_attr_type == "payload":
                _payload_dict = self.payload.check_payload(policy_attr,
                                         policy_value, pkt)
                if _payload_dict["match"]:
                        _match = True
                        _result_dict["continue_to_inspect"] = \
                                     _payload_dict["continue_to_inspect"]
            elif policy_attr_type == "conditions_list":
                #*** Do a recursive call on nested conditions:
                _nested_dict = self._check_conditions(pkt, policy_value)
                _match = _nested_dict["match"]
                #*** TBD: How do we deal with nested continue to inspect
                #***  results that conflict?
                _result_dict["continue_to_inspect"] = \
                                    _nested_dict["continue_to_inspect"]
            elif policy_attr == "match_type":
                #*** Nothing to do:
                pass
            else:
                #*** default to doing a Static Classification match:
                _match = self.static.check_static(policy_attr,
                                                        policy_value, pkt)
            #*** Decide what to do based on match result and match type:
            if _match and self.match_type == "any":
                _result_dict["match"] = True
                return _result_dict
            elif not _match and self.match_type == "all":
                _result_dict["match"] = False
                return _result_dict
            else:
                #*** Not a condition that we take action on so keep going:
                pass
        #*** We've finished loop through all conditions and haven't returned.
        #***  Work out what action to take:
        if not _match and self.match_type == "any":
            _result_dict["match"] = False
            return _result_dict
        elif _match and self.match_type == "all":
            _result_dict["match"] = True
            return _result_dict
        else:
            #*** Unexpected result:
            self.logger.error("Unexpected result at "
                "end of loop through attributes. policy_attr=%s, _match=%s, "
                "self.match_type=%s", policy_attr, _match, self.match_type)
            _result_dict["match"] = False
            return _result_dict

