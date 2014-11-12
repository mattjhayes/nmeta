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
#
# Matt Hayes
# Victoria University, New Zealand
#
# Version 3.1

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (Traffic Classification - TC) metadata.
It expects a file called "tc_policy.yaml" to be in the config subdirectory  
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

#============== For PEP8 this is 79 characters long... ========================

#*** Describe supported syntax in tc_policy.yaml so that it can be tested
#*** for validity:
TC_CONFIG_POLICYRULE_ATTRIBUTES = ('comment', 'match_type', 
                                   'policy_conditions', 'actions')
TC_CONFIG_POLICY_CONDITIONS = ('eth_src', 'eth_dst', 'ip_src', 'ip_dst',
                               'tcp_src', 'tcp_dst', 'eth_type',
                               'identity_lldp_chassisid',
                               'identity_lldp_systemname',
                               'identity_lldp_systemname_re',
                               'payload_type',
                               'statistical_qos_bandwidth_1')
TC_CONFIG_ACTIONS = ('set_qos_tag', 'set_desc_tag', 'pass_return_tags')
TC_CONFIG_MATCH_TYPES = ('any', 'all', 'statistical')

class TrafficClassificationPolicy(object):
    """
    This class is instantiated by nmeta.py and provides methods
    to ingest the policy file tc_policy.yaml and check flows
    against policy to see if actions exist
    """
    def __init__(self):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address = ('localhost', 
                                                      514), facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        #*** Name of the config file:
        self.policy_filename = "tc_policy.yaml"
        self.config_directory = "config"
        #*** Get working directory:
        self.working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        self.fullpathname = os.path.join(self.working_directory,
                                         self.config_directory,
                                         self.policy_filename)
        self.logger.info("INFO:  module=tc_policy About to open config file "
                         "%s", self.fullpathname)
        #*** Ingest the policy file:
        try:
            with open(self.fullpathname, 'r') as filename:
                self._tc_policy = yaml.load(filename)
        except (IOError, OSError) as exception:
            self.logger.error("ERROR: module=tc_policy Failed to open policy "
                              "file %s %s", self.fullpathname, exception)
            sys.exit("Exiting nmeta. Please create traffic classification "
                             "policy file") 
        #*** Instantiate Classes:
        self.static = tc_static.StaticInspect()
        self.identity = tc_identity.IdentityInspect()
        self.payload = tc_payload.PayloadInspect()
        self.statistical = tc_statistical.StatisticalInspect()
        #*** Run a test on the ingested traffic classification policy to ensure
        #*** that it is good:
        self.validate_policy()

    def validate_policy(self):
        """
        Check Traffic Classification (TC) policy to ensure that it is in
        correct format so that it won't cause unexpected errors during
        packet checks. 
        """
        self.logger.debug("DEBUG: module=tc_policy Validating TC Policy...")
        for policy_rule in self._tc_policy.keys():
            self.logger.debug("DEBUG: module=tc_policy Validating PolicyRule "
                              "%s", policy_rule)
            #*** Test for unsupported PolicyRule attributes:
            for policy_rule_parameter in self._tc_policy[policy_rule].keys():
                if not policy_rule_parameter in TC_CONFIG_POLICYRULE_ATTRIBUTES:
                    self.logger.critical("CRITICAL: module=tc_policy The "
                                         "following PolicyRule attribute is "
                                         "invalid: %s ", policy_rule_parameter)
                    sys.exit("Exiting nmeta. Please fix error in "
                             "tc_policy.yaml file")                
                if policy_rule_parameter == 'policy_conditions':
                    #*** Check policy conditions are valid:
                    for policy_condition in self._tc_policy[policy_rule] \
                                  [policy_rule_parameter].keys():
                        if not policy_condition in TC_CONFIG_POLICY_CONDITIONS:
                            self.logger.critical("CRITICAL: module=tc_policy "
                            "The following PolicyCondition attribute is "
                            "invalid: %s", policy_condition)
                            sys.exit("Exiting nmeta. Please fix error in "
                                     "tc_policy.yaml file")
                if policy_rule_parameter == 'actions':
                    #*** Check actions are valid:                    
                    for action in self._tc_policy[policy_rule] \
                                  [policy_rule_parameter].keys():
                        if not action in TC_CONFIG_ACTIONS:
                            self.logger.critical("CRITICAL: module=tc_policy "
                                                 "The following action "
                                                 "attribute is invalid: %s", 
                                                 action)
                            sys.exit("Exiting nmeta. Please fix error in "
                                     "tc_policy.yaml file")  
                if policy_rule_parameter == 'match_type':
                    #*** Check match_type value is valid:
                    if (not self._tc_policy[policy_rule]['match_type'] in 
                        TC_CONFIG_MATCH_TYPES):
                        self.logger.critical("CRITICAL: module=tc_policy The "
                                             "following match_type value is "
                                             "invalid: %s", 
                                             self._tc_policy[policy_rule] \
                                             ['match_type'])
                        sys.exit("Exiting nmeta. Please fix error in "
                                 "tc_policy.yaml file")
    
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
        for policy_rule in self._tc_policy.keys():
            _result_dict = self._check_match(pkt, self._tc_policy[policy_rule] \
                    ['policy_conditions'], 
                    self._tc_policy[policy_rule]['match_type'])
            if _result_dict["match"]:
                self.logger.debug("DEBUG: module=tc_policy Matched policy "
                                  "condition(s), returning "
                                  "continue_to_inspect and actions...")
                #*** Merge actions dictionaries. Do type inspection.
                #*** There has to be a better way...!!!
                if (isinstance(self._tc_policy[policy_rule]['actions'], dict) and
                        isinstance(_result_dict['actions'], dict)):
                    _merged_actions = dict(self._tc_policy[policy_rule]['actions'].items()
                         + _result_dict['actions'].items())
                elif isinstance(self._tc_policy[policy_rule]['actions'], dict):
                    _merged_actions = self._tc_policy[policy_rule]['actions']
                elif isinstance(_result_dict['actions'], dict):
                    _merged_actions = _result_dict['actions']
                else:
                    _merged_actions = False
                _result_dict['actions'] = _merged_actions
                self.logger.debug("DEBUG: module=tc_policy returning dict %s",
                                  _result_dict)
                return _result_dict
        #*** No hits so return false on everything:
        _result_dict = {'match':False, 'continue_to_inspect':False, 
                    'actions': False} 
        return _result_dict
                
    def _check_match(self, pkt, policy_conditions, match_type):
        """
        Passed a packet-in packet, a set of policy conditions and a 
        match type. Check to see if packet matches conditions as per the
        match type and if so return in the dictionary attribute "match" 
        the boolean value True otherwise boolean False.
        The returned dictionary can also contain values indicating
        whether or not a flow should be installed to the switch
        (attribute "continue_to_inspect") and actions
        (attribute "actions")
        A match_type of 'any' will return true as soon as a valid
        match is made and false if end of matching is reached.
        A match_type of 'all' will return false as soon as an invalid 
        match is made and true if end of matching is reached.
        """         
        #*** initial settings for results dictionary:
        _result_dict = {'match':True, 'continue_to_inspect':False, 
                    'actions': False}
        if match_type == 'any':
            for policy_attr in policy_conditions.keys():
                policy_value = policy_conditions[policy_attr]
                policy_attr_type = policy_attr.split("_")
                policy_attr_type = policy_attr_type[0]
                _match = False
                if policy_attr_type == "identity":
                    #*** Identity Classification as part of 'any' match:
                    _match = self.identity.check_identity(policy_attr, policy_value, pkt)
                    if _match:
                        _result_dict["match"] = True
                        return _result_dict  
                elif policy_attr_type == "payload":
                    #*** Payload Classification as part of 'any' match:
                    _payload_dict = self.payload.check_payload(policy_attr, policy_value, pkt)
                    if _payload_dict["match"]:
                        _result_dict["match"] = True
                        _result_dict["continue_to_inspect"] = _payload_dict["continue_to_inspect"]
                        return _result_dict                    
                else:
                    #*** default to doing a Static Classification as part of 'any' match:
                    _match = self.static.check_static(policy_attr, policy_value, pkt)
                    if _match:
                        _result_dict["match"] = True
                        return _result_dict
            #*** Didn't match any so return false:
            _result_dict["match"] = False
            return _result_dict
        elif match_type == 'all':
            for policy_condition in policy_conditions.keys():
                policy_value = policy_conditions[policy_attr]
                policy_attr_type = policy_value.split("_")
                policy_attr_type = policy_attr_type[0]
                _match = False
                if policy_attr_type == "identity":
                    #*** Identity Classification as part of 'all' match:
                    _match = self.identity.check_identity(policy_attr, policy_value, pkt)
                    if not _match:
                        _result_dict["match"] = False
                        return _result_dict
                elif policy_attr_type == "payload":
                    #*** Payload Classification as part of 'all' match:
                    _payload_dict = self.payload.check_payload(policy_attr, policy_value, pkt)
                    if not _payload_dict["match"]:
                        _result_dict["match"] = False
                        _result_dict["continue_to_inspect"] = _payload_dict["continue_to_inspect"]
                        return _result_dict                     
                    if not _match:
                        _result_dict["match"] = False
                        return _result_dict                  
                else:
                    #*** default to doing a Static Classification as part of 'all' match:
                    _match = self.static.check_static(policy_attr, policy_value, pkt)
                    if not _match:
                        _result_dict["match"] = False
                        return _result_dict
            #*** Didn't get any negatives so implied that matched all
            _result_dict["match"] = True
            return _result_dict
        elif match_type == 'statistical':
            for policy_attr in policy_conditions.keys():
                policy_value = policy_conditions[policy_attr]
                _result_statistical = self.statistical.check_statistical(policy_attr, policy_value, pkt)
                self.logger.debug("DEBUG: module=tc_policy statistical continue_to_inspect is %s and actions are %s",
                                      _result_statistical['continue_to_inspect'], _result_statistical['actions'])                    
                if _result_statistical['valid']:
                    _result_dict["match"] = True
                    _result_dict["continue_to_inspect"] = _result_statistical["continue_to_inspect"]
                    _result_dict["actions"] = _result_statistical["actions"]
                    return _result_dict
                else:
                    #*** Strange condition, log an error:
                    self.logger.error("ERROR: module=tc_policy Statistical classifier failed")
                    _result_dict["match"] = False
                    _result_dict["continue_to_inspect"] = False
                    return _result_dict
        else:
            self.logger.critical("CRITICAL: module=tc_policy The following "
                                 "match_type value is invalid: %s", 
                                 match_type)
            sys.exit("Exiting nmeta. Please fix error in tc_policy.yaml file")

      
        

