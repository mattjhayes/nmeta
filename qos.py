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

#*** nmeta - Network Metadata
#*** Quality of Service (QoS) Class and Methods
#
# Matt Hayes
# Victoria University, New Zealand
# Version 0.8

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide Quality of Service (QoS) determinations based on
Traffic Classification (TC) metadata
"""

import logging
import logging.handlers
import struct
import sys
import os

#*** YAML for config and policy file parsing:
import yaml

#============== For PEP8 this is 79 characters long... ========================
#========== For PEP8 DocStrings this is 72 characters long... ==========

#*** Describe supported syntax in qos_policy.yaml so that it can be tested
#*** for validity:
QOS_CONFIG_POLICYRULE_ATTRIBUTES = ('comment', 'QoS_treatment', 'output_queue')
#*** This is the attribute that we look for to contain a value that is an AVP
QOS_FLOW_ACTION = 'set_qos_tag'
QOS_POLICY_TAG = 'QoS_treatment'
QOS_TREATMENT = 'output_queue'

class QoS(object):
    """
    This class is instantiated by flow.py and provides methods to 
    add evaluate flow metadata, DPIDs and forwarding decisions and
    generate a QoS treatment action (i.e. set output queue).
    It also ingests a YAML-format QoS configuration file that contains
    the QoS treatment policy, and uses this to determine appropriate
    treatment action(s)
    """
    def __init__(self):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address = ('localhost', 514),
            facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        #*** Name of the config file:
        self.policy_filename = "qos_policy.yaml"
        self.config_directory = "config"
        #*** Get working directory:
        self.working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        self.fullpathname = os.path.join(self.working_directory,
                                         self.config_directory,
                                         self.policy_filename)
        self.logger.info("INFO:  module=qos About to open config file "
                         "%s", self.fullpathname)
        #*** Ingest the policy file:
        try:
            with open(self.fullpathname, 'r') as filename:
                self._qos_policy = yaml.load(filename)
        except (IOError, OSError) as exception:
            self.logger.error("ERROR: module=qos Failed to open policy "
                              "file %s %s", self.fullpathname, exception)  
            sys.exit("Exiting qos module. Please create qos config file")  
        #*** Run a test on the ingested traffic classification policy to ensure
        #*** that it is good:
        self.validate_policy() 

    def validate_policy(self):
        """
        Check Quality of Service (QoS) policy to ensure that it is in
        correct format so that it won't cause unexpected errors during
        packet checks. 
        """
        self.logger.debug("DEBUG: module=qos Validating QoS Policy...")
        for policy_rule in self._qos_policy.keys():
            self.logger.debug("DEBUG: module=qos Validating PolicyRule "
                              "%s", policy_rule)
            #*** Test for unsupported PolicyRule attributes:            
            for policy_rule_parameter in self._qos_policy[policy_rule].keys():
                if not (policy_rule_parameter in 
                       QOS_CONFIG_POLICYRULE_ATTRIBUTES):
                    self.logger.critical("CRITICAL: module=qos The "
                                         "following PolicyRule attribute is "
                                         "invalid: %s ", policy_rule_parameter)
                    sys.exit("Exiting nmeta. Please fix error in "
                             "qos_policy.yaml file")
                #*** Each policy_rule in qos_policy.yaml file must contain an                
                #*** attribute 'output_queue' with a valid value:
                if not (QOS_TREATMENT in 
                        self._qos_policy[policy_rule].keys()):
                    self.logger.critical("CRITICAL: module=qos The "
                                         "PolicyRule %s is missing attribute "
                                         " %s ", policy_rule, QOS_TREATMENT)
                    sys.exit("Exiting nmeta. Please fix error in "
                             "qos_policy.yaml file")      
                #*** Each policy_rule in qos_policy.yaml file must contain an                
                #*** attribute 'QoS_treatment' with a valid value:
                if not (QOS_POLICY_TAG in 
                        self._qos_policy[policy_rule].keys()):
                    self.logger.critical("CRITICAL: module=qos The "
                                         "PolicyRule %s is missing attribute "
                                         " %s ", policy_rule, QOS_POLICY_TAG)
                    sys.exit("Exiting nmeta. Please fix error in "
                             "qos_policy.yaml file")                              
                             
#============== For PEP8 this is 79 characters long... ========================         
#========== For PEP8 DocStrings this is 72 characters long... ==========

    def check_policy(self, flow_actions):
        """
        Passed a set of Flow Actions. Check if against
        QoS policy rules return any treatment action
        """
        if flow_actions:
            #*** Iterate through the QoS Policy Policy Rules:
            for policy_rule in self._qos_policy.keys():
                if QOS_FLOW_ACTION in flow_actions:
                    result = self._check_policy_rule(flow_actions, 
                                                    policy_rule)
                    #*** Return the QoS output queue to use if we had a hit:
                    if result:
                        return(result)
        #*** No result, so return default queue value:
        return(1)

#============== For PEP8 this is 79 characters long... ========================                     
#========== For PEP8 DocStrings this is 72 characters long... ==========
    def _check_policy_rule(self, flow_actions, policy_rule):
        """
        Passed a set of Flow Actions and a QoS policy rule. Check if against
        QoS policy rules return any treatment action
        """
        qos_avp = flow_actions[QOS_FLOW_ACTION]
        qos_avp_list = qos_avp.split('=')
        if (len(qos_avp_list)>1):
            #*** attribute and value that was passed to us from TC:
            tc_qos_atr = qos_avp_list[0]
            tc_qos_val = qos_avp_list[1]
        else:
            self.logger.error("ERROR: module=qos length of qos_avp_list not "
                              "> 1. Check syntax of QoS policy")
            return(0)
        #*** Sanity checks:
        if not (tc_qos_atr and tc_qos_val):
            return(0)
        if not (tc_qos_atr == QOS_POLICY_TAG):
            return(0)
        #*** assign easy variables:
        qp_match = self._qos_policy[policy_rule][QOS_POLICY_TAG]
        qp_output_queue = self._qos_policy[policy_rule][QOS_TREATMENT]
        if (tc_qos_val == qp_match):
            #*** Matched QoS Treatment Type so return the Output Queue:
            return(qp_output_queue)
        else:
            return(0)

#============== For PEP8 this is 79 characters long... ======================== 
