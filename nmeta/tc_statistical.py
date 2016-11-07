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

#*** nmeta - Network Metadata - Traffic Classification Statistical
#***                                 Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import struct
import time

#*** For logging configuration:
from baseclass import BaseClass

class StatisticalInspect(BaseClass):
    """
    This class is instantiated by tc_policy.py
    (class: TrafficClassificationPolicy) and provides methods to
    run statistical traffic classification matches
    """
    def __init__(self, config):
        #*** Required for BaseClass:
        self.config = config
        #*** Run the BaseClass init to set things up:
        super(StatisticalInspect, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("tc_statistical_logging_level_s",
                                       "tc_statistical_logging_level_c")

    def check_statistical(self, policy_attr, policy_value, pkt):
        """
        Passed a statistical classification attribute, value and flows
        packet object.
        Return a dictionary containing attributes 'valid',
        'continue_to_inspect' and 'actions' with appropriate values set.
        """
        self.logger.debug("check_statistical was called policy_attr=%s "
                            "policy_value=%s", policy_attr, policy_value)
        if policy_attr == "statistical_qos_bandwidth_1":
            #*** call the function for this particular statistical classifier
            results_dict = self._statistical_qos_bandwidth_1(pkt)
            return results_dict
        else:
            self.logger.error("Policy attribute "
                              "%s did not match", policy_attr)
            return {'valid':False, 'continue_to_inspect':False,
                     'actions':'none'}
        return False


