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

class CustomInspect(BaseClass):
    """
    This class is instantiated by tc_policy.py
    (class: TrafficClassificationPolicy) and provides methods to
    run custom traffic classification modules
    """
    def __init__(self, config):
        #*** Required for BaseClass:
        self.config = config
        #*** Run the BaseClass init to set things up:
        super(CustomInspect, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("tc_custom_logging_level_s",
                                       "tc_custom_logging_level_c")

    def check_custom(self, condition, pkt, ident):
        """
        Passed condition, flows packet and identities objects.
        Update the condition match as appropriate.
        """
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

    def instantiate_classifiers(self, _classifiers):
        """
        Dynamically import and instantiate classes for any
        custom classifiers specified in the controller
        nmeta2 main_policy.yaml
        .
        Passed a list of tuples of classifier type / classifer name
        .
        Classifier modules live in the 'classifiers' subdirectory
        .
        """
        self.logger.debug("Loading dynamic classifiers into TC module")

        for tc_type, module_name in _classifiers:
            #*** Dynamically import and instantiate class from classifiers dir:
            self.logger.debug("Importing module type=%s module_name=%s",
                                        tc_type, "classifiers." + module_name)
            try:
                module = importlib.import_module("classifiers." + module_name)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("Failed to dynamically load classifier "
                                    "module %s from classifiers subdirectory."
                                    "Please check that module exists and alter"
                                    " main_policy configuration in controller "
                                    "nmeta2 configuration if required",
                                    module_name)
                self.logger.error("Exception is %s, %s, %s",
                                            exc_type, exc_value, exc_traceback)
                sys.exit("Exiting, please fix error...")

            #*** Dynamically instantiate class 'Classifier':
            self.logger.debug("Instantiating module class")
            class_ = getattr(module, 'Classifier')
            self.classifiers.append(class_(self.logger))







