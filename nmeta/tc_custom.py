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

import sys

#*** For importing custom classifiers:
import importlib

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
        #*** Dictionary to hold dynamically loaded custom classifiers:
        self.custom_classifiers = {}

    def check_custom(self, condition, pkt, ident):
        """
        Passed condition, flows packet and identities objects.
        Call the named custom classifier with these values so that it
        can update the condition match as appropriate.
        """
        classifier = condition.policy_value
        if classifier in self.custom_classifiers:
            custom = self.custom_classifiers[classifier]
            #*** Run the custom classifier:
            custom.classifier(condition, pkt, ident)
            return 1
        else:
            self.logger.error("Failed to find classifier=%s", classifier)
            return 0

    def instantiate_classifiers(self, custom_list):
        """
        Dynamically import and instantiate classes for any
        custom classifiers specified in the controller
        nmeta2 main_policy.yaml

        Passed a deduplicated list of custom classifier names
        (without .py) to load.

        Classifier modules live in the 'classifiers' subdirectory
        """
        self.logger.debug("Loading dynamic classifiers")

        for module_name in custom_list:
            #*** Dynamically import and instantiate class from classifiers dir:
            self.logger.debug("Importing custom module_name=%s", module_name)
            try:
                module = importlib.import_module("custom_classifiers."
                                                                 + module_name)
                # TEMP
                #module = importlib.import_module("classifications")
                #module = importlib.import_module(module_name)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("Failed to dynamically load classifier "
                                    "module %s from classifiers subdirectory."
                                    "Please check that module exists and alter"
                                    " main_policy configuration if required",
                                    module_name)
                self.logger.error("Exception is %s, %s, %s",
                                            exc_type, exc_value, exc_traceback)
                sys.exit("Exiting, please fix error...")

            #*** Dynamically instantiate class 'Classifier':
            self.logger.debug("Instantiating module class module_name=%s",
                                                                   module_name)
            class_ = getattr(module, 'Classifier')
            self.custom_classifiers[module_name] = class_(self.logger)







