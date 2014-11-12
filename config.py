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

#*** nmeta - Network Metadata - Configuration file loading and access to values
#
# Matt Hayes
# Victoria University, New Zealand
# Version 0.2

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata.
It expects a file called "config.yaml" to be in the same directory 
containing properly formed YAML
"""

import logging
import logging.handlers
import struct
import sys
import os

#*** YAML for config and policy file parsing:
import yaml

class Config(object):
    """
    This class is instantiated by nmeta.py and provides methods to ingest the configuration file
    and provides access to the keys/values that it contains
    Config file is in YAML in config subdirectory and is called 'config.yaml'
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
        self.config_filename = "config.yaml"
        self.config_directory = "config"
        #*** Get working directory:
        self.working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        self.fullpathname = os.path.join(self.working_directory,
                                         self.config_directory,
                                         self.config_filename)
        self.logger.info("INFO:  module=config About to open config file %s", self.fullpathname)
        #*** Ingest the config file:
        try:
            with open(self.fullpathname, 'r') as f:
                self._config_yaml = yaml.load(f)
        except (IOError, OSError) as e:
            self.logger.error("ERROR: module=config Failed to open config file %s", self.fullpathname)
            sys.exit("Exiting config module. Please create config file")            

    def get_value(self, config_key):
        """
        Passed a key and see if it exists in the config YAML. If it does
        then return the value, if not return 0
        """
        try:
            return self._config_yaml[config_key]
        except KeyError:
            self.logger.error("ERROR: module=config Config file key %s does not exist", config_key)
            return 0

