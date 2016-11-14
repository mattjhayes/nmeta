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

"""
This module is part of the nmeta suite running on top of the
Ryu SDN controller to provide network identity and flow
(traffic classification) metadata.
It expects a file called "config.yaml" to be in the same directory
containing properly formed YAML
"""

import logging
import logging.handlers
import sys
import os

#*** YAML for config and policy file parsing:
import yaml

#*** This dictionary is used to check validity of config file attributes
#*** and to assign default values if the attribute is missing:
CONFIG_TEMPLATE = \
    {
    'miss_send_len': 1500,
    'ofpc_frag': 0,
    'nmeta_logging_level_c': 'INFO',
    'tc_policy_logging_level_c': 'INFO',
    'tc_static_logging_level_c': 'INFO',
    'tc_identity_logging_level_c': 'INFO',
    'tc_custom_logging_level_c': 'INFO',
    'sa_logging_level_c': 'INFO',
    'forwarding_logging_level_c': 'INFO',
    'api_logging_level_c': 'INFO',
    'flows_logging_level_c': 'INFO',
    'identities_logging_level_c': 'INFO',
    'classifications_logging_level_c': 'INFO',
    'external_api_logging_level_c': 'INFO',
    'nmeta_logging_level_s': 'INFO',
    'tc_policy_logging_level_s': 'INFO',
    'tc_static_logging_level_s': 'INFO',
    'tc_identity_logging_level_s': 'INFO',
    'tc_custom_logging_level_s': 'INFO',
    'sa_logging_level_s': 'INFO',
    'forwarding_logging_level_s': 'INFO',
    'api_logging_level_s': 'INFO',
    'flows_logging_level_s': 'INFO',
    'identities_logging_level_s': 'INFO',
    'classifications_logging_level_s': 'INFO',
    'external_api_logging_level_s': 'INFO',
    'syslog_enabled': 0,
    'loghost': 'localhost',
    'logport': 514,
    'logfacility': 19,
    'syslog_format': \
        "sev=%(levelname)s module=%(name)s func=%(funcName)s %(message)s",
    'console_log_enabled': 1,
    'coloredlogs_enabled': 1,
    'console_format': "%(levelname)s: %(name)s %(funcName)s: %(message)s",
    'mongo_addr': 'localhost',
    'mongo_port': 27017,
    'mongo_dbname': 'nmeta_database',
    'packet_ins_max_bytes': 2000000,
    'flow_time_limit': 30,
    'identities_max_bytes': 2000000,
    'identity_time_limit': 86400,
    'classifications_max_bytes': 2000000,
    'classification_time_limit': 300,
    'external_api_version': 'v1',
    'external_api_host': '0.0.0.0',
    'external_api_port': 8081,
    'external_api_debug': False
}

class Config(object):
    """
    This class is instantiated by nmeta.py and provides methods to
    ingest the configuration file and provides access to the
    keys/values that it contains.
    Config file is in YAML in config subdirectory and is
    called 'config.yaml'
    """
    def __init__(self, config_dir="config", config_filename="config.yaml"):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address= \
             ('localhost', 514), facility=19)
        formatter = logging.Formatter \
            ('sev=%(levelname)s module=%(name)s func=%(funcName)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        #*** Name of the config file:
        self.config_filename = config_filename
        self.config_directory = config_dir
        #*** Get working directory:
        self.working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        self.fullpathname = os.path.join(self.working_directory,
                                         self.config_directory,
                                         self.config_filename)
        self.logger.info("About to open config file %s",
                          self.fullpathname)
        #*** Ingest the config file:
        try:
            with open(self.fullpathname, 'r') as f:
                self._config_yaml = yaml.load(f)
        except (IOError, OSError) as e:
            self.logger.error("Failed to open config "
                                "file %s", self.fullpathname)
            sys.exit("Exiting config module. Please create config file")
        #*** Now for some DATA CLEANSING of the config...
        #*** Check that all attributes are valid and if not, remove them:
        _for_deletion = []
        for key, value in self._config_yaml.iteritems():
            #*** Check if key exists in CONFIG_TEMPLATE dict:
            if not key in CONFIG_TEMPLATE:
                self.logger.error("File config.yaml "
                                  "attribute %s is invalid", key)
                _for_deletion.append(key)
        #*** Now iterate over the list of references to delete any invalid
        #***  attributes:
        for _del_ref in _for_deletion:
            self.logger.info("Deleting %s from "
                               "self._config_yaml", _del_ref)
            del self._config_yaml[_del_ref]
        #*** Now check for any missing attributes and add them with default
        #*** value:
        for key, value in CONFIG_TEMPLATE.iteritems():
            if not key in self._config_yaml:
                #*** Add attribute and the default value:
                self.logger.info("Creating missing key %s"
                                 " with default value %s, as not in config "
                                 "file. You may want to fix this...",
                                 key, value)
                self._config_yaml[key] = value
        #*** TBD - check values are valid...

    def get_value(self, config_key):
        """
        Passed a key and see if it exists in the config YAML. If it does
        then return the value, if not return 0
        """
        try:
            return self._config_yaml[config_key]
        except KeyError:
            self.logger.error("Config file key %s does "
                                "not exist", config_key)
            return 0

