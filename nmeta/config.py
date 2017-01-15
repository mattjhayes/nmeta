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

"""
The config module is part of the nmeta suite.

It represents nmeta configuration data.

It loads configuration from file, validates keys and provides
access to values

It expects a file called "config.yaml" to be in the config
subdirectory, containing properly formed YAML
"""

import logging
import logging.handlers
import coloredlogs

import sys
import os

#*** For logging configuration:
from baseclass import BaseClass

#*** YAML for config and policy file parsing:
import yaml

#*** Default config file location parameters:
CONFIG_DIR_DEFAULT = "config"
CONFIG_DIR_USER = "config/user"
CONFIG_FILENAME = "config.yaml"

class Config(BaseClass):
    """
    This class is instantiated by nmeta.py and provides methods to
    ingest the configuration file and provides access to the
    keys/values that it contains.
    Config file is in YAML in config subdirectory and is
    called 'config.yaml'
    """
    def __init__(self, dir_default=CONFIG_DIR_DEFAULT,
                    dir_user=CONFIG_DIR_USER,
                    config_filename=CONFIG_FILENAME):
        #*** Set up basic logging, as can't use
        #*** inherited method due to chicken and egg issue
        #*** (set up properly later)
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
        coloredlogs.install(level="DEBUG",
                logger=self.logger, fmt="%(asctime)s.%(msecs)03d %(name)s[%(process)d] %(funcName)s %(levelname)s %(message)s", datefmt='%H:%M:%S')

        self.logger.debug("dir_default=%s dir_user=%s config_filename=%s",
                         dir_default, dir_user, config_filename)

        self.ingest_config_default(config_filename, dir_default)
        self.ingest_config_user(config_filename, dir_user)

    def ingest_config_default(self, config_filename, dir_default):
        """
        Ingest default config file
        """
        #*** Get working directory:
        working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        fullpathname = os.path.join(working_directory,
                                         dir_default,
                                         config_filename)
        self._config_yaml = self.ingest_config_file(fullpathname)

    def ingest_config_user(self, config_filename, dir_user):
        """
        Ingest user config file that overrides values set in the
        default config file.
        """
        #*** Get working directory:
        working_directory = os.path.dirname(__file__)
        #*** Build the full path and filename for the config file:
        fullpathname = os.path.join(working_directory,
                                         dir_user,
                                         config_filename)
        #*** File doesn't have to exist, so check if it exists:
        if not os.path.isfile(fullpathname):
            self.logger.info("User-defined config file does not exist, "
                                "file=%s, skipping", fullpathname)
            return 1

        #*** Ingest user-defined config file:
        _user_config_yaml = self.ingest_config_file(fullpathname)
        #*** Go through all keys checking key exists in default yaml.
        #***  If doesn't exist, raise warning
        #***  If does exist, overwrite the value in internal config
        if not isinstance(_user_config_yaml, dict):
            self.logger.info("User-defined config missing, skipping")
            return 1
        if len(_user_config_yaml) == 0:
            self.logger.info("User-defined config is empty, skipping")
            return 1
        for key, value in _user_config_yaml.iteritems():
            if key in self._config_yaml:
                self.logger.info("Overriding a default config parameter"
                                    " with key=%s value=%s", key, value)
                self._config_yaml[key] = value
            else:
                self.logger.error("key=%s does not exist in default "
                        "config so not importing, value=%s", key, value)

    def ingest_config_file(self, fullpath):
        """
        Passed full path to a YAML-formatted config file
        and ingest into a dictionary
        """
        _config = {}
        self.logger.info("Ingesting config file=%s", fullpath)
        try:
            with open(fullpath, 'r') as file_:
                _config = yaml.safe_load(file_)
        except (IOError, OSError) as exception:
            #*** IO exception:
            self.logger.critical("Failed to open config file %s, "
                                    "error=%s", fullpath, exception)
            sys.exit("Exiting config module. Please create config file")
        except yaml.YAMLError, exception:
            #*** YAML exception:
            if hasattr(exception, 'problem_mark'):
                mark = exception.problem_mark
                self.logger.critical("Failed to open config file %s, "
                    "error=%s on line=%s character=%s. Exiting",
                    fullpath, exception, mark.line+1, mark.column+1)
            else:
                self.logger.critical("Failed to open config file=%s, "
                    "error=%s. Exiting", fullpath, exception)
            sys.exit("Exiting config module. Please fix config file")
        return _config

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

    def inherit_logging(self, config):
        """
        Call base class method to set up logging properly for
        this class now that it is running
        """
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "config_logging_level_s",
                                       "config_logging_level_c")
        self.logger.info("Config logging now fully configured")
