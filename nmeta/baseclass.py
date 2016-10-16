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
The baseclass module is part of the nmeta suite and
provides an inheritable class methods for logging
"""

#*** logging imports:
import logging
import logging.handlers
import coloredlogs

class BaseClass(object):
    """
    This class provides the common methods for inheritance by
    other classes
    """
    def __init__(self):
        """
        Initialise the BaseClass class
        """
        pass

    def configure_logging(self, s_name, c_name):
        """
        Configure logging for the class that has inherited
        this method
        """
        #*** Get logging config values from config class:
        _logging_level_s = self.config.get_value(s_name)
        _logging_level_c = self.config.get_value(c_name)
        _syslog_enabled = self.config.get_value('syslog_enabled')
        _loghost = self.config.get_value('loghost')
        _logport = self.config.get_value('logport')
        _logfacility = self.config.get_value('logfacility')
        _syslog_format = self.config.get_value('syslog_format')
        _console_log_enabled = self.config.get_value('console_log_enabled')
        _coloredlogs_enabled = self.config.get_value('coloredlogs_enabled')
        _console_format = self.config.get_value('console_format')
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
            if _coloredlogs_enabled:
                #*** Colourise the logs to make them easier to understand:
                coloredlogs.install(level=_logging_level_c,
                logger=self.logger, fmt=_console_format, datefmt='%H:%M:%S')
            else:
                #*** Add console log handler to logger:
                self.console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(_console_format)
                self.console_handler.setFormatter(console_formatter)
                self.console_handler.setLevel(_logging_level_c)
                self.logger.addHandler(self.console_handler)
        self.logger.setLevel(_logging_level_c)
