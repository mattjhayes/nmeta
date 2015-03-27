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

#*** nmeta - Network Metadata - REST API Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
It provides methods for RESTful API connectivity.
"""

import logging
import logging.handlers

#*** Ryu Imports:
from ryu.exception import RyuException
from ryu.app.wsgi import ControllerBase, WSGIApplication

#*** Web API REST imports:
from webob import Response
import json

#*** Constants for REST API:
REST_RESULT = 'result'
REST_NG = 'failure'
REST_DETAILS = 'details'
NMETA_INSTANCE = 'nmeta_api_app'

# REST command template
#*** Copied from the Ryu rest_router.py example code:
def rest_command(func):
    """
    REST API command template
    """
    def _rest_command(*args, **kwargs):
        """
        Run a REST command and return
        appropriate response
        """
        try:
            msg = func(*args, **kwargs)
            #*** That worked, so return the response:
            return Response(content_type='application/json',
                            body=json.dumps(msg))
        except SyntaxError as e:
            status = 400
            details = e.msg
        except (ValueError, NameError) as e:
            status = 400
            details = e.message
        except NotFoundError as msg:
            status = 404
            details = str(msg)
        #*** Build and return a crafted error response:
        msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
        return Response(status=status, body=json.dumps(msg))
    return _rest_command

class NotFoundError(RyuException):
    message = 'Error occurred talking to function <TBD>'

class RESTAPIController(ControllerBase):
    """
    This class is used to control REST API access to the
    nmeta data and control functions
    """
    def __init__(self, req, link, data, **config):
        super(RESTAPIController, self).__init__(req, link, data, **config)
        self.nmeta_parent_self = data[NMETA_INSTANCE]

    @rest_command
    def get_table_size_rows(self, req, **kwargs):
        """
        REST API function that returns size of all the
        state tables as number of rows
        """
        nmeta = self.nmeta_parent_self
        _results = {}
        _results['fm_table_size_rows'] = \
                        nmeta.flowmetadata.get_fm_table_size_rows()
        _results['id_mac_table_size_rows'] = \
                        nmeta.tc_policy.identity.get_id_mac_table_size_rows()
        _results['id_ip_table_size_rows'] = \
                        nmeta.tc_policy.identity.get_id_ip_table_size_rows()
        return _results

    @rest_command
    def get_event_rates(self, req, **kwargs):
        """
        REST API function that returns event rates (per second averages)
        """
        nmeta = self.nmeta_parent_self
        event_rates = nmeta.measure.get_event_rates()
        return event_rates

    @rest_command
    def get_packet_time(self, req, **kwargs):
        """
        REST API function that returns packet processing time statistics
        through nmeta (does not include time at switch, in transit nor
        time queued in OS or Ryu
        """
        nmeta = self.nmeta_parent_self
        packet_processing_stats = nmeta.measure.get_event_metric_stats \
                        ('packet_delta')
        return packet_processing_stats

    @rest_command
    def list_flow_table(self, req, **kwargs):
        """
        REST API function that returns contents of the
        Flow Metadata (FM) table
        """
        nmeta = self.nmeta_parent_self
        _fm_table = nmeta.flowmetadata.get_fm_table()
        return _fm_table

    @rest_command
    def list_flow_table_by_IP(self, req, **kwargs):
        """
        REST API function that returns contents of the
        Flow Metadata (FM) table filtered on an IP address
        (matches source or destination IP).
        .
        <TBD>
        """
        print "##### list_flow_table_by_IP"
        pass

    @rest_command
    def list_identity_nic_table(self, req, **kwargs):
        """
        REST API function that returns contents of the
        Identity NIC table
        """
        nmeta = self.nmeta_parent_self
        _identity_nic_table = nmeta.tc_policy.identity.get_identity_nic_table()
        return _identity_nic_table

    @rest_command
    def list_identity_system_table(self, req, **kwargs):
        """
        REST API function that returns contents of the
        Identity NIC table
        """
        nmeta = self.nmeta_parent_self
        _identity_system_table = \
                           nmeta.tc_policy.identity.get_identity_system_table()
        return _identity_system_table

    @rest_command
    def get_id_mac(self, req, **kwargs):
        """
        REST API function that returns contents of the identity
        id_mac data structure
        """
        nmeta = self.nmeta_parent_self
        try:
            _id_mac = nmeta.tc_policy.identity.id_mac
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("API could not access id_mac data structure "
                            "Exception %s, %s, %s",
                             exc_type, exc_value, exc_traceback)
            return 0
        return _id_mac

    @rest_command
    def get_id_ip(self, req, **kwargs):
        """
        REST API function that returns contents of the identity
        id_ip data structure
        """
        nmeta = self.nmeta_parent_self
        try:
            _id_ip = nmeta.tc_policy.identity.id_ip
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("API could not access id_ip data structure "
                            "Exception %s, %s, %s",
                             exc_type, exc_value, exc_traceback)
            return 0
        return _id_ip

    @rest_command
    def get_id_service(self, req, **kwargs):
        """
        REST API function that returns contents of the identity
        id_service data structure
        """
        nmeta = self.nmeta_parent_self
        try:
            _id_service = nmeta.tc_policy.identity.id_service
        except:
            #*** Log the error and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("API could not access id_service data structure "
                            "Exception %s, %s, %s",
                             exc_type, exc_value, exc_traceback)
            return 0
        return _id_service

class Api(object):
    """
    This class is instantiated by nmeta.py and provides methods
    for RESTful API connectivity.
    """
    #*** Constants for REST API:
    url_flowtable = '/nmeta/flowtable/'
    url_flowtable_by_ip = '/nmeta/flowtable/{ip}'
    url_identity_nic_table = '/nmeta/identity/nictable/'
    url_identity_system_table = '/nmeta/identity/systemtable/'
    #*** Measurement APIs:
    url_table_size_rows = '/nmeta/measurement/tablesize/rows/'
    url_measure_event_rates = '/nmeta/measurement/eventrates/'
    url_measure_pkt_time = '/nmeta/measurement/metrics/packet_time/'
    #*** New Identity Metadata calls:
    url_identity_mac = '/nmeta/identity/mac/'
    url_identity_ip = '/nmeta/identity/ip/'
    url_identity_service = '/nmeta/identity/service/'
    #
    IP_PATTERN = r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$){4}\b'
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, _nmeta, _config, _wsgi):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('api_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('api_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _console_format = _config.get_value('console_format')
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

        #*** Set up REST API:
        wsgi = _wsgi
        self.data = {NMETA_INSTANCE: self}
        mapper = wsgi.mapper
        #*** Register the RESTAPIController class:
        wsgi.register(RESTAPIController, {NMETA_INSTANCE : _nmeta})
        requirements = {'ip': self.IP_PATTERN}
        mapper.connect('flowtable', self.url_table_size_rows,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='get_table_size_rows',
                       conditions=dict(method=['GET']))
        mapper.connect('flowtable', self.url_measure_event_rates,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='get_event_rates',
                       conditions=dict(method=['GET']))
        mapper.connect('flowtable', self.url_measure_pkt_time,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='get_packet_time',
                       conditions=dict(method=['GET']))
        mapper.connect('flowtable', self.url_flowtable,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_flow_table',
                       conditions=dict(method=['GET']))
        mapper.connect('flowtable', self.url_flowtable_by_ip,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_flow_table_by_ip',
                       conditions=dict(method=['GET']))
        mapper.connect('flowtable', self.url_identity_nic_table,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_identity_nic_table',
                       conditions=dict(method=['GET']))
        mapper.connect('flowtable', self.url_identity_system_table,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_identity_system_table',
                       conditions=dict(method=['GET']))
        mapper.connect('identity_mac', self.url_identity_mac,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='get_id_mac',
                       conditions=dict(method=['GET']))
        mapper.connect('identity_ip', self.url_identity_ip,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='get_id_ip',
                       conditions=dict(method=['GET']))
        mapper.connect('identity_service', self.url_identity_service,
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='get_id_service',
                       conditions=dict(method=['GET']))
