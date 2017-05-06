#!/usr/bin/python

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
The api_external module is part of the nmeta suite, but is run
separately

This module runs a class and methods for an API that
exposes an interface into nmeta MongoDB collections.

It leverages the Eve Python REST API Framework
"""
#*** Python 3 style division results as floating point:
from __future__ import division

import os

#*** Import Eve for REST API Framework:
from eve import Eve

#*** Inherit logging etc:
from baseclass import BaseClass

#*** mongodb Database Import:
from pymongo import MongoClient

#*** nmeta imports
import config
#*** import from api_definitions subdirectory:
from api_definitions import switches_api
from api_definitions import pi_rate
from api_definitions import pi_time
from api_definitions import controller_summary
from api_definitions import identities_api
from api_definitions import identities_ui
from api_definitions import flows_api
from api_definitions import flows_ui
from api_definitions import flow_mods_api

#*** For timestamps:
import datetime

#*** To get request parameters:
from flask import request

#*** Amount of time (seconds) to go back for to calculate Packet-In rate:
PACKET_IN_RATE_INTERVAL = 10

#*** Amount of time (seconds) to go back for to calculate Packet-In rate:
PACKET_TIME_PERIOD = 10

#*** Used for WebUI:
FLOW_SEARCH_LIMIT = 600
FLOW_RESULT_LIMIT = 25
#*** FlowUI attributes to match against for different filter types
FLOW_FILTER_ANY = ['src', 'src_hover', 'dst', 'dst_hover', 'proto',
                            'proto_hover']
FLOW_FILTER_SRC = ['src', 'src_hover']
FLOW_FILTER_DST = ['dst', 'dst_hover']
FLOW_FILTER_SRC_OR_DST = ['src', 'src_hover', 'dst', 'dst_hover']

#*** Number of previous IP identity records to search for a hostname before
#*** giving up. Used for augmenting flows with identity metadata:
HOST_LIMIT = 2000
SERVICE_LIMIT = 250

#*** How far back in time to go back looking for packets in flow:
FLOW_TIME_LIMIT = datetime.timedelta(seconds=3600)
FLOW_REM_TIME_LIMIT = datetime.timedelta(seconds=3600)
CLASSIFICATION_TIME_LIMIT = datetime.timedelta(seconds=4000)

#*** Enumerate some proto numbers, someone's probably already done this...
ETH_TYPES = {
        2048: 'IPv4',
        2054: 'ARP',
        34525: 'IPv6',
        35020: 'LLDP'
        }
IP_PROTOS = {
        1: 'ICMP',
        2: 'IGMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6'
        }

class ExternalAPI(BaseClass):
    """
    This class provides methods for the External API
    """
    def __init__(self, config):
        """
        Initialise the ExternalAPI class
        """
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "api_external_logging_level_s",
                                       "api_external_logging_level_c")

        #*** MongoDB Setup:
        #*** Get database parameters from config:
        mongo_addr = self.config.get_value("mongo_addr")
        mongo_port = self.config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")
        self.logger.info("Connecting to the %s MongoDB database on %s %s",
                                mongo_addr, mongo_port, mongo_dbname)

        #*** Use Pymongo to connect to the nmeta MongoDB database:
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB nmeta database:
        db_nmeta = mongo_client[mongo_dbname]

        #*** Variables for MongoDB Collections:
        self.packet_ins = db_nmeta.packet_ins
        self.identities = db_nmeta.identities
        self.classifications = db_nmeta.classifications
        self.flow_rems = db_nmeta.flow_rems
        self.db_pi_time = db_nmeta.pi_time

    class FlowUI(object):
        """
        An object that represents a flow record to be sent in response
        to the WebUI. Features:
         - Flow direction normalised to direction of
           first packet in flow
         - Src and Dst are IP or Layer 2 to optimise screen space
         - Extra data included for hover-over tips
        Note that there should not be any display-specific data (i.e. don't
        send any HTML, leave this to the client code)
        """
        def __init__(self):
            #*** Initialise flow variables:
            self.flow_hash = ""
            self.timestamp = ""
            self.src_location_logical = ""
            self.src = ""
            self.src_hover = ""
            self.dst = ""
            self.dst_hover = ""
            self.proto = ""
            self.proto_hover = ""
            self.tp_src = ""
            self.tp_src_hover = ""
            self.tp_dst = ""
            self.tp_dst_hover = ""
            self.classification = ""
            self.classification_hover = ""
            self.actions = ""
            self.actions_hover = ""
            self.data_sent = ""
            self.data_sent_hover = ""
            self.data_received = ""
            self.data_received_hover = ""
        def response(self):
            """
            Return a dictionary object of flow parameters
            for sending in response
            """
            return self.__dict__

    def run(self):
        """
        Run the External API instance

        Note that API definitions are from previously imported
        files from api_definitions subdirectory
        """

        #*** Eve Domain for the whole API:
        eve_domain = {
            'pi_rate': pi_rate.pi_rate_settings,
            'pi_time': pi_time.pi_time_settings,
            'controller_summary': controller_summary.controller_summary_settings,
            'switches_col': switches_api.switches_settings,
            'identities': identities_api.identities_settings,
            'identities_ui': identities_ui.identities_ui_settings,
            'flows': flows_api.flows_settings,
            'flows_ui': flows_ui.flows_ui_settings,
            'flow_mods': flow_mods_api.flow_mods_settings
        }

        #*** Set up a settings dictionary for starting Eve app:datasource
        eve_settings = {}
        eve_settings['HATEOAS'] = True
        eve_settings['MONGO_HOST'] =  \
                self.config.get_value('mongo_addr')
        eve_settings['MONGO_PORT'] =  \
                self.config.get_value('mongo_port')
        eve_settings['MONGO_DBNAME'] =  \
                self.config.get_value('mongo_dbname')
        #*** Version, used in URL:
        eve_settings['API_VERSION'] =  \
                self.config.get_value('external_api_version')
        eve_settings['DOMAIN'] = eve_domain
        #*** Allowed Eve methods:
        eve_settings['RESOURCE_METHODS'] = ['GET']
        eve_settings['ITEM_METHODS'] = ['GET']
        #*** Set format of datetime as it appears to API consumers:
        eve_settings['DATE_FORMAT'] = '%H:%M:%S.%f'


        #*** TBD - set up username/password into MongoDB

        #*** Set up static content location:
        file_dir = os.path.dirname(os.path.realpath(__file__))
        static_folder = os.path.join(file_dir, 'webUI')

        #*** Set up Eve:
        self.logger.info("Configuring Eve Python REST API Framework")
        self.app = Eve(settings=eve_settings, static_folder=static_folder)
        self.logger.debug("static_folder=%s", static_folder)

        #*** Hook for adding pi_rate to returned resource:
        self.app.on_fetched_resource_pi_rate += self.response_pi_rate

        #*** Hook for adding pi_time to returned resource:
        self.app.on_fetched_resource_pi_time += self.response_pi_time

        #*** Hook for adding controller_summary to returned resource:
        self.app.on_fetched_resource_controller_summary += \
                                               self.response_controller_summary

        #*** Hook for filtered identities response:
        self.app.on_fetched_resource_identities_ui += \
                                               self.response_identities_ui

        #*** Hook for filtered flows response:
        self.app.on_fetched_resource_flows_ui += \
                                               self.response_flows_ui

        #*** Get necessary parameters from config:
        eve_port = self.config.get_value('external_api_port')
        eve_debug = self.config.get_value('external_api_debug')
        eve_host = self.config.get_value('external_api_host')

        #*** Run Eve:
        self.logger.info("Starting Eve Python REST API Framework")
        self.app.run(port=eve_port, debug=eve_debug, host=eve_host)

        @self.app.route('/')
        def serve_static():
            """
            Serve static content for WebUI
            """
            return 1

    def response_pi_rate(self, items):
        """
        Update the response with the packet_in rate.
        Hooked from on_fetched_resource_pi_rate

        Returns key/values for packet-in processing time in API response:
        - pi_rate
        """
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)
        items['pi_rate'] = self.get_pi_rate()

    def response_pi_time(self, items):
        """
        Update the response with the packet_time min, avg and max.
        Hooked from on_fetched_resource_pi_time

        Returns key/values for packet-in processing time in API response:
        - pi_time_max
        - pi_time_min
        - pi_time_avg
        - pi_time_period
        - pi_time_records

        If no data found within time period then returns without
        key/values
        """
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)
        #*** Get rid of superfluous _items key in response:
        if '_items' in items:
            del items['_items']
        results = self.get_pi_time()
        if results:
            #*** Set values in API response:
            items['pi_time_max'] = results['pi_time_max']
            items['pi_time_min'] = results['pi_time_min']
            items['pi_time_avg'] = results['pi_time_avg']
            items['pi_time_period'] = results['pi_time_period']
            items['pi_time_records'] = results['pi_time_records']

    def response_controller_summary(self, items):
        """
        Update the response with the packet_in rate, packet processing
        time stats

        Hooked from on_fetched_resource_controller_summary

        Rounds seconds results
        """
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)
        #*** Number of decimal places to round seconds results to:
        places = 3
        #*** Get rid of superfluous _items key in response:
        if '_items' in items:
            del items['_items']
        #*** pi_rate:
        items['pi_rate'] = self.get_pi_rate()
        #*** pi_time:
        results = self.get_pi_time()
        if results:
            #*** Set values in API response:
            items['pi_time_max'] = round(results['pi_time_max'], places)
            items['pi_time_min'] = round(results['pi_time_min'], places)
            items['pi_time_avg'] = round(results['pi_time_avg'], places)
            items['pi_time_period'] = results['pi_time_period']
            items['pi_time_records'] = results['pi_time_records']
        else:
            items['pi_time_max'] = 'unknown'
            items['pi_time_min'] = 'unknown'
            items['pi_time_avg'] = 'unknown'
            items['pi_time_period'] = 'unknown'
            items['pi_time_records'] = 'unknown'

    def response_identities_ui(self, items):
        """
        Populate the response with identities that are filtered:
         - Reverse sort by harvest time
         - Deduplicate by id_hash, only returning most recent per id_hash
         - Includes possibly stale records
         - Check DNS A records to see if they are from a CNAME
        Hooked from on_fetched_resource_<name>
        """
        known_hashes = []
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)

        #*** Get URL parameters:
        if 'filter_dns' in request.args:
            filter_dns = request.args['filter_dns']
        else:
            filter_dns = 0
        self.logger.debug("filter_dns=%s", filter_dns)

        #*** Get database and query it:
        identities = self.app.data.driver.db['identities']
        #*** Reverse sort:
        packet_cursor = identities.find().sort('$natural', -1)
        #*** Iterate, adding only new id_hashes to the response:
        for record in packet_cursor:
            if not record['id_hash'] in known_hashes:
                #*** Skip DNS results if filter_dns enabled:
                if filter_dns and (record['harvest_type'] == 'DNS_CNAME' or
                            record['harvest_type'] == 'DNS_A'):
                    continue
                #*** Get IP for DNS CNAME:
                if record['harvest_type'] == 'DNS_CNAME':
                    #*** Check if A record exists, and if so update response:
                    record['ip_address'] = \
                                       self.get_dns_ip(record['service_alias'])
                #*** Add to items dictionary which is returned in response:
                self.logger.debug("Appending _items with record=%s", record)
                items['_items'].append(record)
                #*** Add hash so we don't do it again:
                self.logger.debug("Storing id_hash=%s ", record['id_hash'])
                known_hashes.append(record['id_hash'])

    def response_flows_ui(self, items):
        """
        Populate the response with flow entries that are filtered:
         - Reverse sort by initial ingest time
         - Deduplicate by flow_hash, only returning most recent per flow_hash
         - Enrich with TBD
        Hooked from on_fetched_resource_<name>
        """
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)

        #*** Get URL parameters:
        if 'flowsFilterLogicSelector' in request.args:
            flows_filterlogicselector = request.args['flowsFilterLogicSelector']
        else:
            flows_filterlogicselector = ''
        if 'flowsFilterTypeSelector' in request.args:
            flows_filtertypeselector = request.args['flowsFilterTypeSelector']
        else:
            flows_filtertypeselector = ''
        if 'filterString' in request.args:
            filter_string = request.args['filterString']
        else:
            filter_string = ''
        self.logger.debug("Parameters are flows_filterlogicselector=%s "
                        "flows_filtertypeselector=%s filter_string=%s",
                        flows_filterlogicselector, flows_filtertypeselector,
                        filter_string)

        #*** Connect to packet_ins database and run general query:
        flows = self.app.data.driver.db['packet_ins']
        packet_cursor = flows.find().limit(FLOW_SEARCH_LIMIT) \
                                                         .sort('timestamp', -1)

        #*** Iterate through results, ignoring known hashes:
        known_hashes = []
        for record in packet_cursor:
            #*** Only return unique flow records:
            if not record['flow_hash'] in known_hashes:
                #*** Normalise the direction of the flow:
                record = self.flow_normalise_direction(record)

                #*** Create identity-augmented FlowUI instance:
                flow = self.flow_augment_record(record)

                #*** Apply any filters:
                match = self.flow_match(flow, flows_filterlogicselector,
                                    flows_filtertypeselector, filter_string)

                if match:
                    #*** Add to result:
                    #*** Add to items dictionary, which is returned in response:
                    items['_items'].append(flow.response())

                #*** Add hash so we don't do it again:
                known_hashes.append(record['flow_hash'])

                #*** If we've filled the bucket then return result:
                if len(items['_items']) >= FLOW_RESULT_LIMIT:
                    return

    def flow_match(self, flow, flows_filterlogicselector,
                                    flows_filtertypeselector, filter_string):
        """
        Passed an instance of FlowUI class, a logic selector,
        filter type and filter string.

        Return a boolean on whether or not that theres a match.
        """
        if flows_filtertypeselector == 'any' or flows_filtertypeselector == '':
            filter_attributes = FLOW_FILTER_ANY
        elif flows_filtertypeselector == 'src':
            filter_attributes = FLOW_FILTER_SRC
        elif flows_filtertypeselector == 'dst':
            filter_attributes = FLOW_FILTER_DST
        elif flows_filtertypeselector == 'src_or_dst':
            filter_attributes = FLOW_FILTER_SRC_OR_DST
        else:
            #*** Unknown value, warn and return:
            self.logger.warning("unsupported flows_filtertypeselector=%s "
                                ", exiting...", flows_filtertypeselector)
            return 0
        #*** Iterate through attributes checking for match:
        for attr in filter_attributes:
            if filter_string in str(getattr(flow, attr)):
                if flows_filterlogicselector == 'includes' or \
                                flows_filterlogicselector == '':
                    return 1
                elif flows_filterlogicselector == 'excludes':
                    self.logger.warning("excludes match on attr=%s", attr)
                    return 0
                else:
                    self.logger.error("Unsupported flows_filterlogicselector"
                                    "=%s", flows_filterlogicselector)
                    return 0

        if flows_filterlogicselector == 'excludes':
            #*** Didn't match anything and excludes logic so that's a 1!
            return 1

    def flow_augment_record(self, record):
        """
        Passed a record of a single flow from the packet_ins
        database collection.

        Create FlowUI class instance, add in known data and
        augment with identity data. Logic is specific to the
        webUI user experience.

        Return the FlowUI class instance
        """
        #*** Instantiate an instance of FlowUI class:
        flow = self.FlowUI()
        flow.timestamp = record['timestamp']
        flow.flow_hash = record['flow_hash']
        #*** Augment with source logical location:
        flow.src_location_logical = self.get_location_by_mac(record['eth_src'])
        #*** Mangle src/dest and their hovers dependent on type:
        if record['eth_type'] == 2048:
            #*** It's IPv4, see if we can augment with identity:
            flow.src = self.get_id(record['ip_src'])
            if flow.src != record['ip_src']:
                flow.src_hover = hovertext_ip_addr(record['ip_src'])
            flow.dst = self.get_id(record['ip_dst'])
            if flow.dst != record['ip_dst']:
                flow.dst_hover = hovertext_ip_addr(record['ip_dst'])
            flow.proto = enumerate_ip_proto(record['proto'])
            if flow.proto != record['proto']:
                #*** IP proto enumerated, set hover decimal text:
                flow.proto_hover = \
                                 hovertext_ip_proto(record['proto'])
        else:
            #*** It's not IPv4 (TBD, handle IPv6)
            flow.src = record['eth_src']
            flow.dst = record['eth_dst']
            flow.proto = enumerate_eth_type(record['eth_type'])
            if flow.proto != record['eth_type']:
                #*** Eth type enumerated, set hover decimal eth_type:
                flow.proto_hover = \
                                 hovertext_eth_type(record['eth_type'])
        flow.tp_src = record['tp_src']
        flow.tp_dst = record['tp_dst']
        #*** Enrich with classification and action(s):
        classification = self.get_classification(record['flow_hash'])
        flow.classification = classification['classification_tag']
        #*** Turn actions dictionary into a human-readable string:
        actions_dict = classification['actions']
        actions = ''
        for key in actions_dict:
            actions += str(key) + "=" + str(actions_dict[key]) + " "
        flow.actions = actions
        #*** Enrich with data xfer (only applies to flows that
        #***  have had idle timeout)
        data_xfer = self.get_flow_data_xfer(record)
        if data_xfer['tx_found']:
            flow.data_sent = data_xfer['tx_bytes']
            flow.data_sent_hover = data_xfer['tx_pkts']
        if data_xfer['rx_found']:
            flow.data_received = data_xfer['rx_bytes']
            flow.data_received_hover = data_xfer['rx_pkts']
        return flow

    def get_flow_data_xfer(self, record):
        """
        Passed a record of a single flow from the packet_ins
        database collection.

        Enrich this by looking up data transfer stats
        (which may not exist) in flow_rems database collection,
        and return dictionary of the values.

        Note that the data sent (tx) and received (rx) records
        will have different flow hashes.
        """
        self.logger.debug("In get_flow_data_xfer")
        #*** Set blank result:
        result = {'tx_found': 0, 'rx_found': 0, 'tx_bytes': 0, 'rx_bytes': 0,
                        'tx_pkts': 0, 'rx_pkts': 0}
        ip_A = record['ip_src']
        flow_hash = record['flow_hash']
        #*** Search flow_rems database collection:
        db_data_tx = {'flow_hash': flow_hash, 'ip_A': ip_A,
              'removal_time': {'$gte': datetime.datetime.now() -
                                    FLOW_REM_TIME_LIMIT}}
        db_data_rx = {'flow_hash': flow_hash, 'ip_B': ip_A,
              'removal_time': {'$gte': datetime.datetime.now() -
                                    FLOW_REM_TIME_LIMIT}}
        tx = self.flow_rems.find(db_data_tx).sort('$natural', -1).limit(1)
        rx = self.flow_rems.find(db_data_rx).sort('$natural', -1).limit(1)
        #*** Analyse database results and update result:
        if tx.count():
            result['tx_found'] = 1
            tx_result = list(tx)[0]
            self.logger.debug("tx_result is %s", tx_result)
            result['tx_bytes'] = tx_result['byte_count']
            result['tx_pkts'] = tx_result['packet_count']
        if rx.count():
            result['rx_found'] = 1
            rx_result = list(rx)[0]
            self.logger.debug("rx_result is %s", rx_result)
            result['rx_bytes'] = rx_result['byte_count']
            result['rx_pkts'] = rx_result['packet_count']
        return result

    def get_classification(self, flow_hash):
        """
        Passed flow_hash and return a dictionary
        of a classification object for the flow_hash (if found), otherwise
        a dictionary of an empty classification object.
        """
        db_data = {'flow_hash': flow_hash,
              'classification_time': {'$gte': datetime.datetime.now() -
                                    CLASSIFICATION_TIME_LIMIT}}
        results = self.classifications.find(db_data). \
                                                  sort('$natural', -1).limit(1)
        if results.count():
            return list(results)[0]
        else:
            self.logger.debug("Classification for flow_hash=%s not found",
                                                                     flow_hash)
            return {
                'flow_hash': flow_hash,
                'classified': 0,
                'classification_tag': '',
                'classification_time': 0,
                'actions': {}
            }

    def flow_normalise_direction(self, record):
        """
        Passed a dictionary of an flow record and return a similar
        dictionary that has sources and destinations normalised to the
        direction of the first observed packet in the flow
        """
        #*** Lookup the first source IP seen for the flow:
        client_ip = self.get_flow_client_ip(record['flow_hash'])
        if not client_ip:
            return record
        if client_ip == record['ip_src']:
            return record
        elif client_ip == record['ip_dst']:
            #*** Need to transpose source and destinations:
            orig_ip_src = record['ip_src']
            orig_ip_dst = record['ip_dst']
            orig_tp_src = record['tp_src']
            orig_tp_dst = record['tp_dst']
            record['ip_src'] = orig_ip_dst
            record['ip_dst'] = orig_ip_src
            record['tp_src'] = orig_tp_dst
            record['tp_dst'] = orig_tp_src
            return record
        else:
            #*** First source IP doesn't match src or dst. Strange. Log error:
            self.logger.error("First source ip=%s does not match ip_src=%s or "
                        "ip_dst=%s", client_ip, record['ip_src'],
                        record['ip_dst'])
            return record

    def get_flow_client_ip(self, flow_hash):
        """
        Find the IP that is the originator of a flow searching
        forward by flow_hash

        Finds first packet seen for the flow_hash within the time
        limit and returns the source IP, otherwise 0,
        """
        db_data = {'flow_hash': flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - FLOW_TIME_LIMIT}}
        packets = self.packet_ins.find(db_data).sort('$natural', 1).limit(1)
        if packets.count():
            return list(packets)[0]['ip_src']
        else:
            self.logger.warning("no packets found")
            return 0

    def get_id(self, ip_addr):
        """
        Passed an IP address. Look this up for matching identity
        metadata and return a string that contains either the original
        IP address or an identity string
        """
        host = self.get_host_by_ip(ip_addr)
        service = self.get_service_by_ip(ip_addr)
        if host and service:
            return host + ", " + service
        elif host:
            return host
        elif service:
            return service
        else:
            return ip_addr

    def get_dns_ip(self, service_name):
        """
        Use this to get an IP address for a DNS lookup that returned a CNAME
        Passed a DNS CNAME and look this up in identities
        collection to see if there is a DNS A record, and if so return the
        IP address, otherwise return an empty string.
        """
        db_data = {'service_name': service_name}
        #*** Run db search:
        result = self.identities.find(db_data).sort('$natural', -1).limit(1)
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0['ip_address']
        else:
            self.logger.debug("A record for DNS CNAME=%s not found",
                                                                  service_name)
            return ""

    def get_host_by_ip(self, ip_addr):
        """
        Passed an IP address. Look this up in the identities db collection
        and return a host name if present, otherwise an empty string
        """
        db_data = {'ip_address': ip_addr}
        #*** Run db search:
        cursor = self.identities.find(db_data).limit(HOST_LIMIT) \
                                                          .sort('$natural', -1)
        for record in cursor:
            self.logger.debug("record is %s", record)
            if record['host_name'] != "":
                return str(record['host_name'])
        return ""

    def get_location_by_mac(self, mac_addr):
        """
        Passed a MAC address. Look this up in the identities db collection
        and return a source logical location if present,
        otherwise an empty string
        """
        db_data = {'mac_address': mac_addr}
        #*** Run db search:
        cursor = self.identities.find(db_data).limit(HOST_LIMIT) \
                                                         .sort('timestamp', -1)
        for record in cursor:
            self.logger.debug("record is %s", record)
            if record['location_logical'] != "":
                return str(record['location_logical'])
        return ""

    def get_service_by_ip(self, ip_addr, alias=1):
        """
        Passed an IP address. Look this up in the identities db collection
        and return a service name if present, otherwise an empty string.

        If alias is set, do additional lookup on success to see if service
        name is an alias for another name, and if so return that.
        """
        db_data = {'ip_address': ip_addr, "service_name": {'$ne':""}}
        db_result = self.identities.find(db_data).sort('$natural', -1).limit(1)
        if db_result.count():
            service_result = list(db_result)[0]
            service = service_result['service_name']
            self.logger.debug("service name is %s", service)
        else:
            #*** Didn't find anything, return empty string:
            return ""
        if alias:
            #*** Look up service name as alias:
            db_data = {"service_alias": service}
            db_result = self.identities.find(db_data).sort('$natural', -1). \
                                                                       limit(1)
            if db_result.count():
                service_result = list(db_result)[0]
                service = service_result['service_name']
        return service

    def get_pi_rate(self, test=0):
        """
        Calculate packet-in rate by querying packet_ins database
        collection.

        Setting test=1 returns database query execution statistics
        """
        db_data = {'timestamp': {'$gte': datetime.datetime.now() - \
                          datetime.timedelta(seconds=PACKET_IN_RATE_INTERVAL)}}
        if not test:
            packet_count = self.packet_ins.find(db_data).count()
        else:
            return self.packet_ins.find(db_data).explain()
        pi_rate = float(packet_count / PACKET_IN_RATE_INTERVAL)
        self.logger.debug("pi_rate=%s", pi_rate)
        return pi_rate

    def get_pi_time(self):
        """
        Calculate packet processing time statistics by querying
        packet_ins database collection.
        """
        result = {}
        db_data = {'timestamp': {'$gte': datetime.datetime.now() - \
                          datetime.timedelta(seconds=PACKET_TIME_PERIOD)}}
        pi_time_cursor = self.db_pi_time.find(db_data).sort('timestamp', -1)
        pi_time_list = []
        for record in pi_time_cursor:
            pi_delta = record['pi_delta']
            self.logger.debug("pi_delta=%s", pi_delta)
            pi_time_list.append(pi_delta)
        if len(pi_time_list):
            result['pi_time_max'] = max(pi_time_list)
            result['pi_time_min'] = min(pi_time_list)
            result['pi_time_avg'] = sum(pi_time_list)/len(pi_time_list)
            result['pi_time_period'] = PACKET_TIME_PERIOD
            result['pi_time_records'] = len(pi_time_list)
            return result
        else:
            self.logger.warning("no current records found in pi_time")
            return 0

def enumerate_eth_type(eth_type):
    """
    Passed an eth_type (in decimal) and return an enumerated version,
    or if not found, return the original value.
    Example, pass this function value 2054 and it return will be 'ARP'
    """
    if eth_type in ETH_TYPES:
        return ETH_TYPES[eth_type]
    else:
        return eth_type

def hovertext_eth_type(eth_type):
    """
    Passed an eth_type (decimal, not enumerated) and
    return it wrapped in extra text to convey context
    """
    return "Ethernet Type: " + str(eth_type) + " (decimal)"

def enumerate_ip_proto(ip_proto):
    """
    Passed an IP protocol number (in decimal) and return an
    enumerated version, or if not found, return the original value.
    Example, pass this function value 6 and it return will be 'TCP'
    """
    if ip_proto in IP_PROTOS:
        return IP_PROTOS[ip_proto]
    else:
        return ip_proto

def hovertext_ip_proto(ip_proto):
    """
    Passed an IP protocol number (decimal, not enumerated) and
    return it wrapped in extra text to convey context
    """
    return "IP Protocol: " + str(ip_proto) + " (decimal)"

def hovertext_ip_addr(ip_addr):
    """
    Passed an IP address and return it
    wrapped in extra text to convey context
    """
    return "IP Address: " + str(ip_addr)

if __name__ == '__main__':
    #*** Instantiate config class which imports configuration file
    #*** config.yaml and provides access to keys/values:
    config = config.Config()
    #*** Instantiate the ExternalAPI class:
    api = ExternalAPI(config)
    #*** Start the External API:
    api.run()
