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

#*** For timestamps:
import datetime

#*** Amount of time (seconds) to go back for to calculate Packet-In rate:
PACKET_IN_RATE_INTERVAL = 10

FLOW_LIMIT = 25

#*** Number of previous IP identity records to search for a hostname before
#*** giving up. Used for augmenting flows with identity metadata:
HOST_LIMIT = 250
SERVICE_LIMIT = 250

#*** How far back in time to go back looking for packets in flow:
FLOW_TIME_LIMIT = datetime.timedelta(seconds=3600)
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
        #*** Run the BaseClass init to set things up:
        super(ExternalAPI, self).__init__()

        #*** Set up Logging with inherited base class method:
        self.configure_logging("external_api_logging_level_s",
                                       "external_api_logging_level_c")

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

    def run(self):
        """
        Run the External API instance
        """
        #*** Define the Eve pi_rate schema for what data the API returns:
        i_c_pi_rate_schema = {
                'pi_rate': {
                    'type': 'float'
                }
            }
        #*** Define the Eve identity schema for what data the API returns:
        identity_schema = {
                'dpid': {
                    'type': 'string'
                },
                'in_port': {
                    'type': 'string'
                },
                'harvest_time': {
                    'type': 'string'
                },
                'harvest_type': {
                    'type': 'string'
                },
                'mac_address': {
                    'type': 'string'
                },
                'ip_address': {
                    'type': 'string'
                },
                'host_name': {
                    'type': 'string'
                },
                'host_type': {
                    'type': 'string'
                },
                'host_os': {
                    'type': 'string'
                },
                'host_desc': {
                    'type': 'string'
                },
                'service_name': {
                    'type': 'string'
                },
                'service_alias': {
                    'type': 'string'
                },
                'user_id': {
                    'type': 'string'
                },
                'valid_from': {
                    'type': 'string'
                },
                'valid_to': {
                    'type': 'string'
                },
                'id_hash': {
                    'type': 'string'
                }
            }
        #*** Define the Eve flow UI schema for what data the API returns:
        flow_ui_schema = {
                'flow_hash': {
                    'type': 'string'
                }
            }
        #*** Eve Settings for Measurements of Packet In Rates:
        i_c_pi_rate_settings = {
            'url': 'infrastructure/controllers/pi_rate',
            'schema': i_c_pi_rate_schema
        }
        #*** Eve Settings for Identities Objects. Note the reverse sort
        #*** by harvest time:
        identities_settings = {
            'url': 'identities',
            'item_title': 'identity',
            'schema': identity_schema,
            'datasource': {
                'default_sort': [('harvest_time', -1)],
            }
        }
        #*** Eve Settings for identities/ui Objects. Database lookup
        #*** with deduplication and enhancement filter done by hook function
        identities_ui_settings = {
            'url': 'identities/ui',
            'item_title': 'Identities UI Data',
            'schema': identity_schema
        }
        #*** Eve Settings for flows/ui Objects. Database lookup
        #*** with deduplication and enhancements done by hook function
        flows_ui_settings = {
            'url': 'flows/ui',
            'item_title': 'Flows UI Data',
            'schema': flow_ui_schema
        }
        #*** Eve Domain for the whole API:
        eve_domain = {
            'i_c_pi_rate': i_c_pi_rate_settings,
            'identities': identities_settings,
            'identities_ui': identities_ui_settings,
            'flows_ui': flows_ui_settings
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

        #*** TBD - set up username/password into MongoDB

        #*** Set up static content location:
        file_dir = os.path.dirname(os.path.realpath(__file__))
        static_folder = os.path.join(file_dir, 'webUI')

        #*** Set up Eve:
        self.logger.info("Configuring Eve Python REST API Framework")
        self.app = Eve(settings=eve_settings, static_folder=static_folder)
        self.logger.debug("static_folder=%s", static_folder)

        #*** Hook for adding pi_rate to returned resource:
        self.app.on_fetched_resource_i_c_pi_rate += self.i_c_pi_rate_response

        #*** Hook for filtered identities response:
        self.app.on_fetched_resource_identities_ui += \
                                               self.identities_ui_response

        #*** Hook for filtered flows response:
        self.app.on_fetched_resource_flows_ui += \
                                               self.flows_ui_response

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

    def i_c_pi_rate_response(self, items):
        """
        Update the response with the packet_in rate.
        Hooked from on_fetched_resource_<name>
        """
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)
        #*** Get database and query it:
        packet_ins = self.app.data.driver.db['packet_ins']
        db_data = {'timestamp': {'$gte': datetime.datetime.now() - \
                          datetime.timedelta(seconds=PACKET_IN_RATE_INTERVAL)}}
        packet_cursor = packet_ins.find(db_data).sort('$natural', -1)
        pi_rate = float(packet_cursor.count() / PACKET_IN_RATE_INTERVAL)
        self.logger.debug("pi_rate=%s", pi_rate)
        items['pi_rate'] = pi_rate

    def identities_ui_response(self, items):
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
        #*** Get database and query it:
        identities = self.app.data.driver.db['identities']
        #*** Reverse sort:
        packet_cursor = identities.find().sort('$natural', -1)
        #*** Iterate, adding only new id_hashes to the response:
        for record in packet_cursor:
            if not record['id_hash'] in known_hashes:
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

    def flows_ui_response(self, items):
        """
        Populate the response with flow entries that are filtered:
         - Reverse sort by initial ingest time
         - Deduplicate by flow_hash, only returning most recent per flow_hash
         - Enrich with TBD
        Hooked from on_fetched_resource_<name>
        """
        known_hashes = []
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)
        #*** Get packet_ins database collection and query it:
        flows = self.app.data.driver.db['packet_ins']
        #*** Reverse sort:
        packet_cursor = flows.find().limit(FLOW_LIMIT).sort('$natural', -1)
        #*** Iterate, adding only new id_hashes to the response:
        for record in packet_cursor:
            #*** Only return unique flow records:
            if not record['flow_hash'] in known_hashes:
                #*** Normalise the direction of the flow:
                record = self.flow_normalise_direction(record)
                #*** Dictionary to hold our crafted record that has condensed
                #*** columns for better use of UI real-estate:
                flow = {}
                if record['eth_type'] == 2048:
                    #*** It's IPv4, see if we can augment with identity:
                    flow['src'] = self.get_html_id(record['ip_src'])
                    flow['dst'] = self.get_html_id(record['ip_dst'])
                    flow['proto'] = enumerate_ip_proto(record['proto'])
                else:
                    #*** It's not IPv4 (TBD, handle IPv6)
                    flow['src'] = record['eth_src']
                    flow['dst'] = record['eth_dst']
                    flow['proto'] = self.get_html_proto(record['eth_type'])
                flow['tp_src'] = record['tp_src']
                flow['tp_dst'] = record['tp_dst']
                #*** Enrich with classification and action(s):
                classification = self.get_classification(record['flow_hash'])
                flow['classification'] = \
                                self.get_html_classification(classification)
                #self.classifications
                #*** Add to items dictionary, which is returned in response:
                items['_items'].append(flow)
                #*** Add hash so we don't do it again:
                known_hashes.append(record['flow_hash'])

    def get_classification(self, flow_hash):
        """
        Passed flow_hash and return a dictionary
        of a classification object for the flow_hash (if found), otherwise
        a dictionary of an empty classification object.
        """
        db_data = {'flow_hash': flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() -
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
                'classification_type': '',
                'classification_tag': '',
                'classification_time': 0,
                'self.actions': {}
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

    def get_html_classification(self, classification):
        """
        Passed classification dictionary and return a
        string of augmented HTTP describing the classification
        """
        return "<span data-toggle=\"tooltip\" title=\"classification_type: " \
                        + classification['classification_type'] + "\">" + \
                        classification['classification_tag'] + \
                        "</span>"

    def get_html_proto(self, eth_type):
        """
        Passed an ethernet type and return either the original value
        or augmented HTTP if a lookup of value succeeds
        """
        aug_eth_type = enumerate_eth_type(eth_type)
        if aug_eth_type:
            return "<span data-toggle=\"tooltip\" title=\"eth_type: " + \
                        str(eth_type) + " (decimal)\">" + str(aug_eth_type) + \
                        "</span>"
        else:
            return eth_type

    def get_html_id(self, ip_addr):
        """
        Passed an IP address. Look this up for matching identity
        metadata and return a string that contains either the original
        IP address or an identity string
        """
        host = self.get_host_by_ip(ip_addr)
        service = self.get_service_by_ip(ip_addr)
        if host and service:
            return "<span data-toggle=\"tooltip\" title=\"" + \
                        ip_addr + "\">" + host + "<br>service=" + service + \
                        "</span>"
        elif host:
            return "<span data-toggle=\"tooltip\" title=\"" + \
                        ip_addr + "\">" + host + "</span>"
        elif service:
            return "<span data-toggle=\"tooltip\" title=\"" + \
                        ip_addr + "\">service=" + service + "</span>"
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

    def get_service_by_ip(self, ip_addr):
        """
        Passed an IP address. Look this up in the identities db collection
        and return a service name if present, otherwise an empty string
        """
        db_data = {'ip_address': ip_addr}
        #*** Run db search:
        cursor = self.identities.find(db_data).limit(SERVICE_LIMIT) \
                                                          .sort('$natural', -1)
        for record in cursor:
            if record['service_name'] != "":
                return str(record['service_name'])
        return ""

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

if __name__ == '__main__':
    #*** Instantiate config class which imports configuration file
    #*** config.yaml and provides access to keys/values:
    config = config.Config()
    #*** Instantiate the ExternalAPI class:
    api = ExternalAPI(config)
    #*** Start the External API:
    api.run()
