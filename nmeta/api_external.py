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

import sys, os, ast

#*** Import Eve for REST API Framework:
from eve import Eve

#*** Inherit logging etc:
from baseclass import BaseClass

#*** MongoDB Database Import:
from pymongo import MongoClient

#*** nmeta imports
import config

#*** For timestamps:
import datetime

#*** To convert results into JSON:
from flask import jsonify

#*** Amount of time (seconds) to go back for to calculate Packet-In rate:
PACKET_IN_RATE_INTERVAL = 10

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
        self.logger.info("Connecting to Decision API MongoDB "
                                                "database...")
        #*** Get database parameters from config:
        mongo_addr = self.config.get_value("mongo_addr")
        mongo_port = self.config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")

        #*** Use Pymongo to connect to Decision API database:
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB nmeta database:
        db_nmeta = mongo_client.mongo_dbname

        #*** Variable for Packet-Ins Collection:
        self.packet_ins = db_nmeta.packet_ins

    def run(self):
        """
        Run the External API instance
        """
        packet_ins_settings = {
            'schema': {
                'flow_hash': {
                    'type': 'string',
                },
                'dpid': {
                    'type': 'string',
                },
                'in_port': {
                    'type': 'integer',
                },
                'timestamp': {
                    'type': 'string',
                },
                'length': {
                    'type': 'integer',
                },
                'eth_src': {
                    'type': 'string',
                },
                'eth_dst': {
                    'type': 'string',
                },
                'ip_src': {
                    'type': 'string',
                },
                'ip_dst': {
                    'type': 'string',
                },
                'proto': {
                    'type': 'string',
                },
                'tp_src': {
                    'type': 'string',
                },
                'tp_dst': {
                    'type': 'string',
                },
                'tp_flags': {
                    'type': 'string',
                },
                'tp_seq_src': {
                    'type': 'string',
                },
                'tp_seq_dst': {
                    'type': 'string',
                },
                'payload': {
                    'type': 'string',
                }
            }
        }

        #*** Eve Settings for Measurements of Packet In Rates:
        i_c_pi_rate_settings = {
            'url': 'infrastructure/controllers/pi_rate',
            'schema': {
                'pi_rate': {
                    'type': 'float'
                },
            }
        }

        #*** Eve Settings for Identities Objects. Note the reverse sort
        #*** by harvest time:
        identities_settings = {
            'url': 'identities',
            'item_title': 'identity',
            'schema': {
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
            },
            'datasource': {
                'default_sort': [('harvest_time', -1)],
                'aggregation' : {
                    'pipeline': [
                            {
                            '$group': {
                                'originalId': {'$first': '$_id'},
                                '_id': '$id_hash',
                                'dpid': {'$first': '$dpid'},
                                'in_port': {'$first': '$in_port'},
                                'mac_address': {'$first': '$mac_address'},
                                'ip_address': {'$first': '$ip_address'},
                                'harvest_type': {'$first': '$harvest_type'},
                                'harvest_time': {'$first': '$harvest_time'},
                                'host_name': {'$first': '$host_name'},
                                'host_type': {'$first': '$host_type'},
                                'host_os': {'$first': '$host_os'},
                                'host_desc': {'$first': '$host_desc'},
                                'service_name': {'$first': '$service_name'},
                                'service_alias': {'$first': '$service_alias'},
                                'user_id': {'$first': '$user_id'},
                                'valid_from': {'$first': '$valid_from'},
                                'valid_to': {'$first': '$valid_to'}
                            },
                            '$project': {
                                '_id': '$originalId',
                                'id_hash': '$_id',
                                'dpid': '$dpid',
                                'in_port': '$in_port',
                                'mac_address': '$mac_address',
                                'ip_address': '$ip_address',
                                'harvest_type': '$harvest_type',
                                'harvest_time': '$harvest_time',
                                'host_name': '$host_name',
                                'host_type': '$host_type',
                                'host_os': '$host_os',
                                'host_desc': '$host_desc',
                                'service_name': '$service_name',
                                'service_alias': '$service_alias',
                                'user_id': '$user_id',
                                'valid_from': '$valid_from',
                                'valid_to': '$valid_to'
                            }
                        }
                    ]
                }
            }
        }

        eve_domain = {
                    'packet_ins': packet_ins_settings,
                    'i_c_pi_rate': i_c_pi_rate_settings,
                    'identities': identities_settings
                    }

        #*** Set up a settings dictionary for starting Eve app:datasource
        eve_settings = {}
        eve_settings['HATEOAS'] =  True
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

        #*** Measurement API updates to returned resource:
        self.app.on_fetched_resource_i_c_pi_rate += self.i_c_pi_rate_response

        #*** TEST:
        self.app.on_fetched_resource_identities += self.identities_response

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

    def identities_response(self, items):
        """
        TBD TEST
        """
        self.logger.debug("Hooked on_fetched_resource items=%s ", items)
        items['host_name'] = 'foo'

if __name__ == '__main__':
    #*** Instantiate config class which imports configuration file
    #*** config.yaml and provides access to keys/values:
    config = config.Config()
    #*** Instantiate the ExternalAPI class:
    api = ExternalAPI(config)
    #*** Start the External API:
    api.run()
