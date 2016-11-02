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
        m_pi_rate_settings = {
            'url': 'measurements/pi_rate',
            'schema': {
                'pi_rate': {
                    'type': 'float'
                },
            }
        }

        eve_domain = {
                    'packet_ins': packet_ins_settings,
                    'm_pi_rate': m_pi_rate_settings
                    }

        #*** Set up a settings dictionary for starting Eve app:datasource
        eve_settings = {}
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
        static_folder = os.path.join(file_dir, 'static')

        #*** Set up Eve:
        self.logger.info("Configuring Eve Python REST API Framework")
        self.app = Eve(settings=eve_settings, static_folder=static_folder)
        self.logger.debug("static_folder=%s", static_folder)

        #*** Register a callback on GET requests pre-database:
        self.app.on_pre_GET += self.pre_get_callback

        #*** Register a callback on GET requests after database insertion:
        self.app.on_post_GET += self.post_get_callback

        #*** Register a callback on database insertion:
        self.app.on_inserted += self.on_inserted_callback

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

    def pre_get_callback(self, resource, request, lookup):
        """
        Runs on GET request pre database lookup
        """
        self.logger.info("Hooked Pre-DB GET with resource=%s request=%s "
                            "lookup=%s", resource, request, lookup)


    def post_get_callback(self, resource, request, payload):
        """
        TBD
        """
        self.logger.info("Hooked Post-DB GET with resource=%s request=%s "
                            "payload=%s", resource, request, payload)
        if resource == 'm_pi_rate':
            #*** Filter query to return Packet In rates:
            self.logger.debug("returning Packet In rates")
            #*** Get database and query it:
            packet_ins = self.app.data.driver.db['packet_ins']
            db_data = {'timestamp': {'$gte': datetime.datetime.now() - \
                                                datetime.timedelta(seconds=30)}}
            packet_cursor = packet_ins.find(db_data).sort('$natural', -1)
            pi_rate = float(packet_cursor.count() / 30)
            self.logger.debug("pi_rate=%s", pi_rate)

            #*** TBD put result in return body JSON:
            #json = json.loads(payload.get_data())
            #documents = json['_items']

            return jsonify({'pi_rate':pi_rate})

    def on_inserted_callback(self, resource_name, items):
        """
        Runs on Decision API database inserts, after database insertion
        completed. It places a message onto the multi-process queue
        that contains link to resource in database
        """
        _result = {}
        self.logger.debug("Database insert resource_name=%s items=%s",
                            resource_name, items)
        _result['_id'] = items[0]['_id']
        self.queue.put(_result)

    def ingest_dictionary(self, filename):
        """
        Read text file that is in dictionary format into a Python
        dictionary object. Uses ast module.
        """
        _result = {}
        self.logger.debug("Reading in file %s to dictionary", filename)
        try:
            with open(filename,'r') as file_handle:
                _result = ast.literal_eval(file_handle.read())
        except (IOError, OSError) as exception:
            #*** IO exception:
            self.logger.critical("Failed to open file %s, "
                                    "error=%s", filename, exception)
            sys.exit("Exiting. Please create file")
        return _result

if __name__ == '__main__':
    #*** Instantiate config class which imports configuration file
    #*** config.yaml and provides access to keys/values:
    config = config.Config()
    #*** Instantiate the ExternalAPI class:
    api = ExternalAPI(config)
    #*** Start the External API:
    api.run()
