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
The identities module is part of the nmeta suite

It provides an abstraction for participants (identities), using
a MongoDB database for storage and data retention maintenance.

Identities are identified via  TBD....

There are methods (see class docstring) that provide harvesting
of identity metadata and various retrieval searches
"""

#*** For packet methods:
import socket

#*** Import dpkt for packet parsing:
import dpkt

#*** mongodb Database Import:
import pymongo
from pymongo import MongoClient

#*** For timestamps:
import datetime

#*** For logging configuration:
from baseclass import BaseClass

class Identities(BaseClass):
    """
    An object that represents identity metadata

    Variables available for Classifiers (assumes class instantiated as
    an object called 'ids'):

        ids.TBD
          TBD

        ids.harvest(pkt, flow.packet)
          TBD

    Challenges (not handled - yet):
     - TBD
    """

    def __init__(self, config):
        """
        Initialise an instance of the Identities class
        """
        #*** Required for BaseClass:
        self.config = config
        #*** Run the BaseClass init to set things up:
        super(Identities, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("identities_logging_level_s",
                                       "identities_logging_level_c")
        #*** Get parameters from config:
        mongo_addr = config.get_value("mongo_addr")
        mongo_port = config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")
        #*** Max bytes of the identities capped collection:
        identities_max_bytes = config.get_value("identities_max_bytes")
        #*** How far back in time to go back looking for an identity:
        self.identity_time_limit = datetime.timedelta \
                              (seconds=config.get_value("identity_time_limit"))

        #*** Start mongodb:
        self.logger.info("Connecting to MongoDB database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB nmeta database:
        db_nmeta = mongo_client[mongo_dbname]

        #*** Delete (drop) previous identities collection if it exists:
        self.logger.debug("Deleting previous identities MongoDB collection...")
        db_nmeta.identities.drop()

        #*** Create the identities collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.identities = db_nmeta.create_collection('identities', capped=True,
                                            size=identities_max_bytes)

        #*** Index ip_address key to
        #*** improve look-up performance:
        self.identities.create_index([('ip_address', pymongo.TEXT)],
                                                                unique=False)

    class Identity(object):
        """
        An object that represents an individual Identity Indicator
        """
        def __init__(self):
            #*** Initialise identity variables:
            self.dpid = 0
            self.in_port = 0
            self.mac_address = 0
            self.ip_address = 0
            self.harvest_type = 0
            self.harvest_time = 0
            self.host_name = ""
            self.host_type = ""
            self.host_OS = ""
            self.host_desc = ""
            self.service_name = ""
            self.userID = ""
            self.valid_from = ""
            self.valid_to = ""

    def harvest(self, pkt, flow):
        """
        Check a packet_in event and harvest any relevant identity
        indicators to metadata
        """
        is_id_indicator = 0
        #*** ARP:

        #*** DHCP:

        #*** LLDP:

        #*** DNS:

        if not is_id_indicator:
            return 0
        #*** Instantiate an instance of Identity class:
        #self.identity = self.Identity()

