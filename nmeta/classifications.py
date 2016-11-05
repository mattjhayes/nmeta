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
The classifications module is part of the nmeta suite

It provides an abstraction for traffic classification results,
using a MongoDB database for storage and data retention maintenance.

There are methods (see class docstring) for recording and retrieving
classification results.
"""

#*** mongodb Database Import:
import pymongo
from pymongo import MongoClient

#*** For timestamps:
import datetime

#*** For logging configuration:
from baseclass import BaseClass

#*** For Regular Expression searches:
import re

class Classifications(BaseClass):
    """
    An object that represents traffic classifications

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
        super(Classifications, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("classifications_logging_level_s",
                                       "classifications_logging_level_c")
        #*** Get parameters from config:
        mongo_addr = config.get_value("mongo_addr")
        mongo_port = config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")
        #*** Max bytes of the classifications capped collection:
        classifications_max_bytes = \
                                  config.get_value("classifications_max_bytes")
        #*** How far back in time to go back looking for an identity:
        self.classification_time_limit = datetime.timedelta \
                        (seconds=config.get_value("classification_time_limit"))

        #*** Start mongodb:
        self.logger.info("Connecting to MongoDB database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB nmeta database:
        db_nmeta = mongo_client[mongo_dbname]

        #*** Delete (drop) previous classifications collection if it exists:
        self.logger.debug("Deleting previous classifications MongoDB "
                                                               "collection...")
        db_nmeta.classifications.drop()

        #*** Create the classifications collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.classifications = db_nmeta.create_collection('classifications',
                                   capped=True, size=classifications_max_bytes)

        #*** Indexing TBD
        #*** improve look-up performance:


    class Classification(object):
        """
        An object that represents an individual traffic classification
        """
        def __init__(self):
            #*** Initialise classification variables:
            self.flow_hash = 0
            self.classification_type = ""
            self.classification_time = 0
            self.actions = ""

        def dbdict(self):
            """
            Return a dictionary object of traffic classification
            parameters for storing in the database
            """
            dbdictresult = {}
            dbdictresult['flow_hash'] = self.flow_hash
            dbdictresult['classification_type'] = self.classification_type
            dbdictresult['classification_time'] = self.classification_time
            dbdictresult['actions'] = self.actions
            return dbdictresult

    def record(self):
        """
        Passed a TBD
        """
        pass

    def find(self):
        """
        Passed a TBD
        """
        pass
