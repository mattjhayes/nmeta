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
import sys

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

#*** How long in seconds to cache ARP responses for:
ARP_CACHE_TIME = 60

class Identities(BaseClass):
    """
    An object that represents identity metadata

    Variables available for Classifiers (assumes class instantiated as
    an object called 'ident'):

        ident.TBD
          TBD

        ident.harvest(pkt, flow.packet)
          TBD

        ident.findbymac(mac_address)

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
            self.mac_address = ""
            self.ip_address = ""
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

        def dbdict(self):
            """
            Return a dictionary object of identity metadata
            parameters for storing in the database
            """
            dbdictresult = {}
            dbdictresult['dpid'] = self.dpid
            dbdictresult['in_port'] = self.in_port
            dbdictresult['mac_address'] = self.mac_address
            dbdictresult['ip_address'] = self.ip_address
            dbdictresult['harvest_type'] = self.harvest_type
            dbdictresult['harvest_time'] = self.harvest_time
            dbdictresult['host_name'] = self.host_name
            dbdictresult['host_type'] = self.host_type
            dbdictresult['host_OS'] = self.host_OS
            dbdictresult['host_desc'] = self.host_desc
            dbdictresult['service_name'] = self.service_name
            dbdictresult['userID'] = self.userID
            dbdictresult['valid_from'] = self.valid_from
            dbdictresult['valid_to'] = self.valid_to
            return dbdictresult

    def harvest(self, pkt, flow_pkt):
        """
        Passed a raw packet and packet metadata from flow object.
        Check a packet_in event and harvest any relevant identity
        indicators to metadata
        """
        is_id_indicator = 0
        #*** ARP:
        if flow_pkt.eth_type == 2054:
            eth = dpkt.ethernet.Ethernet(pkt)
            pkt_arp = eth.arp
            if pkt_arp:
                #*** It's an ARP, but is it a reply (opcode 2) for IPv4?:
                if pkt_arp.op == 2 and pkt_arp.pro == 2048:
                    #*** Instantiate an instance of Indentity class:
                    ident = self.Identity()
                    ident.dpid = flow_pkt.dpid
                    ident.in_port = flow_pkt.in_port
                    ident.mac_address = mac_addr(pkt_arp.sha)
                    ident.ip_address = socket.inet_ntoa(pkt_arp.spa)
                    ident.harvest_type = 'ARP'
                    ident.harvest_time = flow_pkt.timestamp
                    ident.valid_from = flow_pkt.timestamp
                    ident.valid_to = flow_pkt.timestamp + \
                                        datetime.timedelta(0, ARP_CACHE_TIME)
                    db_dict = ident.dbdict()
                    #*** Write ARP identity metadata to database collection:
                    self.logger.debug("writing db_dict=%s", db_dict)
                    self.identities.insert_one(db_dict)
            return 1
        #*** DHCP:
        elif flow_pkt.eth_type == 2048 and flow_pkt.proto == 17 and \
                                                         flow_pkt.tp_dst == 67:
            self.logger.debug("Harvesting metadata from DHCP request")
            #*** Use dpkt to parse UDP DHCP data:
            try:
                pkt_dhcp = dpkt.dhcp.DHCP(flow_pkt.payload)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("DHCP extraction failed "
                            "Exception %s, %s, %s",
                             exc_type, exc_value, exc_traceback)
                return 0
            if pkt_dhcp.opts:
                #*** Iterate through options looking for Option 12 (Host Name):
                for opt in pkt_dhcp.opts:
                    if opt[0] == 12:
                        #*** Found option 12 so grab the host name:
                        dhcp_hostname = opt[1]
                        self.logger.debug("dhcp host_name=%s", dhcp_hostname)
                        #*** Instantiate an instance of Indentity class:
                        ident = self.Identity()
                        ident.dpid = flow_pkt.dpid
                        ident.in_port = flow_pkt.in_port
                        ident.mac_address = flow_pkt.eth_src
                        ident.ip_address = flow_pkt.ip_src
                        ident.harvest_type = 'DHCP'
                        ident.host_name = dhcp_hostname
                        ident.harvest_time = flow_pkt.timestamp
                        ident.valid_from = flow_pkt.timestamp
                        ident.valid_to = flow_pkt.timestamp + \
                                        datetime.timedelta(0, ARP_CACHE_TIME)
                        db_dict = ident.dbdict()
                        #*** Write DHCP identity metadata to db collection:
                        self.logger.debug("writing db_dict=%s", db_dict)
                        self.identities.insert_one(db_dict)
                        return 1

        #*** LLDP:
        # TBD

        #*** DNS:
        # TBD

        if not is_id_indicator:
            return 0

    def findbymac(self, mac_addr):
        """
        TEST FIND BY MAC ADDR
        DOC TBD
        """
        db_data = {'mac_address': mac_addr}
        result = self.identities.find(db_data).sort('$natural', -1).limit(1)
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0
        else:
            self.logger.debug("mac_addr=%s not found", mac_addr)
            return 0

    def findbynode(self, host_name):
        """
        TEST FIND BY NODE
        DOC TBD
        """
        db_data = {'host_name': host_name}
        result = self.identities.find(db_data).sort('$natural', -1).limit(1)
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0
        else:
            self.logger.debug("host_name=%s not found", host_name)
            return 0

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
