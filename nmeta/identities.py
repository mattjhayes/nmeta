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
import struct

import binascii

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
            self.service_alias = ""
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
            dbdictresult['service_alias'] = self.service_alias
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
                        # TBD, FIX THIS:
                        ident.valid_to = flow_pkt.timestamp + \
                                        datetime.timedelta(0, ARP_CACHE_TIME)
                        db_dict = ident.dbdict()
                        #*** Write DHCP identity metadata to db collection:
                        self.logger.debug("writing db_dict=%s", db_dict)
                        self.identities.insert_one(db_dict)
                        return 1
        #*** LLDP:
        elif flow_pkt.eth_type == 35020:
            payload = pkt[14:]
            lldp_dict = self._parse_lldp_detail(payload)
            if not len(lldp_dict):
                self.logger.warning("Failed to parse LLDP")
                return 0
            self.logger.debug("LLDP parsed %s", lldp_dict)
            #*** Instantiate an instance of Indentity class:
            ident = self.Identity()
            if 'system_name' in lldp_dict:
                ident.host_name = lldp_dict['system_name']
            if 'system_desc' in lldp_dict:
                ident.host_desc = lldp_dict['system_desc']
            if 'TTL' in lldp_dict:
                ttl = lldp_dict['TTL']
            else:
                #*** TBD, handle this better:
                ttl = 60
            ident.dpid = flow_pkt.dpid
            ident.in_port = flow_pkt.in_port
            ident.mac_address = flow_pkt.eth_src
            ident.harvest_type = 'LLDP'
            ident.harvest_time = flow_pkt.timestamp
            ident.valid_from = flow_pkt.timestamp
            #*** valid to based on LLDP TTL:
            ident.valid_to = flow_pkt.timestamp + \
                                        datetime.timedelta(0, ttl)
            db_dict = ident.dbdict()
            #*** Write LLDP identity metadata to db collection:
            self.logger.debug("writing db_dict=%s", db_dict)
            self.identities.insert_one(db_dict)
            return 1

        #*** DNS:
        elif (flow_pkt.proto == 6 or flow_pkt.proto == 17) and \
                        (flow_pkt.tp_src == 53 or flow_pkt.tp_src == 53):
            self.logger.debug("Checking DNS for metadata")
            #*** Use dpkt to parse DNS:
            try:
                pkt_dns = dpkt.dns.DNS(flow_pkt.payload)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("DNS extraction failed "
                            "Exception %s, %s, %s",
                             exc_type, exc_value, exc_traceback)
                return 0
            answers = pkt_dns.an
            for answer in answers:
                if answer.type == 1:
                    #*** DNS A Record:
                    ident = self.Identity()
                    ident.dpid = flow_pkt.dpid
                    ident.in_port = flow_pkt.in_port
                    ident.harvest_type = 'DNS_A'
                    ident.ip_address = socket.inet_ntoa(answer.rdata)
                    ident.service_name = answer.name
                    ident.harvest_time = flow_pkt.timestamp
                    ident.valid_from = flow_pkt.timestamp
                    ident.valid_to = flow_pkt.timestamp + \
                                        datetime.timedelta(0, answer.ttl)
                    db_dict = ident.dbdict()
                    #*** Write DNS identity metadata to database collection:
                    self.logger.debug("writing db_dict=%s", db_dict)
                    self.identities.insert_one(db_dict)
                elif answer.type == 5:
                    #*** DNS CNAME Record:
                    ident = self.Identity()
                    ident.dpid = flow_pkt.dpid
                    ident.in_port = flow_pkt.in_port
                    ident.harvest_type = 'DNS_CNAME'
                    ident.service_name = answer.name
                    ident.service_alias = answer.cname
                    ident.harvest_time = flow_pkt.timestamp
                    ident.valid_from = flow_pkt.timestamp
                    ident.valid_to = flow_pkt.timestamp + \
                                        datetime.timedelta(0, answer.ttl)
                    db_dict = ident.dbdict()
                    #*** Write DNS identity metadata to database collection:
                    self.logger.debug("writing db_dict=%s", db_dict)
                    self.identities.insert_one(db_dict)
                else:
                    #*** Not a type that we handle yet
                    pass
        else:
            #*** Not an identity indicator
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

    def findbyservice(self, service_name):
        """
        TEST FIND BY SERVICE
        DOC TBD
        """
        db_data = {'service_name': service_name}
        result = self.identities.find(db_data).sort('$natural', -1).limit(1)
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0
        else:
            self.logger.debug("host_name=%s not found", host_name)
            return 0

    #=================== PRIVATE ==============================================
    def _parse_lldp_detail(self, lldpPayload):
        """
        Parse basic LLDP parameters from an LLDP packet payload
        """
        result = {}

        while lldpPayload:
            tlv_header = struct.unpack("!H", lldpPayload[:2])[0]
            tlv_type = tlv_header >> 9
            tlv_len = (tlv_header & 0x01ff)
            lldpDU = lldpPayload[2:tlv_len + 2]
            if tlv_type == 0:
                #*** TLV type 0 is end of TLVs so break the while loop:
                break
            else:
                tlv_subtype = struct.unpack("!B", lldpDU[0:1]) \
                                                    if tlv_type is 2 else ""
                startbyte = 1 if tlv_type is 2 else 0
                tlv_datafield = lldpDU[startbyte:tlv_len]
            #*** Pull out values from specific TLVs:
            if tlv_type == 3:
                result['TTL'] = struct.unpack("!h", tlv_datafield)[0]
            elif tlv_type == 4:
                result['port_desc'] = tlv_datafield
            elif tlv_type == 5:
                result['system_name'] = tlv_datafield
            elif tlv_type == 6:
                result['system_desc'] = tlv_datafield
            else:
                pass
            lldpPayload = lldpPayload[2 + tlv_len:]
        return result

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)
