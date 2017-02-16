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

#*** For Regular Expression searches:
import re

#*** For hashing of identities:
import hashlib

#*** How long in seconds to cache ARP responses for (in seconds):
ARP_CACHE_TIME = 14400
#*** DHCP lease time to use if none present (in seconds):
DHCP_DEFAULT_LEASE_TIME = 3600

class Identities(BaseClass):
    """
    An object that represents identity metadata

    Main function used to harvest identity metadata:
    (assumes class instantiated as an object called 'ident')

        ident.harvest(pkt, flow.packet)
            Passed a raw packet and packet metadata from flow object.
            Check a packet_in event and harvest any relevant identity
            indicators to metadata

    Functions available for Classifiers:
    (assumes class instantiated as an object called 'ident')

        ident.findbymac(mac_address)
            Look up identity object for a MAC address

        ident.findbynode(host_name)
            Look up identity object by host name (aka node)
            Additionally, can set:
                regex=True       Treat service_name as a regular expression
                harvest_type=    Specify what type of harvest (i.e. DHCP)

        ident.findbyservice(service_name)
            Look up identity object by service name
            Additionally, can set:
                regex=True        Treat service_name as a regular expression
                harvest_type=     Specify what type of harvest (i.e. DNS_A)
                ip_address=       Look for specific IP address

    See function docstrings for more information
    """

    def __init__(self, config):
        """
        Initialise an instance of the Identities class
        """
        #*** Required for BaseClass:
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "identities_logging_level_s",
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
        #*** Max bytes of the dhcp_messages capped collection:
        dhcp_messages_max_bytes = config.get_value("dhcp_messages_max_bytes")
        #*** How far back in time to go back looking for an dhcp message:
        self.dhcp_messages_time_limit = datetime.timedelta \
                         (seconds=config.get_value("dhcp_messages_time_limit"))

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

        #*** Index to improve look-up performance:
        self.identities.create_index([('valid_from', pymongo.DESCENDING),
                                        ('valid_to', pymongo.DESCENDING),
                                        ('ip_address', pymongo.ASCENDING),
                                        ('mac_address', pymongo.ASCENDING),
                                        ('host_name', pymongo.ASCENDING),
                                        ('harvest_type', pymongo.ASCENDING),
                                        ('service_name', pymongo.ASCENDING)
                                        ],
                                        unique=False)

        #*** Delete (drop) previous dhcp_messages collection if it exists:
        self.logger.debug("Deleting previous dhcp_messages MongoDB "
                                                               "collection...")
        db_nmeta.dhcp_messages.drop()

        #*** Create the dhcp_messages collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.dhcp_messages = db_nmeta.create_collection('dhcp_messages',
                                     capped=True, size=dhcp_messages_max_bytes)

        #*** Index dhcp_messages to improve look-up performance:
        self.dhcp_messages.create_index([('ingest_time', pymongo.DESCENDING),
                                        ('transaction_id', pymongo.ASCENDING),
                                        ('message_type', pymongo.ASCENDING)
                                        ],
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
            self.host_os = ""
            self.host_desc = ""
            self.service_name = ""
            self.service_alias = ""
            self.user_id = ""
            self.valid_from = ""
            self.valid_to = ""
            self.id_hash = ""

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
            dbdictresult['host_os'] = self.host_os
            dbdictresult['host_desc'] = self.host_desc
            dbdictresult['service_name'] = self.service_name
            dbdictresult['service_alias'] = self.service_alias
            dbdictresult['user_id'] = self.user_id
            dbdictresult['valid_from'] = self.valid_from
            dbdictresult['valid_to'] = self.valid_to
            dbdictresult['id_hash'] = self.id_hash
            return dbdictresult

    class DHCPMessage(object):
        """
        An object that represents an individual DHCP message.
        Used for storing DHCP state by recording DHCP events
        """
        def __init__(self):
            #*** Initialise identity variables:
            self.dpid = 0
            self.in_port = 0
            self.ingest_time = 0
            self.eth_src = 0
            self.eth_dst = 0
            self.ip_src = 0
            self.ip_dst = 0
            self.tp_src = 0
            self.tp_dst = 0
            self.transaction_id = 0
            self.message_type = 0
            self.host_name = ""
            self.ip_assigned = 0
            self.ip_dhcp_server = 0
            self.lease_time = 0

        def dbdict(self):
            """
            Return a dictionary object of dhcp message
            parameters for storing in the database
            """
            return self.__dict__

    def harvest(self, pkt, flow_pkt):
        """
        Passed a raw packet and packet metadata from flow object.
        Check a packet_in event and harvest any relevant identity
        indicators to metadata
        """
        #*** ARP:
        if flow_pkt.eth_type == 2054:
            self.harvest_arp(pkt, flow_pkt)

        #*** DHCP:
        elif flow_pkt.eth_type == 2048 and flow_pkt.proto == 17 and \
                              (flow_pkt.tp_dst == 67 or flow_pkt.tp_dst == 68):
            self.harvest_dhcp(flow_pkt)

        #*** LLDP:
        elif flow_pkt.eth_type == 35020:
            self.harvest_lldp(flow_pkt)

        #*** DNS:
        elif (flow_pkt.proto == 6 or flow_pkt.proto == 17) and \
                        (flow_pkt.tp_src == 53 or flow_pkt.tp_src == 53):
            self.harvest_dns(flow_pkt)

        else:
            #*** Not an identity indicator
            return 0

    def harvest_arp(self, pkt, flow_pkt):
        """
        Harvest ARP identity metadata into database.
        Passed packet-in metadata from flow object.
        Check ARP reply and harvest identity
        indicators to metadata
        """
        self.logger.debug("Harvesting metadata from ARP request")

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
                ident.id_hash = self._hash_identity(ident)
                db_dict = ident.dbdict()
                #*** Write ARP identity metadata to database collection:
                self.logger.debug("writing db_dict=%s", db_dict)
                self.identities.insert_one(db_dict)
        return 1

    def harvest_dhcp(self, flow_pkt):
        """
        Harvest DHCP identity metadata into database.
        Passed packet-in metadata from flow object.
        Check LLDP TLV fields and harvest any relevant identity
        indicators to metadata
        """
        self.logger.debug("Harvesting metadata from DHCP request")
        dhcp_hostname = ""
        dhcp_leasetime = 0
        #*** Use dpkt to parse UDP DHCP data:
        try:
            pkt_dhcp = dpkt.dhcp.DHCP(flow_pkt.payload)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("DHCP extraction failed "
                        "Exception %s, %s, %s",
                         exc_type, exc_value, exc_traceback)
            return 0
        #*** Turn DHCP options list of tuples into a dictionary:
        dhcp_opts = dict(pkt_dhcp.opts)
        self.logger.debug("dhcp_opts=%s", dhcp_opts)
        #*** Get the type of the DHCP message:
        try:
            dhcp_type = ord(dhcp_opts[53])
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("DHCP type extraction failed "
                        "Exception %s, %s, %s",
                         exc_type, exc_value, exc_traceback)
            return 0
        #*** Do stuff based on the DHCP message type:
        if dhcp_type == dpkt.dhcp.DHCPDISCOVER:
            self.logger.debug("Matched DHCPDISCOVER, TBD - not handled")
        elif dhcp_type == dpkt.dhcp.DHCPOFFER:
            self.logger.debug("Matched DHCPOFFER, TBD - not handled")
        elif dhcp_type == dpkt.dhcp.DHCPREQUEST:
            self.logger.debug("Matched DHCPREQUEST")
            if dpkt.dhcp.DHCP_OPT_HOSTNAME in dhcp_opts:
                #*** Instantiate an instance of DHCP class:
                self.dhcp_msg = self.DHCPMessage()
                self.dhcp_msg.dpid = flow_pkt.dpid
                self.dhcp_msg.in_port = flow_pkt.in_port
                self.dhcp_msg.ingest_time = flow_pkt.timestamp
                self.dhcp_msg.eth_src = flow_pkt.eth_src
                self.dhcp_msg.eth_dst = flow_pkt.eth_dst
                self.dhcp_msg.ip_src = flow_pkt.ip_src
                self.dhcp_msg.ip_dst = flow_pkt.ip_dst
                self.dhcp_msg.tp_src = flow_pkt.tp_src
                self.dhcp_msg.tp_dst = flow_pkt.tp_dst
                self.dhcp_msg.transaction_id = hex(pkt_dhcp.xid)
                self.dhcp_msg.host_name = str(dhcp_opts
                                                 [dpkt.dhcp.DHCP_OPT_HOSTNAME])
                self.dhcp_msg.message_type = 'DHCPREQUEST'
                #*** Record DHCP event to db collection:
                db_dict = self.dhcp_msg.dbdict()
                #*** Write DHCP message to db collection:
                self.logger.debug("writing dhcp_messages db_dict=%s", db_dict)
                self.dhcp_messages.insert_one(db_dict)
                return 1
        elif dhcp_type == dpkt.dhcp.DHCPDECLINE:
            self.logger.debug("Matched DHCPDECLINE, TBD - not handled")
        elif dhcp_type == dpkt.dhcp.DHCPACK:
            self.logger.debug("Matched DHCPACK")
            xid = hex(pkt_dhcp.xid)
            #*** Look up dhcp db collection for DHCPREQUEST:
            db_data = {'transaction_id': xid,
                        'message_type': 'DHCPREQUEST'}
            #*** Filter by documents that are still within 'best before' time:
            db_data['ingest_time'] = {'$gte': datetime.datetime.now() -
                                                 self.dhcp_messages_time_limit}
            #*** Run db search:
            result = self.dhcp_messages.find(db_data).sort('ingest_time', -1) \
                                                                      .limit(1)
            if result.count():
                result0 = list(result)[0]
                self.logger.debug("Found DHCPREQUEST for DHCPACK")
                #*** Found a DHCP Request for the ACK, record results:
                #*** Instantiate an instance of DHCP class:
                self.dhcp_msg = self.DHCPMessage()
                self.dhcp_msg.dpid = flow_pkt.dpid
                self.dhcp_msg.in_port = flow_pkt.in_port
                self.dhcp_msg.ingest_time = flow_pkt.timestamp
                self.dhcp_msg.eth_src = flow_pkt.eth_src
                self.dhcp_msg.eth_dst = flow_pkt.eth_dst
                self.dhcp_msg.ip_src = flow_pkt.ip_src
                self.dhcp_msg.ip_dst = flow_pkt.ip_dst
                self.dhcp_msg.tp_src = flow_pkt.tp_src
                self.dhcp_msg.tp_dst = flow_pkt.tp_dst
                self.dhcp_msg.transaction_id = hex(pkt_dhcp.xid)
                self.dhcp_msg.ip_assigned = \
                           socket.inet_ntoa(struct.pack(">L", pkt_dhcp.yiaddr))
                if dpkt.dhcp.DHCP_OPT_LEASE_SEC in dhcp_opts:
                    self.dhcp_msg.lease_time = struct.unpack('>L', dhcp_opts
                                            [dpkt.dhcp.DHCP_OPT_LEASE_SEC])[0]
                    self.logger.debug("Found dhcp_leasetime=%s",
                                                      self.dhcp_msg.lease_time)
                else:
                    self.dhcp_msg.lease_time = DHCP_DEFAULT_LEASE_TIME
                    self.logger.debug("Using default dhcp_leasetime=%s",
                                                      self.dhcp_msg.lease_time)
                self.dhcp_msg.message_type = 'DHCPACK'
                #*** Record DHCP event to db collection:
                db_dict = self.dhcp_msg.dbdict()
                #*** Write DHCP message to db collection:
                self.logger.debug("writing dhcp_messages db_dict=%s", db_dict)
                self.dhcp_messages.insert_one(db_dict)
                #*** Instantiate an instance of Identity class:
                ident = self.Identity()
                ident.dpid = flow_pkt.dpid
                ident.in_port = flow_pkt.in_port
                ident.mac_address = flow_pkt.eth_dst
                ident.ip_address = self.dhcp_msg.ip_assigned
                ident.harvest_type = 'DHCP'
                ident.host_name = result0['host_name']
                ident.harvest_time = flow_pkt.timestamp
                ident.valid_from = flow_pkt.timestamp
                #*** Calculate validity:
                ident.valid_to = flow_pkt.timestamp + \
                                datetime.timedelta(0, self.dhcp_msg.lease_time)
                ident.id_hash = self._hash_identity(ident)
                db_dict = ident.dbdict()
                #*** Write DHCP identity metadata to db collection:
                self.logger.debug("writing db_dict=%s", db_dict)
                self.identities.insert_one(db_dict)
                return 1
            else:
                self.logger.debug("Prev DHCP host_name not found")
                return 0
        elif dhcp_type == dpkt.dhcp.DHCPNAK:
            self.logger.debug("Matched DHCPNAK, TBD - not handled")
        elif dhcp_type == dpkt.dhcp.DHCPRELEASE:
            self.logger.debug("Matched DHCPRELEASE, TBD - not handled")
        elif dhcp_type == dpkt.dhcp.DHCPINFORM:
            self.logger.debug("Matched DHCPINFORM, TBD - not handled")
        else:
            self.logger.debug("Unknown DHCP option 53 value: %s", dhcp_type)
            return 0

    def harvest_lldp(self, flow_pkt):
        """
        Harvest LLDP identity metadata into database.
        Passed packet-in metadata from flow object.
        Check LLDP TLV fields and harvest any relevant identity
        indicators to metadata
        """
        self.logger.debug("Checking LLDP for metadata")
        payload = flow_pkt.payload
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
        #*** Try looking up an IP for the LLDP source MAC:
        ident2 = self.findbymac(ident.mac_address)
        if 'ip_address' in ident2:
            ident.ip_address = ident2['ip_address']
            self.logger.debug("Found ip=%s for LLDP flow_hash=%s",
                                    ident.ip_address, flow_pkt.flow_hash)
        else:
            self.logger.debug("Could not find IP for LLDP flow_hash=%s",
                                    flow_pkt.flow_hash)
        ident.id_hash = self._hash_identity(ident)
        #*** Write LLDP identity metadata to db collection:
        db_dict = ident.dbdict()
        self.logger.debug("writing db_dict=%s", db_dict)
        self.identities.insert_one(db_dict)
        return 1

    def harvest_dns(self, flow_pkt):
        """
        Harvest DNS identity metadata into database.
        Passed packet-in metadata from flow object.
        Check DNS answer(s) and harvest any relevant identity
        indicators to metadata
        """
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
                ident.id_hash = self._hash_identity(ident)
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
                ident.id_hash = self._hash_identity(ident)
                db_dict = ident.dbdict()
                #*** Write DNS identity metadata to database collection:
                self.logger.debug("writing db_dict=%s", db_dict)
                self.identities.insert_one(db_dict)
            else:
                #*** Not a type that we handle yet
                self.logger.debug("Unhandled DNS answer type=%s", answer.type)

    def findbymac(self, mac_addr, test=0):
        """
        Passed a MAC address and reverse search identities collection
        returning first match as a dictionary version of
        an Identity class, or empty dictionary if not found

        Setting test=1 returns database query execution statistics
        """
        db_data = {'mac_address': mac_addr}
        if not test:
            result = self.identities.find(db_data).sort('valid_from', -1).limit(1)
        else:
            return self.identities.find(db_data).sort('valid_from', -1).limit(1).explain()
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0
        else:
            self.logger.debug("mac_addr=%s not found", mac_addr)
            return {}

    def findbynode(self, host_name, harvest_type='any', regex=False):
        """
        Find by node name
        Pass it the name of the node to search for. Additionally,
        can set:
          regex=True       Treat service_name as a regular expression
          harvest_type=    Specify what type of harvest (i.e. DHCP)
        Returns a dictionary version of an Identity class, or 0 if not found
        """
        db_data = {'host_name': host_name}
        if harvest_type != 'any':
            #*** Filter by harvest type:
            db_data['harvest_type'] = harvest_type
        if regex:
            #*** Regular expression search on service name:
            regx = re.compile(host_name)
            db_data['host_name'] = regx
        #*** Filter by documents that are still within 'best before' time:
        db_data['valid_to'] = {'$gte': datetime.datetime.now()}
        #*** Run db search:
        result = self.identities.find(db_data).sort('valid_from', -1).limit(1)
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0
        else:
            self.logger.debug("host_name=%s not found", host_name)
            return 0

    def findbyservice(self, service_name, harvest_type='any', regex=False,
                        ip_address='any'):
        """
        Find by service name
        Pass it the name of the service to search for. Additionally,
        can set:
          regex=True        Treat service_name as a regular expression
          harvest_type=     Specify what type of harvest (i.e. DNS_A)
          ip_address=       Look for specific IP address
        Returns boolean
        """
        db_data = {'service_name': service_name}
        if harvest_type != 'any':
            #*** Filter by harvest type:
            db_data['harvest_type'] = harvest_type
        if ip_address != 'any':
            #*** Filter by IP address:
            db_data['ip_address'] = ip_address
        if regex:
            #*** Regular expression search on service name:
            regx = re.compile(service_name)
            db_data['service_name'] = regx
        #*** Filter by documents that are still within 'best before' time:
        db_data['valid_to'] = {'$gte': datetime.datetime.now()}
        #*** Run db search:
        result = self.identities.find(db_data).sort('valid_from', -1).limit(1)
        if result.count():
            result0 = list(result)[0]
            self.logger.debug("found result=%s len=%s", result0, len(result0))
            return result0
        else:
            self.logger.debug("service_name=%s not found", service_name)
            return 0

    def _hash_identity(self, ident):
        """
        Generate a hash of the current identity used for deduplication
        where the same identity is received periodically, or from multiple
        sources.
        """
        hash_result = hashlib.md5()
        id_tuple = (ident.harvest_type,
                    ident.host_name,
                    ident.service_name,
                    ident.user_id)
        id_tuple_as_string = str(id_tuple)
        hash_result.update(id_tuple_as_string)
        return hash_result.hexdigest()

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
