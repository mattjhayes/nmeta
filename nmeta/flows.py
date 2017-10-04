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
The flows module is part of the nmeta suite

It provides an abstraction for conversations (flows), using
a MongoDB database for storage and data retention maintenance.

Flows are identified via an indexed bi-directionally-unique
hash value, derived from IP-value-ordered 5-tuple (source and
destination IP addresses, IP protocol and transport source and
destination port numbers).

Ingesting a packet puts the flows object into the context of the
packet that flow belongs to, and updates the database object for
that flow with information from the current packet.

There are various methods (see class docstring) that provide views
into the state of the flow.
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

#*** nmeta imports:
import nethash

#*** Seconds to wait before resuppressing a flow on a particular switch:
FLOW_SUPPRESSION_STANDDOWN = datetime.timedelta(seconds=5)

class Flow(BaseClass):
    """
    An object that represents a flow that we are classifying

    Intended to provide an abstraction of a flow that classifiers
    can use to make determinations without having to understand
    implementations such as database lookups etc.

    Be aware that this module is not very mature yet. It does not
    cover some basic corner cases such as packet retransmissions and
    out of order or missing packets.

    Read a packet_in event into flows (assumes class instantiated as
    an object called 'flow'):
        flow.ingest_packet(dpid, in_port, pkt, timestamp)

    Variables available for Classifiers (assumes class instantiated as
    an object called 'flow'):

        **Variables for the current packet**:

        flow.packet.flow_hash
          The hash of the 5-tuple of the current packet

        flow.packet.packet_hash
          The hash of the current packet used for deduplication.
          It is an indexed uni-directionally packet identifier,
          derived from ip_src, ip_dst, proto, tp_src, tp_dst,
          tp_seq_src, tp_seq_dst

        flow.packet.dpid
          The DPID that the current packet was received from
          via a Packet-In message

        flow.packet.in_port
          The switch port that the current packet was received on
          before being sent to the controller

        flow.packet.timestamp
          The time in datetime format that the current packet was
          received at the controller

        flow.packet.length
          Length in bytes of the current packet on wire

        flow.packet.eth_src
          Ethernet source MAC address of current packet

        flow.packet.eth_dst
          Ethernet destination MAC address of current packet

        flow.packet.eth_type
          Ethertype of current packet in decimal

        flow.packet.ip_src
          IP source address of current packet

        flow.packet.ip_dst
          IP destination address of current packet

        flow.packet.proto
          IP protocol number of current packet

        flow.packet.tp_src
          Source transport-layer port number of current packet

        flow.packet.tp_dst
          Destination transport-layer port number of current packet

        flow.packet.tp_flags
          Transport-layer flags of the current packet

        flow.packet.tp_seq_src
          Source transport-layer sequence number (where existing)
          of current packet

        flow.packet.tp_seq_dst
          Destination transport-layer sequence number (where existing)
          of current packet

        flow.packet.payload
          Payload data of current packet

        flow.packet.tcp_fin()
          True if TCP FIN flag is set in the current packet

        flow.packet.tcp_syn()
          True if TCP SYN flag is set in the current packet

        flow.packet.tcp_rst()
          True if TCP RST flag is set in the current packet

        flow.packet.tcp_psh()
          True if TCP PSH flag is set in the current packet

        flow.packet.tcp_ack()
          True if TCP ACK flag is set in the current packet

        flow.packet.tcp_urg()
          True if TCP URG flag is set in the current packet

        flow.packet.tcp_ece()
          True if TCP ECE flag is set in the current packet

        flow.packet.tcp_cwr()
          True if TCP CWR flag is set in the current packet

        **Variables for the whole flow**:

        flow.packet_count()
          Unique packets registered for the flow

        flow.client()
          The IP that is the originator of the flow (if known,
          otherwise 0)

        flow.server()
          The IP that is the destination of the flow (if known,
          otherwise 0)

        flow.packet_direction()
          c2s (client to server) or s2c directionality based on first observed
          packet direction in the flow. Source of first packet in flow is
          assumed to be the client

        flow.max_packet_size()
          Size of largest packet in the flow

        flow.max_interpacket_interval()
          TBD

        flow.min_interpacket_interval()
          TBD

        **Variables for the whole flow relating to classification**:

        classification.TBD

    The Flow class also includes the record_removal method
    that records a flow removal message from a switch to database

    Challenges (not handled - yet):
     - duplicate packets due to retransmissions or multiple switches
       in path
     - IP fragments
     - Flow reuse - TCP source port reused
    """

    def __init__(self, config):
        """
        Initialise an instance of the Flow class
        """
        #*** Required for BaseClass:
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "flows_logging_level_s",
                                       "flows_logging_level_c")
        self.flow_hash = 0

        #*** Get parameters from config:
        mongo_addr = config.get_value("mongo_addr")
        mongo_port = config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")
        #*** Max bytes of the capped collections:
        packet_ins_max_bytes = config.get_value("packet_ins_max_bytes")
        classifications_max_bytes = \
                                  config.get_value("classifications_max_bytes")
        flow_rems_max_bytes = config.get_value("flow_rems_max_bytes")
        flow_mods_max_bytes = config.get_value("flow_mods_max_bytes")
        #*** How far back in time to go back looking for packets in flow:
        self.flow_time_limit = datetime.timedelta \
                                (seconds=config.get_value("flow_time_limit"))
        self.classification_time_limit = datetime.timedelta \
                        (seconds=config.get_value("classification_time_limit"))

        #*** Start mongodb:
        self.logger.info("Connecting to MongoDB database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB nmeta database:
        db_nmeta = mongo_client[mongo_dbname]

        #*** packet_ins collection:
        self.logger.debug("Deleting packet_ins MongoDB collection...")
        db_nmeta.packet_ins.drop()
        #*** Create the packet_ins collection, specifying capped option
        #***  with max size in bytes, so MongoDB handles data retention:
        self.packet_ins = db_nmeta.create_collection('packet_ins', capped=True,
                                            size=packet_ins_max_bytes)

        self.packet_ins.create_index([('flow_hash', pymongo.DESCENDING),
                                        ('timestamp', pymongo.ASCENDING)
                                        ],
                                        unique=False)

        self.packet_ins.create_index([('timestamp', pymongo.DESCENDING)],
                                        unique=False)

        #*** classifications collection:
        self.logger.debug("Deleting classifications MongoDB collection...")
        db_nmeta.classifications.drop()
        #*** Create the classifications collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.classifications = db_nmeta.create_collection('classifications',
                                   capped=True, size=classifications_max_bytes)
        #*** Index flow_hash and classification_time of classifications
        #***  collection to improve look-up performance:

        #*** Index classifications to improve look-up performance:
        self.classifications.create_index([('flow_hash', pymongo.DESCENDING),
                                ('classification_time', pymongo.DESCENDING)],
                                unique=False)

        #*** flow_rems collection for recording flow removals:
        self.logger.debug("Deleting flow_rems MongoDB collection...")
        db_nmeta.flow_rems.drop()
        #*** Create the flow_rems collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.flow_rems = db_nmeta.create_collection('flow_rems',
                                   capped=True, size=flow_rems_max_bytes)
        #*** Note: don't index flow_rems collection as we don't read it

        #*** flow_mods collection:
        self.logger.debug("Deleting flow_mods MongoDB collection...")
        db_nmeta.flow_mods.drop()
        #*** Create the flow_mods collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.flow_mods = db_nmeta.create_collection('flow_mods',
                                   capped=True, size=flow_mods_max_bytes)
        #*** Index flow_mods to improve look-up performance:
        self.flow_mods.create_index([('flow_hash', pymongo.DESCENDING),
                                ('dpid', pymongo.DESCENDING),
                                ('timestamp', pymongo.DESCENDING),
                                ('suppression_type', pymongo.DESCENDING),
                                ('standdown', pymongo.DESCENDING)],
                                unique=False)

    class Packet(object):
        """
        An object that represents the current packet
        """
        def __init__(self):
            #*** Initialise packet variables:
            self.flow_hash = 0
            self.dpid = 0
            self.in_port = 0
            self.timestamp = 0
            self.length = 0
            self.eth_src = 0
            self.eth_dst = 0
            self.eth_type = 0
            self.ip_src = 0
            self.ip_dst = 0
            self.proto = 0
            self.tp_src = 0
            self.tp_dst = 0
            self.tp_flags = 0
            self.tp_seq_src = 0
            self.tp_seq_dst = 0
            self.payload = ""

        def dbdict(self):
            """
            Return a dictionary object of metadata
            parameters of current packet (excludes payload),
            for storing in database
            """
            dbdictresult = {}
            dbdictresult['flow_hash'] = self.flow_hash
            dbdictresult['dpid'] = self.dpid
            dbdictresult['in_port'] = self.in_port
            dbdictresult['timestamp'] = self.timestamp
            dbdictresult['length'] = self.length
            dbdictresult['eth_src'] = self.eth_src
            dbdictresult['eth_dst'] = self.eth_dst
            dbdictresult['eth_type'] = self.eth_type
            dbdictresult['ip_src'] = self.ip_src
            dbdictresult['ip_dst'] = self.ip_dst
            dbdictresult['proto'] = self.proto
            dbdictresult['tp_src'] = self.tp_src
            dbdictresult['tp_dst'] = self.tp_dst
            dbdictresult['tp_flags'] = self.tp_flags
            dbdictresult['tp_seq_src'] = self.tp_seq_src
            dbdictresult['tp_seq_dst'] = self.tp_seq_dst
            return dbdictresult

        def tcp_fin(self):
            """
            Does the current packet have the TCP FIN flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_FIN != 0

        def tcp_syn(self):
            """
            Does the current packet have the TCP SYN flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_SYN != 0

        def tcp_rst(self):
            """
            Does the current packet have the TCP RST flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_RST != 0

        def tcp_psh(self):
            """
            Does the current packet have the TCP PSH flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_PUSH != 0

        def tcp_ack(self):
            """
            Does the current packet have the TCP ACK flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_ACK != 0

        def tcp_urg(self):
            """
            Does the current packet have the TCP URG flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_URG != 0

        def tcp_ece(self):
            """
            Does the current packet have the TCP ECE flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_ECE != 0

        def tcp_cwr(self):
            """
            Does the current packet have the TCP CWR flag set?
            """
            return self.tp_flags & dpkt.tcp.TH_CWR != 0

    class Classification(object):
        """
        An object that represents an individual traffic classification
        """
        def __init__(self, flow_hash, clsfn, time_limit, logger):
            """
            Retrieve classification data from MongoDB collection for a
            particular flow hash within a time range.
            time range is from current time backwards by number of seconds
            defined in config for classification_time_limit

            Setting test returns database query execution statistics
            """
            #*** Initialise classification variables:
            self.flow_hash = flow_hash
            self.classified = 0
            self.classification_tag = ""
            self.classification_time = 0
            self.actions = {}
            self.clsfn = clsfn
            self.time_limit = time_limit
            self.logger = logger

            #*** Put into context of current flow by querying
            #*** classifications database collection:
            db_data = {'flow_hash': self.flow_hash}
            #*** Filter to only recent classifications:
            db_data['classification_time'] = {'$gte': datetime.datetime.now()-
                                                               self.time_limit}
            #*** Run db search:
            result = self.clsfn.find(db_data).sort('classification_time', -1) \
                                                                      .limit(1)
            self.logger.debug("result.count=%s", result.count())
            if result.count():
                #*** We have classification data for this flow:
                result0 = list(result)[0]
                #*** copy db result to flow classification state variables:
                if 'classified' in result0:
                    self.classified = result0['classified']
                if 'classification_tag' in result0:
                    self.classification_tag = result0['classification_tag']
                if 'classification_time' in result0:
                    self.classification_time = result0['classification_time']
                if 'actions' in result0:
                    self.actions = result0['actions']

        def test_query(self):
            """
            Return database query execution statistics
            """
            db_data = {'flow_hash': self.flow_hash}
            #*** Filter to only recent classifications:
            db_data['classification_time'] = {'$gte': datetime.datetime.now()-
                                                               self.time_limit}
            #*** Run db search with explain:
            return self.clsfn.find(db_data).sort('classification_time', -1) \
                                                    .limit(1).explain()

        def dbdict(self):
            """
            Return a dictionary object of traffic classification
            parameters for storing in the database
            """
            dbdictresult = {}
            dbdictresult['flow_hash'] = self.flow_hash
            dbdictresult['classified'] = self.classified
            dbdictresult['classification_tag'] = self.classification_tag
            dbdictresult['classification_time'] = self.classification_time
            dbdictresult['actions'] = self.actions
            return dbdictresult

        def commit(self):
            """
            Record current state of flow classification into MongoDB
            classifications collection.
            """
            self.classification_time = datetime.datetime.now()
            db_dict = self.dbdict()
            #*** Write classification to database collection:
            self.clsfn.insert_one(db_dict)

    class RemovedFlow(object):
        """
        An object that represents an individual removed flow.
        This is a flow that a switch has informed us it has
        removed from its flow table because of an idle timeout
        """
        def __init__(self, logger, flow_rems, msg):
            """
            Initialise the class with logger and flow_rems db
            collection. Initialise removed flow parameters to values
            in the message
            """
            match = msg.match
            self.logger = logger
            self.flow_rems = flow_rems
            #*** Initialise removed flow parameters:
            self.dpid = msg.datapath.id
            self.removal_time = datetime.datetime.now()
            self.cookie = msg.cookie
            self.priority = msg.priority
            self.reason = msg.reason
            self.table_id = msg.table_id
            self.duration_sec = msg.duration_sec
            self.idle_timeout = msg.idle_timeout
            self.hard_timeout = msg.hard_timeout
            self.packet_count = msg.packet_count
            self.byte_count = msg.byte_count
            self.eth_A = ""
            self.eth_B = ""
            self.eth_type = ""
            self.ip_A = ""
            self.ip_B = ""
            self.ip_proto = ""
            self.tp_A = ""
            self.tp_B = ""
            #*** Set values from the match where they exist:
            if 'eth_src' in match:
                self.eth_A = match['eth_src']
            if 'eth_dst' in match:
                self.eth_B = match['eth_dst']
            if 'eth_type' in match:
                self.eth_type = match['eth_type']
            if 'ipv4_src' in match:
                self.ip_A = match['ipv4_src']
            if 'ipv4_dst' in match:
                self.ip_B = match['ipv4_dst']
            if 'ipv6_src' in match:
                self.ip_A = match['ipv6_src']
            if 'ipv6_dst' in match:
                self.ip_B = match['ipv6_dst']
            if 'ip_proto' in match:
                self.ip_proto = match['ip_proto']
            if 'tcp_src' in match:
                self.tp_A = match['tcp_src']
            if 'tcp_dst' in match:
                self.tp_B = match['tcp_dst']
            #*** Set flow hash:
            if self.ip_proto == 6:
                self.flow_hash = nethash.hash_flow((self.ip_A, self.ip_B,
                                          self.tp_A, self.tp_B,
                                          self.ip_proto))
            else:
                self.flow_hash = nethash.hash_flow((self.eth_A, self.eth_B,
                                          self.dpid, self.removal_time,
                                          self.ip_proto))

        def dbdict(self):
            """
            Return a dictionary object of parameters
            from the removed flow for storing in the flow_rems
            database collection
            """
            dbdictresult = {}
            dbdictresult['dpid'] = self.dpid
            dbdictresult['removal_time'] = self.removal_time
            dbdictresult['cookie'] = self.cookie
            dbdictresult['priority'] = self.priority
            dbdictresult['reason'] = self.reason
            dbdictresult['table_id'] = self.table_id
            dbdictresult['duration_sec'] = self.duration_sec
            dbdictresult['idle_timeout'] = self.idle_timeout
            dbdictresult['hard_timeout'] = self.hard_timeout
            dbdictresult['packet_count'] = self.packet_count
            dbdictresult['byte_count'] = self.byte_count
            dbdictresult['eth_A'] = self.eth_A
            dbdictresult['eth_B'] = self.eth_B
            dbdictresult['eth_type'] = self.eth_type
            dbdictresult['ip_A'] = self.ip_A
            dbdictresult['ip_B'] = self.ip_B
            dbdictresult['ip_proto'] = self.ip_proto
            dbdictresult['tp_A'] = self.tp_A
            dbdictresult['tp_B'] = self.tp_B
            dbdictresult['flow_hash'] = self.flow_hash
            return dbdictresult

        def commit(self):
            """
            Record removed flow into MongoDB
            flow_rems collection.
            """
            self.logger.debug("Writing flow removal to database")
            #*** Write to database collection:
            self.flow_rems.insert_one(self.dbdict())

    def record_removal(self, msg):
        """
        Record an idle-timeout flow removal message.
        Passed a Ryu message object for the flow removal.
        Record entry in the flow_rems database collection
        """
        #*** Instantiate class to hold removed flow record:
        remf = self.RemovedFlow(self.logger, self.flow_rems, msg)
        #*** Decide what to record based on the match:
        match = msg.match
        if 'ip_proto' in match:
            if match['ip_proto'] == 6:
                #*** TCP. Write record to database:
                self.logger.debug("Removed flow was TCP, dbdict=%s",
                                                             remf.dbdict())
                remf.commit()
                return 1
            else:
                #*** Non-TCP IP flow
                self.logger.debug("Removed flow was non-TCP, dbdict=%s",
                                                             remf.dbdict())
                remf.commit()
                return 1
        else:
            self.logger.info("match has eth_type=%s", match['eth_type'])
            if match['eth_type'] == 2048:
                #*** IPv4:
                self.logger.debug("Removed flow was IPv4 unknown protocol")
                # TBD

            elif match['eth_type'] == 34525:
                #*** IPv6:
                self.logger.debug("Removed flow was IPv6 unknown protocol")
                # TBD

            else:
                self.logger.warning("Removed flow was unhandled eth_type")
                return 0

    def ingest_packet(self, dpid, in_port, packet, timestamp):
        """
        Ingest a packet into the packet_ins collection and put the flow object
        into the context of the packet.
        Note that timestamp MUST be in datetime format
        """
        #*** Instantiate an instance of Packet class:
        self.packet = self.Packet()
        pkt = self.packet

        #*** DPID of the switch that sent the Packet-In message:
        pkt.dpid = dpid
        #*** Port packet was received on:
        pkt.in_port = in_port
        #*** Packet receive time:
        pkt.timestamp = timestamp
        #*** Packet length on the wire:
        pkt.length = len(packet)

        #*** Read packet into dpkt to parse headers:
        eth = dpkt.ethernet.Ethernet(packet)

        #*** Ethernet parameters:
        pkt.eth_src = _mac_addr(eth.src)
        pkt.eth_dst = _mac_addr(eth.dst)
        pkt.eth_type = eth.type

        if eth.type == 2048:
            #*** IPv4 (TBD: add IPv6 support)
            ip = eth.data
            pkt.ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
            pkt.ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
            pkt.proto = ip.p
            if ip.p == 6:
                #*** TCP
                tcp = ip.data
                pkt.tp_src = tcp.sport
                pkt.tp_dst = tcp.dport
                pkt.tp_flags = tcp.flags
                pkt.tp_seq_src = tcp.seq
                pkt.tp_seq_dst = tcp.ack
                pkt.payload = tcp.data
            elif ip.p == 17:
                #*** UDP
                udp = ip.data
                pkt.tp_src = udp.sport
                pkt.tp_dst = udp.dport
                pkt.tp_flags = ""
                pkt.tp_seq_src = 0
                pkt.tp_seq_dst = 0
                pkt.payload = udp.data
            else:
                #*** Not a transport layer that we understand:
                # TBD: add other transport protocols
                pkt.tp_src = 0
                pkt.tp_dst = 0
                pkt.tp_flags = 0
                pkt.tp_seq_src = 0
                pkt.tp_seq_dst = 0
                pkt.payload = ip.data
        else:
            #*** Non-IP:
            pkt.ip_src = ''
            pkt.ip_dst = ''
            pkt.proto = 0
            pkt.tp_src = 0
            pkt.tp_dst = 0
            pkt.tp_flags = 0
            pkt.tp_seq_src = 0
            pkt.tp_seq_dst = 0
            pkt.payload = eth.data

        #*** Generate a flow_hash unique to flow for pkts in either direction:
        if pkt.proto == 6:
            self.packet.flow_hash = nethash.hash_flow((pkt.ip_src, pkt.ip_dst,
                                          pkt.tp_src, pkt.tp_dst,
                                          pkt.proto))
        else:
            self.packet.flow_hash = nethash.hash_flow((pkt.eth_src, pkt.eth_dst,
                                          dpid, pkt.timestamp,
                                          pkt.proto))
        self.flow_hash = self.packet.flow_hash

        #*** Generate a packet_hash unique to the packet:
        self.packet.packet_hash = nethash.hash_packet(self.packet)

        #*** Instantiate classification data for this flow in context:
        self.classification = self.Classification(self.flow_hash,
                                                self.classifications,
                                                self.classification_time_limit,
                                                self.logger)
        self.logger.debug("clasfn=%s", self.classification.dbdict())
        db_dict = self.packet.dbdict()
        self.logger.debug("packet_in=%s", db_dict)

        #*** Write packet-in metadata to database collection:
        self.packet_ins.insert_one(db_dict)

    def packet_count(self, test=0):
        """
        Return the number of packets in the flow (counting packets in
        both directions). This method should deduplicate for where the
        same packet is received from multiple switches, but is TBD...

        Works by retrieving packets from packet_ins database with
        current packet flow_hash and within flow reuse time limit.

        Setting test=1 returns database query execution statistics
        """
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        if not test:
            packet_cursor = self.packet_ins.find(db_data).sort('timestamp', -1)
        else:
            return self.packet_ins.find(db_data).sort('timestamp', -1).explain()
        self.logger.debug("packet_cursor.count()=%s", packet_cursor.count())
        return packet_cursor.count()

    def packet_direction(self):
        """
        Return the direction of the current packet in the flow
        where c2s is client to server and s2c is server to client.
        """
        flow_client = self.client()
        if self.packet.ip_src == flow_client:
            return 'c2s'
        else:
            return 's2c'

    def client(self):
        """
        The IP that is the originator of the flow (if known,
        otherwise 0)

        Finds first packet seen for the flow_hash within the time limit
        and returns the source IP
        """
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        packets = self.packet_ins.find(db_data).sort('timestamp', 1).limit(1)
        if packets.count():
            return list(packets)[0]['ip_src']
        else:
            self.logger.warning("no packets found")
            return 0

    def server(self):
        """
        The IP that is the destination of the flow (if known,
        otherwise 0)

        Finds first packet seen for the hash within the time limit
        and returns the destination IP
        """
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        packets = self.packet_ins.find(db_data).sort('timestamp', 1).limit(1)
        if packets.count():
            return list(packets)[0]['ip_dst']
        else:
            self.logger.warning("no packets found")
            return 0

    def max_packet_size(self):
        """
        Return the size of the largest packet in the flow (in either direction)
        """
        max_packet_size = 0
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        packet_cursor = self.packet_ins.find(db_data).sort('timestamp', -1)
        if packet_cursor.count():
            for pkt in packet_cursor:
                if pkt['length'] > max_packet_size:
                    max_packet_size = pkt['length']
        return max_packet_size

    def max_interpacket_interval(self):
        """
        Return the size of the largest inter-packet time interval
        in the flow (assessed per direction in flow) as seconds
        (type float)

        Note:
        c2s = client to server direction
        s2c = server to client direction

        Note: results are slightly inaccurate due to floating point
        rounding.
        """
        max_c2s = datetime.timedelta()
        max_s2c = datetime.timedelta()
        count_c2s = 0
        count_s2c = 0
        prev_c2s_ts = 0
        prev_s2c_ts = 0
        #*** Do this once, as is DB call:
        flow_client = self.client()
        #*** Database lookup for whole flow:
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        packet_cursor = self.packet_ins.find(db_data).sort('timestamp', 1)
        #*** Iterate forward through packets in flow:
        if packet_cursor.count():
            for pkt in packet_cursor:
                if pkt['ip_src'] == flow_client:
                    #*** c2s:
                    count_c2s += 1
                    if count_c2s > 1:
                        delta = pkt['timestamp'] - prev_c2s_ts
                        if delta > max_c2s:
                            max_c2s = delta
                    prev_c2s_ts = pkt['timestamp']
                elif pkt['ip_dst'] == flow_client:
                    #*** s2c:
                    count_s2c += 1
                    if count_s2c > 1:
                        delta = pkt['timestamp'] - prev_s2c_ts
                        if delta > max_s2c:
                            max_s2c = delta
                    prev_s2c_ts = pkt['timestamp']
                else:
                    #*** Don't know direction so ignore:
                    pass
        #*** Return the largest interpacket delay overall:
        if max_c2s > max_s2c:
            return max_c2s.total_seconds()
        else:
            return max_s2c.total_seconds()

    def min_interpacket_interval(self):
        """
        Return the size of the smallest inter-packet time interval
        in the flow (assessed per direction in flow) as seconds
        (type float)

        Note:
        c2s = client to server direction
        s2c = server to client direction

        Note: results are slightly inaccurate due to floating point
        rounding.
        """
        min_c2s = datetime.timedelta()
        min_s2c = datetime.timedelta()
        count_c2s = 0
        count_s2c = 0
        prev_c2s_ts = 0
        prev_s2c_ts = 0
        #*** Do this once, as is DB call:
        flow_client = self.client()
        #*** Database lookup for whole flow:
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        packet_cursor = self.packet_ins.find(db_data).sort('timestamp', 1)
        #*** Iterate forward through packets in flow:
        if packet_cursor.count():
            for pkt in packet_cursor:
                if pkt['ip_src'] == flow_client:
                    #*** c2s:
                    count_c2s += 1
                    if count_c2s > 1:
                        delta = pkt['timestamp'] - prev_c2s_ts
                        if not min_c2s or delta < min_c2s:
                            min_c2s = delta
                    prev_c2s_ts = pkt['timestamp']
                elif pkt['ip_dst'] == flow_client:
                    #*** s2c:
                    count_s2c += 1
                    if count_s2c > 1:
                        delta = pkt['timestamp'] - prev_s2c_ts
                        if not min_c2s or delta < min_c2s:
                            min_c2s = delta
                    prev_s2c_ts = pkt['timestamp']
                else:
                    #*** Don't know direction so ignore:
                    pass
        #*** Return the smallest interpacket delay overall, watch out for
        #***  where we didn't get a calculation (don't return 0 unless both 0):
        if not min_s2c:
            #*** min_s2c not set so return min_c2s as it might be:
            return min_c2s.total_seconds()
        elif 0 < min_c2s < min_s2c:
            return min_c2s.total_seconds()
        else:
            return min_s2c.total_seconds()

    def not_suppressed(self, dpid, suppression_type):
        """
        Check flow_mods to see if current flow context is already
        suppressed within suppression stand-down time for that switch,
        and if it is then return False, otherwise True

        The stand-down time is to reduce risk of overloading switch
        with duplicate suppression events.

        Called from nmeta.py
        """
        #*** Database lookup for whole flow:
        db_data = {'flow_hash': self.packet.flow_hash,
                    'dpid': dpid,
                    'timestamp': {'$gte': datetime.datetime.now() - \
                                                FLOW_SUPPRESSION_STANDDOWN},
                    'suppression_type': suppression_type,
                    'standdown': 0}

        #*** Check if already suppressed with-in stand-down time period:
        if self.flow_mods.find_one(db_data):
            #*** There has been a suppression for this flow_hash within
            #*** Stand down period
            self.logger.debug("flow=%s already recorded as suppressed on "
                                "dpid=%s", self.packet.flow_hash, dpid)
            return False
        else:
            return True

    class FlowMod(object):
        """
        An object that represents an individual Flow Modification,
        used for recording the circumstances into the
        flow_mods MongoDB collection
        """
        def __init__(self, flow_mods, flow_hash, dpid, _type, standdown):
            #*** Initialise variables:
            self.flow_mods = flow_mods
            self.flow_hash = flow_hash
            #*** Timestamp of when flow mod made:
            self.timestamp = datetime.datetime.now()
            self.dpid = dpid
            #*** suppression_type is 'forward' or 'drop':
            self.suppression_type = _type
            #*** If set, flow_mod was not sent due to stand down period:
            self.standdown = standdown
            #*** Match type set by switches module (ignore|single|dual)
            #***  ignore means no mod, dual had forward and reverse mods:
            self.match_type = ""
            #*** Cookie for forward flow mod:
            self.forward_cookie = 0
            #*** Match dict set by switches module for forward flow:
            self.forward_match = {}
            #*** Cookie for reverse flow mod:
            self.reverse_cookie = 0
            #*** Match dict set by switches module for reverse flow:
            self.reverse_match = {}

        def dbdict(self):
            """
            Return a dictionary object of specific FlowMod
            parameters for storing in the database
            """
            dbdictresult = {}
            dbdictresult['flow_hash'] = self.flow_hash
            dbdictresult['timestamp'] = self.timestamp
            dbdictresult['dpid'] = self.dpid
            dbdictresult['suppression_type'] = self.suppression_type
            dbdictresult['standdown'] = self.standdown
            dbdictresult['match_type'] = self.match_type
            dbdictresult['forward_cookie'] = self.forward_cookie
            dbdictresult['forward_match'] = self.forward_match
            dbdictresult['reverse_cookie'] = self.reverse_cookie
            dbdictresult['reverse_match'] = self.reverse_match
            return dbdictresult

        def commit(self):
            """
            Record removed mod into MongoDB
            flow_mods collection.
            """
            #*** Write to database collection:
            self.flow_mods.insert_one(self.dbdict())

    def record_suppression(self, dpid, suppression_type, result, standdown=0):
        """
        Record that the flow is being suppressed on a particular
        switch in the flow_mods database collection, so that information
        is available to API consumers, such as the WebUI
        """
        #*** Instantiate a new instance of FlowMod class:
        flow_mod_record = self.FlowMod(self.flow_mods, self.packet.flow_hash,
                                dpid, suppression_type, standdown)
        if not standdown:
            #*** Add values from switches module suppress or drop flow result:
            flow_mod_record.match_type = result['match_type']
            flow_mod_record.forward_cookie = result['forward_cookie']
            flow_mod_record.forward_match = result['forward_match']
            flow_mod_record.reverse_cookie = result['reverse_cookie']
            flow_mod_record.reverse_match = result['reverse_match']

        self.logger.debug("Recording suppression of flow=%s on "
                                "dpid=%s", self.packet.flow_hash, dpid)
        flow_mod_record.commit()

#================== PRIVATE FUNCTIONS ==================

def _is_tcp_syn(tcp_flags):
    """
    Passed a TCP flags object (hex) and return 1 if it
    contains a TCP SYN and no other flags
    """
    if tcp_flags == 2:
        return 1
    else:
        return 0

def _is_tcp_synack(tcp_flags):
    """
    Passed a TCP flags object (hex) and return 1 if it
    contains TCP SYN + ACK flags and no other flags
    """
    if tcp_flags == 0x12:
        return 1
    else:
        return 0

def _mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)

