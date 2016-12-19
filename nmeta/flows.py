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

#*** For hashing flow 5-tuples:
import hashlib

#*** For timestamps:
import datetime

#*** For logging configuration:
from baseclass import BaseClass

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
        #*** Run the BaseClass init to set things up:
        super(Flow, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("flows_logging_level_s",
                                       "flows_logging_level_c")
        #*** Get parameters from config:
        mongo_addr = config.get_value("mongo_addr")
        mongo_port = config.get_value("mongo_port")
        mongo_dbname = self.config.get_value("mongo_dbname")
        #*** Max bytes of the capped collections:
        packet_ins_max_bytes = config.get_value("packet_ins_max_bytes")
        classifications_max_bytes = \
                                  config.get_value("classifications_max_bytes")
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
        #*** Delete (drop) previous packet_ins collection if it exists:
        self.logger.debug("Deleting previous packet_ins MongoDB collection...")
        db_nmeta.packet_ins.drop()

        #*** Create the packet_ins collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.packet_ins = db_nmeta.create_collection('packet_ins', capped=True,
                                            size=packet_ins_max_bytes)

        #*** Index flow_hash key of packet_ins collection to
        #*** improve look-up performance:
        self.packet_ins.create_index([('flow_hash', pymongo.TEXT)],
                                                                unique=False)

        #*** classifications collection:
        #*** Delete (drop) previous classifications collection if it exists:
        self.logger.debug("Deleting previous classifications MongoDB "
                                                               "collection...")
        db_nmeta.classifications.drop()

        #*** Create the classifications collection, specifying capped option
        #*** with max size in bytes, so MongoDB handles data retention:
        self.classifications = db_nmeta.create_collection('classifications',
                                   capped=True, size=classifications_max_bytes)

        #*** Index flow_hash key of classifications collection to
        #*** improve look-up performance:
        self.classifications.create_index([('flow_hash', pymongo.TEXT)],
                                                                unique=False)

        self.flow_hash = 0

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
        def __init__(self, flow_hash, clsfn, time_limit):
            """
            Retrieve classification data from MongoDB collection for a
            particular flow hash within a time range.
            time range is from current time backwards by number of seconds
            defined in config for classification_time_limit
            """
            #*** Initialise classification variables:
            self.flow_hash = flow_hash
            self.classified = 0
            self.classification_tag = ""
            self.classification_time = 0
            self.actions = {}

            #*** Put into context of current flow by querying
            #*** classifications database collection:
            db_data = {'flow_hash': self.flow_hash}
            #*** Filter to only recent classifications:
            db_data['classification_time'] = {'$gte': datetime.datetime.now()-
                                                time_limit}
            #*** Run db search:
            result = clsfn.find(db_data).sort('$natural', -1).limit(1)
            if result.count():
                #*** We have classification data for this flow:
                result0 = list(result)[0]
                #*** copy db result to flow classification state variables:
                if 'classified' in result0:
                    self.classified = result0['classified']
                if 'classification_tag' in result0:
                    self.classified = result0['classification_tag']
                if 'classification_time' in result0:
                    self.classified = result0['classification_time']
                if 'actions' in result0:
                    self.classified = result0['actions']

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
            db_dict = self.classification.dbdict()
            self.logger.debug("classification=%s", db_dict)
            #*** Write classification to database collection:
            self.classifications.insert_one(db_dict)

    def ingest_packet(self, dpid, in_port, pkt, timestamp):
        """
        Ingest a packet into the packet_ins collection and put the flow object
        into the context of the packet.
        Note that timestamp MUST be in datetime format
        """
        #*** Instantiate an instance of Packet class:
        self.packet = self.Packet()

        #*** DPID of the switch that sent the Packet-In message:
        self.packet.dpid = dpid
        #*** Port packet was received on:
        self.packet.in_port = in_port
        #*** Packet receive time:
        self.packet.timestamp = timestamp
        #*** Packet length on the wire:
        self.packet.length = len(pkt)

        #*** Read packet into dpkt to parse headers:
        eth = dpkt.ethernet.Ethernet(pkt)

        #*** Ethernet parameters:
        self.packet.eth_src = _mac_addr(eth.src)
        self.packet.eth_dst = _mac_addr(eth.dst)
        self.packet.eth_type = eth.type

        if eth.type == 2048:
            #*** IPv4 (TBD: add IPv6 support)
            ip = eth.data
            self.packet.ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
            self.packet.ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
            self.packet.proto = ip.p
            if ip.p == 6:
                #*** TCP
                tcp = ip.data
                self.packet.tp_src = tcp.sport
                self.packet.tp_dst = tcp.dport
                self.packet.tp_flags = tcp.flags
                self.packet.tp_seq_src = tcp.seq
                self.packet.tp_seq_dst = tcp.ack
                self.packet.payload = tcp.data
            elif ip.p == 17:
                #*** UDP
                udp = ip.data
                self.packet.tp_src = udp.sport
                self.packet.tp_dst = udp.dport
                self.packet.tp_flags = ""
                self.packet.tp_seq_src = 0
                self.packet.tp_seq_dst = 0
                self.packet.payload = udp.data
            else:
                #*** Not a transport layer that we understand:
                # TBD: add other transport protocols
                self.packet.tp_src = 0
                self.packet.tp_dst = 0
                self.packet.tp_flags = 0
                self.packet.tp_seq_src = 0
                self.packet.tp_seq_dst = 0
                self.packet.payload = ip.data
        else:
            #*** Non-IP:
            self.packet.ip_src = ''
            self.packet.ip_dst = ''
            self.packet.proto = 0
            self.packet.tp_src = 0
            self.packet.tp_dst = 0
            self.packet.tp_flags = 0
            self.packet.tp_seq_src = 0
            self.packet.tp_seq_dst = 0
            self.packet.payload = eth.data

        #*** Generate a flow_hash unique to flow for pkts in either direction:
        self.packet.flow_hash = self._hash_flow()
        self.flow_hash = self.packet.flow_hash

        #*** Generate a packet_hash unique to the packet:
        self.packet.packet_hash = self._hash_packet()

        #*** Instantiate classification data for this flow in context:
        self.classification = self.Classification(self.flow_hash,
                                                self.classifications,
                                                self.classification_time_limit)

        db_dict = self.packet.dbdict()
        self.logger.debug("packet_in=%s", db_dict)

        #*** Write packet-in metadata to database collection:
        self.packet_ins.insert_one(db_dict)

    def packet_count(self):
        """
        Return the number of packets in the flow (counting packets in
        both directions). This method should deduplicate for where the
        same packet is received from multiple switches, but is TBD...

        Works by retrieving packets from packet_ins database with
        current packet flow_hash and within flow reuse time limit.
        """
        db_data = {'flow_hash': self.packet.flow_hash,
              'timestamp': {'$gte': datetime.datetime.now() - \
                                                self.flow_time_limit}}
        packet_cursor = self.packet_ins.find(db_data).sort('$natural', -1)
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
        packets = self.packet_ins.find(db_data).sort('$natural', 1).limit(1)
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
        packets = self.packet_ins.find(db_data).sort('$natural', 1).limit(1)
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
        packet_cursor = self.packet_ins.find(db_data).sort('$natural', -1)
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
        packet_cursor = self.packet_ins.find(db_data).sort('$natural', 1)
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
        packet_cursor = self.packet_ins.find(db_data).sort('$natural', 1)
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

    def suppress_flow(self):
        """
        Set the suppressed attribute in the flow database
        object to the current packet count so that future
        suppressions of the same flow can be backed off
        to prevent overwhelming the controller
        """
        #TBD
        pass

    def _hash_flow(self):
        """
        Generate a predictable flow_hash for the 5-tuple which is the
        same not matter which direction the traffic is travelling
        for packets that are part of a flow.

        For packets that we don't understand as a flow, create a hash
        that is unique to the packet to avoid retrieving unrelated
        packets
        """
        proto = self.packet.proto
        if proto == 6:
            #*** Is a flow (TBD, do UDP):
            ip_A = self.packet.ip_src
            ip_B = self.packet.ip_dst
            tp_src = self.packet.tp_src
            tp_dst = self.packet.tp_dst
            if ip_A > ip_B:
                direction = 1
            elif ip_B > ip_A:
                direction = 2
            elif tp_src > tp_dst:
                direction = 1
            elif tp_dst > tp_src:
                direction = 2
            else:
                direction = 1
        else:
            #*** Isn't a flow, so make hash unique to packet by including
            #*** the DPID and timestamp in the hash:
            ip_A = self.packet.eth_src
            ip_B = self.packet.eth_dst
            tp_src = self.packet.dpid
            tp_dst = self.packet.timestamp
            direction = 1

        hash_5t = hashlib.md5()
        if direction == 1:
            flow_tuple = (ip_A, ip_B, tp_src, tp_dst, proto)
        else:
            flow_tuple = (ip_B, ip_A, tp_dst, tp_src, proto)
        flow_tuple_as_string = str(flow_tuple)
        hash_5t.update(flow_tuple_as_string)
        return hash_5t.hexdigest()

    def _hash_packet(self):
        """
        Generate a hash of the current packet used for deduplication
        where the same packet is received from multiple switches.

        Retransmissions of a packet that is part of a flow should have
        same hash value, so that retransmissions can be measured.

        The packet hash is an indexed uni-directionally packet identifier

        For flow-packets, the hash is derived from:
          ip_src, ip_dst, proto, tp_src, tp_dst, tp_seq_src, tp_seq_dst

        For non-flow packets, the hash is derived from:
          eth_src, eth_dst, eth_type, dpid, timestamp
        """
        hash_result = hashlib.md5()
        if self.packet.proto == 6:
            #*** Is a flow (TBD, do UDP):
            packet_tuple = (self.packet.ip_src,
                        self.packet.ip_dst,
                        self.packet.proto,
                        self.packet.tp_src,
                        self.packet.tp_dst,
                        self.packet.tp_seq_src,
                        self.packet.tp_seq_dst)
        else:
            #*** Isn't a flow, so make hash unique to packet by including
            #*** the DPID and timestamp in the hash:
            packet_tuple = (self.packet.eth_src,
                        self.packet.eth_dst,
                        self.packet.eth_type,
                        self.packet.dpid,
                        self.packet.timestamp)
        packet_tuple_as_string = str(packet_tuple)
        hash_result.update(packet_tuple_as_string)
        return hash_result.hexdigest()

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
