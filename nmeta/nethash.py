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
The nethash module is part of the nmeta suite

It provides functions for hashing packets and flows to
unique identifiers
"""

#*** For hashing flow 5-tuples:
import hashlib

def hash_flow(flow_5_tuple):
    """
    Generate a predictable flow_hash for the 5-tuple. For TCP
    the hash is the same no matter which direction the traffic is
    travelling for all packets that are part of that flow.

    Pass this function a 5-tuple.

    For TCP, this tuple should be:
    (ip_src, ip_dst, tp_src, tp_dst, ip_proto)

    For other IP packets, the tuple should be:
    (eth_src, eth_dst, dpid, packet_timestamp, ip_proto)

    For non-IP packets, the tuple should be:
    (eth_src, eth_dst, dpid, packet_timestamp, 0)
    """
    ip_A = flow_5_tuple[0]
    ip_B = flow_5_tuple[1]
    tp_src = flow_5_tuple[2]
    tp_dst = flow_5_tuple[3]
    proto = flow_5_tuple[4]
    if proto == 6:
        #*** Is a TCP flow:
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
        #*** Isn't a flow, so arbitrarily set direction as 1:
        direction = 1
    if direction == 1:
        flow_tuple = (ip_A, ip_B, tp_src, tp_dst, proto)
    else:
        #*** Flip direction:
        flow_tuple = (ip_B, ip_A, tp_dst, tp_src, proto)
    return hash_tuple(flow_tuple)

def hash_packet(packet):
    """
    Generate a hash of flows packet object for use in deduplication
    where the same packet is received from multiple switches.

    Retransmissions of a packet that is part of a flow should have
    same hash value, so that retransmissions can be measured.

    The packet hash is a unique unidirectional packet identifier

    For TCP packets, the hash is derived from:
      ip_src, ip_dst, proto, tp_src, tp_dst, tp_seq_src, tp_seq_dst

    For non-flow packets, the hash is derived from:
      eth_src, eth_dst, eth_type, dpid, timestamp
    """
    if packet.proto == 6:
        #*** Is TCP:
        packet_tuple = (packet.ip_src,
                    packet.ip_dst,
                    packet.proto,
                    packet.tp_src,
                    packet.tp_dst,
                    packet.tp_seq_src,
                    packet.tp_seq_dst)
    else:
        #*** Isn't a flow, so make hash unique to packet by including
        #*** the DPID and timestamp in the hash:
        packet_tuple = (packet.eth_src,
                    packet.eth_dst,
                    packet.eth_type,
                    packet.dpid,
                    packet.timestamp)
    return hash_tuple(packet_tuple)

def hash_tuple(hash_tuple):
    """
    Simple function to hash a tuple with MD5.
    Returns a hash value for the tuple
    """
    hash_result = hashlib.md5()
    tuple_as_string = str(hash_tuple)
    hash_result.update(tuple_as_string)
    return hash_result.hexdigest()
