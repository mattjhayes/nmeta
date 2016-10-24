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
Packets with metadata to use in testing of nmeta suite

This file is a set of DNS packets

    Note: no testing of max_interpacket_interval and
    min_interpacket_interval as they become imprecise due
    to floating point and when tried using decimal module
    found that would not serialise into Pymongo db.

    To create test packet data, capture packet in Wireshark and:

      For the packet summary:
        Right-click packet in top pane, Copy -> Summary (text).
        Edit pasted text as appropriate

      For the packet hex:
        Right-click packet in top pane, Copy -> Bytes -> Hex Stream

      For the packet timestamp:
        Expand 'Frame' in the middle pane,
        right-click 'Epoch Time' Copy -> Value

Packet capture file is 'packets_ipv4_DNS.pcap'
"""

import binascii

#*** Raw packet data:
RAW = []
#*** Packet on the wire lengths in bytes:
LEN = []
#*** Ethernet parameters:
ETH_SRC = []
ETH_DST = []
ETH_TYPE = []
#*** IP addresses:
IP_SRC = []
IP_DST = []
#*** IP protocol number in decimal:
PROTO = []
#*** Transport-layer protocol numbers in decimal:
TP_SRC = []
TP_DST = []
#*** Transport-layer sequence numbers in decimal:
TP_SEQ_SRC = []
TP_SEQ_DST = []
#*** TCP FLAGS:
TCP_SYN = []
TCP_FIN = []
TCP_RST = []
TCP_PSH = []
TCP_ACK = []
#*** HEX-encoded payload
PAYLOAD = []
#*** Packet direction, c2s (client to server) or s2c
DIRECTION = []
#*** DNS specific:
# TBD


#*** Packet 1 - DNS Query A www.facebook.com
# 76 10.0.2.15 208.67.220.123 DNS Standard query 0x24e8 A www.facebook.com
RAW.append(binascii.unhexlify("5254001235020800278308f008004500003ea14c40004011e0940a00020fd043dc7b1ad20035002a10dd24e801000001000000000000037777770866616365626f6f6b03636f6d0000010001"))
LEN.append(76)
ETH_SRC.append('08:00:27:83:08:f0')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('208.67.220.123')
PROTO.append(17)
TP_SRC.append(6866)
TP_DST.append(53)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("24e801000001000000000000037777770866616365626f6f6b03636f6d0000010001")
DIRECTION.append("")

#*** Packet 2 -
# 121 208.67.220.123 10.0.2.15 DNS Standard query response 0x24e8 A www.facebook.com CNAME star-mini.c10r.facebook.com A 179.60.193.36
RAW.append(binascii.unhexlify("0800278308f052540012350208004500006bcd1a00004011f499d043dc7b0a00020f00351ad2005777cf24e881800001000200000000037777770866616365626f6f6b03636f6d0000010001c00c0005000100000ab0001109737461722d6d696e690463313072c010c02e00010001000000330004b33cc124"))
LEN.append(121)
ETH_SRC.append('52:54:00:12:35:02')
ETH_DST.append('08:00:27:83:08:f0')
ETH_TYPE.append(2048)
IP_SRC.append('208.67.220.123')
IP_DST.append('10.0.2.15')
PROTO.append(17)
TP_SRC.append(53)
TP_DST.append(6866)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("24e881800001000200000000037777770866616365626f6f6b03636f6d0000010001c00c0005000100000ab0001109737461722d6d696e690463313072c010c02e00010001000000330004b33cc124")
DIRECTION.append("")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = ''
FLOW_IP_SERVER = ''
