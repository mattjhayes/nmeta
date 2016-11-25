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

This file is an IPv4 ARP request and response

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

Packet capture file is 'packets_ipv4_ARP.pcap'
"""

import binascii

#======================== ARP ======================
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

#*** Packet 1 - ARP request for 10.1.0.1
# 42 CadmusCo_c8:db:91 Broadcast ARP Who has 10.1.0.1? Tell 10.1.0.2
RAW.append(binascii.unhexlify("ffffffffffff080027c8db9108060001080006040001080027c8db910a0100020000000000000a010001"))
LEN.append(42)
ETH_SRC.append('08:00:27:c8:db:91')
ETH_DST.append('ff:ff:ff:ff:ff:ff')
ETH_TYPE.append(2054)
IP_SRC.append('')
IP_DST.append('')
PROTO.append(0)
TP_SRC.append(0)
TP_DST.append(0)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("0001080006040001080027c8db910a0100020000000000000a010001")
DIRECTION.append("")

#*** Packet 2 - ARP reply for 10.1.0.1
# 60 08:00:27:2a:d6:dd 08:00:27:c8:db:91 ARP 10.1.0.1 is at 08:00:27:2a:d6:dd
RAW.append(binascii.unhexlify("080027c8db910800272ad6dd080600010800060400020800272ad6dd0a010001080027c8db910a010002000000000000000000000000000000000000"))
LEN.append(60)
ETH_SRC.append('08:00:27:2a:d6:dd')
ETH_DST.append('08:00:27:c8:db:91')
ETH_TYPE.append(2054)
IP_SRC.append('')
IP_DST.append('')
PROTO.append(0)
TP_SRC.append(0)
TP_DST.append(0)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("00010800060400020800272ad6dd0a010001080027c8db910a010002")
DIRECTION.append("")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = ''
FLOW_IP_SERVER = ''
