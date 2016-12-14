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

This file is a set of DNS packets, resolving www.facebook.com via a different
DNS server and getting a different A record IP address to the first answer
in the first DNS file.

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

Packet capture file is 'packets_ipv4_DNS_4.pcap'
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
DNS_NAME = []
DNS_CNAME = []
DNS_IP = []


#*** Packet 1 - DNS Query A www.facebook.com
# 76 10.0.2.15 8.8.8.8 DNS Standard query 0x2ba9 A www.facebook.com
RAW.append(binascii.unhexlify("52540012350208002736873908004500003e31a2000040112cef0a00020f0808080892340035002a2f692ba901000001000000000000037777770866616365626f6f6b03636f6d0000010001"))
LEN.append(76)
ETH_SRC.append('08:00:27:36:87:39')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('8.8.8.8')
PROTO.append(17)
TP_SRC.append(37428)
TP_DST.append(53)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("2ba901000001000000000000037777770866616365626f6f6b03636f6d0000010001")
DIRECTION.append("")
DNS_NAME.append("www.facebook.com")
DNS_CNAME.append("")
DNS_IP.append("")

#*** Packet 2 -
# 121 8.8.8.8 10.0.2.15 DNS Standard query response 0x2ba9 A www.facebook.com CNAME star-mini.c10r.facebook.com A 31.13.95.36
RAW.append(binascii.unhexlify("08002736873952540012350208004500006ba36e00004011baf5080808080a00020f003592340057d7e52ba981800001000200000000037777770866616365626f6f6b03636f6d0000010001c00c000500010000081c001109737461722d6d696e690463313072c010c02e000100010000002400041f0d5f24"))
LEN.append(121)
ETH_SRC.append('52:54:00:12:35:02')
ETH_DST.append('08:00:27:36:87:39')
ETH_TYPE.append(2048)
IP_SRC.append('8.8.8.8')
IP_DST.append('10.0.2.15')
PROTO.append(17)
TP_SRC.append(53)
TP_DST.append(37428)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("2ba981800001000200000000037777770866616365626f6f6b03636f6d0000010001c00c000500010000081c001109737461722d6d696e690463313072c010c02e000100010000002400041f0d5f24")
DIRECTION.append("")
DNS_NAME.append("www.facebook.com")
DNS_CNAME.append("star-mini.c10r.facebook.com")
DNS_IP.append("31.13.95.36")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = ''
FLOW_IP_SERVER = ''
