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

This file is a set of three unrelated Link Layer Discovery Protocol
(LLDP) packets

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

Packet capture file is 'packets_ipv4_http.pcapng'
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
#*** LLDP specific:
LLDP_SYSTEM_NAME = []
LLDP_SYSTEM_DESC = []
LLDP_PORT_DESC = []
LLDP_TTL = []


#*** Packet 0 - LLDP from pc1
# 206 08:00:27:2a:d6:dd 01:80:c2:00:00:0e LLDP NoS = 08:00:27:2a:d6:dd TTL = 120 System Name = pc1.example.com
# System Description = Ubuntu 14.04.2 LTS Linux 3.16.0-45-generic #60~14.04.1-Ubuntu SMP Fri Jul 24 21:16:23 UTC 2015 x86_64
RAW.append(binascii.unhexlify("0180c200000e0800272ad6dd88cc0207040800272ad6dd0407030800272ad6dd060200780a0f7063312e6578616d706c652e636f6d0c655562756e74752031342e30342e32204c5453204c696e757820332e31362e302d34352d67656e65726963202336307e31342e30342e312d5562756e747520534d5020467269204a756c2032342032313a31363a3233205554432032303135207838365f36340e04001c0000100c05010a00020f020000000200080465746831fe0900120f030100000000fe0900120f01036c01001e0000"))
LEN.append(206)
ETH_SRC.append('08:00:27:2a:d6:dd')
ETH_DST.append('01:80:c2:00:00:0e')
ETH_TYPE.append(35020)
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
PAYLOAD.append("")
DIRECTION.append("")
LLDP_SYSTEM_NAME.append("pc1.example.com")
LLDP_SYSTEM_DESC.append("Ubuntu 14.04.2 LTS Linux 3.16.0-45-generic #60~14.04.1-Ubuntu SMP Fri Jul 24 21:16:23 UTC 2015 x86_64")
LLDP_PORT_DESC = 'eth1'
LLDP_TTL = 120

#*** Packet 1 - LLDP from sw1
# 206 08:00:27:f7:25:13 01:80:c2:00:00:0e LLDP NoS = 08:00:27:f7:25:13 TTL = 120 System Name = sw1.example.com
# System Description = Ubuntu 14.04.2 LTS Linux 3.16.0-45-generic #60~14.04.1-Ubuntu SMP Fri Jul 24 21:16:23 UTC 2015 x86_64
RAW.append(binascii.unhexlify("0180c200000e080027f7251388cc020704080027f72513040703080027f72513060200780a0f7377312e6578616d706c652e636f6d0c655562756e74752031342e30342e32204c5453204c696e757820332e31362e302d34352d67656e65726963202336307e31342e30342e312d5562756e747520534d5020467269204a756c2032342032313a31363a3233205554432032303135207838365f36340e04001c0000100c05010a00020f020000000200080465746831fe0900120f030100000000fe0900120f01036c01001e0000"))
LEN.append(206)
ETH_SRC.append('08:00:27:f7:25:13')
ETH_DST.append('01:80:c2:00:00:0e')
ETH_TYPE.append(35020)
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
PAYLOAD.append("")
DIRECTION.append("")
LLDP_SYSTEM_NAME.append("sw1.example.com")
LLDP_SYSTEM_DESC.append("Ubuntu 14.04.2 LTS Linux 3.16.0-45-generic #60~14.04.1-Ubuntu SMP Fri Jul 24 21:16:23 UTC 2015 x86_64")
LLDP_PORT_DESC = 'eth1'
LLDP_TTL = 120

#*** Packet 2 - LLDP from lg1
# 206 08:00:27:21:4f:ea 01:80:c2:00:00:0e LLDP NoS = 08:00:27:21:4f:ea TTL = 120 System Name = lg1.example.com
# System Description = Ubuntu 14.04.2 LTS Linux 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64
RAW.append(binascii.unhexlify("0180c200000e080027214fea88cc020704080027214fea040703080027214fea060200780a0f6c67312e6578616d706c652e636f6d0c655562756e74752031342e30342e32204c5453204c696e757820332e31362e302d33302d67656e65726963202334307e31342e30342e312d5562756e747520534d5020546875204a616e2031352031373a34333a3134205554432032303135207838365f36340e04001c0000100c05010a00020f020000000200080465746831fe0900120f030100000000fe0900120f01036c01001e0000"))
LEN.append(206)
ETH_SRC.append('08:00:27:21:4f:ea')
ETH_DST.append('01:80:c2:00:00:0e')
ETH_TYPE.append(35020)
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
PAYLOAD.append("")
DIRECTION.append("")
LLDP_SYSTEM_NAME.append("lg1.example.com")
LLDP_SYSTEM_DESC.append("Ubuntu 14.04.2 LTS Linux 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64")
LLDP_PORT_DESC = 'eth1'
LLDP_TTL = 120

#*** Metadata for whole flow:
FLOW_IP_CLIENT = ''
FLOW_IP_SERVER = ''
