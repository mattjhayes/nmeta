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

This flow is a TCP SYN on port 81 with a RST response from server

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

#======================== IPv4 + TCP + HTTP port 80 flow ======================
#*** Raw packet data:
RAW = []
#*** Packet on the wire lengths in bytes:
LEN = []
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

#*** Packet 1 - TCP SYN
# 74 10.1.0.1 10.1.0.2 TCP 38331 81 [SYN] Seq=1370089506 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=9535205 TSecr=0 WS=64
RAW.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003c96c7400040068fe00a0100010a01000295bb005151a9e82200000000a002721014330000020405b40402080a00917ee50000000001030306"))
LEN.append(74)
IP_SRC.append('10.1.0.1')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(38331)
TP_DST.append(81)
TP_SEQ_SRC.append(1370089506)
TP_SEQ_DST.append(0)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 2 - TCP RST
# 60 10.1.0.2 10.1.0.1 TCP 81 38331 [RST, ACK] Seq=0 Ack=1370089507 Win=0 Len=0
RAW.append(binascii.unhexlify("0800272ad6dd080027c8db91080045100028f819400040062ea20a0100020a010001005195bb0000000051a9e82350140000cbf20000000000000000"))
LEN.append(60)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.1')
PROTO.append(6)
TP_SRC.append(81)
TP_DST.append(38331)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(1370089507)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(1)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = '10.1.0.1'
FLOW_IP_SERVER = '10.1.0.2'

