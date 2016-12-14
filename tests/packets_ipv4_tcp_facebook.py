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
Packets with metadata to use in testing of DNS identity (from separate trace)

This file is a set of IPv4 TCP packets starting a TCP handshake to an IP
address that previously resolved from www.facebook.com query

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

Packet capture file is 'packets_ipv4_tcp_facebook.pcap'
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

#*** Packet 1 - TCP SYN to IP 179.60.193.36 (www.facebook.com, CNAME star-mini.c10r.facebook.com)
# 74 10.0.2.15 179.60.193.36 TCP 41936?443 [SYN] Seq=1025366577 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=1550476 TSecr=0 WS=128
RAW.append(binascii.unhexlify("52540012350208002736873908004500003c72bd40004006478f0a00020fb33cc124a3d001bb3d1dda3100000000a0027210f0010000020405b40402080a0017a88c0000000001030307"))
LEN.append(74)
ETH_SRC.append('08:00:27:36:87:39')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('179.60.193.36')
PROTO.append(6)
TP_SRC.append(41936)
TP_DST.append(443)
TP_SEQ_SRC.append(1025366577)
TP_SEQ_DST.append(0)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 2 -TCP SYN+ACK from IP 179.60.193.36 (www.facebook.com, CNAME star-mini.c10r.facebook.com)
# 60 179.60.193.36 10.0.2.15 TCP 443 41936 [SYN, ACK] Seq=468864001 Ack=1025366578 Win=65535 Len=0 MSS=1460
RAW.append(binascii.unhexlify("08002736873952540012350208004500002c0d4b00004006ed11b33cc1240a00020f01bba3d01bf24c013d1dda326012fffff2d70000020405b40000"))
LEN.append(60)
ETH_SRC.append('52:54:00:12:35:02')
ETH_DST.append('08:00:27:36:87:39')
ETH_TYPE.append(2048)
IP_SRC.append('179.60.193.36')
IP_DST.append('10.0.2.15')
PROTO.append(6)
TP_SRC.append(443)
TP_DST.append(41936)
TP_SEQ_SRC.append(468864001)
TP_SEQ_DST.append(1025366578)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Packet 3 - TCP ACK to IP 179.60.193.36 (www.facebook.com, CNAME star-mini.c10r.facebook.com)
# 54 10.0.2.15 179.60.193.36 TCP 41936 443 [ACK] Seq=1025366578 Ack=468864002 Win=29200 Len=0
RAW.append(binascii.unhexlify("52540012350208002736873908004500002872be4000400647a20a00020fb33cc124a3d001bb3d1dda321bf24c025010721098840000"))
LEN.append(54)
ETH_SRC.append('08:00:27:36:87:39')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('179.60.193.36')
PROTO.append(6)
TP_SRC.append(41936)
TP_DST.append(443)
TP_SEQ_SRC.append(1025366578)
TP_SEQ_DST.append(468864002)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = '10.0.2.15'
FLOW_IP_SERVER = '179.60.193.36'
