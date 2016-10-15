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

This flow is IPv4 + TCP + HTTP with a GET returning a "HTTP/1.1
400 Bad Request"

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

#*** Packet 1 - TCP handshake packet 1
# 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=5982511 TSecr=0 WS=64
RAW.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003c19fd400040060cab0a0100010a010002a9210050c37250d200000000a002721014330000020405b40402080a005b492f0000000001030306"))
LEN.append(74)
IP_SRC.append('10.1.0.1')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(43297)
TP_DST.append(80)
TP_SEQ_SRC.append(3279048914)
TP_SEQ_DST.append(0)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 2 - TCP handshake packet 2
# 10.1.0.2 10.1.0.1 TCP 74 http > 43297 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=5977583 TSecr=5982511 WS=64
RAW.append(binascii.unhexlify("0800272ad6dd080027c8db9108004500003c00004000400626b80a0100020a0100010050a9219e5c9d99c37250d3a0127120494a0000020405b40402080a005b35ef005b492f01030306"))
LEN.append(74)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.1')
PROTO.append(6)
TP_SRC.append(80)
TP_DST.append(43297)
TP_SEQ_SRC.append(2656869785)
TP_SEQ_DST.append(3279048915)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Packet 3 - TCP handshake packet 3
# 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=1 Ack=1 Win=29248 Len=0 TSval=5982512 TSecr=5977583
RAW.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003419fe400040060cb20a0100010a010002a9210050c37250d39e5c9d9a801001c9142b00000101080a005b4930005b35ef"))
LEN.append(66)
IP_SRC.append('10.1.0.1')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(43297)
TP_DST.append(80)
TP_SEQ_SRC.append(3279048915)
TP_SEQ_DST.append(2656869786)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 4 - Client to server payload 1 "GET\r\n"
#  10.1.0.1 10.1.0.2 TCP 71 [TCP segment of a reassembled PDU] [PSH + ACK]
RAW.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003919ff400040060cac0a0100010a010002a9210050c37250d39e5c9d9a801801c9143000000101080a005b4d59005b35ef4745540d0a"))
LEN.append(71)
IP_SRC.append('10.1.0.1')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(43297)
TP_DST.append(80)
TP_SEQ_SRC.append(3279048915)
TP_SEQ_DST.append(2656869786)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(1)
TCP_ACK.append(1)
PAYLOAD.append("4745540d0a")
DIRECTION.append("c2s")

#*** Packet 5 - TCP ACK server to client
# 10.1.0.2 10.1.0.1 TCP 66 http > 43297 [ACK] Seq=1 Ack=6 Win=28992 Len=0 TSval=5978648 TSecr=5983577
RAW.append(binascii.unhexlify("0800272ad6dd080027c8db91080045000034a875400040067e4a0a0100020a0100010050a9219e5c9d9ac37250d8801001c5df1800000101080a005b3a18005b4d59"))
LEN.append(66)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.1')
PROTO.append(6)
TP_SRC.append(80)
TP_DST.append(43297)
TP_SEQ_SRC.append(2656869786)
TP_SEQ_DST.append(3279048920)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Packet 6 - Server to client response
# 10.1.0.2 10.1.0.1 HTTP 162 HTTP/1.1 400 Bad Request  (text/plain)  [PSH + ACK]
RAW.append(binascii.unhexlify("0800272ad6dd080027c8db91080045000094a876400040067de90a0100020a0100010050a9219e5c9d9ac37250d8801801c5792f00000101080a005b3a18005b4d59485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65"))
LEN.append(162)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.1')
PROTO.append(6)
TP_SRC.append(80)
TP_DST.append(43297)
TP_SEQ_SRC.append(2656869786)
TP_SEQ_DST.append(3279048920)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(1)
TCP_ACK.append(1)
PAYLOAD.append("485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65")
DIRECTION.append("s2c")

#*** Packet 7- Client to server ACK
# 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=6 Ack=97 Win=29248 Len=0 TSval=5983577 TSecr=5978648
RAW.append(binascii.unhexlify("080027c8db910800272ad6dd0800451000341a00400040060cb00a0100010a010002a9210050c37250d89e5c9dfa801001c9142b00000101080a005b4d59005b3a18"))
LEN.append(66)
IP_SRC.append('10.1.0.1')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(43297)
TP_DST.append(80)
TP_SEQ_SRC.append(3279048920)
TP_SEQ_DST.append(2656869882)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = '10.1.0.1'
FLOW_IP_SERVER = '10.1.0.2'

