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
IPv4_HTTP = []
#*** Packet on the wire lengths in bytes:
IPv4_HTTP_LEN = []
#*** IP addresses:
IPv4_HTTP_IP_SRC = []
IPv4_HTTP_IP_DST = []
#*** IP protocol number in decimal:
IPv4_HTTP_PROTO = []
#*** Transport-layer protocol numbers in decimal:
IPv4_HTTP_TP_SRC = []
IPv4_HTTP_TP_DST = []

#*** TCP handshake packet 1
# 10.1.0.1 10.1.0.2 TCP 74 43297 > http [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=5982511 TSecr=0 WS=64
IPv4_HTTP.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003c19fd400040060cab0a0100010a010002a9210050c37250d200000000a002721014330000020405b40402080a005b492f0000000001030306"))
IPv4_HTTP_LEN.append(74)
IPv4_HTTP_IP_SRC.append('10.1.0.1')
IPv4_HTTP_IP_DST.append('10.1.0.2')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(43297)
IPv4_HTTP_TP_DST.append(80)

#*** TCP handshake packet 2
# 10.1.0.2 10.1.0.1 TCP 74 http > 43297 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=5977583 TSecr=5982511 WS=64
IPv4_HTTP.append(binascii.unhexlify("0800272ad6dd080027c8db9108004500003c00004000400626b80a0100020a0100010050a9219e5c9d99c37250d3a0127120494a0000020405b40402080a005b35ef005b492f01030306"))
IPv4_HTTP_LEN.append(74)
IPv4_HTTP_IP_SRC.append('10.1.0.2')
IPv4_HTTP_IP_DST.append('10.1.0.1')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(80)
IPv4_HTTP_TP_DST.append(43297)

#*** TCP handshake packet 3
# 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=1 Ack=1 Win=29248 Len=0 TSval=5982512 TSecr=5977583
IPv4_HTTP.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003419fe400040060cb20a0100010a010002a9210050c37250d39e5c9d9a801001c9142b00000101080a005b4930005b35ef"))
IPv4_HTTP_LEN.append(66)
IPv4_HTTP_IP_SRC.append('10.1.0.1')
IPv4_HTTP_IP_DST.append('10.1.0.2')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(43297)
IPv4_HTTP_TP_DST.append(80)

#*** Client to server payload 1 "GET\r\n"
#  10.1.0.1 10.1.0.2 TCP 71 [TCP segment of a reassembled PDU] [PSH + ACK]
IPv4_HTTP.append(binascii.unhexlify("080027c8db910800272ad6dd08004510003919ff400040060cac0a0100010a010002a9210050c37250d39e5c9d9a801801c9143000000101080a005b4d59005b35ef4745540d0a"))
IPv4_HTTP_LEN.append(71)
IPv4_HTTP_IP_SRC.append('10.1.0.1')
IPv4_HTTP_IP_DST.append('10.1.0.2')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(43297)
IPv4_HTTP_TP_DST.append(80)

#*** TCP ACK server to client
# 10.1.0.2 10.1.0.1 TCP 66 http > 43297 [ACK] Seq=1 Ack=6 Win=28992 Len=0 TSval=5978648 TSecr=5983577
IPv4_HTTP.append(binascii.unhexlify("0800272ad6dd080027c8db91080045000034a875400040067e4a0a0100020a0100010050a9219e5c9d9ac37250d8801001c5df1800000101080a005b3a18005b4d59"))
IPv4_HTTP_LEN.append(66)
IPv4_HTTP_IP_SRC.append('10.1.0.2')
IPv4_HTTP_IP_DST.append('10.1.0.1')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(80)
IPv4_HTTP_TP_DST.append(43297)

#*** Server to client response
# 10.1.0.2 10.1.0.1 HTTP 162 HTTP/1.1 400 Bad Request  (text/plain)  [PSH + ACK]
IPv4_HTTP.append(binascii.unhexlify("0800272ad6dd080027c8db91080045000094a876400040067de90a0100020a0100010050a9219e5c9d9ac37250d8801801c5792f00000101080a005b3a18005b4d59485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65"))
IPv4_HTTP_LEN.append(162)
IPv4_HTTP_IP_SRC.append('10.1.0.2')
IPv4_HTTP_IP_DST.append('10.1.0.1')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(80)
IPv4_HTTP_TP_DST.append(43297)

#*** Client to server ACK
# 10.1.0.1 10.1.0.2 TCP 66 43297 > http [ACK] Seq=6 Ack=97 Win=29248 Len=0 TSval=5983577 TSecr=5978648
IPv4_HTTP.append(binascii.unhexlify("080027c8db910800272ad6dd0800451000341a00400040060cb00a0100010a010002a9210050c37250d89e5c9dfa801001c9142b00000101080a005b4d59005b3a18"))
IPv4_HTTP_LEN.append(66)
IPv4_HTTP_IP_SRC.append('10.1.0.1')
IPv4_HTTP_IP_DST.append('10.1.0.2')
IPv4_HTTP_PROTO.append(6)
IPv4_HTTP_TP_SRC.append(43297)
IPv4_HTTP_TP_DST.append(80)

#*** Metadata for whole flow:
IPv4_HTTP_FLOW_IP_CLIENT = '10.1.0.1'
IPv4_HTTP_FLOW_IP_SERVER = '10.1.0.2'
