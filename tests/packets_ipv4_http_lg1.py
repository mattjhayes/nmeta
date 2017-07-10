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

Packet capture file is 'packets_ipv4_http_lg1.pcapng'
"""

import binascii

#======================== IPv4 + TCP + HTTP port 80 flow ======================
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

#*** Packet 0 - TCP handshake
# 10.1.0.6 10.1.0.2 TCP 46333 > 80 [SYN] Seq=1779453979 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=310025 TSecr=0 WS=64
RAW.append(binascii.unhexlify("080027c8db91080027214fea08004510003ceb12400040063b900a0100060a010002b4fd00506a10501b00000000a002721097600000020405b40402080a0004bb090000000001030306"))
LEN.append(74)
ETH_SRC.append('08:00:27:21:4f:ea')
ETH_DST.append('08:00:27:c8:db:91')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.6')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(46333)
TP_DST.append(80)
TP_SEQ_SRC.append(1779453979)
TP_SEQ_DST.append(0)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 1 - TCP handshake
# 10.1.0.2 10.1.0.6 TCP	80 > 46333 [SYN, ACK] Seq=3285287208 Ack=1779453980 Win=28960 Len=0 MSS=1460 SACK_PERM=1 TSval=4369946 TSecr=310025 WS=64
RAW.append(binascii.unhexlify("080027214fea080027c8db9108004500003c00004000400626b30a0100020a0100060050b4fdc3d181286a10501ca0127120a4e80000020405b40402080a0042ae1a0004bb0901030306"))
LEN.append(74)
ETH_SRC.append('08:00:27:c8:db:91')
ETH_DST.append('08:00:27:21:4f:ea')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.6')
PROTO.append(6)
TP_SRC.append(80)
TP_DST.append(46333)
TP_SEQ_SRC.append(3285287208)
TP_SEQ_DST.append(1779453980)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Packet 2 - TCP handshake
# 10.1.0.6 10.1.0.2 TCP	46333 > 80 [ACK] Seq=1779453980 Ack=3285287209 Win=29248 Len=0 TSval=310026 TSecr=4369946
RAW.append(binascii.unhexlify("080027c8db91080027214fea080045100034eb13400040063b970a0100060a010002b4fd00506a10501cc3d18129801001c9430a00000101080a0004bb0a0042ae1a"))
LEN.append(66)
ETH_SRC.append('08:00:27:21:4f:ea')
ETH_DST.append('08:00:27:c8:db:91')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.6')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(46333)
TP_DST.append(80)
TP_SEQ_SRC.append(1779453980)
TP_SEQ_DST.append(3285287209)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 3 - Client to server payload 1 "GET\r\n"
# 10.1.0.6 10.1.0.2 TCP [TCP segment of a reassembled PDU] [PSH + ACK]
RAW.append(binascii.unhexlify("080027c8db91080027214fea080045100039eb14400040063b910a0100060a010002b4fd00506a10501cc3d18129801801c99c1b00000101080a0004bc990042ae1a4745540d0a"))
LEN.append(71)
ETH_SRC.append('08:00:27:21:4f:ea')
ETH_DST.append('08:00:27:c8:db:91')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.6')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(46333)
TP_DST.append(80)
TP_SEQ_SRC.append(1779453985)
TP_SEQ_DST.append(3285287209)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(1)
TCP_ACK.append(1)
PAYLOAD.append("4745540d0a")
DIRECTION.append("c2s")

#*** Packet 4 - TCP ACK server to client
# 10.1.0.2 10.1.0.6 TCP	80 > 46333 [ACK] Seq=3285287209 Ack=1779453985 Win=28992 Len=0 TSval=4370345 TSecr=310425
RAW.append(binascii.unhexlify("080027214fea080027c8db910800450000342f3340004006f7870a0100020a0100060050b4fdc3d181296a105021801001c53feb00000101080a0042afa90004bc99"))
LEN.append(66)
ETH_SRC.append('08:00:27:c8:db:91')
ETH_DST.append('08:00:27:21:4f:ea')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.6')
PROTO.append(6)
TP_SRC.append(80)
TP_DST.append(46333)
TP_SEQ_SRC.append(3285287209)
TP_SEQ_DST.append(1779453985)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Packet 5 - Server to client response
# 10.1.0.2 10.1.0.6 HTTP HTTP/1.1 400 Bad Request  (text/plain)
RAW.append(binascii.unhexlify("080027214fea080027c8db910800450000942f3440004006f7260a0100020a0100060050b4fdc3d181296a105021801801c5da0100000101080a0042afa90004bc99485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65"))
LEN.append(162)
ETH_SRC.append('08:00:27:c8:db:91')
ETH_DST.append('08:00:27:21:4f:ea')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.2')
IP_DST.append('10.1.0.6')
PROTO.append(6)
TP_SRC.append(80)
TP_DST.append(46333)
TP_SEQ_SRC.append(3285287209)
TP_SEQ_DST.append(1779453985)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(1)
TCP_ACK.append(1)
PAYLOAD.append("485454502f312e31203430302042616420526571756573740d0a436f6e74656e742d4c656e6774683a2032320d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a0d0a4d616c666f726d656420526571756573742d4c696e65")
DIRECTION.append("s2c")

#*** Packet 6 - Client to server ACK
# 10.1.0.6 10.1.0.2 TCP	46333 > 80 [ACK] Seq=1779453985 Ack=3285287305 Win=29248 Len=0 TSval=310425 TSecr=4370345
RAW.append(binascii.unhexlify("080027c8db91080027214fea080045100034eb15400040063b950a0100060a010002b4fd00506a105021c3d18189801001c93f8700000101080a0004bc990042afa9"))
LEN.append(66)
ETH_SRC.append('08:00:27:21:4f:ea')
ETH_DST.append('08:00:27:c8:db:91')
ETH_TYPE.append(2048)
IP_SRC.append('10.1.0.6')
IP_DST.append('10.1.0.2')
PROTO.append(6)
TP_SRC.append(46333)
TP_DST.append(80)
TP_SEQ_SRC.append(1779453985)
TP_SEQ_DST.append(3285287305)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(1)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = '10.1.0.6'
FLOW_IP_SERVER = '10.1.0.2'
