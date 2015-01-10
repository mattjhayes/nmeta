"""
Nmeta Integration Tests 
.
To run, type in nosetests in the nmeta directory
"""

import tc_policy
from ryu.ofproto import ether
from ryu.lib.packet import ethernet, arp, packet

#==================== Policy Integration Tests ===============+==========
#*** Instantiate classes:
tc = tc_policy.TrafficClassificationPolicy \
                    ("DEBUG","DEBUG","DEBUG","DEBUG","DEBUG")
#*** Test values for policy_conditions:
policy_conditions1 = {'tcp_src': 6633, 'tcp_dst': 6633}
policy_conditions2 = {'eth_src': '08:60:6e:7f:74:e7', 
                         'eth_dst': '08:60:6e:7f:74:e8'}
policy_conditions3 = {'ip_dst': '192.168.57.12', 'ip_src': '192.168.56.32'}
policy_conditions4 = {'tcp_src': 22, 'tcp_dst': 22}

#*** Check Match Validity Tests:
def test_check_match():
    #*** Test Packets:
    pkt1 = build_packet_ARP()
    tc._check_match(pkt1, policy_conditions1, 'any') == 0
    tc._check_match(pkt1, policy_conditions2, 'any') == 1
    tc._check_match(pkt1, policy_conditions2, 'all') == 0

#=========== Misc Functions to Generate Data for Unit Tests ===================

def build_packet_ARP():
    """
    Build an ARP packet for use in tests.
    Based on code from 
    http://ryu.readthedocs.org/en/latest/library_packet.html
    """
    e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
                      src='08:60:6e:7f:74:e7',
                      ethertype=ether.ETH_TYPE_ARP)
    a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
            src_mac='08:60:6e:7f:74:e7', src_ip='192.0.2.1',
            dst_mac='00:00:00:00:00:00', dst_ip='192.0.2.2')
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    print repr(p.data)  # the on-wire packet
    return p
