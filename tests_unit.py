"""
Nmeta unit tests 
.
To run, type in nosetests in the nmeta directory
"""

import tc_policy

#*** Instantiate classes:
tc = tc_policy.TrafficClassificationPolicy \
                    ("DEBUG","DEBUG","DEBUG","DEBUG","DEBUG")

#======================== tc_policy.py unit tests ============================
#*** Transport Port Validity Tests:
def test_is_valid_transport_port_abc123():
    assert tc.is_valid_transport_port('abc123') == 0
    assert tc.is_valid_transport_port('1') == 1
    assert tc.is_valid_transport_port('65535') == 1
    assert tc.is_valid_transport_port('65536') == 0

#*** MAC Address Validity Tests:
def test_is_valid_MACAddress():
    assert tc.is_valid_MACAddress('192.168.3.4') == 0
    assert tc.is_valid_MACAddress('fe80:dead:beef') == 1
    assert tc.is_valid_MACAddress('fe80deadbeef') == 1
    assert tc.is_valid_MACAddress('fe:80:de:ad:be:ef') == 1
    assert tc.is_valid_MACAddress('foo 123') == 0

#*** IP Address Space Validity Tests:
def test_is_valid_IP_space():
    assert tc.is_valid_IP_space('192.168.3.4') == 1
    assert tc.is_valid_IP_space('192.168.3.0/24') == 1
    assert tc.is_valid_IP_space('192.168.322.0/24') == 0
    assert tc.is_valid_IP_space('foo') == 0
    assert tc.is_valid_IP_space('10.168.3.15/24') == 1
    assert tc.is_valid_IP_space('192.168.3.25-192.168.4.58') == 1
    assert tc.is_valid_IP_space('192.168.4.25-192.168.3.58') == 0
    assert tc.is_valid_IP_space('192.168.3.25-43') == 0
    assert tc.is_valid_IP_space('fe80::dead:beef') == 1
    assert tc.is_valid_IP_space('10.1.2.2-10.1.2.3') == 1
    assert tc.is_valid_IP_space('10.1.2.3-fe80::dead:beef') == 0
    assert tc.is_valid_IP_space('10.1.2.3-10.1.2.5-10.1.2.8') == 0
    assert tc.is_valid_IP_space('fe80::dead:beef-fe80::dead:beff') == 1

#====================================================================
