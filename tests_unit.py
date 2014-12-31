"""
Nmeta Unit Tests 
.
To run, type in nosetests in the nmeta directory
"""

import tc_policy

#======================== tc_policy.py Unit Tests ============================
#*** Instantiate classes:
tc = tc_policy.TrafficClassificationPolicy \
                    ("DEBUG","DEBUG","DEBUG","DEBUG","DEBUG")

#*** MAC Address Validity Tests:
def test_is_valid_macaddress():
    assert tc.static.is_valid_macaddress('192.168.3.4') == 0
    assert tc.static.is_valid_macaddress('fe80:dead:beef') == 1
    assert tc.static.is_valid_macaddress('fe80deadbeef') == 1
    assert tc.static.is_valid_macaddress('fe:80:de:ad:be:ef') == 1
    assert tc.static.is_valid_macaddress('foo 123') == 0

#*** EtherType Validity Tests:
def test_is_valid_ethertype():
    assert tc.static.is_valid_ethertype('0x0800') == 1
    assert tc.static.is_valid_ethertype('foo') == 0
    assert tc.static.is_valid_ethertype('0x08001') == 1
    assert tc.static.is_valid_ethertype('0x18001') == 0
    assert tc.static.is_valid_ethertype('35020') == 1
    assert tc.static.is_valid_ethertype('350201') == 0

#*** IP Address Space Validity Tests:
def test_is_valid_ip_space():
    assert tc.static.is_valid_ip_space('192.168.3.4') == 1
    assert tc.static.is_valid_ip_space('192.168.3.0/24') == 1
    assert tc.static.is_valid_ip_space('192.168.322.0/24') == 0
    assert tc.static.is_valid_ip_space('foo') == 0
    assert tc.static.is_valid_ip_space('10.168.3.15/24') == 1
    assert tc.static.is_valid_ip_space('192.168.3.25-192.168.4.58') == 1
    assert tc.static.is_valid_ip_space('192.168.4.25-192.168.3.58') == 0
    assert tc.static.is_valid_ip_space('192.168.3.25-43') == 0
    assert tc.static.is_valid_ip_space('fe80::dead:beef') == 1
    assert tc.static.is_valid_ip_space('10.1.2.2-10.1.2.3') == 1
    assert tc.static.is_valid_ip_space('10.1.2.3-fe80::dead:beef') == 0
    assert tc.static.is_valid_ip_space('10.1.2.3-10.1.2.5-10.1.2.8') == 0
    assert tc.static.is_valid_ip_space('fe80::dead:beef-fe80::dead:beff') == 1

#*** Transport Port Validity Tests:
def test_is_valid_transport_port_abc123():
    assert tc.static.is_valid_transport_port('abc123') == 0
    assert tc.static.is_valid_transport_port('1') == 1
    assert tc.static.is_valid_transport_port('65535') == 1
    assert tc.static.is_valid_transport_port('65536') == 0

#*** MAC Address Match Tests:
def test_is_match_macaddress():
    assert tc.static.is_match_macaddress('fe80:dead:beef', '0000:0000:0002') \
                                                    == 0
    assert tc.static.is_match_macaddress('0000:0000:0002', '0000:0000:0002') \
                                                    == 1
    assert tc.static.is_match_macaddress('fe80:dead:beef', 'fe80deadbeef') \
                                                    == 1
    assert tc.static.is_match_macaddress('0000:0000:0002', '2') \
                                                    == 1
    assert tc.static.is_match_macaddress('0000:0000:0002', 'f00') \
                                                    == 0

#*** EtherType Match Tests:
def test_is_match_ethertype():
    assert tc.static.is_match_ethertype('35020', '35020') == 1
    assert tc.static.is_match_ethertype('35020', '0x88cc') == 1
    assert tc.static.is_match_ethertype('foo', '0x88cc') == 0
    assert tc.static.is_match_ethertype('35020', 'foo') == 0
    assert tc.static.is_match_ethertype('0xfoo', '35020') == 0
    assert tc.static.is_match_ethertype('35020', '0xfoo') == 0

#*** IP Address Match Tests:
def test_is_match_ip_space():
    assert tc.static.is_match_ip_space('192.168.56.12', '192.168.56.12') == 1
    assert tc.static.is_match_ip_space('192.168.56.11', '192.168.56.12') == 0
    assert tc.static.is_match_ip_space('192.168.56.12', '192.168.56.0/24') == 1
    assert tc.static.is_match_ip_space('192.168.56.12', '192.168.57.0/24') == 0
    assert tc.static.is_match_ip_space('192.168.56.12', \
                                            '192.168.56.10-192.168.56.42') == 1
    assert tc.static.is_match_ip_space('192.168.56.12', \
                                            '192.168.57.10-192.168.57.42') == 0
