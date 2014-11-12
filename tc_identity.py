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

#*** nmeta - Network Metadata - TC Identity Class and Methods
#
# Matt Hayes
# Victoria University, New Zealand
# Version 2.2

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import logging
import logging.handlers
import struct
import time
import re

#*** Ryu imports:
from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

#*** nmeta imports:
import nmisc

#============== For PEP8 this is 79 characters long... ========================
#========== For PEP8 DocStrings this is 72 characters long... ==========

class IdentityInspect(object):
    """
    This class is instantiated by tc_policy.py 
    (class: TrafficClassificationPolicy) and provides methods to 
    ingest identity updates and query identities
    """
    def __init__(self):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address = ('localhost', 514),
            facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        #*** Instantiate the System and NIC Identity Tables:
        self._sys_identity_table = nmisc.AutoVivification()
        self._nic_identity_table = nmisc.AutoVivification()
        #*** Initialise Identity Tables unique reference numbers:
        #*** Start at 1 so that value 0 can be used for boolean
        #*** false on checks
        self._sys_id_ref = 1
        self._nic_id_ref = 1
        
    def check_identity(self, policy_attr, policy_value, pkt):
        """
        Passed an identity attribute, value and packet and
        return True or False based on whether or not the packet strongly
        correlates to the identity attribute/value
        """
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)         
        if policy_attr == "identity_lldp_chassisid":
            sys_ref = self._get_sys_ref_by_chassisid(policy_value)
            if sys_ref:
                #*** Have matched a chassis ID record, now check if the packet
                #*** relates to that system:
                nic_ref = self._get_sys_nic_ref(sys_ref)
                if nic_ref:
                    if pkt_eth.src == self._get_nic_MAC_addr(nic_ref):
                        #*** Source MAC addr matches the NIC MAC address
                        return True
                    if pkt_eth.dst == self._get_nic_MAC_addr(nic_ref):
                        #*** Dest MAC addr matches the NIC MAC address
                        return True                        
                    if pkt_ip4:                                         
                        if pkt_ip4.src == self._get_nic_ip4_addr(nic_ref):
                            #*** Source IP addr matches the NIC identity IP
                            return True
                        if pkt_ip4.dst == self._get_nic_ip4_addr(nic_ref):
                            #*** Dest IP addr matches the NIC identity IP
                            return True                                
            else:
                #*** Didn't match that LLDP Chassis ID so return false:
                return False  
        elif ((policy_attr == "identity_lldp_systemname") or 
              (policy_attr == "identity_lldp_systemname_re")):
            sys_ref = self._get_sys_ref_by_systemname(policy_attr, policy_value)
            if sys_ref:
                #*** Have matched a record with that system name, now check 
                #*** if the packet relates to that system:
                nic_ref = self._get_sys_nic_ref(sys_ref)
                if nic_ref:
                    if pkt_eth.src == self._get_nic_MAC_addr(nic_ref):
                        #*** Source MAC addr matches the NIC MAC address
                        return True
                    if pkt_eth.dst == self._get_nic_MAC_addr(nic_ref):
                        #*** Dest MAC addr matches the NIC MAC address
                        return True                        
                    if pkt_ip4:                                          
                        if pkt_ip4.src == self._get_nic_ip4_addr(nic_ref):
                            #*** Source IP addr matches the NIC identity IP
                            return True
                        if pkt_ip4.dst == self._get_nic_ip4_addr(nic_ref):
                            #*** Dest IP addr matches the NIC identity IP
                            return True        
            else:
                #*** Didn't match that LLDP system name so return false:
                return False          
        else:
            self.logger.error("ERROR: module=tc_identity Policy attribute %s did not match", policy_attr)
            return False

    def lldp_in(self, pkt, dpid, inport):
        """
        Passed an lldp packet, a Data Path ID (dpid) and in port
        and update identity tables (if required) with this identity
        information
        """
        _pkt_lldp = pkt.get_protocol(lldp.lldp)
        if (_pkt_lldp):
            _tlv_chassis_id = _pkt_lldp.tlvs[0]
            _chassis_id = _tlv_chassis_id.chassis_id
            _chassis_id_text = addrconv.mac.bin_to_text(_chassis_id)
            _tlv_system_name = _pkt_lldp.tlvs[3]
            _system_name = _tlv_system_name.tlv_info
            _table_ref = self._get_sys_ref_by_chassisid(_chassis_id_text)
            if _table_ref:
                #*** Update the last seen timestamp on the System table entry:
                self._sys_identity_table[_table_ref]['time_last'] = time.time()
            else:
                #*** Add a new record to the System table:
                self._set_sys_record_new_chassisid(_chassis_id_text, _system_name, pkt, dpid, inport)
        else:
            self.logger.warning("WARNING: module=tc_identity Passed an LLDP packet that did not parse properly")
            return(0)

    def ip4_in(self, pkt):
        """
        Passed an IPv4 packet
        and update NIC identity table (if required) with the IPv4
        address if the MAC address matches an entry
        """
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip4:
            #*** Get the NIC identity table reference for the source MAC address
            #*** (if it exists):
            _nic_table_ref = self._get_nic_ref_by_MAC(pkt_eth.src)
            if _nic_table_ref:
                #*** Write the IP address to this table row:
                self._set_nic_record_add_IP4_addr(_nic_table_ref, pkt_ip4.src)
        else:
            self.logger.warning("WARNING: module=tc_identity Passed an IPv4 packet that did not parse properly")
            return(0)

    def get_identity_nic_table(self):
        """
        Return the Identity NIC table
        """
        return self._nic_identity_table
        
    def get_identity_system_table(self):
        """
        Return the Identity System table
        """
        return self._sys_identity_table
        
    def maintain_identity_tables(self, max_age_nic, max_age_sys):
        """
        Deletes old entries from Identity NIC and 
        System tables.
        This function is passed maximum age values
        and deletes any entries in the
        tables that have a time_last that is
        older than that when compared to
        current time
        """
        _time = time.time()
        _for_deletion = []
        for _table_ref in self._nic_identity_table:
            if self._nic_identity_table[_table_ref]['time_last']:
                _last = self._nic_identity_table[_table_ref]['time_last']
                if (_time - _last > max_age_nic):
                    self.logger.debug("DEBUG: module=tc_identity Deleting NIC table ref %s", _table_ref)
                    #*** Can't delete while iterating dictionary so just note the table ref:
                    _for_deletion.append(_table_ref)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            del self._nic_identity_table[_del_ref]
        #*** Now do same for system identity table:
        _for_deletion = []
        for _table_ref in self._sys_identity_table:
            if self._sys_identity_table[_table_ref]['time_last']:
                _last = self._sys_identity_table[_table_ref]['time_last']
                if (_time - _last > max_age_sys):
                    self.logger.debug("DEBUG: module=tc_identity Deleting System table ref %s", _table_ref)
                    #*** Can't delete while iterating dictionary so just note the table ref:
                    _for_deletion.append(_table_ref)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            del self._sys_identity_table[_del_ref]
            

    def _get_sys_ref_by_chassisid(self, chassis_id_text):
        """
        Passed a Chassis ID in text format and check to
        see if it already exists in the system identity table. 
        If it does, return the table reference otherwise
        return 0
        """
        for table_ref in self._sys_identity_table:
            if (chassis_id_text == self._sys_identity_table[table_ref]['chassis_id']):
                return(table_ref)
        return(0)
        
    def _get_sys_ref_by_systemname(self, policy_attr, systemname):
        """
        Passed a system name in text format and check to
        see if it already exists in the system identity table. 
        If it does, return the table reference otherwise
        return 0
        """
        if policy_attr == 'identity_lldp_systemname': 
            for table_ref in self._sys_identity_table:
                if (systemname == self._sys_identity_table[table_ref]['system_name']):
                    return(table_ref)
            return(0)
        elif policy_attr == 'identity_lldp_systemname_re':
            for table_ref in self._sys_identity_table:
                if (re.match(systemname, self._sys_identity_table[table_ref]['system_name'])):
                    return(table_ref)
            return(0)
        else:
            return(0)           
        
    def _get_nic_ref_by_MAC(self, mac_addr):
        """
        Check for a matching NIC record in NIC identity table.
        Passed a MAC address
        Check if the MAC address is recorded in the
        table and if so, return the table reference.
        """       
        for table_ref in self._nic_identity_table:
            if (mac_addr == self._nic_identity_table[table_ref]['mac_addr']):
                self.logger.debug("DEBUG: module=tc_identity Matched on nic table_ref %s", table_ref)
                return(table_ref)
        return(0)

    def _get_nic_MAC_addr(self, table_ref):
        """
        Check for existance of an IPv4 address in NIC identity table
        record as per passed reference. If an IPv4 address is recorded
        return it otherwise return 0.
        """
        result = self._nic_identity_table[table_ref]['mac_addr']
        return(result)
        
    def _get_nic_ip4_addr(self, table_ref):
        """
        Check for existence of an IPv4 address in NIC identity table
        record as per passed reference. If an IPv4 address is recorded
        return it otherwise return 0.
        """
        result = self._nic_identity_table[table_ref]['ip4_addr']
        return(result)

    def _get_sys_nic_ref(self, sys_ref):
        """
        Return reference to a NIC table (if it exists) from a 
        system identity table entry, otherwise return 0
        """
        result = self._sys_identity_table[sys_ref]['nic_table_ref']
        return(result)
        
    def _set_sys_record_new_chassisid(self, chassis_id_text, system_name, pkt, dpid, inport):
        """
        Record a new system identity into the system identity table.
        Passed an LLDP Chassis ID in text format, an LLDP system name,
        a packet, a Data Path ID (dpid)
        and in port and write a row describing this identity into the
        system identity table. Check the NIC identity table and update
        this too if required.
        """
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        #*** Check to see if a NIC identity table record exists
        #*** and if not create one:
        _nic_table_ref = self._get_nic_ref_by_MAC(eth.src)
        if not _nic_table_ref:
            _nic_table_ref = self._set_nic_record_new(pkt, dpid, inport)
        #*** Write a new row into the system identity table:
        self._sys_identity_table[self._sys_id_ref] = {'chassis_id' : chassis_id_text,
                                                      'system_name' : system_name,
                                                      'nic_table_ref' : _nic_table_ref,
                                                      'time_first' : time.time(),
                                                      'time_last' : time.time()
                                                      }         
        #*** Update the NIC table ref with a reference back to the system identity table:
        self._set_nic_record_add_sys_ref(_nic_table_ref, self._sys_id_ref)
        self.logger.debug("DEBUG: module=tc_identity Adding new sys identity table entry: %s ref: %s",
                          self._sys_identity_table[self._sys_id_ref], self._sys_id_ref)
        #*** increment table ref:
        self._sys_id_ref += 1
        
    def _set_nic_record_new(self, pkt, dpid, inport):
        """
        Create a new NIC identity record and return
        the table reference
        """
        eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        #*** add the source MAC address:
        self._nic_identity_table[self._nic_id_ref]['mac_addr'] = eth.src
        #*** add the source IP (if we have one):
        if (pkt_ip4):
            self._nic_identity_table[self._nic_id_ref]['ip4_addr'] =  pkt_ip4.src
        #*** add details about the switch port:
        self._nic_identity_table[self._nic_id_ref]['dpid'] = dpid
        self._nic_identity_table[self._nic_id_ref]['inport'] = inport
        #*** add timestamps:
        self._nic_identity_table[self._nic_id_ref]['time_first'] = time.time()
        self._nic_identity_table[self._nic_id_ref]['time_last'] = time.time()
        #*** record table ref:
        table_ref = self._nic_id_ref
        self.logger.debug("DEBUG: module=tc_identity Adding new NIC identity table entry: %s ref: %s",
                          self._nic_identity_table[table_ref], table_ref)        
        #*** increment table ref:
        self._nic_id_ref += 1
        #*** return a reference to the table row:
        return(table_ref)
        
    def _set_nic_record_add_sys_ref(self, nic_ref, sys_ref):
        """
        Update an existing NIC identity record with a sys identity
        table reference
        """
        self._nic_identity_table[nic_ref]['sys_ref'] = sys_ref
        self.logger.debug("DEBUG: module=tc_identity Adding sys_ref: %s to nic_ref: %s", sys_ref, nic_ref)
        #*** Update timestamp:
        self._nic_identity_table[nic_ref]['time_last'] = time.time()
        
    def _set_nic_record_add_IP4_addr(self, nic_ref, ip4_addr):
        """
        Update an existing NIC identity record with an IPv4
        address
        """
        self._nic_identity_table[nic_ref]['ip4_addr'] = ip4_addr
        self.logger.debug("DEBUG: module=tc_identity Adding ip4_addr: %s to nic_ref: %s", ip4_addr, nic_ref)
        #*** Update timestamp:
        self._nic_identity_table[nic_ref]['time_last'] = time.time()       

