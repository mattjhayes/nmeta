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

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import logging
import logging.handlers
import struct
import time
import re

import socket

#*** Ryu imports:
from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import lldp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import tcp

#*** nmeta imports:
import nmisc

class IdentityInspect(object):
    """
    This class is instantiated by tc_policy.py
    (class: TrafficClassificationPolicy) and provides methods to
    ingest identity updates and query identities
    """
    def __init__(self, _config):
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('tc_identity_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('tc_identity_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _console_format = _config.get_value('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(address=(
                                                _loghost, _logport),
                                                facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            self.console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(_console_format)
            self.console_handler.setFormatter(console_formatter)
            self.console_handler.setLevel(_logging_level_c)
            #*** Add console log handler to logger:
            self.logger.addHandler(self.console_handler)

        #*** Instantiate the System and NIC Identity Tables (Legacy):
        self._sys_identity_table = nmisc.AutoVivification()
        self._nic_identity_table = nmisc.AutoVivification()
        #*** Identity Dictionaries
        #***  Let these be accessed directly to avoid overhead of getters:
        self.id_mac = {}
        self.id_ip = {}
        self.id_node = {}
        self.id_service = {}
        #*** Initialise Identity Tables unique reference numbers:
        #*** Start at 1 so that value 0 can be used for boolean
        #*** false on checks
        self._sys_id_ref = 1
        self._nic_id_ref = 1
        #*** Get config values for tidy up of dynamic data:
        self.max_age_nic = _config.get_value('identity_nic_table_max_age')
        self.max_age_sys = _config.\
                                     get_value('identity_system_table_max_age')
        self.arp_max = _config.get_value('identity_arp_max_age')

    def check_identity(self, policy_attr, policy_value, pkt, ident):
        """
        Passed an identity attribute, value and flows packet object and
        an instance of the identities class. Return True or False based
        on whether or not the packet strongly
        correlates to the identity attribute/value.
        Uses methods of the Identities class to work this out
        Returns boolean
        """
        if policy_attr == "identity_lldp_systemname":
            result = ident.findbynode(policy_value, harvest_type='LLDP')
        elif policy_attr == "identity_lldp_systemname_re":
            result = ident.findbynode(policy_value, harvest_type='LLDP',
                                                                    regex=True)
        elif policy_attr == "identity_service_dns":
            #*** Handle potential CNAME indirection:
            result = ident.findbyservice(policy_value, harvest_type='DNS_A')
            if not result:
                result = ident.findbyservice(policy_value,
                                                      harvest_type='DNS_CNAME')
                if result:
                    result = ident.findbyservice(result['service_alias'],
                                                          harvest_type='DNS_A')
        elif policy_attr == "identity_service_dns_re":
            #*** Handle potential CNAME indirection:
            result = ident.findbyservice(policy_value, harvest_type='DNS_A',
                                                                    regex=True)
            if not result:
                result = ident.findbyservice(policy_value,
                                          harvest_type='DNS_CNAME', regex=True)
                if result:
                    result = ident.findbyservice(result['service_alias'],
                                                          harvest_type='DNS_A')
        else:
            self.logger.error("Policy attribute %s did not match", policy_attr)
            return False

        if result:
            #*** Does the source or destination IP of the packet match?
            if pkt.ip_src == result['ip_address'] or \
                                            pkt.ip_dst == result['ip_address']:
                return True
            else:
                return False
        else:
            return False

    def valid_id_ip_service(self, ctx, ip, service):
        """
        Passed variables to look up a service in id_ip structure.
        Check that this service is valid (i.e. not stale)
        Return boolean
        """
        _time = time.time()
        svc = self.id_ip[ctx][ip]['service'][service]
        if 'source' in svc:
            if svc['source'] == 'dns' or svc['source'] == 'dns_cname':
                last_seen = svc['last_seen']
                ttl = svc['ttl']
                if (last_seen + ttl) > _time:
                    #*** TTL is current, so service is valid:
                    return True
        return False

    def get_augmented_fm_table(self, _flows):
        """
        Return the flow metadata table augmented with
        appropriate identity metadata
        """
        _result_dict = {}
        for idx in _flows:
            flow = _flows[idx]
            if 'ip_A' in flow:
                ip = flow['ip_A']
                #self.logger.debug("checking ip_A=%s", ip)
                for ctx in self.id_ip:
                    ip_ctx = self.id_ip[ctx]
                    if ip:
                        if ip in ip_ctx:
                            ip_ctx_ip = ip_ctx[ip]
                            #*** Found IP in id_ip, add any metadata to flow:
                            if 'service' in ip_ctx_ip:
                                flow['ip_A_services'] = ip_ctx_ip['service']
            if 'ip_B' in flow:
                ip = flow['ip_B']
                #self.logger.debug("checking ip_B=%s", ip)
                for ctx in self.id_ip:
                    ip_ctx = self.id_ip[ctx]
                    if ip:
                        if ip in ip_ctx:
                            ip_ctx_ip = ip_ctx[ip]
                            #*** Found IP in id_ip, add any metadata to flow:
                            if 'service' in ip_ctx_ip:
                                flow['ip_B_services'] = ip_ctx_ip['service']
            #*** Accumulate updated flows into results dict
            _result_dict[idx] = flow
        return _result_dict

    def _get_nic_ref_by_MAC(self, mac_addr):
        """
        Check for a matching NIC record in NIC identity table.
        Passed a MAC address
        Check if the MAC address is recorded in the
        table and if so, return the table reference.
        """
        for table_ref in self._nic_identity_table:
            if (mac_addr == self._nic_identity_table[table_ref]['mac_addr']):
                self.logger.debug("Matched on nic table_ref id=%s", table_ref)
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

    def _set_sys_record_new_chassisid(self, chassis_id_text, system_name, pkt,
                                                      dpid, inport):
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
        self._sys_identity_table[self._sys_id_ref] = \
            {
            'chassis_id' : chassis_id_text,
            'system_name' : system_name,
            'nic_table_ref' : _nic_table_ref,
            'time_first' : time.time(),
            'time_last' : time.time()
        }
        #*** Update the NIC table ref with a reference back to the system
        #*** identity table:
        self._set_nic_record_add_sys_ref(_nic_table_ref, self._sys_id_ref)
        self.logger.debug("Adding new sys identity table entry: %s ref: %s",
                          self._sys_identity_table[self._sys_id_ref],
                          self._sys_id_ref)
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
        self.logger.debug("Adding new NIC identity table entry: %s ref: %s",
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
        self.logger.debug("Adding sys_ref: %s to nic_ref: %s",
                                         sys_ref, nic_ref)
        #*** Update timestamp:
        self._nic_identity_table[nic_ref]['time_last'] = time.time()

    def _set_nic_record_add_IP4_addr(self, nic_ref, ip4_addr):
        """
        Update an existing NIC identity record with an IPv4
        address
        """
        self._nic_identity_table[nic_ref]['ip4_addr'] = ip4_addr
        self.logger.debug("Adding ip4_addr: %s to nic_ref: %s", ip4_addr, nic_ref)
        #*** Update timestamp:
        self._nic_identity_table[nic_ref]['time_last'] = time.time()

