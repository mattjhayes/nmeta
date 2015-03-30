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

    def check_identity(self, policy_attr, policy_value, pkt, ctx):
        """
        Passed an identity attribute, value and packet and
        return True or False based on whether or not the packet strongly
        correlates to the identity attribute/value
        """
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ip6 = pkt.get_protocol(ipv6.ipv6)
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
            sys_ref = self._get_sys_ref_by_systemname(policy_attr,
                                                           policy_value)
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

        elif policy_attr == "identity_service_dns":
            #*** Look up service in id_ip structure:
            ips = []
            if pkt_ip4:
                #*** turn the src and dst IPs into a list so can iterate:
                ips = [pkt_ip4.src, pkt_ip4.dst]
            if pkt_ip6:
                #*** turn the src and dst IPs into a list so can iterate:
                ips = [pkt_ip6.src, pkt_ip6.dst]
            if ctx in self.id_ip:
                ip_ctx = self.id_ip[ctx]
                for ip in ips:
                    if ip in self.id_ip[ctx]:
                        ip_ctx_ip = ip_ctx[ip]
                        if 'service' in ip_ctx_ip:
                            for service in ip_ctx_ip['service']:
                                if service == policy_value:
                                    #*** Matched service but is it valid?:
                                    if self.valid_id_ip_service(ctx, ip,
                                                                    service):
                                        return True

        elif policy_attr == "identity_service_dns_re":
            #*** Look up service in id_ip structure:
            ips = []
            if pkt_ip4:
                #*** turn the src and dst IPs into a list so can iterate:
                ips = [pkt_ip4.src, pkt_ip4.dst]
            if pkt_ip6:
                #*** turn the src and dst IPs into a list so can iterate:
                ips = [pkt_ip6.src, pkt_ip6.dst]
            if ctx in self.id_ip:
                ip_ctx = self.id_ip[ctx]
                for ip in ips:
                    if ip in self.id_ip[ctx]:
                        ip_ctx_ip = ip_ctx[ip]
                        if 'service' in ip_ctx_ip:
                            for service in ip_ctx_ip['service']:
                                if (re.match(policy_value, service)):
                                    #*** Matched service but is it valid?:
                                    if self.valid_id_ip_service(ctx, ip,
                                                                    service):
                                        return True

        else:
            self.logger.error("Policy attribute %s did not match", policy_attr)
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
                self._set_sys_record_new_chassisid(_chassis_id_text, 
                                               _system_name, pkt, dpid, inport)
        else:
            self.logger.warning("Passed an LLDP packet that did not parse "
                                       "properly")
            return(0)

    def dns_reply_in(self, queries, answers, ctx):
        """
        Passed a DNS parameters and a context
        and add to relevant metadata
        """
        #*** TBD: Need to add security to this... Checks are
        #*** needed to ensure that the answer is a response
        #*** to a query, and that the relevant fields match
        #*** to ensure response is not spoofed.
        for qname in queries:
            self.logger.debug("dns_query=%s", qname.name)
        for answer in answers:
            if answer.type == 1:
                #*** DNS A Record:
                answer_ip = socket.inet_ntoa(answer.rdata)
                answer_name = answer.name
                answer_ttl = answer.ttl
                self.logger.debug("dns_answer_name=%s dns_answer_A=%s "
                                "answer_ttl=%s", 
                                answer_name, answer_ip, answer_ttl)
                #*** Make sure context key exists:
                self.id_ip.setdefault(ctx, {})
                if not answer_ip in self.id_ip[ctx]:
                    #*** MAC not in table, add it:
                    self.id_ip[ctx].setdefault(answer_ip, {})
                #*** Ensure 'service' key exists:
                self.id_ip[ctx][answer_ip].setdefault('service', {})
                #*** Check if know mapping to service:
                if not answer_name in self.id_ip[ctx][answer_ip]['service']:
                    #*** Add service name to this IP:
                    self.id_ip[ctx][answer_ip]['service'][answer_name] = {}
                #*** Update time last seen and set source attribution:
                svc = self.id_ip[ctx][answer_ip]['service'][answer_name]
                svc['last_seen'] = time.time()
                svc['ttl'] = answer_ttl
                svc['source'] = 'dns'
                #*** Check if service is a CNAME for another domain:
                #*** Make sure context key exists:
                self.id_service.setdefault(ctx, {})
                if answer_name in self.id_service[ctx]:
                    #*** Add the original domain to the IP so that
                    #*** rules can be written for services without
                    #*** needing to understand CNAMES
                    #*** Update the service that is the cname to ref this:
                    svc['source'] = 'dns_cname'
                    #*** Could be multiple original domains for the cname:
                    odom_dict = self.id_service[ctx][answer_name]['domain']
                    for odom_value in odom_dict:
                        ipsvcodom = self.id_ip[ctx][answer_ip]['service'] \
                                                .setdefault(odom_value, {})
                        ipsvcodom['last_seen'] = time.time()
                        ipsvcodom['ttl'] = answer.ttl
                        ipsvcodom['source'] = 'dns'
            elif answer.type == 5:
                #*** DNS CNAME Record:
                answer_cname = answer.cname
                answer_name = answer.name
                self.logger.debug("dns_answer_name=%s dns_answer_CNAME=%s", 
                                answer_name, answer_cname)
                svc_ctx = self.id_service.setdefault(ctx, {})
                svc_cname = svc_ctx.setdefault(answer_cname, {})
                svc_cname['type'] = 'dns_cname'
                svc_cname_dom = svc_cname.setdefault('domain', {})
                svc_cname_dom_a = svc_cname_dom.setdefault(answer.name, {})
                svc_cname_dom_a['last_seen'] = time.time()
                svc_cname_dom_a['ttl'] = answer.ttl
            else:
                #*** Not a type that we handle yet
                pass

    def arp_reply_in(self, arped_ip, arped_mac, ctx):
        """
        Passed an IPv4 ARP reply MAC and IPv4 address and a context
        and add to relevant metadata
        """
        #*** Make sure context key exists:
        self.id_mac.setdefault(ctx, {})
        if not arped_mac in self.id_mac[ctx]:
            #*** MAC not in table, add it:
            self.id_mac[ctx].setdefault(arped_mac, {})
        #*** Ensure 'ip' key exists:
        self.id_mac[ctx][arped_mac].setdefault('ip', {})
        #*** Check if know mapping to IPv4 addr:
        if not arped_ip in self.id_mac[ctx][arped_mac]['ip']:
            #*** Add IP to this MAC:
            self.id_mac[ctx][arped_mac]['ip'][arped_ip] = {}
        #*** Update time last seen and set source attribution:
        self.id_mac[ctx][arped_mac]['ip'][arped_ip]['last_seen'] = time.time()
        self.id_mac[ctx][arped_mac]['ip'][arped_ip]['source'] = 'arp'

    def ip4_in(self, pkt):
        """
        Passed an IPv4 packet
        and update NIC identity table (if required) with the IPv4
        address if the MAC address matches an entry
        """
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip4:
            #*** Get the NIC identity table reference for the source
            #*** MAC address (if it exists):
            _nic_table_ref = self._get_nic_ref_by_MAC(pkt_eth.src)
            if _nic_table_ref:
                #*** Write the IP address to this table row:
                self._set_nic_record_add_IP4_addr(_nic_table_ref, pkt_ip4.src)
        else:
            self.logger.warning("Passed an IPv4 packet that did not parse"
                                "properly")
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

    def maintain_identity_tables(self):
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
                if (_time - _last > self.max_age_nic):
                    self.logger.debug("Deleting NIC"
                                      " table ref id=%s", _table_ref)
                    #*** Can't delete while iterating dictionary so just note
                    #***  the table ref:
                    _for_deletion.append(_table_ref)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            del self._nic_identity_table[_del_ref]
        #*** Now do same for system identity table:
        _for_deletion = []
        for _table_ref in self._sys_identity_table:
            if self._sys_identity_table[_table_ref]['time_last']:
                _last = self._sys_identity_table[_table_ref]['time_last']
                if (_time - _last > self.max_age_sys):
                    self.logger.debug("Deleting "
                                      "System table ref id=%s", _table_ref)
                    #*** Can't delete while iterating dictionary so just note
                    #***  the table ref:
                    _for_deletion.append(_table_ref)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            del self._sys_identity_table[_del_ref]

        #*** Maintain the id_mac structure:
        _for_deletion = []
        self.logger.debug("Maintaining the id_mac structure")
        for ctx in self.id_mac:
            mac_ctx = self.id_mac[ctx]
            for mac in mac_ctx:
                mac_ctx_mac = mac_ctx[mac]
                for ip in mac_ctx_mac['ip']:
                    mac_ctx_mac_ip = mac_ctx_mac['ip'][ip]
                    last_seen = mac_ctx_mac_ip['last_seen']
                    #*** Has the ARP not been seen for more than max age?: 
                    if (last_seen + self.arp_max) < _time:
                        #*** Mark for deletion:
                        del_dict = {'ctx': ctx, 'mac': mac, 'ip': ip}
                        _for_deletion.append(del_dict)
                        age = _time - last_seen
                        self.logger.debug("marking ARP ip=%s mac=%s age=%s "
                                     "seconds for deletion", ip, mac, age)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            ctx = _del_ref['ctx']
            mac = _del_ref['mac']
            ip = _del_ref['ip']
            del self.id_mac[ctx][mac]['ip'][ip]
            #*** TBD: check if that was the only IP for that MAC and if so
            #*** delete the MAC:
            if self.id_mac[ctx][mac]['ip'] == {}:
                del self.id_mac[ctx][mac]['ip']
                if self.id_mac[ctx][mac] == {}:
                    del self.id_mac[ctx][mac]

        #*** Maintain the id_ip structure:
        _for_deletion = []
        self.logger.debug("Maintaining the id_ip structure")
        for ctx in self.id_ip:
            ip_ctx = self.id_ip[ctx]
            for ip in ip_ctx:
                ip_ctx_ip = ip_ctx[ip]
                if 'service' in ip_ctx_ip:
                    for service in ip_ctx_ip['service']:
                        ip_ctx_ip_svc = ip_ctx_ip['service'][service]
                        self.logger.debug("service is %s", service)
                        if ip_ctx_ip_svc['source'] == 'dns' or \
                                        ip_ctx_ip_svc['source'] == 'dns_cname':
                            self.logger.debug("source is dns or dns_cname")
                            last_seen = ip_ctx_ip_svc['last_seen']
                            ttl = ip_ctx_ip_svc['ttl']
                            if (last_seen + ttl) < _time:
                                #*** Mark for deletion:
                                del_dict = {'ctx': ctx, 'ip': ip, 
                                                 'service': service}
                                _for_deletion.append(del_dict)
                                self.logger.debug("marking IP del_dict=%s "
                                     "for deletion", del_dict)
        #*** Now iterate over the list of references to delete:
        for _del_ref in _for_deletion:
            ctx = _del_ref['ctx']
            ip = _del_ref['ip']
            service = _del_ref['service']
            del self.id_ip[ctx][ip]['service'][service]
            #*** also delete the IP address if no other services or other keys
            #*** exist:
            if self.id_ip[ctx][ip]['service'] == {}:
                del self.id_ip[ctx][ip]['service']
                if self.id_ip[ctx][ip] == {}:
                    self.logger.debug("struct=id_ip deleting ip=%s", ip)
                    del self.id_ip[ctx][ip]

    def _get_sys_ref_by_chassisid(self, chassis_id_text):
        """
        Passed a Chassis ID in text format and check to
        see if it already exists in the system identity table. 
        If it does, return the table reference otherwise
        return 0
        """
        for table_ref in self._sys_identity_table:
            if (chassis_id_text == self._sys_identity_table[table_ref] \
                                ['chassis_id']):
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
                if (systemname == self._sys_identity_table[table_ref] \
                                            ['system_name']):
                    return(table_ref)
            return(0)
        elif policy_attr == 'identity_lldp_systemname_re':
            for table_ref in self._sys_identity_table:
                if (re.match(systemname, self._sys_identity_table[table_ref] \
                                            ['system_name'])):
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

