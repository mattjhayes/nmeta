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

#*** For logging configuration:
from baseclass import BaseClass

class IdentityInspect(BaseClass):
    """
    This class is instantiated by tc_policy.py
    (class: TrafficClassificationPolicy) and provides methods to
    ingest identity updates and query identities
    """
    def __init__(self, config):
        #*** Required for BaseClass:
        self.config = config
        #*** Run the BaseClass init to set things up:
        super(IdentityInspect, self).__init__()
        #*** Set up Logging with inherited base class method:
        self.configure_logging("tc_identity_logging_level_s",
                                       "tc_identity_logging_level_c")

    def check_identity(self, condition, pkt, ident):
        """
        Checks if a given packet matches a given identity match rule.
        Passed condition, flows packet and identities objects and
        update the condition match based on whether or not either
        of the packet IP addresses matches the identity attribute/value.
        Uses methods of the Identities class to work this out
        """
        result = False
        if condition.policy_attr == "identity_lldp_systemname":
            result = self.check_lldp(condition.policy_value, pkt, ident)
        elif condition.policy_attr == "identity_lldp_systemname_re":
            result = self.check_lldp(condition.policy_value, pkt, ident,
                                                                is_regex=True)
        elif condition.policy_attr == "identity_service_dns":
            result = self.check_dns(condition.policy_value, pkt, ident)
        elif condition.policy_attr == "identity_service_dns_re":
            result = self.check_dns(condition.policy_value, pkt, ident,
                                                                is_regex=True)
        else:
            self.logger.error("Unknown policy_attr=%s", condition.policy_attr)
            result = False
        #*** Update the match object with the result:
        condition.match = result

    def check_lldp(self, host_name, pkt, ident, is_regex=False):
        """
        Passed a hostname, flows packet object, an instance of
        the identities class and a regex boolean (if true, hostname
        is treated as regex).
        Return True or False based on whether or not the packet has
        a source or destination IP address that matches the IP address
        registered to the given hostname (if one even exists).
        Uses methods of the Identities class to work this out.
        Returns boolean
        """
        result = ident.findbynode(host_name, harvest_type='LLDP',
                                                                regex=is_regex)
        if result:
            #*** Does the source or destination IP of the packet match?
            if pkt.ip_src == result['ip_address'] or \
                                            pkt.ip_dst == result['ip_address']:
                return True
            else:
                return False
        else:
            return False

    def check_dns(self, dns_name, pkt, ident, is_regex=False):
        """
        Passed a DNS name, flows packet object, an instance of
        the identities class and a regex boolean (if true, DNS name
        is treated as regex).
        Return True or False based on whether or not the packet has
        a source or destination IP address that has been resolved from the
        DNS name. Uses methods of the Identities class to work this out.
        Returns boolean
        """
        #*** Look up DNS name by Source IP:
        result = ident.findbyservice(dns_name, harvest_type='DNS_A',
                                                    ip_address=pkt.ip_src,
                                                    regex=is_regex)
        if not result:
            #*** Look up DNS name by Dest IP:
            result = ident.findbyservice(dns_name,
                                            harvest_type='DNS_A',
                                            ip_address=pkt.ip_dst,
                                            regex=is_regex)
            if not result:
                #*** Failed to find A record for NAME by Source or Dest IP
                result = ident.findbyservice(dns_name,
                                                harvest_type='DNS_CNAME',
                                                regex=is_regex)
                if result:
                    #*** Look up IP against the CNAME:
                    service_alias = result['service_alias']
                    result = ident.findbyservice(service_alias,
                                harvest_type='DNS_A', ip_address=pkt.ip_src)
                    if not result:
                        #*** Failed to find Source IP by CNAME
                        result = ident.findbyservice(service_alias,
                                harvest_type='DNS_A', ip_address=pkt.ip_dst)
                        if result:
                            #*** Found Dest IP by CNAME
                            return True
                        else:
                            #*** Failed to find Dest IP by CNAME
                            return False
                    else:
                        #*** Found Source IP by CNAME
                        return True
                else:
                    #*** Failed to find by CNAME
                    return False
            else:
                #*** Found A by Dest IP
                return True
        else:
            #*** Found A by Source IP
            return True










