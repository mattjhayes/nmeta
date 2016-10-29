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
            result = ident.findbyservice(policy_value, harvest_type='DNS_A',
                                            ip_address=pkt.ip_src)
            if not result:
                result = ident.findbyservice(policy_value,
                                harvest_type='DNS_A', ip_address=pkt.ip_dst)
            self.logger.debug("TEMP: identity_service_dns DNS_A result=%s", result)
            if not result:
                result = ident.findbyservice(policy_value,
                                                      harvest_type='DNS_CNAME')
                self.logger.debug("TEMP: identity_service_dns DNS_CNAME result=%s", result)
                if result:
                    service_alias = result['service_alias']
                    result = ident.findbyservice(service_alias,
                                harvest_type='DNS_A', ip_address=pkt.ip_src)
                    if not result:
                        self.logger.debug("TEMP: pkt.ip_dst=%s service_alias=%s", pkt.ip_dst, service_alias)
                        result = ident.findbyservice(service_alias,
                                harvest_type='DNS_A', ip_address=pkt.ip_dst)
                    self.logger.debug("TEMP: identity_service_dns Second DNS_A result=%s", result)
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
            self.logger.debug("TEMP: result['ip_address']=%s", result['ip_address'])
            if pkt.ip_src == result['ip_address'] or \
                                            pkt.ip_dst == result['ip_address']:
                return True
            else:
                return False
        else:
            return False












