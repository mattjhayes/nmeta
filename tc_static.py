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

#*** nmeta - Network Metadata - TC Static Class and Methods
#
# Matt Hayes
# Victoria University, New Zealand
# Version 0.3

"""
This module is part of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
"""

import logging
import logging.handlers
import struct
import time

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

class StaticInspect(object):
    """
    This class is instantiated by tc_policy.py 
    (class: TrafficClassificationPolicy) and provides methods to 
    query static traffic classification matches
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
        
    def check_static(self, policy_attr, policy_value, pkt):
        """
        Passed a static classification attribute, value and packet and
        return true or false based on whether or not the packet matches
        the attribute/value
        """
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)        
        if (policy_attr == 'eth_src'):
            if pkt_eth:
                if pkt_eth.src == policy_value:
                    return True
                else:
                    return False                      
        elif (policy_attr == 'eth_dst'):
            if pkt_eth:
                if pkt_eth.dst == policy_value:
                    return True
                else:
                    return False
        elif (policy_attr == 'eth_type'):
            if pkt_eth:
                if pkt_eth.ethertype == policy_value:
                    return True
                else:
                    return False
        elif (policy_attr == 'ip_src'):
            if pkt_ip4:
                if pkt_ip4.src == policy_value:
                    return True
                else:
                    return False                       
        elif (policy_attr == 'ip_dst'):
            if pkt_ip4:
                if pkt_ip4.dst == policy_value:
                    return True
                else:
                    return False   
        elif (policy_attr == 'tcp_src'):
            if pkt_tcp:
                if pkt_tcp.src_port == policy_value:
                    return True
                else:
                    return False                     
        elif (policy_attr == 'tcp_dst'):
            if pkt_tcp:
                if pkt_tcp.dst_port == policy_value:
                    return True
                else:
                    return False   
        else:
            #*** didn't match any policy conditions so return false and log an error:
            self.logger.error("ERROR: module=tc_static Policy attribute %s did not match", policy_attr)            
            return False                           
