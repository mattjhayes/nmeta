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

#*** nmeta - Network Metadata
#
# Matt Hayes
# Victoria University, New Zealand
# matthew_john_hayes@hotmail.com
# October 2014
#
# Version 8.7

"""
This is the main module of the nmeta suite running on top of Ryu SDN controller
to provide network identity and flow (traffic classification) metadata
.
Do not use this code for production deployments - it is proof of concept code
and carries no warrantee whatsoever. You have been warned.
"""

#*** REST API Calls (examples to run on local host):
#
#*** Return the Flow Metadata Table:
#*** curl -X GET http://127.0.0.1:8080/nmeta/flowtable/
#
#*** Return the Identity NIC Table:
#*** curl -X GET http://127.0.0.1:8080/nmeta/identity/nictable/
#
#*** Return the Identity System Table:
#*** curl -X GET http://127.0.0.1:8080/nmeta/identity/systemtable/


#*** General Imports:
import logging
import struct
import time
import binascii

#*** Ryu Imports:
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib import addrconv
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import lldp
from ryu.exception import RyuException

#*** nmeta imports:
import flow
import tc_policy
import config
import versionsafe

#*** Web API REST imports:
from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json

#*** YAML for config and policy file parsing:
import yaml

#*** Rulers for PEP8 line length compliance:
#============== For PEP8 this is 79 characters long... ========================
#========== For PEP8 DocStrings this is 72 characters long... ==========

#*** Constants for REST API:
REST_RESULT = 'result'
REST_NG = 'failure'
REST_DETAILS = 'details'
nmeta_instance_name = 'nmeta_api_app'

class NMeta(app_manager.RyuApp):
    """
    This is the main class used to run nmeta
    """
    #*** Supports OpenFlow versions 1.0 and 1.3:
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION] 
                    
    #*** Constants for REST API:
    url_flowtable =             '/nmeta/flowtable/'
    url_flowtable_by_ip =       '/nmeta/flowtable/{ip}'
    url_identity_nic_table =    '/nmeta/identity/nictable/'
    url_identity_system_table = '/nmeta/identity/systemtable/'
    #
    IP_PATTERN = r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$){4}\b'
    _CONTEXTS = { 'wsgi': WSGIApplication }
    

    def __init__(self, *args, **kwargs):
        super(NMeta, self).__init__(*args, **kwargs)
        #*** Instantiate config class which imports configuration file 
        #*** config.yaml and provides access to keys/values:
        self.config = config.Config()
        #*** Set up logging to write to syslog:
        logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', 
            level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(
                        address = ('localhost', 514),
                        facility=19)
        self.logger.addHandler(self.handler)
        #*** Set up variables:        
        #*** Get max bytes of new flow packets to send to controller from 
        #*** config file:
        self.miss_send_len = self.config.get_value("miss_send_len")
        if (self.miss_send_len < 1500):
            self.logger.info("INFO:  module=nmeta Be aware that setting "
                             "miss_send_len to less than a full size packet " 
                             "may result in errors due to truncation. "
                             "Configured value is %s bytes",
                             self.miss_send_len)
        #*** Tell switch how to handle fragments (see OpenFlow spec):
        self.ofpc_frag = self.config.get_value("ofpc_frag")
        
        #*** Table maintenance settings from config.yaml file:
        self.fm_table_max_age = self.config.get_value('fm_table_max_age')
        if not self.fm_table_max_age:
            self.fm_table_max_age = 30
            self.logger.warning("WARNING:  module=nmeta config.yaml did not have value for "
                             "fm_table_max_age so setting value to %s", self.fm_table_max_age)
        self.fm_table_tidyup_interval = self.config.get_value('fm_table_tidyup_interval')
        if not self.fm_table_tidyup_interval:
            self.fm_table_tidyup_interval = 10
            self.logger.warning("WARNING:  module=nmeta config.yaml did not have value for "
                             "fm_table_tidyup_interval so setting value to %s", self.fm_table_tidyup_interval) 
        self.identity_nic_table_max_age = self.config.get_value('identity_nic_table_max_age')
        if not self.identity_nic_table_max_age:
            self.identity_nic_table_max_age = 600
            self.logger.warning("WARNING:  module=nmeta config.yaml did not have value for "
                             "identity_nic_table_max_age so setting value to %s", self.identity_nic_table_max_age)        
        self.identity_system_table_max_age = self.config.get_value('identity_system_table_max_age')
        if not self.identity_system_table_max_age:
            self.identity_system_table_max_age = 600
            self.logger.warning("WARNING:  module=nmeta config.yaml did not have value for "
                             "identity_system_table_max_age so setting value to %s", self.identity_system_table_max_age)        
        self.identity_table_tidyup_interval = self.config.get_value('identity_table_tidyup_interval')
        if not self.identity_table_tidyup_interval:
            self.identity_table_tidyup_interval = 5
            self.logger.warning("WARNING:  module=nmeta config.yaml did not have value for "
                             "identity_table_tidyup_interval so setting value to %s", self.identity_table_tidyup_interval) 
        #*** Set initial value of the variable that holds last time for tidy-ups:
        self.fm_table_last_tidyup_time = time.time()
        self.identity_table_last_tidyup_time = time.time()        
        #*** Initiate the mac_to_port dictionary for switching:
        self.mac_to_port = {}
        #*** Set up REST API:
        wsgi = kwargs['wsgi'] 
        self.data = {nmeta_instance_name: self}        
        mapper = wsgi.mapper
        wsgi.register(RESTAPIController, {nmeta_instance_name : self})
	requirements = {'ip': self.IP_PATTERN}
        mapper.connect('flowtable', self.url_flowtable, 
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_flow_table',
                       conditions=dict(method=['GET']))	
        mapper.connect('flowtable', self.url_flowtable_by_ip, 
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_flow_table_by_ip',
                       conditions=dict(method=['GET']))	
        mapper.connect('flowtable', self.url_identity_nic_table, 
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_identity_nic_table',
                       conditions=dict(method=['GET']))	
        mapper.connect('flowtable', self.url_identity_system_table, 
                       controller=RESTAPIController,
                       requirements=requirements,
                       action='list_identity_system_table',
                       conditions=dict(method=['GET']))	                        
        #*** Instantiate Classes:
        self.flowmetadata = flow.FlowMetadata()
        self.tc_policy = tc_policy.TrafficClassificationPolicy()
        self.vs = versionsafe.VersionSafe()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connection_handler(self, ev):
        """ 
        Set switch miss_send_len parameter in bytes.
        A larger value can help avoid truncated packets
        """            
        datapath = ev.msg.datapath
        self.logger.info("INFO:  module=nmeta Setting config on switch "
                         "datapath %s to OFPC_FRAG flag %s and "
                         "miss_send_len %s bytes",
                          datapath.id, self.ofpc_frag, self.miss_send_len)
        if datapath.ofproto.OFP_VERSION == 1:
            _of_version = "1.0"
        elif datapath.ofproto.OFP_VERSION == 4:
            _of_version = "1.3"
        else:
            _of_version = "Unknown version " + str(datapath.ofproto.OFP_VERSION)
        self.logger.debug("DEBUG:  module=nmeta Switch OpenFlow version is %s", _of_version)
        datapath.send_msg(datapath.ofproto_parser.OFPSetConfig(
                                     datapath,
                                     self.ofpc_frag,
                                     self.miss_send_len))   
        
    def add_flow(self, datapath, match, actions):
        """ 
        Add a flow match to a switch:
        """
        ofproto = datapath.ofproto
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=5, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        A switch has sent us a Packet In event
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)  
        dst = eth.dst
        src = eth.src
        
        inport = self.vs.get_in_port(msg, datapath, ofproto)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        #*** Some debug about the Packet In:
        pkt_ip4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            self.logger.debug("DEBUG: module=nmeta Packet In: dpid:%s in_port:"
                              "%s TCP %s %s %s %s", 
                              dpid, inport, pkt_ip4.src, 
                              pkt_tcp.src_port, pkt_ip4.dst, pkt_tcp.dst_port)
        elif pkt_ip4:
            self.logger.debug("DEBUG: module=nmeta Packet In: dpid:%s in_port:"
                              "%s IP src %s dst %s proto %s",
                              dpid, inport, 
                              pkt_ip4.src, pkt_ip4.dst, pkt_ip4.proto)
        else:
            self.logger.debug("DEBUG: module=nmeta Packet In: dpid:%s in_port:"
                             "%s src:%s dst:%s", dpid, inport, src, dst) 
        #*** Traffic Classification:
        #*** Check traffic classification policy to see if packet matches  
        #*** against policy and if it does return a dictionary of actions:
        flow_actions = self.tc_policy.check_policy(pkt, dpid, inport)       
        #*** Forwarding Decision:
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = inport
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD  
        
        #*** Call Flow Metadata to get a match to install (if desired)
        #*** and output queue:
        (match, output_queue) = self.flowmetadata.update_flowmetadata(msg, 
                                                          out_port, 
                                                          flow_actions)
        #*** Check to see if we have a flow to install:
        if match:                                                          
            #*** Build an action of output port(s) and QoS queueing treatment:
            actions = [datapath.ofproto_parser.OFPActionEnqueue(out_port, 
                       output_queue)]        
            self.logger.debug("DEBUG: module=nmeta Installing actions "
                              "%s on datapath %s", actions, datapath.id)                
            #*** Install flow match to switch:
            self.add_flow(datapath, match, actions)         
        #*** Packet Out:
        action = [datapath.ofproto_parser.OFPActionOutput(out_port, )]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=inport,
            actions=action)
        datapath.send_msg(out)
        
        #*** Now check if table maintenance is needed:
        #*** Flow Metadata (FM) table maintenance:
        _time = time.time()
        if ((_time - self.fm_table_last_tidyup_time) > self.fm_table_tidyup_interval):
            #*** Call function to do tidy-up on the Flow Metadata (FM) table:
            self.logger.debug("DEBUG: module=nmeta Calling function to do tidy-up on the Flow Metadata (FM) table")
            self.flowmetadata.maintain_fm_table(self.fm_table_max_age)
        #*** Identity NIC and System table maintenance:
        _time = time.time()
        if ((_time - self.identity_table_last_tidyup_time) > self.identity_table_tidyup_interval):
            #*** Call function to do tidy-up on the Identity NIC and System tables:
            self.logger.debug("DEBUG: module=nmeta Calling function to do tidy-up on the Identity NIC and System tables")
            self.tc_policy.identity.maintain_identity_tables(self.identity_nic_table_max_age,
                                                             self.identity_system_table_max_age)        

    
# REST command template
#*** Copied from the Ryu rest_router.py example code:
def rest_command(func):
    def _rest_command(*args, **kwargs):
        try:
            msg = func(*args, **kwargs)
            return Response(content_type='application/json',
                            body=json.dumps(msg))
        except SyntaxError as e:
            status = 400
            details = e.msg
        except (ValueError, NameError) as e:
            status = 400
            details = e.message
        except NotFoundError as msg:
            status = 404
            details = str(msg)
        msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
        return Response(status=status, body=json.dumps(msg))
    return _rest_command

class NotFoundError(RyuException):
    message = 'Error occurred talking to function <TBD>'

class RESTAPIController(ControllerBase):
    """
    This class is used to control REST API access to the
    nmeta data and control functions
    """
    def __init__(self, req, link, data, **config):
        super(RESTAPIController, self).__init__(req, link, data, **config)
        self.nmeta_parent_self = data[nmeta_instance_name]

    @rest_command
    def list_flow_table(self, req, **kwargs):
        """
        REST API function that returns contents of the 
        Flow Metadata (FM) table
        """
        nmeta = self.nmeta_parent_self
        _fm_table = nmeta.flowmetadata.get_fm_table()
        return _fm_table
    
    @rest_command
    def list_flow_table_by_IP(self, req, **kwargs):
        """
        REST API function that returns contents of the 
        Flow Metadata (FM) table filtered on an IP address
        (matches source or destination IP).
        .
        <TBD>
        """
        print "##### list_flow_table_by_IP"
        pass

    @rest_command
    def list_identity_nic_table(self, req, **kwargs):
        """
        REST API function that returns contents of the 
        Identity NIC table
        """
        nmeta = self.nmeta_parent_self
        _identity_nic_table = nmeta.tc_policy.identity.get_identity_nic_table()
        return _identity_nic_table

    @rest_command
    def list_identity_system_table(self, req, **kwargs):
        """
        REST API function that returns contents of the 
        Identity NIC table
        """
        nmeta = self.nmeta_parent_self
        _identity_system_table = nmeta.tc_policy.identity.get_identity_system_table()
        return _identity_system_table

@set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
def _port_status_handler(self, ev):
    """
    Switch Port Status event
    """
    msg = ev.msg
    reason = msg.reason
    port_no = msg.desc.port_no

    ofproto = msg.datapath.ofproto
    if reason == ofproto.OFPPR_ADD:
        self.logger.info("port added %s", port_no)
    elif reason == ofproto.OFPPR_DELETE:
        self.logger.info("port deleted %s", port_no)
    elif reason == ofproto.OFPPR_MODIFY:
        self.logger.info("port modified %s", port_no)
    else:
        self.logger.info("Illegal port state %s %s", port_no, reason)

#*** Borrowed from rest_router.py code:
def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]

