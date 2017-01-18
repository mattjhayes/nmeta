"""
nmeta switch abstraction unit tests
"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta')

#*** For tests that need a logger:
import logging
logger = logging.getLogger(__name__)

#*** Testing imports:
import mock
import unittest

#*** Ryu imports:
from ryu.base import app_manager  # To suppress cyclic import
from ryu.controller import controller
from ryu.controller import handler
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_2_parser
from ryu.ofproto import ofproto_v1_0_parser
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.app.wsgi import route

#*** nmeta imports:
import switches
import config

#*** Instantiate Config class:
config = config.Config()

#====================== switch_abstraction.py Unit Tests ======================
#*** Instantiate class:
switches = switches.Switches(config)

sock_mock = mock.Mock()
addr_mock = mock.Mock()

#*** Constant to use for a port not found value:
PORT_NOT_FOUND = 999999999

#*** Test Constants:
MAC123 = '00:00:00:00:01:23'
PORT123 = 123
CONTEXT1 = 1

MAC456 = '00:00:00:00:04:56'
PORT456 = 456
CONTEXT2 = 2

#*** Test Switches and Switch classes that abstract OpenFlow switches:
def test_switches():
    with mock.patch('ryu.controller.controller.Datapath.set_state'):
        #*** Set up fake switch datapaths:
        datapath1 = controller.Datapath(sock_mock, addr_mock)
        datapath1.id = 12345
        datapath1.address = ('172.16.1.10', 12345)
        datapath2 = controller.Datapath(sock_mock, addr_mock)
        datapath2.id = 67890
        datapath2.address = ('172.16.1.11', 23456)

        #*** Should have 0 switches:
        assert len(switches.switches) == 0
        assert switches.switches_col.count() == 0

        #*** Add switches
        assert switches.add(datapath1) == 1
        assert switches.add(datapath2) == 1

        #*** Should have 2 switches:
        assert len(switches.switches) == 2
        assert switches.switches_col.count() == 2

        #*** Delete switch
        assert switches.delete(datapath2) == 1

        #*** Should have 1 switch:
        assert len(switches.switches) == 1
        assert switches.switches_col.count() == 1

# TBD
