"""
nmeta tc_custom.py Tests

Uses pytest, install with:
    sudo apt-get install python-pytest

To run test, type in:
    py.test -vs

Note that packets + metadata are imported from local packets_* modules

TBD: everything

"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta')

import logging

#*** nmeta imports:
import nmeta
import config
import flows as flow_class
import identities as identities_class
import tc_policy
import tc_custom

#*** Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

#======================== tc_identity.py Tests ================================

def test_instantiate_classifiers():
    """
    Test instantiating custom classifiers
    """
    tc_cust = tc_custom.CustomInspect(config)
    tc_cust.instantiate_classifiers(['statistical_qos_bandwidth_1'])
    # TBD
