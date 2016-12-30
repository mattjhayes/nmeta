"""
nmeta config.py Unit Tests
"""

#*** Handle tests being in different directory branch to app code:
import sys

sys.path.insert(0, '../nmeta')

import logging

#*** Testing imports:
import unittest

#*** toffca import:
import config

#*** Config file location parameters:
CONFIG_FILENAME = "config.yaml"
CONFIG_DIR_DEFAULT = "config"
CONFIG_DIR_USER = "config/tests/user"
#*** Config bad parameters to test error handling
CONFIG_BAD_PATH = "/foo/config.yaml"

logger = logging.getLogger(__name__)

#*** Instantiate Config class:
_config = config.Config(dir_default=CONFIG_DIR_DEFAULT,
                            dir_user=CONFIG_DIR_USER,
                            config_filename=CONFIG_FILENAME)

#*** Now set config module to log properly:
_config.inherit_logging(_config)

#======================== config.py Unit Tests =========================
class TestConfig(unittest.TestCase):
    def test_ingest(self):
        """
        Test ingesting a config file to YAML:
        """
        logger.debug("Testing bad config file location raises system exit")
        #*** Bad config file location should raise system exit:
        with self.assertRaises(SystemExit):
            assert _config.ingest_config_file(CONFIG_BAD_PATH) == {}

    def test_get_value(self):
        """
        Test retrieving values from config
        """
        logger.debug("Testing logport value hasn't been overriden")
        #*** Assume the logport value hasn't been overriden:
        assert _config.get_value('logport') == 514
        logger.debug("Testing user config value overwrite")
        #*** Check that we've successfully overwritten this:
        assert _config.get_value('nmeta_logging_level_s') == 'DEBUG'
