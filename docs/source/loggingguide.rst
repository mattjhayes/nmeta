#######
Logging
#######

Logging is configured separately for syslog and to the console, and levels
are configurable per Python module. The log format is also customisable.

Logging configuration is controlled by the system configuration YAML file.

Logging settings are configured separately for *console* and
*syslog* logging.

By default, logging levels are set to INFO.

Supported logging levels are:

- CRITICAL
- ERROR
- WARNING
- INFO
- DEBUG

To change the default logging levels, create a user configuration
YAML file (if it doesn't already exist) as the following filename:

.. code-block:: text

  ~/nmeta/nmeta/config/user/config.yaml

Override specific settings from the default configuration file from the
directory below.

Example:

.. code-block:: text

  # Set nmeta.py console logging to DEBUG level:
  nmeta_logging_level_c: DEBUG
