###############
Configure Nmeta
###############

********************
System Configuration
********************

A YAML file holds the system configuration. It's location is:

.. code-block:: text

  ~/nmeta/nmeta/config/config.yaml

These default configuration parameters can be overwritten by creating a file:

.. code-block:: text

  ~/nmeta/nmeta/config/user/config.yaml

Add the parameters to the file that you want to override. For example, to
override the default console logging level for the tc_policy module, add
the following line to the user config file:

.. code-block:: text

  tc_policy_logging_level_c: INFO

Note that the user-defined config file will not be part of the git
distribution, as it is excluded in the .gitignore file.



