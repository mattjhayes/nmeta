#######
Install
#######

This guide is for installing on Ubuntu 16.04.2 LTS

********
Pre-Work
********

Ensure packages are up-to-date
==============================

.. code-block:: text

  sudo apt-get update
  sudo apt-get upgrade

***********************
Install Debian Packages
***********************

The following command installs these packages:
- pip (Python package manager)
- git (version control system)
- git flow (branching model for Git)
- python-pytest (used to run unit tests)
- python-yaml (YAML parser for Python)

.. code-block:: text

  sudo apt-get install python-pip git git-flow dpkt python-pytest python-yaml

***********************
Install Python Packages
***********************

Ensure pip (Python package manager) is latest version:

.. code-block:: text

  pip install --upgrade pip

The following command installs these Python packages:
- Ryu (OpenFlow Software-Defined Networking (SDN) controller application that handles communications with the switch)
- dpkt (library is used to parse and build packets)
- mock (Testing library)
- Requests (HTTP library)
- simplejson (JSON encoder and decoder)
- eve (REST API framework)
- coloredlogs (Add colour to log entries in terminal output)
- voluptuous (data validation library)

.. code-block:: text

  pip install ryu dpkt mock requests simplejson eve coloredlogs voluptuous --user

***************
Install MongoDB
***************

MongoDB is the database used by nmeta. Install MongoDB as per `their instructions <https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/>`_ (Note: Ubuntu 16.04 specific)

Import the MongoDB public GPG Key:

.. code-block:: text

  sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6

Create a list file for MongoDB:

.. code-block:: text

  echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.4.list

Reload local package database:

.. code-block:: text

  sudo apt-get update

Install MongoDB:

.. code-block:: text

  sudo apt-get install -y mongodb-org

Set MongoDB to autostart:

.. code-block:: text

  systemctl enable mongod.service
  
Start MongoDB (if required) with:

.. code-block:: text

  sudo service mongod start


*************
Install nmeta
*************

Clone nmeta

.. code-block:: text

  cd
  git clone https://github.com/mattjhayes/nmeta.git

Test nmeta
==========

Tests should all pass:

.. code-block:: text

  cd ~/nmeta/tests/; py.test

Run nmeta
==========

Test nmeta runs:

.. code-block:: text

  ryu-manager ~/nmeta/nmeta/nmeta.py


******************
Configure Switches
******************

Configure OpenFlow
==================

Switches will need to be configured to use Ryu/nmeta as their controller.
The configuration details will differ depending on the type of switch.

Here is an example configuration for Open vSwitch to use a controller at
IP address 172.16.0.3 on TCP port 6633:

.. code-block:: text

  sudo ovs-vsctl set-controller br0 tcp:172.16.0.3:6633

You will need to work out setting that are appropriate for your topology
and switches.

Configure QoS Queues
====================

To run Quality of Service (QoS), switches will need to be configured with QoS
queues.

See the documentation for your switch(es) for how to configure QoS queues.

Be aware that using a queue number that is not configured on the switch may
result in the switch dropping the packet.

*******
Aliases
*******

Aliases can be used to make it easier to run common commands.
To add the aliases, edit the .bash_aliases file in your home directory:

.. code-block:: text

  cd
  sudo vi .bash_aliases

Paste in the following:

.. code-block:: text

  # Test nmeta:
  alias nmt='cd ~/nmeta/tests/; py.test'
  #
  # Run nmeta:
  alias nm="ryu-manager ~/nmeta/nmeta/nmeta.py"
  #
  # Run nmeta external API:
  alias nma='~/nmeta/nmeta/api_external.py'
  #
  # Retrieve Packet-In rate via external API:
  alias nma_pi_rate='curl http://localhost:8081/v1/infrastructure/controllers/pi_rate/ | python -m json.tool'

