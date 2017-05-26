#######
Install
#######

This guide is for installing on Ubuntu.

********
Pre-Work
********

Ensure packages are up-to-date
==============================

.. code-block:: text

  sudo apt-get update
  sudo apt-get upgrade

Install Python pip
==================

.. code-block:: text

  sudo apt-get install python-pip

Install git
===========

Install git and git-flow for software version control:

.. code-block:: text

  sudo apt-get install git git-flow

*******************************
Install Ryu OpenFlow Controller
*******************************

Ryu is the OpenFlow Software-Defined Networking (SDN) controller application
that handles communications with the switch:

.. code-block:: text

  sudo pip install ryu

**********************************
Install Packages Required by nmeta
**********************************

Install dpkt library
====================

The dpkt library is used to parse and build packets:

.. code-block:: text

  sudo pip install dpkt

Install pytest
==============
Pytest is used to run unit tests:

.. code-block:: text

  sudo apt-get install python-pytest

Install YAML
============

Install Python YAML ("YAML Ain't Markup Language") for parsing config
and policy files:

.. code-block:: text

  sudo apt-get install python-yaml

Install simplejson
==================

.. code-block:: text

  sudo pip install simplejson

Install eve
===========
Eve is used to power the external API

.. code-block:: text

  sudo pip install eve

Install coloredlogs
===================

Install coloredlogs to improve readability of terminal logs by colour-coding:

.. code-block:: text

  sudo pip install coloredlogs

Install Voluptuous
==================

Install Voluptuous data validation library for policy and input validation
against schema:

.. code-block:: text

  sudo pip install voluptuous

***************
Install MongoDB
***************

MongoDB is the database used by nmeta. Install MongoDB as per `their instructions <https://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/>`_ :

Import the MongoDB public GPG Key:

.. code-block:: text

  sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927

Create a list file for MongoDB:

.. code-block:: text

  echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list

Reload local package database:

.. code-block:: text

  sudo apt-get update

Install MongoDB:

.. code-block:: text

  sudo apt-get install -y mongodb-org

Add pymongo for a Python API into MongoDB:

.. code-block:: text

  sudo apt-get install build-essential python-dev
  sudo pip install pymongo

Turn on smallfiles to cope with small file system size:

.. code-block:: text

  sudo vi /etc/mongod.conf

Add this to the storage section of the config:

.. code-block:: text

  mmapv1:
    smallFiles: true

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

*********
Run nmeta
*********

.. code-block:: text

  cd
  cd ryu
  PYTHONPATH=. ./bin/ryu-manager ../nmeta/nmeta/nmeta.py

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
  alias nm="cd; cd ryu; PYTHONPATH=. ./bin/ryu-manager ../nmeta/nmeta/nmeta.py"
  #
  # Run nmeta external API:
  alias nma='~/nmeta/nmeta/api_external.py'
  #
  # Retrieve Packet-In rate via external API:
  alias nma_pi_rate='curl http://localhost:8081/v1/infrastructure/controllers/pi_rate/ | python -m json.tool'

