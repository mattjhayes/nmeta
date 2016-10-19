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

  pip install eve

TBD
===
mongodb + pymongo

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

  # Run nmeta:
  alias nm="cd; cd ryu; PYTHONPATH=. ./bin/ryu-manager ../nmeta/nmeta/nmeta.py"
  #
  # Retrieve nmeta network metadata:
  alias idmac="sudo python nmeta/misc/jsonpretty.py http://127.0.0.1:8080/nmeta/identity/mac/"
  alias idip="sudo python nmeta/misc/jsonpretty.py http://127.0.0.1:8080/nmeta/identity/ip/"
  alias idsvc="sudo python nmeta/misc/jsonpretty.py http://127.0.0.1:8080/nmeta/identity/service/"
  alias idsys="sudo python nmeta/misc/jsonpretty.py http://127.0.0.1:8080/nmeta/identity/systemtable/"
  alias idnic="sudo python nmeta/misc/jsonpretty.py http://127.0.0.1:8080/nmeta/identity/nictable/"
