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

.. code-block:: text

  sudo apt-get install git

*******************************
Install Ryu OpenFlow Controller
*******************************

This is the OpenFlow controller application that handles communications
with the switch

.. code-block:: text

  sudo pip install ryu

**********************************
Install Packages Required by nmeta
**********************************

Install pytest
==============
Pytest is used to run unit tests

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

*************
Install nmeta
*************

Clone nmeta

.. code-block:: text

  cd
  git clone https://github.com/mattjhayes/nmeta2.git

