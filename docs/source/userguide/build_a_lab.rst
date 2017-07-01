###########
Build a Lab
###########

There are many different options for building a nmeta lab network. The
choice is likely to come down to what resources you have and the use cases
you want to test.

Virtual labs are easy to set up and don't require specialised hardware,
but aren't useful for testing devices in the real world.

Physical labs are harder to construct and require hardware, but can be
used to connect real-world devices.

UNDER CONSTRUCTION

************
Virtual Labs
************

VirtualBox
==========

TBD

Mininet
=======

Get in touch if you want to contribute instructions on building a lab with
Mininet.


*************
Physical Labs
*************

OpenWRT with Open vSwitch
=========================

UNDER CONSTRUCTION

This lab is based on a TP-Link TL-WR1043ND Hardware Version 2.1 home router
that is re-flashed to run OpenWRT with Open vSwitch running OpenFlow (yes,
that's three different pieces of software that have the word 'Open' in them...)

Compile OpenWRT with Open vSwitch Image
---------------------------------------

Start with an Ubuntu 16.04.2 server or desktop (can be virtual) with at least
30GB of disk space.

Clone OpenWRT
^^^^^^^^^^^^^

Cloned OpenWRT (note: GitHub, not direct from OpenWRT site):

.. code-block:: text

  git clone https://github.com/openwrt/openwrt.git 

Install Dependancies
^^^^^^^^^^^^^^^^^^^^

.. code-block:: text

  sudo apt-get update
  sudo apt-get install git-core build-essential libssl-dev libncurses5-dev unzip gawk zlib1g-dev
  sudo apt-get install subversion mercurial
  sudo apt-get install gcc-multilib flex gettext

Update Feeds
^^^^^^^^^^^^

.. code-block:: text

  cd openwrt
  ./scripts/feeds update -a
  ./scripts/feeds install -a

Make MenuConfig
^^^^^^^^^^^^^^^

.. code-block:: text

  make menuconfig

Change Target Profile:

TBD


Links
-----

Instructions were based on these tutorials:

`Building and Configuring Open vSwitch on OpenWrt for Cloud Networking byPravin R. <http://www.zymr.com/building-and-configuring-open-vswitch-on-openwrt-for-cloud-networking/>`_
 
