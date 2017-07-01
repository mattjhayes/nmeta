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
that's three different pieces of software that start with the word 'Open'...)

Be warned that reflashing a router is likely to void it's warrantee, and may
result in the router becoming 'bricked', whereby it is unrecoverable. Continue
at your own risk...

Compile OpenWRT with Open vSwitch Image
---------------------------------------

Start by compiling the router firmware on an Ubuntu 16.04.2 server or desktop
(can be virtual) with at least 30GB of disk space:

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

Change Target Profile to suit hardware (select *TP-LINK TL-WR1043N/ND* for
TP-Link TL-WR1043ND Hardware Version 2.1):

.. image:: images/OpenWRT_build_1.png

Then select Kernel Modules -> Network Support -> kmod-tun:

.. image:: images/OpenWRT_build_2.png

Exit out back to main screen, then select *Network ->  Open vSwitch* and
select:

.. image:: images/OpenWRT_build_3.png

Save on exit:

.. image:: images/OpenWRT_build_4.png

This one takes a while:

.. code-block:: text

  make kernel_menuconfig

When finished brings up another menu. Navigate to 
*Networking support -> Networking options* and select
*Hierarchical Token Bucket (HTB)*:

.. image:: images/OpenWRT_build_5.png


TBD


Links
-----

Instructions were based on these tutorials:

`Building and Configuring Open vSwitch on OpenWrt for Cloud Networking byPravin R. <http://www.zymr.com/building-and-configuring-open-vswitch-on-openwrt-for-cloud-networking/>`_
 
