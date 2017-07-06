###########
Build a Lab
###########

To run nmeta, you're going to need an OpenFlow network to provide the data
plane connectivity.

There are many different options for building a lab network. The
choice is likely to come down to what resources you have and the use cases
you want to test.

Virtual labs are easy to set up and don't require specialised hardware,
but aren't useful for testing devices in the real world.

Physical labs are harder to construct and require hardware, but can be
used to connect real-world devices.

OpenFlow SDN disaggregates the data and control planes;
this means the lab environments can be used with different
OpenFlow controllers and apps, should you wish.

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
**at your own risk**...

These instructions haven't been tested end-to-end. Please raise an issue if
there are changes required.

Convert Router to OpenWRT
-------------------------

Start by converting the TP-Link TL-WR1043ND to running OpenWRT as per the
instructions from the OpenWRT website at:

`<https://wiki.openwrt.org/toh/tp-link/tl-wr1043nd>`_

When router is successfully running OpenWRT, proceed to the next step:

Configure the Router
--------------------

Apply a basic configuration to the router to allow remote access.

Connect a device with SSH capability to a LAN port on the TP-Link, set a static IP
address of 192.168.1.2 mask 255.255.255.0 (or use DHCP) and SSH to 192.168.1.1.

Set root password to something secure, and not used elsewhere.

Compile OpenWRT with Open vSwitch Image
---------------------------------------

Note: If you don't want to compile your own image then consider using 
an image from `<https://github.com/mattjhayes/TP-Link-TL-1043ND-OpenvSwitch>`_

Compilation Host
^^^^^^^^^^^^^^^^

To compile the router firmware, use an Ubuntu 16.04.2 server or desktop
(can be virtual) with at least 30GB of disk space.

Clone OpenWRT
^^^^^^^^^^^^^

On the compilation host, clone OpenWRT (note: GitHub, not direct from OpenWRT site):

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

Run Make
^^^^^^^^

This may take a couple of hours...

.. code-block:: text

  make

Patch for Wi-Fi Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Standard OpenWRT build with Open vSwitch cannot run authentication on Wi-Fi,
see: `<https://forum.openwrt.org/viewtopic.php?id=59129>`_

We apply a patch to fix this:

.. code-block:: text

  cd ~/openwrt/package/network/services/hostapd/
  vi 710-hostapd-Initial-OVS-support.patch

Paste in contents of patch (starting from the ---) from `<https://github.com/helmut-jacob/hostapd/commit/c89daaeca4ee90c8bc158e37acb1b679c823d7ab.patch>`_
Save and exit.

Patch with Quilt. Install quilt:

.. code-block:: text

  sudo apt install quilt

In home dir, need to run this once:

.. code-block:: text

  cat > ~/.quiltrc <<EOF
  QUILT_DIFF_ARGS="--no-timestamps --no-index -p ab --color=auto"
  QUILT_REFRESH_ARGS="--no-timestamps --no-index -p ab"
  QUILT_SERIES_ARGS="--color=auto"
  QUILT_PATCH_OPTS="--unified"
  QUILT_DIFF_OPTS="-p"
  EDITOR="nano"
  EOF

Run this from ~/openwrt/

.. code-block:: text

  make package/network/services/hostapd/{clean,prepare} V=s QUILT=1

cd to created directory:

.. code-block:: text

  cd ~/openwrt/build_dir/target-mips_34kc_musl-1.1.16/hostapd-wpad-mini/hostapd-2016-06-15/

Apply existing patches:

.. code-block:: text

  quilt push -a

Now at patch 710-hostapd-Initial-OVS-support.patch. Run this:

.. code-block:: text

  quilt edit src/main.c

Run this:

.. code-block:: text

  quilt refresh

Change dir to the build root and run 

.. code-block:: text

  cd ../../../../
  make package/network/services/hostapd/update V=s

Then run:

.. code-block:: text

  make package/network/services/hostapd/{clean,compile} package/index V=s

Then run:

.. code-block:: text

  make

Copy Image
^^^^^^^^^^
Navigate to the directory where the output files are:

.. code-block:: text

  cd bin/ar71xx

There should be multiple files in the directory, including this file:

.. code-block:: text

  openwrt-ar71xx-generic-tl-wr1043nd-v2-squashfs-factory.bin
  openwrt-ar71xx-generic-tl-wr1043nd-v2-squashfs-sysupgrade.bin

Use SCP to copy the appropriate file to the router:

.. code-block:: text

  scp ./openwrt-ar71xx-generic-tl-wr1043nd-v2-squashfs-sysupgrade.bin USERNAME@192.168.1.1:tmp/

Upgrade
^^^^^^^

Note: consider backing up config etc first...

On the TPLink:

.. code-block:: text

  sysupgrade -v /tmp/openwrt-ar71xx-generic-tl-wr1043nd-v2-squashfs-sysupgrade.bin

Configure OpenWRT
-----------------

TBD

To assist with patching of Wi-Fi auth, edit the file:

.. code-block:: text

  /var/run/hostapd-phy0.conf

(TBD: run tests to confirm this is required)

Add this line:

.. code-block:: text

  bridge=br0

Dropbear
^^^^^^^^

Configure Dropbear (SSH server) to listen on the WAN interface, in addition
to the LAN interface. This gives an additional way to access 
the device to administer it, lowering the risk of bricking it.
Note: not a great idea doing this if Internet-facing, remember to revert if
you ever convert device back to an Internet router.

Backup dropbear config:

.. code-block:: text

  cp /etc/config/dropbear /etc/config/dropbear.original

Add these lines to /etc/config/dropbear:

.. code-block:: text

  config dropbear
          option PasswordAuth 'on'
          option Port '22'
          option Interface 'wan'

Configure Open vSwitch
----------------------

TBD


Links
-----

Instructions were based on these tutorials:

`Building and Configuring Open vSwitch on OpenWrt for Cloud Networking byPravin R. <http://www.zymr.com/building-and-configuring-open-vswitch-on-openwrt-for-cloud-networking/>`_
`Turning TP-LINK WR1043NDv2.1 router into OpenFlow-enabled switch by Lucas Burson <http://blog.ljdelight.com/turning-tp-link-wr1043ndv2-1-router-into-openflow-enabled-switch/>`_


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
