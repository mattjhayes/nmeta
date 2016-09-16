#################
Quick Start Guide
#################

.. image:: images/quickstart_number_1.png

First, you'll need an **OpenFlow Network** with one or more switches.
If you don't have a suitable one to hand then consider building the virtual
lab in the `Extras section <extras.html>`_

.. image:: images/quickstart_number_2.png

Next, you'll need an **SDN Controller** to run the control plane of the
network and host the nmeta application. If you built the virtual lab then
you've already got this covered.

If not, build a physical or virtual server. The preferred OS is Ubuntu.
Now install Ryu and nmeta as per the `Install Guide <install.html>`_

.. image:: images/quickstart_number_3.png

You'll need some **participants** (hosts) on your network. Again, if you've
built the virtual lab you're already covered for this.

If not, decide what types and numbers of hosts you want on your network,
then connect them up.

.. image:: images/quickstart_number_4.png

**Configure** nmeta as per the `User Guide <userguide.html>`_

.. image:: images/quickstart_number_5.png

**Run** nmeta:

.. code-block:: text

  cd
  cd ryu
  PYTHONPATH=. ./bin/ryu-manager ../nmeta/nmeta.py

Now start experimenting. Use the calls in the aliases to show network metadata
