============
Introduction
============

The nmeta *(pronounced en-meta)* project is founded on the belief that
innovation in networks requires a foundation layer of knowledge
about both the participants and their types of conversation.

Today, networks generally have only a limited view of participants
and conversation types

.. image:: images/nmeta_concept.png

The goal of the nmeta project is to produce network metadata enriched with
participant identities and conversation types to provide a foundation for
innovation in networking.

The production of enriched network metadata requires policy-based control,
and ability to adapt to new purposes through extensibility.

Enriched network metadata has a number of uses, including classifying flows
for QoS, billing, traffic engineering, troubleshooting and security.

Nmeta is a research platform for traffic classification on Software Defined
Networking (SDN).  It runs on top of the Ryu SDN controller
(see: `<http://osrg.github.io/ryu/>`_).


How it Works
------------

Nmeta uses OpenFlow Software-Defined Networking (SDN) to selectively control
flows through switches so that packets can be classified and actions taken.
It instructs connected OpenFlow switches to send packets from unknown flows
to the Ryu SDN Controller, on which nmeta runs, for analysis.

.. image:: images/nmeta_logical_core.png

Nmeta configures a single flow table per switch with a table-miss
flow entry (FE) that sends full unmatched packets to the controller. As flows
are classified, specific higher-priority FEs are configured to suppress
sending further packets to the controller.


Limitations
-----------
Nmeta does not scale well. Every new flow has a processing overhead, and this
workload cannot be scaled horizontally on the controller. The nmeta2 system is
being developed to address this limitation.

Nmeta has no security, it was written to demonstrate SDN functionality
and has omitted addressing security requirements. A future rewrite may address
security, but for now there is no security whatsoever.

Feature Enhancement Wishlist
----------------------------

See `Issues <https://github.com/mattjhayes/nmeta/issues>`_ for list of
enhancements and bugs

Privacy Considerations
----------------------
Collecting network metadata brings with it ethical and legal considerations
around privacy. Please ensure that you have permission to monitor traffic
before deploying this software.

Disclaimer
----------

This code carries no warrantee whatsoever. Use at your own risk.

How to Contribute
-----------------

Code contributions and suggestions are welcome. Enhancement or bug fixes
can be raised as issues through GitHub.

Please get in touch if you want to be added as a contributor to the project:

Email: `Nmeta Maintainer <mailto:nmeta-maintainer@outlook.com>`_


