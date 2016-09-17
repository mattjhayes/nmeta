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

.. image:: images/flow_metadata_screenshot3.png

Nmeta is a research platform for traffic classification on Software Defined
Networking (SDN).  It runs on top of the Ryu SDN controller
(see: `<http://osrg.github.io/ryu/>`_).

Limitations
-----------
Nmeta does not scale well. Every new flow has a processing overhead, and this
workload cannot be scaled horizontally on the controller. The nmeta2 system is
being developed to address this limitation.

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


