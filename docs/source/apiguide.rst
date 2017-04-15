#########
API Guide
#########

This guide is UNDER CONSTRUCTION

*************
External APIs
*************

Controller Summary
==================

The Controller Summary API is a read-only summary of the current controller
performance metrics.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/controller_summary.py

Flow Mods
=========

The Flow Mods API is a read-only summary of all flow modifications made
to switches by the controller.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/flow_mods_api.py

Flows
=====

The Flows API is a read-only summary of all flows recorded by the controller.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/flows_api.py



*************
Internal APIs
*************

No internal APIs exist yet. They are planned to implement connectivity between
the API instance and the main nmeta code for interaction into non-database
components of nmeta.
