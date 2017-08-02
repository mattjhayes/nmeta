############
Extend Nmeta
############

******************
Custom Classifiers
******************

Nmeta supports the creation of custom classifiers to extend classification,
leveraging any network metadata. See the configure chapter for how to
reference a custom classifier from main_policy.yaml.

Custom classifiers have access to the flow and identity abstractions (see
develop chapter)


*************
External APIs
*************

External APIs expose nmeta performance and state data. They are used by the
nmeta WebUI and can be used for other applications.

Be aware that non-native Python Eve APIs have limited feature support (i.e.
may not support filtering)

Controller Summary API
======================

The Controller Summary API is a read-only summary of the current controller
performance metrics.

It is not a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/controller_summary.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/infrastructure/controllers/summary/ | python -m json.tool

Flow Mods API
=============

The Flow Mods API is a read-only summary of all flow modifications made
to switches by the controller.

It is a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/flow_mods_api.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flow_mods/ | python -m json.tool

Flows API
=========

The Flows API is a read-only summary of all flows recorded by the controller.

It is a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/flows_api.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flows/ | python -m json.tool

Flows UI API
============

The Flows UI API is a read-only summary of all flows recorded by the
controller, tailored for use by the WebUI. It features the following:
- Flow direction normalised to direction of first packet in flow
- Src and Dst are IP or Layer 2 to optimise screen space
- Extra data included for hover-over tips
- Enriched with classification and action(s)
- Enriched with data xfer (only applies to flows that have had idle timeout)

It is not a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/flows_ui.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flows/ui/ | python -m json.tool

Identities API
==============

The Identities API is a read-only summary of all identity records harvested
by the controller.

It is a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/identities_api.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/identities/ | python -m json.tool

Identities UI API
=================

The Identities API is a read-only summary of all identity records harvested
by the controller, tailored for use by the WebUI. It features the following:
- Reverse sort by harvest time
- Deduplicate by id_hash, only returning most recent per id_hash
- Includes possibly stale records
- Checks DNS identities to see if they are from a CNAME, and if so includes
  IP address from the A record
- Optional filtering out of DNS identities by setting '?filter_dns=1' on URI

It is not a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/identities_ui.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/identities/ui/ | python -m json.tool

PI Rate API
===========

The PI Rate API is a read-only metric for the rate at which the controller
is receiving packet-in (PI) messages.

It is not a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/pi_rate.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/infrastructure/controllers/pi_rate/ | python -m json.tool

PI Time API
===========

The PI Time API is a read-only set of metrics for the timeliness of the
controller in processing packet-in (PI) messages. It is measured over the
length of time defined by PACKET_TIME_PERIOD, as defined in api_external.py,
and returned in the API as the key pi_time_period.

It is not a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/pi_time.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/infrastructure/controllers/pi_time/ | python -m json.tool

Example result:

.. code-block:: text

    {
        "_meta": {
            "max_results": 25,
            "page": 1,
            "total": 814
        },
        "pi_time_avg": 0.039634871482849124,
        "pi_time_max": 0.08309197425842285,
        "pi_time_min": 0.017210960388183594,
        "pi_time_period": 10,
        "pi_time_records": 20,
        "ryu_time_avg": 0.0019985318183898928,
        "ryu_time_max": 0.01230311393737793,
        "ryu_time_min": 0.0004711151123046875,
        "ryu_time_period": 10,
        "ryu_time_records": 20
    }

Switches API
============

The Switches API is a read-only summary of all switches currently
connected to controller.

It is a native Python Eve API.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/switches_api.py

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/infrastructure/switches/ | python -m json.tool

*************
Internal APIs
*************

No internal APIs exist yet. They are planned to implement connectivity between
the API instance and the main nmeta code for interaction into non-database
components of nmeta.
