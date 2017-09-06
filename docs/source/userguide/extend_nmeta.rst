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

Example result:

.. code-block:: text

    {
        "pi_rate": 0.2,
        "timestamp": "19:21:35"
    }


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
    "pi_time_avg": 0.05947005748748779,
    "pi_time_max": 0.06364011764526367,
    "pi_time_min": 0.055299997329711914,
    "pi_time_period": 10,
    "pi_time_records": 2,
    "ryu_time_avg": 0.0007699728012084961,
    "ryu_time_max": 0.0008089542388916016,
    "ryu_time_min": 0.0007309913635253906,
    "ryu_time_period": 10,
    "ryu_time_records": 2,
    "timestamp": "19:50:40"
    }

Switches API
============

The Switches API provides information on switches connected to the
controller.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/switches_api.py

Switch Details
--------------

The Switch Details API is a read-only summary of all switches currently
connected to controller.

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/infrastructure/switches/ | python -m json.tool

Example result:

.. code-block:: text

    {
        "_items": [
            {
                "_created": "00:00:00.000000",
                "_etag": "e9cf4f29afa425bc0486cda334c56017d3d6e2ca",
                "_id": "59854e3ee14ebffa9f4f4e7b",
                "_updated": "00:00:00.000000",
                "dp_desc": "None",
                "dpid": 1,
                "hw_desc": "Open vSwitch",
                "ip_address": "172.16.0.5",
                "mfr_desc": "Nicira, Inc.",
                "port": 46074,
                "serial_num": "None",
                "sw_desc": "2.5.2",
                "time_connected": "16:49:01.795000"
            },
            {
                "_created": "00:00:00.000000",
                "_etag": "e8ff778368901540349b2a9625893b1b4763b362",
                "_id": "59854e41e14ebffa9f4f4e80",
                "_updated": "00:00:00.000000",
                "dp_desc": "None",
                "dpid": 2,
                "hw_desc": "Open vSwitch",
                "ip_address": "172.16.0.9",
                "mfr_desc": "Nicira, Inc.",
                "port": 34090,
                "serial_num": "None",
                "sw_desc": "2.5.2",
                "time_connected": "16:49:05.706000"
            }
        ],
        "_meta": {
            "max_results": 25,
            "page": 1,
            "total": 2
        }
    }

Switch Count
------------

The Switch Count API is a read-only count of all switches currently
connected to controller.

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/infrastructure/switches/stats/connected_switches | python -m json.tool

Example result:

.. code-block:: text

    TBD



*************
Internal APIs
*************

No internal APIs exist yet. They are planned to implement connectivity between
the API instance and the main nmeta code for interaction into non-database
components of nmeta.
