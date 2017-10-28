####
APIs
####

Nmeta uses Python Eve to expose various RESTful API types:

* :ref:`flow-apis`
* :ref:`identity-apis`
* :ref:`infrastructure-apis`
* :ref:`internal-apis`

.. _flow-apis:

*********
Flow APIs
*********

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

Example response (showing only one of multiple records):

.. code-block:: text

    {
        "_items": [

            {
                "_created": "00:00:00.000000",
                "_etag": "21a20685ccf9080fbd31de81eb2802146907bf13",
                "_id": "59d807e101186126d01fc216",
                "_updated": "00:00:00.000000",
                "dpid": 1,
                "flow_hash": "c907986d4796fb669acb37efba3afc8e",
                "forward_cookie": 1,
                "forward_match": {
                    "eth_type": 2048,
                    "ip_proto": 6,
                    "ipv4_dst": "10.1.0.1",
                    "ipv4_src": "10.1.0.2",
                    "tcp_dst": 36296,
                    "tcp_src": 80
                },
                "match_type": "dual",
                "reverse_cookie": 2,
                "reverse_match": {
                    "eth_type": 2048,
                    "ip_proto": 6,
                    "ipv4_dst": "10.1.0.2",
                    "ipv4_src": "10.1.0.1",
                    "tcp_dst": 80,
                    "tcp_src": 36296
                },
                "standdown": 0,
                "suppress_type": "suppress",
                "timestamp": "11:46:57.940000"
            },

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

Example response (showing only one of multiple records):

.. code-block:: text

    {
        "_items": [
            {
                "_created": "00:00:00.000000",
                "_etag": "6fbc72e6d279932c763db5852312ccd4b4f6d4cc",
                "_id": "59d81f3a0118612dd314c8b0",
                "_updated": "00:00:00.000000",
                "client_ip": "10.1.0.1",
                "dpid": 2,
                "flow_hash": "3c1a773547e36469500f64ad0b34efb2",
                "forward_cookie": 1,
                "forward_match": {
                    "eth_type": 2048,
                    "ip_proto": 6,
                    "ipv4_dst": "10.1.0.2",
                    "ipv4_src": "10.1.0.1",
                    "tcp_dst": 80,
                    "tcp_src": 36299
                },
                "match_type": "dual",
                "reverse_cookie": 2,
                "reverse_match": {
                    "eth_type": 2048,
                    "ip_proto": 6,
                    "ipv4_dst": "10.1.0.1",
                    "ipv4_src": "10.1.0.2",
                    "tcp_dst": 36299,
                    "tcp_src": 80
                },
                "standdown": 0,
                "suppress_type": "suppress",
                "timestamp": "13:26:34.546000"
            }



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


Flows Removed API
=================

The Flows Removed API is a read-only summary of all removed flows recorded by
the controller (switches send flow removal messages to the controller). It
does not deduplicate for same flow being removed from multiple switches.

The API definition file is at:

.. code-block:: text

  ~/nmeta/nmeta/api_definitions/flows_removed_api.py

Flows Removed API
-----------------

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flows_removed/ | python -m json.tool

Example response (showing only one of multiple records):

.. code-block:: text

    {
        "_items": [
            {
                "_created": "00:00:00.000000",
                "_etag": "4c6fba64b571e392f578aa6804b5ad45149a1b5c",
                "_id": "59b3213f01186111d817494c",
                "_updated": "00:00:00.000000",
                "byte_count": 468,
                "cookie": 5,
                "dpid": 1,
                "duration_sec": 31,
                "eth_A": "",
                "eth_B": "",
                "eth_type": 2048,
                "flow_hash": "fada031e16b76ef92e68aa516123c500",
                "hard_timeout": 0,
                "idle_timeout": 30,
                "ip_A": "10.1.0.1",
                "ip_B": "10.1.0.2",
                "ip_proto": 6,
                "packet_count": 7,
                "priority": 1,
                "reason": 0,
                "removal_time": "11:01:19.121000",
                "table_id": 0,
                "tp_A": 45593,
                "tp_B": 80
            },

Flows Removed Stats Count
-------------------------

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flows_removed/stats/count | python -m json.tool

Example response:

.. code-block:: text

    {
        "flows_removed": 4
    }

Flows Removed Stats Bytes Sent
------------------------------

Aggregates and sums byte_count by source IP address. Deduplicates for same
flow hash removed from multiple switches and reverse sorts by bytes 

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flows_removed/stats/bytes_sent | python -m json.tool

Example response:

.. code-block:: text

    {
        "_items": [
            {
                "_id": "10.1.0.2",
                "identity": "10.1.0.2",
                "total_bytes_sent": 3532
            },
            {
                "_id": "10.1.0.1",
                "identity": "pc1",
                "total_bytes_sent": 1404
            }
        ]
    }

Flows Removed Stats Bytes Received
----------------------------------

Aggregates and sums byte_count by destination IP address. Deduplicates for same
flow hash removed from multiple switches and reverse sorts by bytes 

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/flows_removed/stats/bytes_received | python -m json.tool

Example response:

.. code-block:: text

    {
        "_items": [
            {
                "_id": "10.1.0.1",
                "identity": "pc1",
                "total_bytes_received": 3532
            },
            {
                "_id": "10.1.0.2",
                "identity": "10.1.0.2",
                "total_bytes_received": 1404
            }
        ]
    }

Classifications
===============

The classifications API returns the results of traffic classifications on
flows.

Example manual invocation of the API:

.. code-block:: text

  curl http://localhost:8081/v1/classifications | python -m json.tool

Example response (showing only one of multiple records):

.. code-block:: text

{
    "_items": [
        {
            "_created": "00:00:00.000000",
            "_etag": "2edf91b82d854695895ee44cffbcd5886209d12b",
            "_id": "59f4e7f2011861131aea939a",
            "_updated": "00:00:00.000000",
            "actions": {
                "qos_treatment": "constrained_bw",
                "set_desc": "Constrained Bandwidth Traffic"
            },
            "classification_tag": "Constrained Bandwidth Traffic",
            "classification_time": "09:26:26.131000",
            "classified": true,
            "flow_hash": "7af8ea9080506199633414caba6259e6"
        },


.. _identity-apis:

*************
Identity APIs
*************

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

Example response (showing only one of multiple records):

.. code-block:: text

    {
        "_items": [
            {
                "_created": "00:00:00.000000",
                "_etag": "79b7626eba366805e4723ce81751c100b447d04c",
                "_id": "59b3206801186111d817487b",
                "_updated": "00:00:00.000000",
                "dpid": 2,
                "harvest_time": "10:57:43.997000",
                "harvest_type": "ARP",
                "host_desc": "",
                "host_name": "",
                "host_os": "",
                "host_type": "",
                "id_hash": "aafeaa6798c9ef3761f7afe51dd3cf7d",
                "in_port": 2,
                "ip_address": "10.1.0.1",
                "mac_address": "08:00:27:2a:d6:dd",
                "service_alias": "",
                "service_name": "",
                "user_id": "",
                "valid_from": "10:57:43.997000",
                "valid_to": "14:57:43.997000"
            },

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

Example response (showing only one of multiple records):

.. code-block:: text

    {
        "_items": [
            {
                "_id": "59b31fc301186111d81747ae",
                "dpid": 1,
                "harvest_time": "10:54:59.131000",
                "harvest_type": "LLDP",
                "host_desc": "Ubuntu 16.04.2 LTS Linux 4.4.0-93-generic #116-Ubuntu SMP Fri Aug 11 21:17:51 UTC 2017 x86_64",
                "host_name": "sw2.example.com",
                "host_os": "",
                "host_type": "",
                "id_hash": "ab044209ef247d208ca1e88c5727ba0c",
                "in_port": 2,
                "ip_address": "",
                "location_logical": "internal",
                "location_physical": "",
                "mac_address": "08:00:27:ea:23:84",
                "service_alias": "",
                "service_name": "",
                "user_id": "",
                "valid_from": "10:54:59.131000",
                "valid_to": "10:56:59.131000"
            },


.. _infrastructure-apis:

*******************
Infrastructure APIs
*******************

APIs expose nmeta performance and state data. They are used by the
nmeta WebUI and can be used for other applications.

Be aware that some non-native Python Eve APIs have limited feature support
(i.e. may not support filtering)

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

Example response:

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

Example response:

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

Example response:

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

Example response:

.. code-block:: text

    {
        "connected_switches": 2
    }


.. _internal-apis:

*************
Internal APIs
*************

No internal APIs exist yet. They are planned to implement connectivity between
the API instance and the main nmeta code for interaction into non-database
components of nmeta.
