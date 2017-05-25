#######
Recipes
#######

These recipes are to provide ideas on how nmeta can be used through examples.

This page is under construction...

*******************
Home Network Recipe
*******************

This recipe is for running an OpenFlow switch on a home network.

It makes the following assumptions:

- The gateway to the Internet is provided by a separate router on switch
  dpid=1 port=3.

The recipe does the following:

- DNS lookups are allowed against OpenDNS servers 208.67.222.123
  and 208.67.220.123
- All other DNS traffic is dropped and logged
- Drops SSDP traffic from the router
- Drops Bonjour traffic
- Implicit allow of all other traffic, as well of harvesting of
  conversation and identity metadata


Main Policy:
============

Use this main_policy.yaml file in the user config directory:

.. code-block:: text

  ~/nmeta/nmeta/config/user/

Here's the YAML:

.. code-block:: YAML

    ---
    #*** Main Policy for nmeta - Home Router Custom User Policy
    #*** Written in YAML
    #
    tc_rules:
        # Traffic Classification Rulesets and Rules
        tc_ruleset_1:
            - comment: Allow OpenDNS
              match_type: any
              conditions_list:
                  - match_type: all
                    udp_dst: 53
                    ip_dst: 208.67.222.123
                  - match_type: all
                    udp_src: 53
                    ip_src: 208.67.222.123
                  - match_type: all
                    udp_dst: 53
                    ip_dst: 208.67.220.123
                  - match_type: all
                    udp_src: 53
                    ip_src: 208.67.220.123
              actions:
                  set_desc: "OpenDNS Name Resolution"
            - comment: Block all other DNS
              match_type: any
              conditions_list:
                  - match_type: any
                    udp_src: 53
                  - match_type: any
                    udp_dst: 53
                  - match_type: any
                    tcp_src: 53
                  - match_type: any
                    tcp_dst: 53
              actions:
                  set_desc: "Bad DNS"
                  drop: at_controller
            - comment: Drop Bonjour Sleep Proxy
              match_type: any
              conditions_list:
                  - match_type: all
                    udp_src: 5353
                    udp_dst: 5353
              actions:
                  set_desc: "Drop Bonjour Sleep Proxy"
                  drop: at_controller_and_switch
            - comment: Drop Router SSDP
              match_type: any
              conditions_list:
                  - match_type: all
                    ip_src: 192.168.1.1
                    ip_dst: 239.255.255.250
              actions:
                  set_desc: "Drop SSDP UPnP"
                  drop: at_controller_and_switch
    #
    qos_treatment:
      # Control Quality of Service (QoS) treatment mapping of
      #  names to output queue numbers:
      default_priority: 0
      constrained_bw: 1
      high_priority: 2
      low_priority: 3
    #
    port_sets:
        # Port Sets control what data plane ports policies and
        #  features are applied on. Names must be unique.
        port_set_list:
            - name: port_set_location_internal
              port_list:
                  - name: TPLink-internal
                    DPID: 1
                    ports: 1-2,4
                    vlan_id: 0

            - name: port_set_location_external
              port_list:
                  - name: TPLink-external
                    DPID: 1
                    ports: 3
                    vlan_id: 0

    #
    locations:
        # Locations are logical groupings of ports. Takes first match.
        locations_list:
            - name: internal
              port_set_list:
                - port_set: port_set_location_internal

            - name: external
              port_set_list:
                - port_set: port_set_location_external


        default_match: unknown


