#######
Recipes
#######

These recipes are to provide ideas on how nmeta can be used through examples.

Note that policies have an **implicit allow** at the end of the policy. Also,
actions implicitly allow if there is no drop action.

Recipes:

:ref:`parental-control-recipe`
:ref:`lan-traffic-clean-up-recipe`
:ref:`qos-recipe`

.. _parental-control-recipe:

***********************
Parental Control Recipe
***********************

This recipe is for using nmeta to provide parental control on a home network.
It is just an example of some capabilities, the exact configuration needs to
be tailored to your specific requirements. Note that parental controls on
network should be part of a wider strategy, including controls on the devices
used by children, and education on internet safety.

In this fictional example, there are two children, conveniently named Alice
and Bob. Alice has a Chromebook, which does not register a hostname via DHCP,
but does have a consistent Wi-Fi MAC address (01:23:45:67:89:ab). Bob has
an iPhone with a DHCP host name of *Bobs-iPhone*.

In this recipe we enforce the following parental controls on Alice and Bob:

- All devices on the home network can only do DNS lookups against OpenDNS
  FamilyShield servers (that attempt to block adult content), apart from 
  Chromecast which doesn't honour the DNS allocations in DHCP and insists on
  talking to Google's DNS servers
- Alice's Chromebook is blocked from accessing YouTube
- Alice's Chromebook and Bob's iPhone are only allowed to access the Internet
  between 7am and 9pm

Main Policy:
============

Use this main_policy.yaml file in the user config directory:

.. code-block:: text

  ~/nmeta/nmeta/config/user/

Here's the YAML:

.. code-block:: YAML

    ---
    #*** Main Policy for nmeta - Home Router Parental Control Policy
    #*** Written in YAML
    #
    tc_rules:
        # Traffic Classification Rulesets and Rules
        tc_ruleset_1:
            - comment: Allow OpenDNS
              match_type: any
              conditions_list:
                  - match_type: all
                    classifiers_list:
                        - udp_dst: 53
                        - ip_dst: 208.67.222.123
                  - match_type: all
                    classifiers_list:
                        - udp_src: 53
                        - ip_src: 208.67.222.123
                  - match_type: all
                    classifiers_list:
                        - udp_dst: 53
                        - ip_dst: 208.67.220.123
                  - match_type: all
                    classifiers_list:
                        - udp_src: 53
                        - ip_src: 208.67.220.123
              actions:
                  set_desc: "OpenDNS Name Resolution"
            - comment: Allow Chromecast DNS to Google 
              match_type: any
              conditions_list:
                  - match_type: all
                    classifiers_list:
                        - identity_dhcp_hostname: Chromecast
                        - udp_dst: 53
                        - ip_dst: 8.8.8.8
                  - match_type: all
                    classifiers_list:
                        - identity_dhcp_hostname: Chromecast
                        - udp_src: 53
                        - ip_src: 8.8.8.8
              actions:
                  set_desc: "Allow Chromecast DNS to Google"
            - comment: Block all other DNS
              match_type: any
              conditions_list:
                  - match_type: any
                    classifiers_list:
                        - udp_src: 53
                  - match_type: any
                    classifiers_list:
                        - udp_dst: 53
                  - match_type: any
                    classifiers_list:
                        - tcp_src: 53
                  - match_type: any
                    classifiers_list:
                        - tcp_dst: 53
              actions:
                  set_desc: "Bad DNS, needs investigating"
                  drop: at_controller
            - comment: Drop Alice Chromebook to YouTube
              match_type: any
              conditions_list:
                  - match_type: all
                    classifiers_list:
                        - eth_src: 01:23:45:67:89:ab
                        - identity_service_dns_re: '.*\.youtube\*'
                  - match_type: all
                    classifiers_list:
                        - eth_src: 01:23:45:67:89:ab
                        - identity_service_dns_re: '.*\.googlevideo\.com'
              actions:
                  set_desc: "Drop Alice Chromebook to YouTube"
                  drop: at_controller
            - comment: Time of Day restriction on Alice and Bob
              match_type: all
              conditions_list:
                  - match_type: any
                    classifiers_list:
                        - eth_src: 01:23:45:67:89:ab
                        - identity_dhcp_hostname: Bobs-iPhone
                  - match_type: all
                    classifiers_list:
                        - time_of_day: 21:00-06:59
              actions:
                  set_desc: "Drop Kids Internet after hours"
                  drop: at_controller
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


.. _lan-traffic-clean-up-recipe:

********************
LAN Traffic Clean-up
********************

This recipe blocks undesirable LAN traffic. What counts as undesirable is
up for debate, this recipe just demonstrates some mechanisms for writing
a policy

It does the following:

- Drops SSDP (UPnP) traffic
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
    #*** Main Policy for nmeta - Home Router LAN Clean-up Policy
    #*** Written in YAML
    #
    tc_rules:
        # Traffic Classification Rulesets and Rules
        tc_ruleset_1:
            - comment: Drop Bonjour Sleep Proxy
              match_type: any
              conditions_list:
                  - match_type: all
                    classifiers_list:
                        - udp_src: 5353
                        - udp_dst: 5353
              actions:
                  set_desc: "Drop Bonjour Sleep Proxy"
                  drop: at_controller_and_switch
            - comment: Drop SSDP UPnP
              match_type: any
              conditions_list:
                  - match_type: all
                    classifiers_list:
                        - ip_dst: 239.255.255.250
                        - udp_dst: 1900
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


.. _qos-recipe:

*******************************
Quality of Service (QoS) Recipe
*******************************

This recipe uses QoS to constrain bandwidth of YouTube video traffic, purely
as an example of how to do QoS.

Traffic is identified with a classification list, then marked with a
QoS treatment action (constrained_bw).

The *qos_treatment* section maps *constrained_bw* to QoS queue number 1.

QoS queues need to be separately configured on switches. Failure to have a
queue defined on the switch (other than 0) may result in traffic being dropped.

Main Policy:
============

Use this main_policy.yaml file in the user config directory:

.. code-block:: text

  ~/nmeta/nmeta/config/user/

Here's the YAML:

.. code-block:: YAML

    ---
    #*** Main Policy for nmeta - Example QoS Recipe.
    #*** Written in YAML
    #
    # Example QoS constraint of YouTube Video traffic
    #
    tc_rules:
        # Traffic Classification Rulesets and Rules
        tc_ruleset_1:
            - comment: Constrained Bandwidth Traffic
              match_type: any
              conditions_list:
                  - match_type: any
                    classifiers_list:
                        - identity_service_dns_re: '.*\.youtube\*'
                        - identity_service_dns_re: '.*\.googlevideo\.com'
              actions:
                set_desc: "Constrained YouTube Bandwidth Traffic"
                qos_treatment: constrained_bw
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
                  - name: VirtualSwitch1-internal
                    DPID: 1
                    ports: 1-3,5,66
                    vlan_id: 0

                  - name: VirtualSwitch2-internal
                    DPID: 255
                    ports: 3,5
                    vlan_id: 0

            - name: port_set_location_external
              port_list:
                  - name: VirtualSwitch1-external
                    DPID: 1
                    ports: 6
                    vlan_id: 0

                  - name: VirtualSwitch2-external
                    DPID: 255
                    ports: 1-2,4
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

        default_match: external

