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
  dpid=TBD port=TBD.

The recipe does the following:

- Drops SSDP traffic from the router
- Drops Bonjour traffic
- DNS lookups are only allowed against OpenDNS server 208.67.222.123
  (TBD, support second server at 208.67.220.123)

Main Policy:
============

Use this main_policy.yaml file in the user config directory:

.. code-block:: text

  ~/nmeta/nmeta/config/user/

Here's the YAML:

.. code-block:: YAML

    ---
    TBD: not done yet

