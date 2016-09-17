###############
Configure Nmeta
###############

Configuration files are in the config subdirectory and are written
in YAML ("YAML Ain't Markup Language") format.

General configuration parameters are stored in the file:

.. code-block:: text

  ~/nmeta/nmeta/config/config.yaml

*********************
Configure Main Policy
*********************

The main policy configures how nmeta works with data plane traffic.
This includes traffic classification rules.
The main policy is stored in the YAML file:

.. code-block:: text

  ~/nmeta/nmeta/config/main_policy.yaml

It is used to control what classifiers are used, in what order and what
actions are taken.

The traffic classification policy is based off a root key *tc_rules*.
This root contains a *ruleset* name (only one ruleset supported at this
stage), which in turn contains one or more *rules*.

Rules are an ordered list (denoted by preceding dash). Each rule contains:

:Comment: A *comment* to describe the purpose of the rule (optional). A
  comment must start with the attribute *comment:* and any single-line string
  can follow
:Match Type: A *match type* is one of *any* or *all*
:Conditions List: A single *conditions_list* stanza that contains one or more
  *conditions* stanzas

Example simple traffic classification policy with a single rule:

.. image:: images/simple_tc_policy.png

A *conditions_list* stanza contains:

- A match type, consisting of *any* or *all*
- One or more *conditions* as list items (denoted by dash preceding the
  first item)
- One or more *classifiers* (see below)

A *conditions* stanza is a list item in a conditions list and contains:

- A match type, consisting of *any* or *all*
- One or more *classifiers* (see below)

A *actions* stanza contains one or more attribute/value pairs

Here is a more complex traffic classification policy:

.. image:: images/complex_tc_policy.png

Conditions invoke classifiers. There are four types of classifier supported:

- Static
- Identity
- Payload
- Statistical

Static Classifiers
------------------

Static classifiers match on attributes in packet headers, or on environmental
attributes such as port numbers.

Supported attributes are:

:eth_src: | Ethernet source MAC address.
  | **Example**:
  | eth_src: 08:00:27:4a:2d:41
:eth_dst: | Ethernet destination MAC address.
  | **Example**:
  | eth_dst: 08:00:27:4a:2d:42
:eth_type: | Ethernet type. Can be in hex (starting with 0x) or decimal.
  | **Examples**:
  | eth_type: 0x0800
  | eth_type: 35020
:ip_src: | IP source address. Can be a single address, a network with a mask in
  CIDR notation, or an IP range with two addresses separated by a hyphen.
  Both addresses in a range must be the same type, and the second
  address must be higher than the first.
  | **Examples**:
  | ip_src: 192.168.56.12
  | ip_src: 192.168.56.0/24
  | ip_src: 192.168.56.12-192.168.56.31
:ip_dst: | IP destination address. Can be a single address, a network with a
  mask in CIDR notation, or an IP range with two addresses separated by a
  hyphen. Both addresses in a range must be the same type, and the second
  address must be higher than the first.
  | **Examples**:
  | ip_dst: 192.168.57.40
  | ip_dst: 192.168.57.0/24
  | ip_dst: 192.168.57.36\-192.168.78.31
:tcp_src: | TCP source port.
  | **Example**:
  | tcp_src: 22
:tcp_dst: | TCP destination port.
  | **Example**:
  | tcp_dst: 80







