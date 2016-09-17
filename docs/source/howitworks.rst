############
How it Works
############

Nmeta uses OpenFlow Software-Defined Networking (SDN) to selectively control
flows through switches so that packets can be classified and actions taken.
It instructs connected OpenFlow switches to send packets from unknown flows
to the Ryu SDN Controller, on which nmeta runs, for analysis.

Nmeta configures a single flow table per switch with a table-miss
flow entry (FE) that sends full unmatched packets to the controller. As flows
are classified, specific higher-priority FEs are configured to suppress
sending further packets to the controller.
