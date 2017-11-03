# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module is part of the nmeta suite
.
It provides a simple method for collecting training data samples for
use in machine learning classifiers. Flows with more than a threshold
of packets have their metrics dumped into the classification tag.
.
"""

class Classifier(object):
    """
    A custom classifier module for import by nmeta
    """
    def __init__(self, logger):
        """
        Initialise the classifier
        """
        self.logger = logger

    def classifier(self, classifier_result, flow, ident):
        """
        This custom classifier provides a simple method for
        collecting training data samples for use in machine
        learning classifiers.

        Flows with more than a defined threshold of packets
        have their metrics dumped into the classification tag
        so that they can be recorded and used for ML training.
        The ground truth about the flow type must be recorded
        separately out-of-band and matched with the flow
        metrics.
        .
        This method is passed:
        * A TCClassifierResult class object
        * A Flow class object holding the current flow context
        * An Identities class object
        .
        It updates the TCClassifierResult class object with flow
        metrics in the classification_tag
        """
        #*** Threshold number of packets in flow to return
        #*** metrics on (ignores flows with fewer or more packets):
        packet_theshold = 5

        #*** Used to separate terms in classification tag:
        separator = ','

        #*** Get number of packets in flow so far:
        packets = flow.packet_count()

        if packets == packet_theshold:
            #*** Turn off continue_to_inspect to suppress flow:
            classifier_result.match = True
            classifier_result.continue_to_inspect = False
            classifier_result.actions['qos_treatment'] = 'default_priority'
            #*** Assemble flow metrics and return as classification tag:
            result = 'ML'
            #*** Identity of server to help with ground truth marking:
            identity_record = ident.get_service_by_ip(flow.server())
            if identity_record:
                service_name = identity_record['service_name']
            else:
                service_name = ""
            result += separator + str(service_name)
            #*** Packet header information:
            result += separator + str(flow.packet.ip_src)
            result += separator + str(flow.packet.ip_dst)
            result += separator + str(flow.packet.proto)
            result += separator + str(flow.packet.tp_src)
            result += separator + str(flow.packet.tp_dst)
            #*** Flow features:
            result += separator + str(flow.max_packet_size())
            result += separator + str(flow.max_interpacket_interval())
            result += separator + str(flow.min_interpacket_interval())
            result += separator + str(flow.packet_count())
            result += separator + str(flow.packet_directions())
            result += separator + str(flow.packet_sizes())
            classifier_result.classification_tag = result
        elif packets > packet_theshold:
            #*** Turn off continue_to_inspect to suppress flow:
            classifier_result.match = True
            classifier_result.continue_to_inspect = False
        else:
            self.logger.debug("Continuing to inspect flow_hash=%s packets=%s",
                                                       flow.flow_hash, packets)
            #*** Don't suppress flow so we get sent more packets:
            classifier_result.match = True
            classifier_result.continue_to_inspect = True
