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

#*** nmeta - Network Metadata - Measurement Class and Methods

"""
This module is part of the nmeta suite running on top of Ryu SDN
controller to provide network identity and flow metadata.
It is provides methods to record events and retrieve
data related to these measurements.
"""

#*** Python 3 style division results as floating point:
from __future__ import division

import logging
import logging.handlers
import time
import collections

#*** Constants:
#*** How many seconds to aggregate data into a bucket:
BUCKET_SIZE_SECONDS = 2
#*** How many seconds of buckets to retain:
BUCKET_MAX_AGE = 600

class Measurement(object):
    """
    This class is instantiated by nmeta.py and provides methods
    to record events and retrieve data related to these measurements.
    """

    def __init__(self, measure_logging_level):
        #*** Set up logging to write to syslog:
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(measure_logging_level)
        #*** Log to syslog on localhost
        self.handler = logging.handlers.SysLogHandler(address=('localhost',
                                                      514), facility=19)
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        self.handler.setFormatter(formatter)
        self.logger.addHandler(self.handler)
        #*** Initialise the Packet-In bucket:
        self._pi_buckets = collections.defaultdict \
                             (lambda: collections.defaultdict(int))
        self.current_bucket = int(time.time())
        self._pi_buckets[self.current_bucket]['packets_in'] = 0

    def record_packet_in(self):
        """
        Record that a packet in event occurred so that data can be
        stored to record packet in rate.
        """
        current_time = int(time.time())
        bucket_delete_list = list()
        if (current_time - self.current_bucket) > BUCKET_SIZE_SECONDS:
            #*** Need a new bucket:
            self.logger.debug("DEBUG: module=measure Creating new bucket id "
                               "%s", current_time)
            self._pi_buckets[current_time]['packets_in'] = 1
            self.current_bucket = current_time
            self.logger.debug("DEBUG: module=measure Number of buckets is %s",
                                  len(self._pi_buckets))
            #*** Delete any old buckets:
            for bucket_id in self._pi_buckets:
                if bucket_id < (current_time - BUCKET_MAX_AGE):
                    #*** Mark the bucket for deletion (can't delete while
                    #*** iterating):
                    bucket_delete_list.append(bucket_id)
            for dead_bucket in bucket_delete_list:
                self.logger.debug("DEBUG: module=measure Deleting dead bucket "
                                     "%s", dead_bucket)
                del self._pi_buckets[dead_bucket]
        else:
            self._pi_buckets[self.current_bucket]['packets_in'] += 1

    def record_packet_out(self):
        """
        Record that a packet out event occurred so that data can be
        stored to record the packet out rate.
        """
        current_time = int(time.time())
        if (current_time - self.current_bucket) > BUCKET_SIZE_SECONDS:
            #*** Need a new bucket:
            self.logger.debug("DEBUG: module=measure Creating new bucket id "
                               "%s", current_time)
            self._pi_buckets[current_time]['packet_out'] = 1
            self.current_bucket = current_time
            self.logger.debug("DEBUG: module=measure Number of buckets is %s",
                                  len(self._pi_buckets))
        else:
            self._pi_buckets[self.current_bucket]['packet_out'] += 1

    def record_modify_flow(self):
        """
        Record that a modify flow event occurred so that data can be
        stored to record the modify flow rate.
        """
        current_time = int(time.time())
        if (current_time - self.current_bucket) > BUCKET_SIZE_SECONDS:
            #*** Need a new bucket:
            self.logger.debug("DEBUG: module=measure Creating new bucket id "
                               "%s", current_time)
            self._pi_buckets[current_time]['modify_flow'] = 1
            self.current_bucket = current_time
            self.logger.debug("DEBUG: module=measure Number of buckets is %s",
                                  len(self._pi_buckets))
        else:
            self._pi_buckets[self.current_bucket]['modify_flow'] += 1

    def get_event_rates(self, rate_interval):
        """
        Return the event type rates for all event types
        """
        _results_dict = dict()
        _results_dict['packet_in_rate'] = \
                        self.get_event_rate('packets_in', rate_interval)
        _results_dict['modify_flow_rate'] = \
                        self.get_event_rate('modify_flow', rate_interval)
        _results_dict['packet_out_rate'] = \
                        self.get_event_rate('packet_out', rate_interval)
        return _results_dict


    def get_event_rate(self, event_type, rate_interval):
        """
        Return the event type rate per second for last x seconds
        """
        current_time = int(time.time())
        events_in = 0
        overlap_bucket = 0
        actual_interval = 0
        event_rate = 0
        self.logger.debug("DEBUG: module=measure event_type %s rate_interval "
                            "%s", event_type, rate_interval)
        #*** Add contents of buckets that have a start time in that window
        #*** and note if there is an overlap bucket as start of window:
        for bucket_time in self._pi_buckets:
                if bucket_time > (current_time - rate_interval):
                    #*** Accumulate:
                    self.logger.debug("DEBUG: module=measure Adding %s from "
                        "bucket %s", 
                        self._pi_buckets[bucket_time][event_type],
                        bucket_time)
                    events_in = events_in + \
                                   self._pi_buckets[bucket_time][event_type]
                #*** Check if overlap:
                if (bucket_time > (current_time - (rate_interval + 
                         BUCKET_SIZE_SECONDS)) and (bucket_time < 
                         (current_time - rate_interval))):
                    self.logger.debug("DEBUG: module=measure Overlapping "
                           "bucket id %s", bucket_time)
                    overlap_bucket = bucket_time
        #*** Work out the dividing time for rate calculation. It is the lesser
        #*** of (current_time - overlap_bucket_end_time) and rate_interval:
        if (current_time - (overlap_bucket + BUCKET_SIZE_SECONDS) 
                  < rate_interval):
            actual_interval = current_time - (overlap_bucket + 
                                                BUCKET_SIZE_SECONDS)
        else:
            actual_interval = rate_interval
        #*** Return the rate:
        try:
            event_rate = events_in / actual_interval
        except:
            #*** Log the error (Divide by Zero error?) and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("ERROR: module=measure "
                "Divide by Zero error? Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        return event_rate
            
            
