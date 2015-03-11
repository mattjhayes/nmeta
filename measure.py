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

import logging
import logging.handlers
import time
import collections

#*** Constants:
#*** How many seconds to aggregate data into a bucket:
BUCKET_SIZE_SECONDS = 2
#*** How many seconds of buckets to retain:
BUCKET_MAX_AGE = 60

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

    def packet_in(self):
        """
        Record that a packet in event occurred so that data can be
        stored to record packet in rate.
        """
        current_time = int(time.time())
        bucket_delete_list = list()
        self.logger.debug("DEBUG: module=measure Packet in. is %s - %s = %s gt %s?",
            current_time, self.current_bucket, current_time-self.current_bucket, BUCKET_SIZE_SECONDS)
        if (current_time - self.current_bucket) > BUCKET_SIZE_SECONDS:
            #*** Need a new bucket:
            print "creating a new bucket with 1 packet_in event"
            self._pi_buckets[current_time]['packets_in'] = 1
            self.current_bucket = current_time
            #*** Delete any old buckets:
            for bucket_id in self._pi_buckets:
                if self._pi_buckets[bucket_id] < \
                          (current_time - BUCKET_MAX_AGE):
                    #*** Mark the bucket for deletion (can't delete while
                    #*** iterating):
                    print "adding bucket %s to delete list" % bucket_id
                    bucket_delete_list.append(bucket_id)
            for dead_bucket in bucket_delete_list:
                print "Tidy-up - deleting bucket %s" % self._pi_buckets[dead_bucket]
                del self._pi_buckets[dead_bucket]
        else:
            self._pi_buckets[self.current_bucket]['packets_in'] += 1
            print "there's now %s in the bucket" % self._pi_buckets[self.current_bucket]['packets_in']

    def get_packet_in_rate_10s(self):
        """
        Return the packet in rate for last 10 seconds
        """
        #*** Measurement period for the rate calculation:
        rate_interval = 10
        #*** Add contents of buckets that have a start time in that window
        #*** and note if there is an overlap bucket as start of window:
        
        #*** Work out the dividing time for rate calculation. It is the lesser
        #*** of (current_time - overlap_bucket_end_time) and rate_interval:
        
        #*** Return the rate:
        #try:
            
            
