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
#*** How many seconds to aggregate data into buckets:
RATE_BUCKET_SIZE_SECONDS = 2
METRIC_BUCKET_SIZE_SECONDS = 2

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
        #*** Initialise the bucket dictionaries:
        self._rate_buckets = collections.defaultdict \
                             (lambda: collections.defaultdict(int))
        self.current_rate_bucket = int(time.time())
        self._metric_buckets = collections.defaultdict \
                             (lambda: collections.defaultdict(int))
        self.current_metric_bucket = int(time.time())

    def record_rate_event(self, event_type):
        """
        Record a rate event of a particular type occurred
        """
        current_time = int(time.time())
        if (current_time - self.current_rate_bucket) > \
                                        RATE_BUCKET_SIZE_SECONDS:
            #*** Need a new bucket:
            self.logger.debug("DEBUG: module=measure Creating new rate bucket"
                               " id %s", current_time)
            self._rate_buckets[current_time][event_type] = 1
            self.current_rate_bucket = current_time
            self.logger.debug("DEBUG: module=measure Number of rate buckets is"
                                   " %s", len(self._rate_buckets))
        else:
            #*** Accumulate 1 to the event type in the bucket:
            self._rate_buckets[self.current_rate_bucket][event_type] += 1

    def record_metric(self, event_type, event_value):
        """
        Store an event in a bucket in such a manner that avg/max/min
        can be retrieved
        """
        current_time = int(time.time())
        if (current_time - self.current_metric_bucket) > \
                          METRIC_BUCKET_SIZE_SECONDS:
            #*** Need a new bucket:
            self.logger.debug("DEBUG: module=measure Creating new metric "
                               "bucket id %s", current_time)
            self.current_metric_bucket = current_time
            self.logger.debug("DEBUG: module=measure Number of metric buckets"
                                  " is %s", len(self._metric_buckets))
        #*** Create a key for the event type in metrics buckets dict if 
        #***  doesn't exist:
        if not event_type in self._metric_buckets[self.current_metric_bucket]:
            self._metric_buckets[self.current_metric_bucket][event_type] = {}
        #*** Record as max if largest:
        if not 'max' in self._metric_buckets[self.current_metric_bucket] \
                                                                  [event_type]:
            self._metric_buckets[self.current_metric_bucket][event_type] \
                                                         ['max'] = event_value
        if event_value > self._metric_buckets[self.current_metric_bucket]\
                                                         [event_type]['max']:
            self._metric_buckets[self.current_metric_bucket][event_type] \
                                                         ['max'] = event_value
        #*** Record as min if smallest:
        if not 'min' in self._metric_buckets[self.current_metric_bucket] \
                                                                  [event_type]:
            self._metric_buckets[self.current_metric_bucket][event_type] \
                                                         ['min'] = event_value
        if event_value < self._metric_buckets[self.current_metric_bucket]\
                                                         [event_type]['min']:
            self._metric_buckets[self.current_metric_bucket][event_type] \
                                                         ['min'] = event_value
        #*** For averages, accumulate a running total and number of events:
        if not 'total' in self._metric_buckets[self.current_metric_bucket] \
                                                                  [event_type]:
            self._metric_buckets[self.current_metric_bucket][event_type] \
                                                        ['total'] = event_value
        else:
            self._metric_buckets[self.current_metric_bucket]\
                                        [event_type]['total'] += event_value
        if not 'events' in self._metric_buckets[self.current_metric_bucket] \
                                                                  [event_type]:
            self._metric_buckets[self.current_metric_bucket][event_type] \
                                                        ['events'] = 1
        else:
            self._metric_buckets[self.current_metric_bucket]\
                                        [event_type]['events'] += 1

    def get_event_rates(self, rate_interval):
        """
        Return the event type rates for all rate event types
        """
        _results_dict = dict()
        _results_dict['packet_in_rate'] = \
                        self.get_event_rate('packet_in', rate_interval)
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
        for bucket_time in self._rate_buckets:
            if bucket_time > (current_time - rate_interval):
                #*** Accumulate:
                self.logger.debug("DEBUG: module=measure Adding %s from "
                        "rate bucket %s", 
                        self._rate_buckets[bucket_time][event_type],
                        bucket_time)
                events_in = events_in + \
                                   self._rate_buckets[bucket_time][event_type]
            #*** Check if overlap:
            if (bucket_time > (current_time - (rate_interval + 
                         RATE_BUCKET_SIZE_SECONDS)) and (bucket_time < 
                         (current_time - rate_interval))):
                self.logger.debug("DEBUG: module=measure Overlapping "
                           "rate bucket id %s", bucket_time)
                overlap_bucket = bucket_time
        #*** Work out the dividing time for rate calculation. It is the lesser
        #*** of (current_time - overlap_bucket_end_time) and rate_interval:
        if (current_time - (overlap_bucket + RATE_BUCKET_SIZE_SECONDS) 
                  < rate_interval):
            actual_interval = current_time - (overlap_bucket + 
                                                RATE_BUCKET_SIZE_SECONDS)
        else:
            actual_interval = rate_interval
        #*** Return the rate:
        try:
            event_rate = events_in / actual_interval
        except:
            #*** Log the error (Divide by Zero error?) and return 0:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.logger.error("ERROR: module=measure in get_event_rate"
                "Divide by Zero error? Exception %s, %s, %s",
                            exc_type, exc_value, exc_traceback)
            return 0
        return event_rate

    def get_event_metric_stats(self, event_type, rate_interval):
        """
        Return the event metric stats for specified event type
        as a dictionary
        """
        current_time = int(time.time())
        #*** Variables for accumulation from buckets:
        first_time = True
        acc_total = 0
        acc_events = 0
        acc_buckets = 0
        self.logger.debug("DEBUG: module=measure get_event_metric_stats "
                            "event_type %s rate_interval %s", 
                             event_type, rate_interval)
        #*** Calc on contents of buckets that have a start time in that window
        for bucket_time in self._metric_buckets:
            if bucket_time > (current_time - rate_interval):
                acc_buckets += 1
                if first_time:
                    #*** Its the first time so set initial stats values:
                    max_max = self._metric_buckets \
                                   [self.current_metric_bucket] \
                                   [event_type]['max']
                    min_min = self._metric_buckets \
                                   [self.current_metric_bucket] \
                                   [event_type]['min']
                    first_time = False
                #*** Is this a new MaxMax?:
                cur_max = self._metric_buckets[self.current_metric_bucket] \
                                   [event_type]['max']
                if cur_max > max_max:
                    max_max = cur_max
                #*** Is this a new MinMin?:
                cur_min = self._metric_buckets[self.current_metric_bucket] \
                                   [event_type]['min']
                if cur_min < min_min:
                    min_min = cur_min
                #*** Accumulate the totals for metric and number of events:
                acc_total += self._metric_buckets[self.current_metric_bucket] \
                                   [event_type]['total']
                acc_events += self._metric_buckets \
                                   [self.current_metric_bucket] \
                                   [event_type]['events']
        #*** Calculate average:
        if acc_events:
            #*** Do division:
            try:
                acc_avg = acc_total / acc_events
            except:
                #*** Log the error and set acc_avg to 0:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                self.logger.error("ERROR: module=measure in "
                     "get_event_metric_stats Divide by Zero error? Exception "
                     "%s, %s, %s",
                     exc_type, exc_value, exc_traceback)
                acc_avg = 0
        else:
            #*** No events so result is 0:
            acc_avg = 0
        #*** Build results dictionary:
        _results_dict = dict()
        _results_dict[event_type] = {}
        _results_dict[event_type]['max_max'] = max_max
        _results_dict[event_type]['min_min'] = min_min
        _results_dict[event_type]['avg'] = acc_avg
        _results_dict[event_type]['number_of_measurements'] = acc_events
        _results_dict[event_type]['number_of_buckets'] = acc_buckets
        _results_dict[event_type]['bucket_size_seconds'] = \
                                          METRIC_BUCKET_SIZE_SECONDS
        return _results_dict

    def kick_the_rate_buckets(self, bucket_max_age):
        """
        Tidy-up by deleting old rate buckets.
        """
        current_time = int(time.time())
        bucket_delete_list = list()
        #*** Delete any old buckets:
        for bucket_id in self._rate_buckets:
            if bucket_id < (current_time - bucket_max_age):
                #*** Mark the bucket for deletion (can't delete while
                #*** iterating):
                bucket_delete_list.append(bucket_id)
        for dead_bucket in bucket_delete_list:
            self.logger.debug("DEBUG: module=measure Deleting dead rate bucket"
                                     " %s", dead_bucket)
            del self._rate_buckets[dead_bucket]
            
    def kick_the_metric_buckets(self, bucket_max_age):
        """
        Tidy-up by deleting old metric buckets.
        """
        current_time = int(time.time())
        bucket_delete_list = list()
        #*** Delete any old buckets:
        for bucket_id in self._metric_buckets:
            if bucket_id < (current_time - bucket_max_age):
                #*** Mark the bucket for deletion (can't delete while
                #*** iterating):
                bucket_delete_list.append(bucket_id)
        for dead_bucket in bucket_delete_list:
            self.logger.debug("DEBUG: module=measure Deleting dead metric "
                                     "bucket %s", dead_bucket)
            del self._metric_buckets[dead_bucket]

