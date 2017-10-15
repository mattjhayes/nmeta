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

#*** nmeta - Network Metadata - API definition file

#*** This API provides min/avg/max telemetry on processing times for Packet-In
#*** events in Ryu and nmeta

pi_time_schema = {
        'timestamp': {
            'type': 'datetime'
        },
        'ryu_time_min': {
            'type': 'float'
        },
        'ryu_time_avg': {
            'type': 'float'
        },
        'ryu_time_max': {
            'type': 'float'
        },
        'ryu_time_period': {
            'type': 'float'
        },
        'ryu_time_records': {
            'type': 'float'
        },
        'pi_time_min': {
            'type': 'float'
        },
        'pi_time_avg': {
            'type': 'float'
        },
        'pi_time_max': {
            'type': 'float'
        },
        'pi_time_period': {
            'type': 'float'
        },
        'pi_time_records': {
            'type': 'float'
        }
    }

pi_time_settings = {
    'url': 'infrastructure/controllers/pi_time',
    'item_title': 'Packet-In Processing Time',
    'schema': pi_time_schema
}

