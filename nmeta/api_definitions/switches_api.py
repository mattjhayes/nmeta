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

switches_schema = {
        'dpid': {
            'type': 'integer'
        },
        'ip_address': {
            'type': 'string'
        },
        'port': {
            'type': 'integer'
        },
        'time_connected': {
            'type': 'string'
        },
        'mfr_desc': {
            'type': 'string'
        },
        'hw_desc': {
            'type': 'string'
        },
        'sw_desc': {
            'type': 'string'
        },
        'serial_num': {
            'type': 'string'
        },
        'dp_desc': {
            'type': 'string'
        }
    }

switches_settings = {
    'url': 'infrastructure/switches',
    'item_title': 'OpenFlow Switches',
    'schema': switches_schema
}

#*** A count of the number of connected switches:
switches_count_schema = {
        'connected_switches': {
            'type': 'integer'
        }
    }

switches_count_settings = {
    'url': 'infrastructure/switches/stats/connected_switches',
    'item_title': 'Count of Connected OpenFlow Switches',
    'schema': switches_count_schema
}
