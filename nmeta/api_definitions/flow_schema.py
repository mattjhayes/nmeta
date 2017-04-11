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

flow_schema = {
        'flow_hash': {
            'type': 'string'
        },
        'timestamp': {
            'type': 'string'
        },
        'dpid': {
            'type': 'integer'
        },
        'in_port': {
            'type': 'integer'
        },
        'length': {
            'type': 'integer'
        },
        'eth_src': {
            'type': 'string'
        },
        'eth_dst': {
            'type': 'string'
        },
        'eth_type': {
            'type': 'integer'
        },
        'ip_src': {
            'type': 'string'
        },
        'ip_dst': {
            'type': 'string'
        },
        'proto': {
            'type': 'string'
        },
        'tp_src': {
            'type': 'string'
        },
        'tp_dst': {
            'type': 'string'
        },
        'tp_flags': {
            'type': 'string'
        },
        'tp_seq_src': {
            'type': 'string'
        },
        'tp_seq_dst': {
            'type': 'string'
        }
    }
