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

# UNDER CONSTRUCTION

flow_mods_schema = {
        'flow_hash': {
            'type': 'string'
        },
        'timestamp': {
            'type': 'string'
        },
        'dpid': {
            'type': 'integer'
        },
        'suppress_type': {
            'type': 'string'
        },
        'standdown': {
            'type': 'integer'
        },
        'match_type': {
            'type': 'string'
        },
        'forward_cookie': {
            'type': 'integer'
        },
        'forward_match': {
            'type': 'dict'
        },
        'reverse_cookie': {
            'type': 'integer'
        },
        'reverse_match': {
            'type': 'dict'
        },
        'client_ip': {
            'type': 'string'
        }
    }

flow_mods_settings = {
    'url': 'flow_mods',
    'item_title': 'Flow Modification Data',
    'schema': flow_mods_schema,
    'datasource': {
        'source': 'flow_mods'
    }
}
