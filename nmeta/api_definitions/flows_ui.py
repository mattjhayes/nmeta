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

flows_ui_schema = {
        'flow_hash': {
            'type': 'string'
        },
        'actions': {
            'type': 'string'
        },
        'actions_hover': {
            'type': 'string'
        },
        'classification': {
            'type': 'string'
        },
        'classification_hover': {
            'type': 'string'
        },
        'data_received': {
            'type': 'string'
        },
        'data_received_hover': {
            'type': 'string'
        },
        'data_sent': {
            'type': 'string'
        },
        'data_sent_hover': {
            'type': 'string'
        },
        'dst': {
            'type': 'string'
        },
        'dst_hover': {
            'type': 'string'
        },
        'proto': {
            'type': 'string'
        },
        'proto_hover': {
            'type': 'string'
        },
        'src': {
            'type': 'string'
        },
        'src_hover': {
            'type': 'string'
        },
        'timestamp': {
            'type': 'datetime'
        },
        'tp_dst': {
            'type': 'string'
        },
        'tp_dst_hover': {
            'type': 'string'
        },
        'tp_src': {
            'type': 'string'
        },
        'tp_src_hover': {
            'type': 'string'
        }
    }

#*** Eve Settings for flows/ui Objects. Database lookup
#*** with deduplication and enhancements done by hook function
flows_ui_settings = {
    'url': 'flows/ui',
    'item_title': 'Flows UI Data',
    'schema': flows_ui_schema
}
