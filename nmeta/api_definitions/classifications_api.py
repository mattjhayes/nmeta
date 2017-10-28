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

classification_schema = {
    'flow_hash': {
        'type': 'string'
    },
    'classified': {
        'type': 'integer'
    },
    'classification_tag': {
        'type': 'string'
    },
    'classification_time': {
        'type': 'datetime'
    },
    'actions': {
        'type': 'string'
    }
}

classifications_settings = {
    'url': 'classifications',
    'item_title': 'Classification Data',
    'schema': classification_schema,
    'datasource': {
        'source': 'classifications'
    }
}
