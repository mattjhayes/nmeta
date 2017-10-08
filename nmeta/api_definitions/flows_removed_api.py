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

# Records of flows that have been removed by switches
# (generally due to idle timeout)
# Not deduplicated for multiple switches

flows_removed_schema = {
    'dpid': {
        'type': 'integer'
    },
    'removal_time': {
        'type': 'datetime'
    },
    'cookie': {
        'type': 'string'
    },
    'priority': {
        'type': 'integer'
    },
    'reason': {
        'type': 'string'
    },
    'table_id': {
        'type': 'integer'
    },
    'duration_sec': {
        'type': 'string'
    },
    'idle_timeout': {
        'type': 'string'
    },
    'hard_timeout': {
        'type': 'string'
    },
    'packet_count': {
        'type': 'integer'
    },
    'byte_count': {
        'type': 'integer'
    },
    'eth_A': {
        'type': 'string'
    },
    'eth_B': {
        'type': 'string'
    },
    'eth_type': {
        'type': 'string'
    },
    'ip_A': {
        'type': 'string'
    },
    'ip_B': {
        'type': 'string'
    },
    'ip_proto': {
        'type': 'string'
    },
    'tp_A': {
        'type': 'string'
    },
    'tp_B': {
        'type': 'string'
    },
    'flow_hash': {
        'type': 'string'
    },
    'direction': {
        'type': 'string'
    }
}

flows_removed_settings = {
    'url': 'flows_removed',
    'item_title': 'Flows Removed',
    'schema': flows_removed_schema,
    'datasource': {
        'source': 'flow_rems'
    }
}

#*** Removed flows count (does not deduplicate for multiple switches):
flows_removed_stats_count_schema = {
    'flows_removed_count': {
        'type': 'integer'
    }
}

flows_removed_stats_count_settings = {
    'url': 'flows_removed/stats/count',
    'item_title': 'Count of Removed Flows',
    'schema': flows_removed_stats_count_schema
}

#*** Removed flows bytes sent by source IP (dedup for multiple switches):
flows_removed_src_bytes_sent_schema = {
    '_items': {
        '_id': 'string',
        'identity': 'string',
        'total_bytes_sent': 'integer'
    }
}

flows_removed_src_bytes_sent_settings = {
    'url': 'flows_removed/stats/src_bytes_sent',
    'item_title': 'Removed Flows Bytes Sent by Source IP',
    'schema': flows_removed_src_bytes_sent_schema
}

#*** Removed flows bytes received by source IP (dedup for multiple switches):
flows_removed_src_bytes_received_schema = {
    '_items': {
        '_id': 'string',
        'identity': 'string',
        'total_bytes_received': 'integer'
    }
}

flows_removed_src_bytes_received_settings = {
    'url': 'flows_removed/stats/src_bytes_received',
    'item_title': 'Removed Flows Bytes Received by Source IP',
    'schema': flows_removed_src_bytes_received_schema
}

#*** Removed flows bytes sent by destination IP (dedup for multiple switches):
flows_removed_dst_bytes_sent_schema = {
    '_items': {
        '_id': 'string',
        'identity': 'string',
        'total_bytes_sent': 'integer'
    }
}

flows_removed_dst_bytes_sent_settings = {
    'url': 'flows_removed/stats/dst_bytes_sent',
    'item_title': 'Removed Flows Bytes Sent by Source IP',
    'schema': flows_removed_dst_bytes_sent_schema
}

#*** Removed flows bytes received by destination IP (dedup for multiple switches):
flows_removed_dst_bytes_received_schema = {
    '_items': {
        '_id': 'string',
        'identity': 'string',
        'total_bytes_received': 'integer'
    }
}

flows_removed_dst_bytes_received_settings = {
    'url': 'flows_removed/stats/dst_bytes_received',
    'item_title': 'Removed Flows Bytes Received by Source IP',
    'schema': flows_removed_dst_bytes_received_schema
}


# LEGACY:

#*** Removed flows bytes sent by source IP (dedup for multiple switches):
flows_removed_stats_bytes_sent_schema = {
    '_items': {
        '_id': 'string',
        'identity': 'string',
        'total_bytes_sent': 'integer'
    }
}

flows_removed_stats_bytes_sent_settings = {
    'url': 'flows_removed/stats/bytes_sent',
    'item_title': 'Removed Flows Bytes Sent by Source IP',
    'schema': flows_removed_stats_bytes_sent_schema
}

#*** Removed flows bytes received by source IP (dedup for multiple switches):
flows_removed_stats_bytes_received_schema = {
    '_items': {
        '_id': 'string',
        'identity': 'string',
        'total_bytes_received': 'integer'
    }
}

flows_removed_stats_bytes_received_settings = {
    'url': 'flows_removed/stats/bytes_received',
    'item_title': 'Removed Flows Bytes Received by Source IP',
    'schema': flows_removed_stats_bytes_received_schema
}
