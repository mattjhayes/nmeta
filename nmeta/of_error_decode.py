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

#*** nmeta - Network Metadata - Decode OpenFlow Error Messages

"""
This module is part of the nmeta suite running on top of Ryu SDN controller.
It decodes OpenFlow error messages
.
Example usage:
        import of_error_decode
        ...
        type1, type2, code1, code2 = of_error_decode.decode(error_type,
                                                                    error_code)
        self.logger.error('error_type=%s %s error_code=%s %s', type1, type2,
                                code1, code2)
"""

#*** OpenFlow Error Enumeration from v1.3.3 specification:
OF_ERRORS = {}
OF_ERRORS[0] = {'type': 'OFPET_HELLO_FAILED',
                'desc': 'Hello protocol failed.',
                'list':
                ['OFPHFC_INCOMPATIBLE, No compatible version.',
                'OFPHFC_EPERM, Permissions error.']}
OF_ERRORS[1] = {'type': 'OFPET_BAD_REQUEST',
                'desc': 'Request was not understood.',
                'list':
                ['OFPBRC_BAD_VERSION, ofp_header.version not supported.',
                'OFPBRC_BAD_TYPE, ofp_header.type not supported.',
                'OFPBRC_BAD_MULTIPART, ofp_multipart_request.type not supported.',
                'OFPBRC_BAD_EXPERIMENTER, Experimenter id not supported',
                'OFPBRC_BAD_EXP_TYPE, Experimenter type not supported.',
                'OFPBRC_EPERM, Permissions error.',
                'OFPBRC_BAD_LEN, Wrong request length for type.',
                'OFPBRC_BUFFER_EMPTY, Specified buffer has already been used.',
                'OFPBRC_BUFFER_UNKNOWN, Specified buffer does not exist.',
                'OFPBRC_BAD_TABLE_ID, Specified table-id invalid or does not exist.',
                'OFPBRC_IS_SLAVE, Denied because controller is slave.',
                'OFPBRC_BAD_PORT, Invalid port.',
                'OFPBRC_BAD_PACKET, Invalid packet in packet-out.',
                'OFPBRC_MULTIPART_BUFFER_OVERFLOW, ofp_multipart_request overflowed the assigned buffer.']}
OF_ERRORS[2] = {'type': 'OFPET_BAD_ACTION',
                'desc': 'Error in action description.',
                'list':
                ['OFPBAC_BAD_TYPE, Unknown or unsupported action type.',
                'OFPBAC_BAD_LEN, Length problem in actions.',
                'OFPBAC_BAD_EXPERIMENTER, Unknown experimenter id specified.',
                'OFPBAC_BAD_EXP_TYPE, Unknown action for experimenter id.',
                'OFPBAC_BAD_OUT_PORT, Problem validating output port.',
                'OFPBAC_BAD_ARGUMENT, Bad action argument.',
                'OFPBAC_EPERM, Permissions error.',
                'OFPBAC_TOO_MANY, Cannot handle this many actions.',
                'OFPBAC_BAD_QUEUE, Problem validating output queue.',
                'OFPBAC_BAD_OUT_GROUP, Invalid group id in forward action.',
                'OFPBAC_MATCH_INCONSISTENT, Action cannot apply for this match, or Set-Field missing prerequisite.',
                'OFPBAC_UNSUPPORTED_ORDER, Action order is unsupported for the action list in an Apply-Actions instruction',
                'OFPBAC_BAD_TAG, Actions uses an unsupported tag/encap.',
                'OFPBAC_BAD_SET_TYPE, Unsupported type in SET_FIELD action.',
                'OFPBAC_BAD_SET_LEN, Length problem in SET_FIELD action.',
                'OFPBAC_BAD_SET_ARGUMENT, Bad argument in SET_FIELD action.']}
OF_ERRORS[3] = {'type': 'OFPET_BAD_INSTRUCTION',
                'desc': 'Error in instruction list.',
                'list':
                ['OFPBIC_UNKNOWN_INST, Unknown instruction.',
                'OFPBIC_UNSUP_INST, Switch or table does not support the instruction.',
                'OFPBIC_BAD_TABLE_ID, Invalid Table-ID specified.',
                'OFPBIC_UNSUP_METADATA, Metadata value unsupported by datapath.',
                'OFPBIC_UNSUP_METADATA_MASK, Metadata mask value unsupported by datapath.',
                'OFPBIC_BAD_EXPERIMENTER, Unknown experimenter id specified.',
                'OFPBIC_BAD_EXP_TYPE, Unknown instruction for experimenter id.',
                'OFPBIC_BAD_LEN, Length problem in instructions.',
                'OFPBIC_EPERM, Permissions error.']}
OF_ERRORS[4] = {'type': 'OFPET_BAD_MATCH',
                'desc': 'Error in match.',
                'list':
                ['OFPBMC_BAD_TYPE, Unsupported match type specified by the match',
                'OFPBMC_BAD_LEN, Length problem in match.',
                'OFPBMC_BAD_TAG, Match uses an unsupported tag/encap.',
                'OFPBMC_BAD_DL_ADDR_MASK, Unsupported datalink addr mask - switch does not support arbitrary datalink address mask.',
                'OFPBMC_BAD_NW_ADDR_MASK, Unsupported network addr mask - switch does not support arbitrary network address mask.',
                'OFPBMC_BAD_WILDCARDS, Unsupported combination of fields masked or omitted in the match.',
                'OFPBMC_BAD_FIELD, Unsupported field type in the match.',
                'OFPBMC_BAD_VALUE, Unsupported value in a match field.',
                'OFPBMC_BAD_MASK, Unsupported mask specified in the match, field is not dl-address or nw-address.',
                'OFPBMC_BAD_PREREQ, A prerequisite was not met.',
                'OFPBMC_DUP_FIELD, A field type was duplicated.',
                'OFPBMC_EPERM, Permissions error.']}
OF_ERRORS[5] = {'type': 'OFPET_FLOW_MOD_FAILED',
                'desc': 'Problem modifying flow entry.',
                'list':
                ['OFPFMFC_UNKNOWN, Unspecified error.',
                'OFPFMFC_TABLE_FULL, Flow not added because table was full.',
                'OFPFMFC_BAD_TABLE_ID, Table does not exist.',
                'OFPFMFC_OVERLAP, Attempted to add overlapping flow with CHECK_OVERLAP flag set.'
                'OFPFMFC_EPERM, Permissions error.',
                'OFPFMFC_BAD_TIMEOUT, Flow not added because of unsupported idle/hard timeout.',
                'OFPFMFC_BAD_COMMAND, Unsupported or unknown command.',
                'OFPFMFC_BAD_FLAGS, Unsupported or unknown flags.']}
OF_ERRORS[6] = {'type': 'OFPET_GROUP_MOD_FAILED',
                'desc': 'Problem modifying group entry.',
                'list':
                ['OFPGMFC_GROUP_EXISTS, Group not added because a group ADD attempted to replace an already-present group.',
                'OFPGMFC_INVALID_GROUP, Group not added because Group specified is invalid.',
                'OFPGMFC_WEIGHT_UNSUPPORTED, Switch does not support unequal load sharing with select groups.',
                'OFPGMFC_OUT_OF_GROUPS, The group table is full.',
                'OFPGMFC_OUT_OF_BUCKETS, The maximum number of action buckets for a group has been exceeded.'
                'OFPGMFC_CHAINING_UNSUPPORTED, Switch does not support groups that forward to groups.',
                'OFPGMFC_WATCH_UNSUPPORTED, This group cannot watch the watch_port or watch_group specified.',
                'OFPGMFC_LOOP, Group entry would cause a loop.',
                'OFPGMFC_UNKNOWN_GROUP, Group not modified because a group MODIFY attempted to modify a non-existent group.',
                'OFPGMFC_CHAINED_GROUP, Group not deleted because another group is forwarding to it.',
                'OFPGMFC_BAD_TYPE, Unsupported or unknown group type.',
                'OFPGMFC_BAD_COMMAND, Unsupported or unknown command.',
                'OFPGMFC_BAD_BUCKET, Error in bucket.',
                'OFPGMFC_BAD_WATCH, Error in watch port/group',
                'OFPGMFC_EPERM, Permissions error.']}
OF_ERRORS[7] = {'type': 'OFPET_PORT_MOD_FAILED',
                'desc': 'Port mod request failed.',
                'list':
                ['OFPPMFC_BAD_PORT, Specified port number does not exist.',
                'OFPPMFC_BAD_HW_ADDR, Specified hardware address does not match the port number.',
                'OFPPMFC_BAD_CONFIG, Specified config is invalid.',
                'OFPPMFC_BAD_ADVERTISE, Specified advertise is invalid.',
                'OFPPMFC_EPERM, Permissions error.']}
OF_ERRORS[8] = {'type': 'OFPET_TABLE_MOD_FAILED',
                'desc': 'Table mod request failed.',
                'list':
                ['OFPTMFC_BAD_TABLE, Specified table does not exist.',
                'OFPTMFC_BAD_CONFIG, Specified config is invalid.',
                'OFPTMFC_EPERM, Permissions error.']}
OF_ERRORS[9] = {'type': 'OFPET_QUEUE_OP_FAILED',
                'desc': 'Queue operation failed.',
                'list':
                ['OFPQOFC_BAD_PORT, Invalid port (or port does not exist).',
                'OFPQOFC_BAD_QUEUE, Queue does not exist.',
                'OFPQOFC_EPERM, Permissions error.']}
OF_ERRORS[10] = {'type': 'OFPET_SWITCH_CONFIG_FAILED',
                'desc': 'Switch config request failed.',
                'list':
                ['OFPSCFC_BAD_FLAGS, Specified flags is invalid.',
                'OFPSCFC_BAD_LEN, Specified len is invalid.',
                'OFPSCFC_EPERM, Permissions error.']}
OF_ERRORS[11] = {'type': 'OFPET_ROLE_REQUEST_FAILED',
                'desc': 'Controller Role request failed.',
                'list':
                ['OFPRRFC_STALE, Stale Message: old generation_id.',
                'OFPRRFC_UNSUP, Controller role change unsupported.',
                'OFPRRFC_BAD_ROLE, Invalid role.']}
OF_ERRORS[12] = {'type': 'OFPET_METER_MOD_FAILED',
                'desc': 'Error in meter.',
                'list':
                ['OFPMMFC_UNKNOWN, Unspecified error.',
                'OFPMMFC_METER_EXISTS, Meter not added because a Meter ADD attempted to replace an existing Meter.',
                'OFPMMFC_INVALID_METER, Meter not added because Meter specified is invalid.',
                'OFPMMFC_UNKNOWN_METER, Meter not modified because a Meter MODIFY attempted to modify a non-existent Meter.',
                'OFPMMFC_BAD_COMMAND, Unsupported or unknown command.',
                'OFPMMFC_BAD_FLAGS, Flag configuration unsupported.',
                'OFPMMFC_BAD_RATE, Rate unsupported.',
                'OFPMMFC_BAD_BURST, Burst size unsupported.',
                'OFPMMFC_BAD_BAND, Band unsupported.',
                'OFPMMFC_BAD_BAND_VALUE, Band value unsupported.',
                'OFPMMFC_OUT_OF_METERS, No more meters available.',
                'OFPMMFC_OUT_OF_BANDS, The maximum number of properties for a meter has been exceeded.']}
OF_ERRORS[13] = {'type': 'OFPET_TABLE_FEATURES_FAILED',
                'desc': 'Setting table features failed.',
                'list':
                ['OFPTFFC_BAD_TABLE, Specified table does not exist.',
                'OFPTFFC_BAD_METADATA, Invalid metadata mask.',
                'OFPTFFC_BAD_TYPE, Unknown property type.',
                'OFPTFFC_BAD_LEN, Length problem in properties.',
                'OFPTFFC_BAD_ARGUMENT, Unsupported property value.',
                'OFPTFFC_EPERM, Permissions error.']}
OF_ERRORS[65535] = {'type': 'OFPET_EXPERIMENTER',
                    'desc': 'Experimenter error messages.'}

def decode(error_type, error_code):
    """
    Return a decoded explaination of an OpenFlow error
    type/code
    """
    if error_type in OF_ERRORS:
        nice_type = OF_ERRORS[error_type]['type']
        nice_type_desc = OF_ERRORS[error_type]['desc']
    else:
        nice_type = 'Unknown'
        nice_type_desc = 'Unknown'
    try:
        nice_code = OF_ERRORS[error_type]['list'][error_code]
    except:
        nice_code = 'Unknown'
    nice_code, nice_code_desc = nice_code.split(',')
    return nice_type, nice_type_desc, nice_code, nice_code_desc
