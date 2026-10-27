# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from kuryr_libnetwork.schemata import commons

NETWORK_CREATE_SCHEMA = {
    'links': [{
        'method': 'POST',
        'href': '/NetworkDriver.CreateNetwork',
        'description': 'Create a Network',
        'rel': 'self',
        'title': 'Create'
    }],
    'title': 'Create network',
    'required': ['NetworkID', 'IPv4Data', 'IPv6Data'],
    'definitions': {'commons': {}},
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
    'properties': {
        'NetworkID': {
            'description': 'ID of a Network to be created',
            '$ref': '#/definitions/commons/definitions/id'
        },
        'IPv4Data': {
            'description': 'IPv4 data for the network',
            'type': 'array',
            'items': {
                '$ref': '#/definitions/commons/definitions/ipv4datum'
            }
        },
        'IPv6Data': {
            'description': 'IPv6 data for the network',
            'type': 'array',
            'items': {
                '$ref': '#/definitions/commons/definitions/ipv6datum'
            }
        },
        'Options': {
            'type': ['object', 'null'],
            'description': 'Options',
            'example': {}
        }
    }
}

NETWORK_CREATE_SCHEMA['definitions']['commons'] = commons.COMMONS
