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

from kuryr_libnetwork.schemata.commons import COMMONS


JOIN_SCHEMA = {
    'links': [{
        'method': 'POST',
        'href': '/NetworkDriver.Join',
        'description': 'Join the network',
        'rel': 'self',
        'title': 'Create'
    }],
    'title': 'Join endpoint',
    'required': [
        'NetworkID',
        'EndpointID',
        'SandboxKey'
    ],
    'properties': {
        'NetworkID': {
            'description': 'Network ID',
            '$ref': '#/definitions/commons/definitions/id'
        },
        'SandboxKey': {
            'description': 'Sandbox Key',
            '$ref': '#/definitions/commons/definitions/sandbox_key'
        },
        'Options': {
            '$ref': '#/definitions/commons/definitions/options'
        },
        'EndpointID': {
            'description': 'Endpoint ID',
            '$ref': '#/definitions/commons/definitions/id'
        }
    },
    'definitions': {'commons': {}},
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
}

JOIN_SCHEMA['definitions']['commons'] = COMMONS
