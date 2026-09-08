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

ENDPOINT_CREATE_SCHEMA = {
    'links': [{
        'method': 'POST',
        'href': '/NetworkDriver.CreateEndpoint',
        'description': 'Create an Endpoint',
        'rel': 'self',
        'title': 'Create'
    }],
    'title': 'Create endpoint',
    'required': ['NetworkID', 'EndpointID', 'Options', 'Interface'],
    'definitions': {'commons': {}},
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
    'properties': {
        'NetworkID': {
            'description': 'Network ID',
            '$ref': '#/definitions/commons/definitions/id'
        },
        'Interface': {
            '$ref': '#/definitions/commons/definitions/interface',
            'description': 'Interface information'
        },
        'Options': {
            'description': 'Options',
            '$ref': '#/definitions/commons/definitions/options'
        },
        'EndpointID': {
            'description': 'Endpoint ID',
            '$ref': '#/definitions/commons/definitions/id'
        }
    }
}

ENDPOINT_CREATE_SCHEMA['definitions']['commons'] = commons.COMMONS
