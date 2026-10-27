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

NETWORK_DELETE_SCHEMA = {
    'links': [{
        'method': 'POST',
        'href': '/NetworkDriver.DeleteNetwork',
        'description': 'Delete a Network',
        'rel': 'self',
        'title': 'Delete'
    }],
    'title': 'Delete network',
    'required': ['NetworkID'],
    'definitions': {'commons': {}},
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
    'properties': {
        'NetworkID': {
            'description': 'ID of the Network ID to be deleted',
            '$ref': '#/definitions/commons/definitions/id'
        }
    }
}

NETWORK_DELETE_SCHEMA['definitions']['commons'] = commons.COMMONS
