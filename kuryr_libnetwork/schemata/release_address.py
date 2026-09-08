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

RELEASE_ADDRESS_SCHEMA = {
    'links': [{
        'method': 'POST',
        'href': '/IpamDriver.ReleaseAddress',
        'description': 'Release an ip address',
        'rel': 'self',
        'title': 'Release'
    }],
    'title': 'Release an IP',
    'required': ['PoolID', 'Address'],
    'definitions': {'commons': {}},
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
    'properties': {
        'PoolID': {
            'description': 'neutron uuid of allocated subnetpool',
            '$ref': '#/definitions/commons/definitions/uuid'
        },
        'Address': {
            'description': 'Address in IP(v4 or v6) form',
            '$ref': '#/definitions/commons/definitions/ipv4_or_ipv6'
        }
    }

}

RELEASE_ADDRESS_SCHEMA['definitions']['commons'] = commons.COMMONS
