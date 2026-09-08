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

REQUEST_POOL_SCHEMA = {
    'links': [{
        'method': 'POST',
        'href': '/IpamDriver.RequestPool',
        'description': 'Allocate pool of ip addresses',
        'rel': 'self',
        'title': 'Create'
    }],
    'title': 'Create pool',
    'required': ['AddressSpace', 'Pool', 'SubPool', 'V6'],
    'definitions': {'commons': {}},
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
    'properties': {
        'AddressSpace': {
            'description': 'The name of the address space.',
            'type': 'string',
            'example': 'foo',
        },
        'Pool': {
            'description': 'A range of IP Addresses represented in '
                           'CIDR format address/mask.',
            '$ref': '#/definitions/commons/definitions/cidrv4_or_cidrv6'
        },
        'SubPool': {
            'description': 'A subset of IP range from Pool in '
                           'CIDR format address/mask.',
            '$ref': '#/definitions/commons/definitions/cidrv4_or_cidrv6'
        },
        'Options': {
            'type': ['object', 'null'],
            'description': 'Options',
            'example': {},
        },
        'V6': {
            'description': 'If set to "True", requesting IPv6 pool and '
                           'vice-versa.',
            'type': 'boolean',
            'example': False
        }
    }
}

REQUEST_POOL_SCHEMA['definitions']['commons'] = commons.COMMONS
