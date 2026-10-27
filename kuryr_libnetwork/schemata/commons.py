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

EPSILON_PATTERN = '^$'
IPV4_PATTERN_BASE = ('((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\\.){3}'
                     '(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])')
IPV4_PATTERN = EPSILON_PATTERN + '|^' + IPV4_PATTERN_BASE + '$'
CIDRV4_PATTERN = EPSILON_PATTERN + '|^(' + IPV4_PATTERN_BASE + \
    '(/(1[0-2][0-8]|[1-9]?[0-9]))' + ')$'

IPV6_PATTERN_BASE = ('('
                     '([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|'
                     '([0-9a-fA-F]{1,4}:){1,7}:|'
                     '([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
                     '([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|'
                     '([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|'
                     '([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|'
                     '([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|'
                     '[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|'
                     ':((:[0-9a-fA-F]{1,4}){1,7}|:)|'
                     'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|'
                     '::(ffff(:0{1,4}){0,1}:){0,1}'
                     '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}'
                     '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|'
                     '([0-9a-fA-F]{1,4}:){1,4}:'
                     '((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}'
                     '(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
IPV6_PATTERN = EPSILON_PATTERN + '|^' + IPV6_PATTERN_BASE + '$'
CIDRV6_PATTERN = EPSILON_PATTERN + '|^(' + IPV6_PATTERN_BASE + \
    '(/(1[0-2][0-8]|[1-9]?[0-9]))' + ')$'
IPV4_OR_IPV6_PATTERN = IPV4_PATTERN + '|^' + IPV6_PATTERN_BASE + '$'
CIDRV4_OR_CIDRV6_PATTERN = CIDRV4_PATTERN + '|^' + CIDRV6_PATTERN + '$'
UUID_BASE = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
UUID_PATTERN = EPSILON_PATTERN + '|' + UUID_BASE

COMMONS = {
    'description': 'Common data schemata shared among other schemata.',
    'links': [],
    'title': 'Kuryr Common Data Schema Definitions',
    'properties': {
        'options': {'$ref': '/schemata/commons#/definitions/options'},
        'mac': {'$ref': '/schemata/commons#/definitions/mac'},
        'cidrv6': {'$ref': '/schemata/commons#/definitions/cidrv6'},
        'interface': {'$ref': '/schemata/commons#/definitions/interface'},
        'cidr': {'$ref': '/schemata/commons#/definitions/cidr'},
        'id': {'$ref': '/schemata/commons#/definitions/id'},
        'uuid': {'$ref': '/schemata/commons#/definitions/uuid'},
        'ipv4': {'$ref': '/schemata/commons#/definitions/ipv4'},
        'ipv4_or_ipv6': {
            '$ref': '/schemata/commons#/definitions/ipv4_or_ipv6'}
    },
    'definitions': {
        'options': {
            'type': ['object', 'null'],
            'description': 'Options.',
            'example': {}
        },
        'mac': {
            'pattern': (EPSILON_PATTERN + '|'
                        '^((?:[0-9a-f]{2}:){5}[0-9a-f]{2}|'
                        '(?:[0-9A-F]{2}:){5}[0-9A-F]{2})$'),
            'type': 'string',
            'description': 'A MAC address.',
            'example': 'aa:bb:cc:dd:ee:ff'
        },
        'cidrv6': {
            'pattern': CIDRV6_PATTERN,
            'type': 'string',
            'description': 'A IPv6 CIDR of the subnet'
        },
        'interface': {
            'properties': {
                'ID': {
                    'description': 'Index of the interface',
                    'type': 'number',
                },
                'AddressIPv6': {
                    'description': 'IPv6 CIDR',
                    '$ref': '#/definitions/commons/definitions/cidrv6'
                },
                'MacAddress': {
                    'description': 'MAC address',
                    '$ref': '#/definitions/commons/definitions/mac'
                },
                'Address': {
                    'description': 'IPv4 CIDR',
                    '$ref': '#/definitions/commons/definitions/cidr'
                }
            },
            'type': ['object', 'null'],
            'description': 'Interface used in requests against Endpoints.',
            'example': {
                'AddressIPv6': 'fe80::f816:3eff:fe20:57c3/64',
                'MacAddress': 'fa:16:3e:20:57:c3',
                'Address': '192.168.1.42/24'
            }
        },
        'cidr': {
            'pattern': CIDRV4_PATTERN,
            'type': 'string',
            'description': 'A IPv4 CIDR of the subnet.',
            'example': '10.0.0.0/24'
        },
        'cidrv4_or_cidrv6': {
            'pattern': CIDRV4_OR_CIDRV6_PATTERN,
            'type': 'string',
            'description': 'An IPv4 or IPv6 CIDR of the subnet.'
        },
        'id': {
            'oneOf': [
                {'pattern': '^([0-9a-f]{64})$'},
                {'pattern': '^([0-9a-z]{25})$'}],
            'type': 'string',
            'description': '64 or 25 length ID value of Docker.',
            'example': [
                '51c75a2515d47edecc3f720bb541e287224416fb66715eb7802011d6ffd4'
                '99f1',
                'xqqzd9p112o4kvok38n3caxjm'
            ]
        },
        'ipv4': {
            'pattern': IPV4_PATTERN,
            'type': 'string',
            'description': 'An IPv4 address',
            'example': '10.0.0.1'
        },
        'ipv4datum': {
            'description': 'IPv4 data',
            'required': ['AddressSpace', 'Pool'],
            'type': 'object',
            'example': {
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
                'AuxAddresses': {
                    'web': '192.168.42.2',
                    'db': '192.168.42.3'
                }
            },
            'properties': {
                'AddressSpace': {
                    'description': 'The name of the address space.',
                    'type': 'string',
                    'example': 'foo',
                },
                'Pool': {
                    'description': 'A range of IP Addresses requested in '
                                   'CIDR format address/mask.',
                    '$ref': '#/definitions/commons/definitions/cidr'
                },
                'Gateway': {
                    'description': 'Optionally, the IPAM driver may provide '
                                   'a Gateway for the subnet represented by '
                                   'the Pool.',
                    '$ref': '#/definitions/commons/definitions/cidr',
                },
                'AuxAddresses': {
                    'description': 'A list of pre-allocated ip-addresses '
                                   'with an associated identifier as '
                                   'provided by the user to assist network '
                                   'driver if it requires specific '
                                   'ip-addresses for its operation.',
                    'type': 'object',
                    'patternProperties': {
                        '.+': {
                            'description': 'key-value pair of the ID and '
                                           'the IP address',
                            '$ref': '#/definitions/commons/definitions/ipv4'
                        }
                    }
                }
            }
        },
        'ipv6': {
            'pattern': IPV6_PATTERN,
            'type': 'string',
            'description': 'An IPv6 address.',
            'example': 'fe80::f816:3eff:fe20:57c4'
        },
        'ipv6datum': {
            'description': 'IPv6 data',
            'required': [
                'AddressSpace', 'Pool', 'Gateway'],
            'type': 'object',
            'example': {
                'AddressCpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
                'AuxAddresses': {
                    'web': 'fe80::f816:3eff:fe20:57c4',
                    'db': 'fe80::f816:3eff:fe20:57c5'
                }
            },
            'properties': {
                'AddressSpace': {
                    'description': 'The name of the address space.',
                    'type': 'string',
                    'example': 'foo',
                },
                'Pool': {
                    'description': 'A range of IP Addresses requested in '
                                   'CIDR format address/mask.',
                    '$ref': '#/definitions/commons/definitions/cidrv6'
                },
                'Gateway': {
                    'description': 'Optionally, the IPAM driver may provide '
                                   'a Gateway for the subnet represented by '
                                   'the Pool.',
                    '$ref': '#/definitions/commons/definitions/cidrv6',
                },
                'AuxAddresses': {
                    'description': 'A list of pre-allocated ip-addresses '
                                   'with an associated identifier as '
                                   'provided by the user to assist network '
                                   'driver if it requires specific '
                                   'ip-addresses for its operation.',
                    'type': 'object',
                    'patternProperties': {
                        '.+': {
                            'description': 'key-vavule pair of the ID and '
                                           'the IP address',
                            '$ref': '#/definitions/commons/definitions/ipv6'
                        }
                    }
                }
            }
        },
        'ipv4_or_ipv6': {
            'pattern': IPV4_OR_IPV6_PATTERN,
            'type': 'string',
            'description': 'An IPv4 or IPv6 address.',
            'example': 'fe80::f816:3eff:fe20:57c4'
        },
        'sandbox_key': {
            'pattern': '^(/var/run/docker/netns/[0-9a-f]{12})$',
            'type': 'string',
            'description': 'Sandbox information of netns.',
            'example': '/var/run/docker/netns/12bbda391ed0'
        },
        'uuid': {
            'pattern': UUID_PATTERN,
            'type': 'string',
            'description': 'uuid of neutron resources.',
            'example': 'dfe39822-ad5e-40bd-babd-3954113b3687'
        }
    },
    '$schema': 'http://json-schema.org/draft-04/hyper-schema',
    'type': 'object',
    'id': 'schemata/commons'
}
