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

import jsonschema
from jsonschema.exceptions import ValidationError

from kuryr_libnetwork import schemata
from kuryr_libnetwork.schemata import commons
from kuryr_libnetwork.tests.unit import base


class TestKuryrSchema(base.TestKuryrBase):
    """Unit tests for Kuryr schema."""

    def test_network_id_64_len(self):
        network_id = '51c75a2515d47edecc3f720bb541e287224416fb66715eb' \
                     '7802011d6ffd499f1'
        target_schema = commons.COMMONS[u'definitions'][u'id']
        self._validate_schema(network_id, target_schema)

    def test_network_id_25_len(self):
        network_id = 'xqqzd9p112o4kvok38n3caxjm'
        target_schema = commons.COMMONS[u'definitions'][u'id']
        self._validate_schema(network_id, target_schema)

    def test_network_id_invalid_charactor(self):
        network_id = '@#qzd9p112o4kvok38n3cax&%'
        target_schema = commons.COMMONS[u'definitions'][u'id']
        self.assertRaises(ValidationError, jsonschema.validate, network_id,
                          target_schema)

    def test_network_id_invalid_length(self):
        network_id = 'xqqzd9p112o4kvok38n3caxjmabcd'
        target_schema = commons.COMMONS[u'definitions'][u'id']
        self.assertRaises(ValidationError, jsonschema.validate, network_id,
                          target_schema)

    def test_network_create_schema(self):
        docker_network_id = '51c75a2515d47edecc3f720bb541e287224416fb66715eb' \
                            '7802011d6ffd499f1'
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
                'AuxAddresses': {}
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
                'AuxAddresses': {}
            }],
            'Options': {}
        }
        self._validate_schema(network_request, schemata.NETWORK_CREATE_SCHEMA)

    def test_network_create_schema_missing_required(self):
        docker_network_id = '51c75a2515d47edecc3f720bb541e287224416fb66715eb' \
                            '7802011d6ffd499f1'
        net_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
                'AuxAddresses': {}
            }],
            'Options': {}
        }
        self.assertRaises(ValidationError, jsonschema.validate, net_request,
                          schemata.NETWORK_CREATE_SCHEMA)

    @classmethod
    def _validate_schema(self, target, schema):
        try:
            jsonschema.validate(target, schema)
        except ValidationError:
            self.fail("Unexpected validation error raised!")
