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

import ddt
import mock
from neutronclient.common import exceptions
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


@ddt.ddt
class TestKuryrEndpointCreateFailures(base.TestKuryrFailures):
    """Unit tests for the failures for creating endpoints.

    This test covers error responses listed in the spec:
      http://developer.openstack.org/api-ref-networking-v2.html#createSubnet  # noqa
      http://developer.openstack.org/api-ref-networking-v2-ext.html#createPort  # noqa
    """
    def _invoke_create_request(self, docker_network_id, docker_endpoint_id):
        data = {
            'NetworkID': docker_network_id,
            'EndpointID': docker_endpoint_id,
            'Options': {},
            'Interface': {
                'Address': '192.168.1.2/24',
                'AddressIPv6': 'fe80::f816:3eff:fe20:57c4/64',
                'MacAddress': "fa:16:3e:20:57:c3"
            }
        }
        response = self.app.post('/NetworkDriver.CreateEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))
        return response

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @ddt.data(exceptions.Unauthorized, exceptions.Forbidden,
              exceptions.NotFound, exceptions.ServiceUnavailable)
    def test_create_endpoint_port_failures(self, GivenException,
            mock_list_ports, mock_list_subnets, mock_list_networks,
            mock_create_port):
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_subnet_v4_id = uuidutils.generate_uuid()
        fake_neutron_subnet_v6_id = uuidutils.generate_uuid()
        fake_subnets = self._get_fake_subnets(
            fake_docker_endpoint_id, fake_neutron_network_id,
            fake_neutron_subnet_v4_id, fake_neutron_subnet_v6_id)

        fake_fixed_ips = ['subnet_id=%s' % fake_neutron_subnet_v4_id,
                          'ip_address=192.168.1.2',
                          'subnet_id=%s' % fake_neutron_subnet_v6_id,
                          'ip_address=fe80::f816:3eff:fe20:57c4']
        fake_port_response = {"ports": []}
        t = utils.make_net_tags(fake_docker_network_id)
        fake_neutron_network = self._get_fake_list_network(
            fake_neutron_network_id)
        mock_list_ports.return_value = fake_port_response

        def mock_fake_subnet(*args, **kwargs):
            if kwargs['cidr'] == '192.168.1.0/24':
                return fake_subnets
            return {'subnets': []}
        mock_list_subnets.side_effect = mock_fake_subnet
        mock_list_networks.return_value = fake_neutron_network
        mock_create_port.side_effect = GivenException
        fake_port_request = self._get_fake_port_request(
            fake_neutron_network_id, fake_docker_endpoint_id,
            fake_neutron_subnet_v4_id, fake_neutron_subnet_v6_id)

        response = self._invoke_create_request(
            fake_docker_network_id, fake_docker_endpoint_id)

        self.assertEqual(GivenException.status_code, response.status_code)
        mock_list_networks.assert_called_with(tags=t)
        mock_create_port.assert_called_with(fake_port_request)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_network_id, cidr='192.168.1.0/24')
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_network_id, cidr='fe80::/64')
        mock_list_ports.assert_called_with(
            fixed_ips=fake_fixed_ips)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertEqual({'Err': GivenException.message}, decoded_json)

    def test_create_endpoint_bad_request(self):
        fake_docker_network_id = lib_utils.get_hash()
        invalid_docker_endpoint_id = 'id-should-be-hexdigits'

        response = self._invoke_create_request(
            fake_docker_network_id, invalid_docker_endpoint_id)

        self.assertEqual(400, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        # TODO(tfukushima): Add the better error message validation.
        self.assertIn(invalid_docker_endpoint_id, decoded_json['Err'])
        self.assertIn('EndpointID', decoded_json['Err'])


@ddt.ddt
class TestKuryrEndpointDeleteFailures(base.TestKuryrFailures):
    """Unit tests for the failures for deleting endpoints."""
    def _invoke_delete_request(self, docker_network_id, docker_endpoint_id):
        data = {'NetworkID': docker_network_id,
                'EndpointID': docker_endpoint_id}
        response = self.app.post('/NetworkDriver.DeleteEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))
        return response

    def test_delete_endpoint_bad_request(self):
        fake_docker_network_id = lib_utils.get_hash()
        invalid_docker_endpoint_id = 'id-should-be-hexdigits'

        response = self._invoke_delete_request(
            fake_docker_network_id, invalid_docker_endpoint_id)

        self.assertEqual(400, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        # TODO(tfukushima): Add the better error message validation.
        self.assertIn(invalid_docker_endpoint_id, decoded_json['Err'])
        self.assertIn('EndpointID', decoded_json['Err'])
