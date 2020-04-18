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

from unittest import mock

import ddt
from neutronclient.common import exceptions as n_exceptions
from oslo_concurrency import processutils
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from werkzeug import exceptions as w_exceptions

from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions as k_exceptions
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


@ddt.ddt
class TestKuryrEndpointCreateFailures(base.TestKuryrFailures):
    """Unit tests for the failures for creating endpoints.

    This test covers error responses listed in the spec:
      https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
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
    @ddt.data(n_exceptions.Unauthorized, n_exceptions.Forbidden,
              n_exceptions.NotFound, n_exceptions.ServiceUnavailable)
    def test_create_endpoint_port_failures(self, GivenException,
            mock_list_ports, mock_list_subnets, mock_list_networks,
            mock_create_port):
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_subnet_v4_id = uuidutils.generate_uuid()
        fake_neutron_subnet_v6_id = uuidutils.generate_uuid()

        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_network_id,
            fake_docker_endpoint_id,
            fake_neutron_subnet_v4_id)
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_network_id,
            fake_docker_endpoint_id,
            fake_neutron_subnet_v6_id)
        fake_v4_subnet_response = {
            "subnets": [
                fake_v4_subnet['subnet']
            ]
        }
        fake_v6_subnet_response = {
            "subnets": [
                fake_v6_subnet['subnet']
            ]
        }

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
                return fake_v4_subnet_response
            elif kwargs['cidr'] == 'fe80::/64':
                return fake_v6_subnet_response
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

    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.create_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @ddt.data(k_exceptions.VethCreationFailure,
              processutils.ProcessExecutionError,
              k_exceptions.KuryrException,
              n_exceptions.NeutronClientException)
    def test_create_host_iface_failures(self, GivenException,
            mock_list_networks, mock_list_ports, mock_list_subnets,
            mock_update_port, mock_create_host_iface):
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_network_id = uuidutils.generate_uuid()

        fake_neutron_network = self._get_fake_list_network(
            fake_neutron_network_id)
        t = utils.make_net_tags(fake_docker_network_id)
        mock_list_networks.return_value = fake_neutron_network

        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(fake_docker_network_id,
                                                  fake_docker_endpoint_id,
                                                  fake_neutron_v4_subnet_id)
        fake_v6_subnet = self._get_fake_v6_subnet(fake_docker_network_id,
                                                  fake_docker_endpoint_id,
                                                  fake_neutron_v6_subnet_id)
        fake_v4_subnet_response = {
            "subnets": [
                fake_v4_subnet['subnet']
            ]
        }
        fake_v6_subnet_response = {
            "subnets": [
                fake_v6_subnet['subnet']
            ]
        }

        def fake_subnet_response(network_id, cidr):
            if cidr == '192.168.1.0/24':
                return fake_v4_subnet_response
            elif cidr == 'fe80::/64':
                return fake_v6_subnet_response
            else:
                return {'subnets': []}

        mock_list_subnets.side_effect = fake_subnet_response

        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_fixed_ips = ['subnet_id=%s' % fake_neutron_v4_subnet_id,
                          'ip_address=192.168.1.2',
                          'subnet_id=%s' % fake_neutron_v6_subnet_id,
                          'ip_address=fe80::f816:3eff:fe20:57c4']
        fake_port_response = self._get_fake_port(
            fake_docker_endpoint_id, fake_neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            tags=utils.create_port_tags(fake_docker_endpoint_id))
        fake_ports_response = {
            "ports": [
                fake_port_response['port']
            ]
        }
        mock_list_ports.return_value = fake_ports_response
        fake_updated_port = fake_port_response['port']
        fake_updated_port['name'] = utils.get_neutron_port_name(
            fake_docker_endpoint_id)
        mock_update_port.return_value = fake_port_response['port']

        fake_neutron_subnets = [fake_v4_subnet['subnet'],
                                fake_v6_subnet['subnet']]

        fake_message = "fake message"
        if GivenException == n_exceptions.NeutronClientException:
            fake_exception = GivenException(fake_message, status_code=500)
        else:
            fake_exception = GivenException(fake_message)
        mock_create_host_iface.side_effect = fake_exception

        response = self._invoke_create_request(
            fake_docker_network_id, fake_docker_endpoint_id)

        self.assertEqual(
            w_exceptions.InternalServerError.code, response.status_code)
        mock_list_networks.assert_called_with(tags=t)
        expect_calls = [mock.call(cidr='192.168.1.0/24',
            network_id=fake_neutron_network_id),
            mock.call(cidr='fe80::/64', network_id=fake_neutron_network_id)]
        mock_list_subnets.assert_has_calls(expect_calls, any_order=True)
        mock_list_ports.assert_called_with(fixed_ips=fake_fixed_ips)
        mock_update_port.assert_called_with(fake_port_response['port'],
                                            fake_docker_endpoint_id,
                                            "fa:16:3e:20:57:c3",
                                            tags=True)
        mock_create_host_iface.assert_called_with(
            fake_docker_endpoint_id, fake_updated_port, fake_neutron_subnets,
            fake_neutron_network['networks'][0])

        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertIn(fake_message, decoded_json['Err'])

    def test_create_endpoint_bad_request(self):
        fake_docker_network_id = lib_utils.get_hash()
        invalid_docker_endpoint_id = 'id-should-be-hexdigits'

        response = self._invoke_create_request(
            fake_docker_network_id, invalid_docker_endpoint_id)

        self.assertEqual(w_exceptions.BadRequest.code, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        # TODO(tfukushima): Add the better error message validation.
        self.assertIn(invalid_docker_endpoint_id, decoded_json['Err'])
        self.assertIn('Failed validating ', decoded_json['Err'])


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

    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.delete_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @ddt.data(k_exceptions.VethDeletionFailure,
              k_exceptions.KuryrException,
              n_exceptions.NeutronClientException,
              processutils.ProcessExecutionError)
    def test_delete_endpoint_delete_host_iface_failure(self, GivenException,
            mock_list_networks, mock_list_ports, mock_delete_host_iface):
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_network_id)
        mock_list_networks.return_value = self._get_fake_list_network(
            fake_neutron_network_id)
        port_tags = utils.make_port_tags(fake_docker_endpoint_id)
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        mock_list_ports.return_value = fake_neutron_ports_response
        fake_neutron_port = fake_neutron_ports_response['ports'][0]

        fake_message = "fake message"
        if GivenException == n_exceptions.NeutronClientException:
            fake_exception = GivenException(fake_message, status_code=500)
        else:
            fake_exception = GivenException(fake_message)
        mock_delete_host_iface.side_effect = fake_exception
        response = self._invoke_delete_request(
            fake_docker_network_id, fake_docker_endpoint_id)

        self.assertEqual(
            w_exceptions.InternalServerError.code, response.status_code)
        mock_list_networks.assert_called_with(tags=t)
        mock_list_ports.assert_called_with(tags=port_tags)
        mock_delete_host_iface.assert_called_with(fake_docker_endpoint_id,
            fake_neutron_port)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertIn(fake_message, decoded_json['Err'])

    def test_delete_endpoint_bad_request(self):
        fake_docker_network_id = lib_utils.get_hash()
        invalid_docker_endpoint_id = 'id-should-be-hexdigits'

        response = self._invoke_delete_request(
            fake_docker_network_id, invalid_docker_endpoint_id)

        self.assertEqual(w_exceptions.BadRequest.code, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        # TODO(tfukushima): Add the better error message validation.
        self.assertIn(invalid_docker_endpoint_id, decoded_json['Err'])
        self.assertIn('Failed validating ', decoded_json['Err'])
