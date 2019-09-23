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

from ddt import data
from ddt import ddt
import mock
from neutronclient.common import exceptions
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import constants as const
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


class TestKuryrNetworkCreateFailures(base.TestKuryrFailures):
    """Unittests for the failures for creating networks.

    This test covers error responses listed in the spec:
      http://developer.openstack.org/api-ref-networking-v2-ext.html#createProviderNetwork  # noqa
    """
    def _invoke_create_request(self, network_request):
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))
        return response

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id',
        return_value=None)
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_create_network_unauthorized(self, mock_list_subnetpools,
            mock_get_default_network, mock_create_network):
        docker_network_id = lib_utils.get_hash()
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

        fake_kuryr_v4_subnetpool_id = uuidutils.generate_uuid()
        fake_v4_pool_name = lib_utils.get_neutron_subnetpool_name(
            network_request['IPv4Data'][0]['Pool'])
        kuryr_v4_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_v4_subnetpool_id, name=fake_v4_pool_name)

        fake_kuryr_v6_subnetpool_id = uuidutils.generate_uuid()
        fake_v6_pool_name = lib_utils.get_neutron_subnetpool_name(
            network_request['IPv6Data'][0]['Pool'])
        kuryr_v6_subnetpools = self._get_fake_v6_subnetpools(
            fake_kuryr_v6_subnetpool_id, name=fake_v6_pool_name)
        fake_v4_pool_attrs = {'name': fake_v4_pool_name}
        fake_v6_pool_attrs = {'name': fake_v6_pool_name}
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]

        fake_request = {
            "network": {
                "name": utils.make_net_name(docker_network_id),
                "admin_state_up": True,
                "shared": False
            }
        }
        mock_create_network.side_effect = exceptions.Unauthorized
        response = self._invoke_create_request(network_request)
        self.assertEqual(401, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        mock_list_subnetpools.assert_any_call(**fake_v4_pool_attrs)
        mock_list_subnetpools.assert_any_call(**fake_v6_pool_attrs)
        mock_create_network.assert_called_with(fake_request)
        self.assertIn('Err', decoded_json)
        self.assertEqual(
            {'Err': exceptions.Unauthorized.message}, decoded_json)

    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_create_network_get_default_network_id_unauthorized(self,
            mock_list_subnetpools, mock_get_default_network_id):
        docker_network_id = lib_utils.get_hash()
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

        fake_kuryr_v4_subnetpool_id = uuidutils.generate_uuid()
        fake_v4_pool_name = lib_utils.get_neutron_subnetpool_name(
            network_request['IPv4Data'][0]['Pool'])
        kuryr_v4_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_v4_subnetpool_id, name=fake_v4_pool_name)

        fake_kuryr_v6_subnetpool_id = uuidutils.generate_uuid()
        fake_v6_pool_name = lib_utils.get_neutron_subnetpool_name(
            network_request['IPv6Data'][0]['Pool'])
        kuryr_v6_subnetpools = self._get_fake_v6_subnetpools(
            fake_kuryr_v6_subnetpool_id, name=fake_v6_pool_name)
        fake_v4_pool_attrs = {'name': fake_v4_pool_name}
        fake_v6_pool_attrs = {'name': fake_v6_pool_name}
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]

        mock_get_default_network_id.side_effect = exceptions.Unauthorized
        response = self._invoke_create_request(network_request)
        self.assertEqual(401, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        mock_list_subnetpools.assert_any_call(**fake_v4_pool_attrs)
        mock_list_subnetpools.assert_any_call(**fake_v6_pool_attrs)
        mock_get_default_network_id.assert_called()
        self.assertIn('Err', decoded_json)
        self.assertEqual(
            {'Err': exceptions.Unauthorized.message}, decoded_json)

    def test_create_network_bad_request(self):
        invalid_docker_network_id = 'id-should-be-hexdigits'
        network_request = {
            'NetworkID': invalid_docker_network_id,
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

        response = self._invoke_create_request(network_request)
        self.assertEqual(400, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        # TODO(tfukushima): Add the better error message validation.
        self.assertIn(invalid_docker_network_id, decoded_json['Err'])
        self.assertIn('Failed validating ', decoded_json['Err'])


@ddt
class TestKuryrNetworkDeleteFailures(base.TestKuryrFailures):
    """Unittests for the failures for deleting networks.

    This test covers error responses listed in the spec:
      http://developer.openstack.org/api-ref-networking-v2-ext.html#deleteProviderNetwork  # noqa
    """
    def _invoke_delete_request(self, network_name):
        data = {'NetworkID': network_name}
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))
        return response

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @data(exceptions.Unauthorized, exceptions.NotFound, exceptions.Conflict)
    def test_delete_network_failures(self, GivenException,
            mock_list_networks, mock_list_subnets,
            mock_list_subnetpools, mock_delete_subnet,
            mock_delete_network):
        fake_subnetpools_response = {"subnetpools": []}
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_network_id = "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
        t = utils.make_net_tags(docker_network_id)
        te = t + ',' + utils.existing_net_tag(docker_network_id)
        subnet_v4_id = "9436e561-47bf-436a-b1f1-fe23a926e031"
        subnet_v6_id = "64dd4a98-3d7a-4bfd-acf4-91137a8d2f51"

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_network_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                if GivenException == exceptions.NotFound:
                    return self._get_fake_list_network(
                        fake_neutron_network_id,
                        check_existing=True)
                return self._get_fake_list_network(
                    fake_neutron_network_id)

        fake_v4_subnet = self._get_fake_v4_subnet(
            docker_network_id, docker_endpoint_id, subnet_v4_id)
        fake_v6_subnet = self._get_fake_v6_subnet(
            docker_network_id, docker_endpoint_id, subnet_v6_id)
        fake_subnets_response = {
            "subnets": [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_list_networks.side_effect = mock_network
        mock_list_subnets.return_value = fake_subnets_response
        mock_list_subnetpools.return_value = fake_subnetpools_response
        mock_delete_subnet.return_value = None
        mock_delete_network.side_effect = GivenException

        response = self._invoke_delete_request(docker_network_id)
        decoded_json = jsonutils.loads(response.data)
        if GivenException == exceptions.NotFound:
            self.assertEqual(GivenException.status_code, 404)
            self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)
        else:
            self.assertEqual(GivenException.status_code, response.status_code)
            fake_v4_pool_attrs = {'name': 'kuryr'}
            fake_v6_pool_attrs = {'name': 'kuryr6'}
            mock_list_subnetpools.assert_any_call(**fake_v6_pool_attrs)
            mock_list_subnetpools.assert_any_call(**fake_v4_pool_attrs)
            mock_delete_subnet.assert_any_call(subnet_v4_id)
            mock_delete_subnet.assert_any_call(subnet_v6_id)
            mock_delete_network.assert_called_with(fake_neutron_network_id)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_network_id)
            self.assertIn('Err', decoded_json)
            self.assertEqual({'Err': GivenException.message}, decoded_json)
        mock_list_networks.assert_any_call(tags=t)
        mock_list_networks.assert_any_call(tags=te)

    def test_delete_network_bad_request(self):
        invalid_docker_network_id = 'invalid-network-id'

        response = self._invoke_delete_request(invalid_docker_network_id)

        self.assertEqual(400, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertIn(invalid_docker_network_id, decoded_json['Err'])
        self.assertIn('Failed validating ', decoded_json['Err'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @data(exceptions.Unauthorized, exceptions.NotFound, exceptions.Conflict)
    def test_delete_network_with_subnet_deletion_failures(self,
            GivenException, mock_list_networks, mock_list_subnets,
            mock_list_subnetpools, mock_delete_subnet):

        fake_subnetpools_response = {"subnetpools": []}
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_network_id = "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
        t = utils.make_net_tags(docker_network_id)
        te = t + ',' + utils.existing_net_tag(docker_network_id)
        subnet_v4_id = "9436e561-47bf-436a-b1f1-fe23a926e031"
        subnet_v6_id = "64dd4a98-3d7a-4bfd-acf4-91137a8d2f51"

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_network_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_network_id)

        fake_v4_subnet = self._get_fake_v4_subnet(
            docker_network_id, docker_endpoint_id, subnet_v4_id)
        fake_v6_subnet = self._get_fake_v6_subnet(
            docker_network_id, docker_endpoint_id, subnet_v6_id)
        fake_subnets_response = {
            "subnets": [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_list_networks.side_effect = mock_network
        mock_list_subnets.return_value = fake_subnets_response
        mock_list_subnetpools.return_value = fake_subnetpools_response
        mock_delete_subnet.side_effect = GivenException
        response = self._invoke_delete_request(docker_network_id)

        self.assertEqual(GivenException.status_code, response.status_code)
        mock_list_networks.assert_any_call(tags=t)
        mock_list_networks.assert_any_call(tags=te)
        mock_list_subnets.assert_called_with(
            network_id=fake_neutron_network_id)
        fake_v4_pool_attrs = {'name': 'kuryr'}
        fake_v6_pool_attrs = {'name': 'kuryr6'}
        mock_list_subnetpools.assert_any_call(**fake_v6_pool_attrs)
        mock_list_subnetpools.assert_any_call(**fake_v4_pool_attrs)
        mock_delete_subnet.assert_called_with(subnet_v4_id)

        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertEqual({'Err': GivenException.message}, decoded_json)
