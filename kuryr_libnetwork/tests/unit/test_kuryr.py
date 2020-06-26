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
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from kuryr.lib.binding.drivers import utils as driver_utils
from kuryr.lib import constants as lib_const
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import app
from kuryr_libnetwork import config
from kuryr_libnetwork import constants
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


@ddt.ddt
class TestKuryr(base.TestKuryrBase):
    """Basic unitests for libnetwork remote driver URI endpoints.

    This test class covers the following HTTP methods and URIs as described in
    the remote driver specification as below:

      https://github.com/docker/libnetwork/blob/3c8e06bc0580a2a1b2440fe0792fbfcd43a9feca/docs/remote.md  # noqa

    - POST /Plugin.Activate
    - POST /NetworkDriver.GetCapabilities
    - POST /NetworkDriver.CreateNetwork
    - POST /NetworkDriver.DeleteNetwork
    - POST /NetworkDriver.CreateEndpoint
    - POST /NetworkDriver.EndpointOperInfo
    - POST /NetworkDriver.DeleteEndpoint
    - POST /NetworkDriver.Join
    - POST /NetworkDriver.Leave
    - POST /NetworkDriver.DiscoverNew
    - POST /NetworkDriver.DiscoverDelete
    - POST /NetworkDriver.AllocateNetwork
    - POST /NetworkDriver.FreeNetwork
    """
    @ddt.data(('/Plugin.Activate', constants.SCHEMA['PLUGIN_ACTIVATE']),
        ('/NetworkDriver.GetCapabilities',
         {'Scope': config.CONF.capability_scope}),
        ('/NetworkDriver.DiscoverNew', constants.SCHEMA['SUCCESS']),
        ('/NetworkDriver.DiscoverDelete', constants.SCHEMA['SUCCESS']))
    @ddt.unpack
    def test_remote_driver_endpoint(self, endpoint, expected):
        response = self.app.post(endpoint)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(expected, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    @ddt.data((True), (False))
    def test_network_driver_create_v4_network(self,
            driver_default_net, mock_get_default_network_id,
            mock_list_networks, mock_create_network, mock_add_tag,
            mock_create_subnet, mock_list_subnetpools, mock_list_subnets):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()

        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
            }],
            'IPv6Data': [],
            'Options': {}
        }

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = lib_utils.get_neutron_subnetpool_name(
            network_request['IPv4Data'][0]['Pool'])
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, name=fake_name)

        fake_neutron_net_id = uuidutils.generate_uuid()
        driver_value = fake_neutron_net_id if driver_default_net else None
        mock_get_default_network_id.return_value = driver_value
        fake_network = {
            "status": "ACTIVE",
            "subnets": [],
            "admin_state_up": True,
            "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
            "router:external": False,
            "segments": [],
            "shared": False,
            "id": fake_neutron_net_id,
            "tags": [],
        }

        if driver_value:
            fake_existing_networks_response = {
                "networks": [fake_network]
            }
            mock_list_networks.return_value = fake_existing_networks_response
        else:
            fake_create_network_request = {
                "network": {
                    "name": utils.make_net_name(docker_network_id),
                    "admin_state_up": True,
                    "shared": False
                }
            }
            fake_network['name'] = utils.make_net_name(docker_network_id)
            # The following fake response is retrieved from the Neutron doc:
            #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
            fake_create_network_response = {
                "network": fake_network
            }
            mock_create_network.return_value = fake_create_network_response

        tags = utils.create_net_tags(docker_network_id)

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'

        fake_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': '192.168.42.1',
                'subnetpool_id': fake_kuryr_subnetpool_id
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, docker_endpoint_id, subnet_v4_id,
            fake_kuryr_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_subnet_response
        mock_list_subnetpools.return_value = {'subnetpools':
            kuryr_subnetpools['subnetpools']}
        mock_list_subnets.return_value = fake_existing_subnets_response

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)

        mock_get_default_network_id.assert_any_call()

        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        if driver_value:
            mock_list_networks.assert_called_with(id=fake_neutron_net_id)
            mock_add_tag.assert_any_call(
                'networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_create_network.assert_called_with(fake_create_network_request)
        mock_create_subnet.assert_called_with(fake_subnet_request)
        mock_list_subnetpools.assert_called_with(name=fake_name)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    @ddt.data((True), (False))
    def test_network_driver_create_v6_network(self,
            driver_default_net, mock_get_default_network_id,
            mock_list_networks, mock_create_network, mock_add_tag,
            mock_create_subnet, mock_list_subnetpools, mock_list_subnets):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()

        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {}
        }

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = lib_utils.get_neutron_subnetpool_name(
            network_request['IPv6Data'][0]['Pool'])
        kuryr_subnetpools = self._get_fake_v6_subnetpools(
            fake_kuryr_subnetpool_id, name=fake_name)

        fake_neutron_net_id = uuidutils.generate_uuid()
        driver_value = fake_neutron_net_id if driver_default_net else None
        mock_get_default_network_id.return_value = driver_value
        fake_network = {
            "status": "ACTIVE",
            "subnets": [],
            "admin_state_up": True,
            "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
            "router:external": False,
            "segments": [],
            "shared": False,
            "id": fake_neutron_net_id,
            "tags": [],
        }

        if driver_value:
            fake_existing_networks_response = {
                "networks": [fake_network]
            }
            mock_list_networks.return_value = fake_existing_networks_response
        else:
            fake_create_network_request = {
                "network": {
                    "name": utils.make_net_name(docker_network_id),
                    "admin_state_up": True,
                    "shared": False
                }
            }
            fake_network['name'] = utils.make_net_name(docker_network_id)
            # The following fake response is retrieved from the Neutron doc:
            #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
            fake_create_network_response = {
                "network": fake_network
            }
            mock_create_network.return_value = fake_create_network_response

        tags = utils.create_net_tags(docker_network_id)

        fake_existing_subnets_response = {
            "subnets": []
        }

        fake_cidr_v6 = 'fe80::/64'
        fake_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, docker_endpoint_id, subnet_v6_id,
            fake_kuryr_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)

        fake_subnet_response = {
            'subnets': [
                fake_v6_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_subnet_response
        mock_list_subnetpools.return_value = {'subnetpools':
            kuryr_subnetpools['subnetpools']}
        mock_list_subnets.return_value = fake_existing_subnets_response

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)

        mock_get_default_network_id.assert_any_call()

        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        if driver_value:
            mock_list_networks.assert_called_with(id=fake_neutron_net_id)
            mock_add_tag.assert_any_call(
                'networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_create_network.assert_called_with(fake_create_network_request)
        mock_create_subnet.assert_called_with(fake_subnet_request)
        mock_list_subnetpools.assert_called_with(name=fake_name)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    @ddt.data((True), (False))
    def test_network_driver_create_v4_v6_network(self,
            driver_default_net, mock_get_default_network_id,
            mock_list_networks, mock_create_network, mock_add_tag,
            mock_create_subnet, mock_list_subnetpools, mock_list_subnets):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()

        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
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

        fake_neutron_net_id = uuidutils.generate_uuid()
        driver_value = fake_neutron_net_id if driver_default_net else None
        mock_get_default_network_id.return_value = driver_value
        fake_network = {
            "status": "ACTIVE",
            "subnets": [],
            "admin_state_up": True,
            "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
            "router:external": False,
            "segments": [],
            "shared": False,
            "id": fake_neutron_net_id,
            "tags": [],
        }

        if driver_value:
            fake_existing_networks_response = {
                "networks": [fake_network]
            }
            mock_list_networks.return_value = fake_existing_networks_response
        else:
            fake_create_network_request = {
                "network": {
                    "name": utils.make_net_name(docker_network_id),
                    "admin_state_up": True,
                    "shared": False
                }
            }
            fake_network['name'] = utils.make_net_name(docker_network_id)
            # The following fake response is retrieved from the Neutron doc:
            #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
            fake_create_network_response = {
                "network": fake_network
            }
            mock_create_network.return_value = fake_create_network_response

        tags = utils.create_net_tags(docker_network_id)

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'
        fake_cidr_v6 = 'fe80::/64'

        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': '192.168.42.1',
                'subnetpool_id': fake_kuryr_v4_subnetpool_id
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, docker_endpoint_id, subnet_v4_id,
            fake_kuryr_v4_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)

        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_v6_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, docker_endpoint_id, subnet_v6_id,
            fake_kuryr_v6_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)

        fake_v4_v6_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_v4_v6_subnets_response

        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        mock_list_subnets.return_value = fake_existing_subnets_response

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)

        mock_get_default_network_id.assert_any_call()

        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        if driver_value:
            mock_list_networks.assert_called_with(id=fake_neutron_net_id)
            mock_add_tag.assert_any_call(
                'networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_create_network.assert_called_with(fake_create_network_request)
        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    def test_network_driver_create_network_with_net_name_option(self,
            mock_list_networks, mock_list_subnetpools,
            mock_list_subnets, mock_create_subnet,
            mock_add_tag):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {
                'com.docker.network.enable_ipv6': True,
                'com.docker.network.generic': {
                    'neutron.net.name': 'my_network_name'
                }
            }
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

        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_net_name = 'my_network_name'
        fake_existing_networks_response = {
            "networks": [{
                "status": "ACTIVE",
                "subnets": [],
                "admin_state_up": True,
                "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                "router:external": False,
                "segments": [],
                "shared": False,
                "id": fake_neutron_net_id,
                "name": fake_neutron_net_name,
                "tags": [],
            }]
        }
        tags = utils.create_net_tags(docker_network_id)
        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'
        fake_cidr_v6 = 'fe80::/64'
        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': '192.168.42.1',
                'subnetpool_id': fake_kuryr_v4_subnetpool_id
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, docker_endpoint_id, subnet_v4_id,
            fake_kuryr_v4_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)

        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_v6_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, docker_endpoint_id, subnet_v6_id,
            fake_kuryr_v6_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)

        fake_v4_v6_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_list_networks.return_value = fake_existing_networks_response

        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]

        mock_list_subnets.return_value = fake_existing_subnets_response
        mock_create_subnet.return_value = fake_v4_v6_subnets_response

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)
        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        mock_add_tag.assert_any_call('networks', fake_neutron_net_id,
            utils.existing_net_tag(docker_network_id))
        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        mock_list_networks.assert_called_with(name=fake_neutron_net_name)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_network_driver_create_network_with_netid_option(self,
            mock_list_subnets, mock_list_subnetpools,
            mock_list_networks, mock_add_tag, mock_create_subnet):
        docker_network_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {
                'com.docker.network.enable_ipv6': True,
                'com.docker.network.generic': {
                    'neutron.net.uuid': fake_neutron_net_id
                }
            }
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

        fake_existing_networks_response = {
            "networks": [{
                "status": "ACTIVE",
                "subnets": [],
                "admin_state_up": True,
                "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                "router:external": False,
                "segments": [],
                "shared": False,
                "id": fake_neutron_net_id,
                "tags": [],
            }]
        }

        tags = utils.create_net_tags(docker_network_id)
        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'

        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': '192.168.42.1',
                'subnetpool_id': fake_kuryr_v4_subnetpool_id
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id,
            fake_kuryr_v4_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)

        fake_cidr_v6 = 'fe80::/64'
        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_v6_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, subnet_v6_id,
            fake_kuryr_v6_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)

        fake_v4_v6_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_v4_v6_subnets_response
        mock_list_networks.return_value = fake_existing_networks_response
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        mock_list_subnets.return_value = fake_existing_subnets_response

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)
        for tag in tags:
            mock_add_tag.assert_any_call('networks', fake_neutron_net_id, tag)
        mock_add_tag.assert_any_call(
            'networks', fake_neutron_net_id,
            utils.existing_net_tag(docker_network_id))
        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        mock_list_networks.assert_called_with(id=fake_neutron_net_id)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    @ddt.data((True), (False))
    def test_network_driver_create_network_with_pool_name_option(self,
            driver_default_net, mock_get_default_network_id,
            mock_list_networks, mock_create_network, mock_add_tag,
            mock_create_subnet, mock_list_subnetpools,
            mock_list_subnets):
        """Test for create network with v4 subnetpool name"""
        fake_kuryr_v4_subnetpool_id = uuidutils.generate_uuid()
        fake_v4_pool_name = "fake_pool_name"
        kuryr_v4_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_v4_subnetpool_id, name=fake_v4_pool_name)

        fake_kuryr_v6_subnetpool_id = uuidutils.generate_uuid()
        fake_v6_pool_name = "fake_v6pool_name"
        kuryr_v6_subnetpools = self._get_fake_v6_subnetpools(
            fake_kuryr_v6_subnetpool_id, name=fake_v6_pool_name)

        docker_network_id = lib_utils.get_hash()
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {
                'com.docker.network.enable_ipv6': True,
                'com.docker.network.generic': {
                    'neutron.pool.name': fake_v4_pool_name,
                    'neutron.pool.v6.name': fake_v6_pool_name,
                }
            }
        }

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
        fake_neutron_net_id = uuidutils.generate_uuid()
        driver_value = fake_neutron_net_id if driver_default_net else None
        mock_get_default_network_id.return_value = driver_value

        fake_network = {
            "status": "ACTIVE",
            "subnets": [],
            "admin_state_up": True,
            "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
            "router:external": False,
            "segments": [],
            "shared": False,
            "id": fake_neutron_net_id,
            "tags": [],
        }

        if driver_value:
            fake_existing_networks_response = {
                "networks": [fake_network]
            }
            mock_list_networks.return_value = fake_existing_networks_response
        else:
            fake_create_network_request = {
                "network": {
                    "name": utils.make_net_name(docker_network_id),
                    "admin_state_up": True,
                    "shared": False
                }
            }
            fake_network['name'] = utils.make_net_name(docker_network_id)
            # The following fake response is retrieved from the Neutron doc:
            #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
            fake_create_network_response = {
                "network": fake_network
            }
            mock_create_network.return_value = fake_create_network_response

        tags = utils.create_net_tags(docker_network_id)

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'

        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': '192.168.42.1',
                'subnetpool_id': fake_kuryr_v4_subnetpool_id,
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)

        fake_cidr_v6 = 'fe80::/64'
        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_v6_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, subnet_v6_id,
            fake_kuryr_v6_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)
        fake_v4_v6_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }

        mock_create_subnet.return_value = fake_v4_v6_subnets_response
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        mock_list_subnets.return_value = fake_existing_subnets_response
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)

        mock_get_default_network_id.assert_any_call()

        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        if driver_value:
            mock_list_networks.assert_called_with(id=fake_neutron_net_id)
            mock_add_tag.assert_any_call(
                'networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_create_network.assert_called_with(fake_create_network_request)

        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @ddt.data((True), (False))
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    def test_network_driver_create_network_with_pool_id_option(self,
            driver_default_net, mock_get_default_network_id,
            mock_list_networks, mock_create_network, mock_add_tag,
            mock_create_subnet, mock_list_subnetpools,
            mock_list_subnets):
        fake_kuryr_v4_subnetpool_id = uuidutils.generate_uuid()
        kuryr_v4_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_v4_subnetpool_id)

        fake_kuryr_v6_subnetpool_id = uuidutils.generate_uuid()
        kuryr_v6_subnetpools = self._get_fake_v6_subnetpools(
            fake_kuryr_v6_subnetpool_id)

        docker_network_id = lib_utils.get_hash()
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.1.0/24',
                'Gateway': '192.168.1.1/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {
                'com.docker.network.enable_ipv6': False,
                'com.docker.network.generic': {
                    'neutron.pool.uuid': fake_kuryr_v4_subnetpool_id,
                    'neutron.pool.v6.uuid': fake_kuryr_v6_subnetpool_id,
                }
            }
        }

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
        fake_neutron_net_id = "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
        driver_value = fake_neutron_net_id if driver_default_net else None
        mock_get_default_network_id.return_value = driver_value

        fake_network = {
            "status": "ACTIVE",
            "subnets": [],
            "admin_state_up": True,
            "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
            "router:external": False,
            "segments": [],
            "shared": False,
            "id": fake_neutron_net_id,
            "tags": [],
        }

        if driver_value:
            fake_existing_networks_response = {
                "networks": [fake_network]
            }
            mock_list_networks.return_value = fake_existing_networks_response
        else:
            fake_create_network_request = {
                "network": {
                    "name": utils.make_net_name(docker_network_id),
                    "admin_state_up": True,
                    "shared": False
                }
            }
            fake_network['name'] = utils.make_net_name(docker_network_id)
            # The following fake response is retrieved from the Neutron doc:
            #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
            fake_create_network_response = {
                "network": fake_network
            }
            mock_create_network.return_value = fake_create_network_response

        tags = utils.create_net_tags(docker_network_id)

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.1.0/24'

        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': '192.168.1.1',
                'subnetpool_id': fake_kuryr_v4_subnetpool_id,
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id,
            fake_kuryr_v4_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)

        fake_cidr_v6 = 'fe80::/64'
        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_v6_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, subnet_v6_id,
            fake_kuryr_v6_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)
        fake_v4_v6_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_v4_v6_subnets_response
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        mock_list_subnets.return_value = fake_existing_subnets_response
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)

        mock_get_default_network_id.assert_any_call()

        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        if driver_value:
            mock_list_networks.assert_called_with(id=fake_neutron_net_id)
            mock_add_tag.assert_any_call(
                'networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_create_network.assert_called_with(fake_create_network_request)

        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        mock_list_subnetpools.assert_any_call(id=fake_kuryr_v4_subnetpool_id)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @ddt.data((True), (False))
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.driver.get_default_network_id')
    def test_network_driver_create_network_wo_gw(self,
            driver_default_net, mock_get_default_network_id,
            mock_list_subnets, mock_list_subnetpools,
            mock_add_tag, mock_list_networks, mock_create_network,
            mock_create_subnet):
        docker_network_id = lib_utils.get_hash()
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
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

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
        fake_neutron_net_id = uuidutils.generate_uuid()
        driver_value = fake_neutron_net_id if driver_default_net else None
        mock_get_default_network_id.return_value = driver_value

        fake_network = {
            "status": "ACTIVE",
            "subnets": [],
            "admin_state_up": True,
            "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
            "router:external": False,
            "segments": [],
            "shared": False,
            "id": fake_neutron_net_id,
            "tags": [],
        }

        if driver_value:
            fake_existing_networks_response = {
                "networks": [fake_network]
            }
            mock_list_networks.return_value = fake_existing_networks_response
        else:
            fake_create_network_request = {
                "network": {
                    "name": utils.make_net_name(docker_network_id),
                    "admin_state_up": True,
                    "shared": False
                }
            }
            # The following fake response is retrieved from the Neutron doc:
            #   https://docs.openstack.org/api-ref/network/v2/index.html#create-network  # noqa
            fake_network['name'] = utils.make_net_name(docker_network_id)
            fake_create_network_response = {
                "network": fake_network
            }
            mock_create_network.return_value = fake_create_network_response

        tags = utils.create_net_tags(docker_network_id)

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'

        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': app.enable_dhcp,
                'subnetpool_id': fake_kuryr_v4_subnetpool_id
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id,
            fake_kuryr_v4_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)

        fake_cidr_v6 = 'fe80::/64'
        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': app.enable_dhcp,
                'gateway_ip': 'fe80::f816:3eff:fe20:57c3',
                'subnetpool_id': fake_kuryr_v6_subnetpool_id
            }]
        }

        subnet_v6_id = uuidutils.generate_uuid()
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, subnet_v6_id,
            fake_kuryr_v6_subnetpool_id,
            name=fake_cidr_v6, cidr=fake_cidr_v6)
        fake_v4_v6_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_v4_v6_subnets_response
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        mock_list_subnets.return_value = fake_existing_subnets_response

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)

        mock_get_default_network_id.assert_any_call()

        for tag in tags:
            mock_add_tag.assert_any_call('networks',
                fake_neutron_net_id, tag)
        if driver_value:
            mock_list_networks.assert_called_with(id=fake_neutron_net_id)
            mock_add_tag.assert_any_call(
                'networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_create_network.assert_called_with(fake_create_network_request)

        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_network_driver_create_network_with_network_id_not_exist(self,
            mock_list_subnetpools, mock_list_networks):
        docker_network_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {
                constants.NETWORK_GENERIC_OPTIONS: {
                    constants.NEUTRON_UUID_OPTION: fake_neutron_net_id
                }
            }
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

        fake_existing_networks_response = {
            "networks": []
        }
        mock_list_networks.return_value = fake_existing_networks_response
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))
        self.assertEqual(500, response.status_code)
        mock_list_networks.assert_called_with(id=fake_neutron_net_id)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        err_message = ("Specified network id/name({0}) does not "
                      "exist.").format(fake_neutron_net_id)
        self.assertEqual({'Err': err_message}, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_network_driver_create_network_with_network_name_not_exist(
            self, mock_list_subnetpools, mock_list_networks):
        docker_network_id = lib_utils.get_hash()
        fake_neutron_network_name = "fake_network"
        network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
            }],
            'IPv6Data': [{
                'AddressSpace': 'bar',
                'Pool': 'fe80::/64',
                'Gateway': 'fe80::f816:3eff:fe20:57c3/64',
            }],
            'Options': {
                constants.NETWORK_GENERIC_OPTIONS: {
                    constants.NEUTRON_NAME_OPTION: fake_neutron_network_name
                }
            }
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

        fake_existing_networks_response = {
            "networks": []
        }
        mock_list_networks.return_value = fake_existing_networks_response
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))
        self.assertEqual(500, response.status_code)
        mock_list_networks.assert_called_with(name=fake_neutron_network_name)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        err_message = ("Specified network id/name({0}) does not "
                      "exist.").format(fake_neutron_network_name)
        self.assertEqual({'Err': err_message}, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    def test_network_driver_delete_network(self, mock_delete_network,
            mock_list_subnets, mock_list_networks):
        mock_delete_network.return_value = None
        docker_network_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()

        fake_neutron_subnets_response = {"subnets": []}
        mock_list_subnets.return_value = fake_neutron_subnets_response

        data = {'NetworkID': docker_network_id}
        t = utils.make_net_tags(docker_network_id)
        te = t + ',' + utils.existing_net_tag(docker_network_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_networks.assert_any_call(tags=t)
        mock_list_networks.assert_any_call(tags=te)
        mock_delete_network.assert_called_with(fake_neutron_net_id)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_network_driver_delete_network_with_subnets(self,
            mock_list_subnets, mock_list_subnetpools,
            mock_delete_subnet, mock_delete_network, mock_list_networks):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(docker_network_id)
        te = t + ',' + utils.existing_net_tag(docker_network_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        # The following fake response is retrieved from the Neutron doc:
        # https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
        subnet_v4_id = "9436e561-47bf-436a-b1f1-fe23a926e031"
        subnet_v6_id = "64dd4a98-3d7a-4bfd-acf4-91137a8d2f51"
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

        fake_subnetpools_response = {"subnetpools": []}

        mock_delete_network.return_value = None
        mock_delete_subnet.return_value = None
        mock_list_subnetpools.return_value = fake_subnetpools_response
        mock_list_subnets.return_value = fake_subnets_response

        data = {'NetworkID': docker_network_id}
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_delete_network.assert_called_with(fake_neutron_net_id)
        mock_delete_subnet.assert_any_call(subnet_v6_id)
        mock_delete_subnet.assert_any_call(subnet_v4_id)
        mock_list_subnetpools.assert_any_call(name='kuryr')
        mock_list_subnetpools.assert_any_call(name='kuryr6')
        mock_list_networks.assert_any_call(tags=te)
        mock_list_networks.assert_any_call(tags=t)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.create_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (False), (True))
    def test_network_driver_create_endpoint(self, vif_plug_is_fatal,
            mock_app, mock_list_subnets, mock_list_ports,
            mock_update_port, mock_show_port, mock_list_networks,
            mock_create_host_iface):
        mock_app.vif_plug_is_fatal = vif_plug_is_fatal
        mock_app.tag = True
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_network_id)
        te = t + ',' + utils.existing_net_tag(fake_docker_network_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        fake_neutron_network = self._get_fake_list_network(
            fake_neutron_net_id)

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_docker_network_id, fake_docker_endpoint_id, subnet_v4_id)
        fake_v4_subnet_response = {
            "subnets": [
                fake_v4_subnet['subnet']
            ]
        }

        def mock_fake_subnet(*args, **kwargs):
            if kwargs['cidr'] == '192.168.1.0/24':
                return fake_v4_subnet_response
        mock_list_subnets.side_effect = mock_fake_subnet

        fake_port_id = uuidutils.generate_uuid()
        fake_fixed_ips = ['subnet_id=%s' % subnet_v4_id,
                          'ip_address=192.168.1.2']
        fake_port_response = self._get_fake_port(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
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

        fake_create_iface_response = ('fake stdout', '')

        mock_create_host_iface.return_value = fake_create_iface_response

        if vif_plug_is_fatal:
            fake_neutron_ports_response_2 = self._get_fake_port(
                fake_docker_endpoint_id, fake_neutron_net_id,
                fake_port_id, lib_const.PORT_STATUS_ACTIVE,
                subnet_v4_id,
                tags=utils.create_port_tags(fake_docker_endpoint_id))
            mock_show_port.return_value = fake_neutron_ports_response_2

        data = {
            'NetworkID': fake_docker_network_id,
            'EndpointID': fake_docker_endpoint_id,
            'Options': {},
            'Interface': {
                'Address': '192.168.1.2/24',
                'AddressIPv6': '',
                'MacAddress': 'fa:16:3e:20:57:c3'
            }
        }
        response = self.app.post('/NetworkDriver.CreateEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id, cidr='192.168.1.0/24')
        mock_list_ports.assert_called_with(fixed_ips=fake_fixed_ips)
        mock_update_port.assert_called_with(fake_port_response['port'],
                                            fake_docker_endpoint_id,
                                            'fa:16:3e:20:57:c3',
                                            tags=True)
        mock_list_networks.assert_any_call(tags=t)
        mock_create_host_iface.assert_called_with(fake_docker_endpoint_id,
            fake_updated_port, [fake_v4_subnet['subnet']],
            fake_neutron_network['networks'][0])
        if vif_plug_is_fatal:
            mock_show_port.assert_called_with(fake_port_id)
        decoded_json = jsonutils.loads(response.data)
        expected = {'Interface': {}}
        self.assertEqual(expected, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.create_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (False), (True))
    def test_network_driver_create_v4_v6_endpoint(self, vif_plug_is_fatal,
            mock_vif, mock_list_subnets, mock_list_ports, mock_delete_port,
            mock_create_port, mock_show_port, mock_list_networks,
            mock_create_host_iface):
        mock_vif.vif_plug_is_fatal = vif_plug_is_fatal
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_network_id)
        te = t + ',' + utils.existing_net_tag(fake_docker_network_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        fake_neutron_network = self._get_fake_list_network(
            fake_neutron_net_id)

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v6_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, fake_docker_endpoint_id, subnet_v4_id)
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, fake_docker_endpoint_id, subnet_v6_id)
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

        def mock_fake_subnet(*args, **kwargs):
            if kwargs['cidr'] == '192.168.1.0/24':
                return fake_v4_subnet_response
            elif kwargs['cidr'] == 'fe80::/64':
                return fake_v6_subnet_response
        mock_list_subnets.side_effect = mock_fake_subnet

        fake_port_id = uuidutils.generate_uuid()
        fake_fixed_ips = ['subnet_id=%s' % subnet_v4_id,
                          'ip_address=192.168.1.2',
                          'subnet_id=%s' % subnet_v6_id,
                          'ip_address=fe80::f816:3eff:fe20:57c4']
        fake_mac_address = 'fa:16:3e:20:57:c5'
        fake_new_port_response = self._get_fake_port(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id, subnet_v6_id, fake_mac_address)

        fake_v4_port_id = uuidutils.generate_uuid()
        fake_v4_port_response = self._get_fake_port(
            "fake-name1", fake_neutron_net_id,
            fake_v4_port_id, lib_const.PORT_STATUS_DOWN,
            subnet_v4_id, name=constants.KURYR_UNBOUND_PORT)

        fake_v6_port_id = uuidutils.generate_uuid()
        fake_v6_port_response = self._get_fake_port(
            "fake-name2", fake_neutron_net_id,
            fake_v6_port_id, lib_const.PORT_STATUS_DOWN,
            subnet_v6_id, neutron_mac_address="fa:16:3e:20:57:c4",
            name=constants.KURYR_UNBOUND_PORT)

        fake_ports_response = {
            "ports": [
                fake_v4_port_response['port'],
                fake_v6_port_response['port']
            ]
        }
        mock_list_ports.return_value = fake_ports_response

        mock_create_port.return_value = fake_new_port_response

        fake_neutron_subnets = [fake_v4_subnet['subnet'],
                                fake_v6_subnet['subnet']]
        fake_create_iface_response = ('fake stdout', '')

        mock_create_host_iface.return_value = fake_create_iface_response

        if vif_plug_is_fatal:
            fake_neutron_ports_response_2 = self._get_fake_port(
                fake_docker_endpoint_id, fake_neutron_net_id,
                fake_port_id, lib_const.PORT_STATUS_ACTIVE,
                subnet_v4_id, subnet_v6_id)
            mock_show_port.return_value = fake_neutron_ports_response_2

        data = {
            'NetworkID': fake_docker_network_id,
            'EndpointID': fake_docker_endpoint_id,
            'Options': {},
            'Interface': {
                'Address': '192.168.1.2/24',
                'AddressIPv6': 'fe80::f816:3eff:fe20:57c4/64',
                'MacAddress': fake_mac_address
            }
        }
        response = self.app.post('/NetworkDriver.CreateEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id, cidr='192.168.1.0/24')
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id, cidr='fe80::/64')
        mock_list_ports.assert_called_with(fixed_ips=fake_fixed_ips)
        mock_delete_port.assert_any_call(fake_v4_port_id)
        mock_delete_port.assert_any_call(fake_v6_port_id)
        fixed_ips = lib_utils.get_dict_format_fixed_ips_from_kv_format(
            fake_fixed_ips)
        port = {
            'name': utils.get_neutron_port_name(fake_docker_endpoint_id),
            'admin_state_up': True,
            'network_id': fake_neutron_net_id,
            'device_owner': lib_const.DEVICE_OWNER,
            'device_id': fake_docker_endpoint_id,
            'binding:host_id': lib_utils.get_hostname(),
            'fixed_ips': fixed_ips,
            'mac_address': fake_mac_address
        }
        mock_create_port.assert_called_with({'port': port})
        mock_list_networks.assert_any_call(tags=t)
        mock_create_host_iface.assert_called_with(fake_docker_endpoint_id,
            fake_new_port_response['port'], fake_neutron_subnets,
            fake_neutron_network['networks'][0])
        if vif_plug_is_fatal:
            mock_show_port.assert_called_with(fake_port_id)
        decoded_json = jsonutils.loads(response.data)
        expected = {'Interface': {}}
        self.assertEqual(expected, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.create_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (False), (True))
    def test_network_driver_create_v4_endpoint_in_dual_net(
            self, vif_plug_is_fatal,
            mock_app, mock_list_subnets, mock_list_ports, mock_delete_port,
            mock_update_port, mock_show_port, mock_list_networks,
            mock_create_host_iface):
        mock_app.vif_plug_is_fatal = vif_plug_is_fatal
        mock_app.tag = True
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_network_id)
        te = t + ',' + utils.existing_net_tag(fake_docker_network_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        fake_neutron_network = self._get_fake_list_network(
            fake_neutron_net_id)

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v6_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, fake_docker_endpoint_id, subnet_v4_id)
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id, fake_docker_endpoint_id, subnet_v6_id)
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

        def mock_fake_subnet(*args, **kwargs):
            if kwargs['cidr'] == '192.168.1.0/24':
                return fake_v4_subnet_response
            elif kwargs['cidr'] == 'fe80::/64':
                return fake_v6_subnet_response
        mock_list_subnets.side_effect = mock_fake_subnet

        fake_fixed_ips = ['subnet_id=%s' % subnet_v4_id,
                          'ip_address=192.168.1.2']
        fake_mac_address = 'fa:16:3e:20:57:c5'
        fake_v4_port_id = uuidutils.generate_uuid()
        fake_new_port_response = self._get_fake_port(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_v4_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id, neutron_mac_address=fake_mac_address,
            tags=utils.create_port_tags(fake_docker_endpoint_id))

        fake_v4_port_response = self._get_fake_port(
            "fake-name1", fake_neutron_net_id,
            fake_v4_port_id, lib_const.PORT_STATUS_DOWN,
            subnet_v4_id,
            tags=utils.create_port_tags(fake_docker_endpoint_id))

        fake_v6_port_id = uuidutils.generate_uuid()
        fake_v6_port_response = self._get_fake_port(
            "fake-name2", fake_neutron_net_id,
            fake_v6_port_id, lib_const.PORT_STATUS_DOWN,
            subnet_v6_id, name=constants.KURYR_UNBOUND_PORT,
            neutron_mac_address="fa:16:3e:20:57:c4",
            tags=utils.create_port_tags(fake_docker_endpoint_id))

        fake_ports_response = {
            "ports": [
                fake_v4_port_response['port'],
                fake_v6_port_response['port']
            ]
        }
        mock_list_ports.return_value = fake_ports_response

        mock_update_port.return_value = fake_new_port_response['port']

        fake_neutron_subnets = [fake_v4_subnet['subnet']]
        fake_create_iface_response = ('fake stdout', '')

        mock_create_host_iface.return_value = fake_create_iface_response

        if vif_plug_is_fatal:
            fake_neutron_ports_response_2 = self._get_fake_port(
                fake_docker_endpoint_id, fake_neutron_net_id,
                fake_v4_port_id, lib_const.PORT_STATUS_ACTIVE,
                subnet_v4_id, subnet_v6_id,
                tags=utils.create_port_tags(fake_docker_endpoint_id))
            mock_show_port.return_value = fake_neutron_ports_response_2

        data = {
            'NetworkID': fake_docker_network_id,
            'EndpointID': fake_docker_endpoint_id,
            'Options': {},
            'Interface': {
                'Address': '192.168.1.2/24',
                'MacAddress': fake_mac_address
            }
        }
        response = self.app.post('/NetworkDriver.CreateEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id, cidr='192.168.1.0/24')
        mock_list_ports.assert_called_with(fixed_ips=fake_fixed_ips)
        mock_delete_port.assert_any_call(fake_v6_port_id)
        mock_update_port.assert_called_with(
            fake_v4_port_response['port'], fake_docker_endpoint_id,
            fake_mac_address, tags=True)
        mock_list_networks.assert_any_call(tags=t)
        mock_create_host_iface.assert_called_with(fake_docker_endpoint_id,
            fake_new_port_response['port'], fake_neutron_subnets,
            fake_neutron_network['networks'][0])
        if vif_plug_is_fatal:
            mock_show_port.assert_called_with(fake_v4_port_id)
        decoded_json = jsonutils.loads(response.data)
        expected = {'Interface': {}}
        self.assertEqual(expected, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.create_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (False), (True))
    def test_network_driver_create_endpoint_with_no_mac_address(self,
            vif_plug_is_fatal, mock_app, mock_list_subnets, mock_list_ports,
            mock_update_port, mock_show_port, mock_list_networks,
            mock_create_host_iface):
        mock_app.vif_plug_is_fatal = vif_plug_is_fatal
        mock_app.tag = True
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_network_id)
        te = t + ',' + utils.existing_net_tag(fake_docker_network_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)

        mock_list_networks.side_effect = mock_network
        fake_neutron_network = self._get_fake_list_network(
            fake_neutron_net_id)

        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v6_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_docker_network_id, fake_docker_endpoint_id, subnet_v4_id)
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_docker_network_id, fake_docker_endpoint_id, subnet_v6_id)
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

        def mock_fake_subnet(*args, **kwargs):
            if kwargs['cidr'] == '192.168.1.0/24':
                return fake_v4_subnet_response
            elif kwargs['cidr'] == 'fe80::/64':
                return fake_v6_subnet_response

        mock_list_subnets.side_effect = mock_fake_subnet

        fake_port_id = uuidutils.generate_uuid()
        fake_fixed_ips = ['subnet_id=%s' % subnet_v4_id,
                          'ip_address=192.168.1.2',
                          'subnet_id=%s' % subnet_v6_id,
                          'ip_address=fe80::f816:3eff:fe20:57c4']
        fake_mac_address = 'fa:16:3e:20:57:c3'
        fake_port_response = self._get_fake_port(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id, subnet_v6_id, neutron_mac_address=fake_mac_address,
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
        fake_create_iface_response = ('fake stdout', '')

        mock_create_host_iface.return_value = fake_create_iface_response

        if vif_plug_is_fatal:
            fake_neutron_ports_response_2 = self._get_fake_port(
                fake_docker_endpoint_id, fake_neutron_net_id,
                fake_port_id, lib_const.PORT_STATUS_ACTIVE,
                subnet_v4_id, subnet_v6_id,
                tags=utils.create_port_tags(fake_docker_endpoint_id))
            mock_show_port.return_value = fake_neutron_ports_response_2

        data = {
            'NetworkID': fake_docker_network_id,
            'EndpointID': fake_docker_endpoint_id,
            'Options': {},
            'Interface': {
                'Address': '192.168.1.2/24',
                'AddressIPv6': 'fe80::f816:3eff:fe20:57c4/64'
            }
        }
        response = self.app.post('/NetworkDriver.CreateEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id, cidr='192.168.1.0/24')
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id, cidr='fe80::/64')
        mock_list_ports.assert_called_with(fixed_ips=fake_fixed_ips)
        mock_update_port.assert_called_with(fake_port_response['port'],
                                            fake_docker_endpoint_id, '',
                                            tags=True)
        mock_list_networks.assert_any_call(tags=t)
        mock_create_host_iface.assert_called_with(fake_docker_endpoint_id,
                                                  fake_updated_port,
                                                  fake_neutron_subnets,
                                                  fake_neutron_network[
                                                      'networks'][0])
        if vif_plug_is_fatal:
            mock_show_port.assert_called_with(fake_port_id)
        decoded_json = jsonutils.loads(response.data)
        expected = {'Interface': {'MacAddress': fake_mac_address}}
        self.assertEqual(expected, decoded_json)

    def test_network_driver_endpoint_operational_info_with_no_port(self):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        fake_port_response = {"ports": []}

        with mock.patch.object(app.neutron, 'list_ports') as mock_list_ports:
            data = {
                'NetworkID': docker_network_id,
                'EndpointID': docker_endpoint_id,
            }

            mock_list_ports.return_value = fake_port_response
            response = self.app.post('/NetworkDriver.EndpointOperInfo',
                                     content_type='application/json',
                                     data=jsonutils.dumps(data))
            decoded_json = jsonutils.loads(response.data)
            self.assertEqual(200, response.status_code)

            port_tags = utils.make_port_tags(docker_endpoint_id)
            mock_list_ports.assert_called_once_with(tags=port_tags)

            self.assertEqual({}, decoded_json['Value'])

    def test_network_driver_endpoint_operational_info(self):
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_port_id = uuidutils.generate_uuid()
        fake_port = self._get_fake_port(
            docker_endpoint_id, fake_neutron_net_id,
            fake_port_id, lib_const.PORT_STATUS_ACTIVE)

        fake_port_response = {
            "ports": [
                fake_port['port']
            ]
        }

        with mock.patch.object(app.neutron, 'list_ports') as mock_list_ports:
            data = {
                'NetworkID': docker_network_id,
                'EndpointID': docker_endpoint_id,
            }

            mock_list_ports.return_value = fake_port_response
            response = self.app.post('/NetworkDriver.EndpointOperInfo',
                                     content_type='application/json',
                                     data=jsonutils.dumps(data))
            decoded_json = jsonutils.loads(response.data)
            self.assertEqual(200, response.status_code)

            port_tags = utils.make_port_tags(docker_endpoint_id)
            mock_list_ports.assert_called_once_with(tags=port_tags)

            self.assertEqual(fake_port_response['ports'][0]['status'],
                             decoded_json['Value']['status'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.DEFAULT_DRIVER'
                '.delete_host_iface')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    def test_network_driver_delete_endpoint(self, mock_list_networks,
            mock_list_ports, mock_delete_host_iface, mock_remove_tag):
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()

        fake_iface_deletion_response = ('fake stdout', '')
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            tags=utils.make_port_tags(fake_docker_endpoint_id))
        fake_neutron_port = fake_neutron_ports_response['ports'][0]

        t = utils.make_net_tags(fake_docker_net_id)
        port_tags = utils.make_port_tags(fake_docker_endpoint_id)
        mock_list_networks.return_value = self._get_fake_list_network(
            fake_neutron_net_id)
        mock_list_ports.return_value = fake_neutron_ports_response
        mock_delete_host_iface.return_value = fake_iface_deletion_response

        data = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
        }
        response = self.app.post('/NetworkDriver.DeleteEndpoint',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_networks.assert_called_with(tags=t)
        mock_list_ports.assert_called_with(tags=port_tags)
        mock_delete_host_iface.assert_called_with(fake_docker_endpoint_id,
            fake_neutron_port)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch.object(driver_utils, 'get_veth_pair_names')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch(
        'kuryr_libnetwork.controllers.DEFAULT_DRIVER.get_container_iface_name')
    def test_network_driver_join(self, mock_get_container_iface_name,
            mock_list_subnets, mock_list_ports, mock_list_networks,
            mock_get_veth_pair_names):
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_container_id = lib_utils.get_hash()

        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_net_id)
        te = t + ',' + utils.existing_net_tag(fake_docker_net_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        fake_neutron_port_id = uuidutils.generate_uuid()
        port_tags = utils.make_port_tags(fake_docker_endpoint_id)
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_DOWN,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)

        fake_neutron_subnets_response = self._get_fake_subnets(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        fake_neutron_subnets = fake_neutron_subnets_response['subnets']
        fake_iface_name = 'fake-name'

        mock_get_container_iface_name.return_value = fake_iface_name

        fake_subnets_dict_by_id = {subnet['id']: subnet
                                   for subnet in fake_neutron_subnets}

        mock_list_ports.return_value = fake_neutron_ports_response
        mock_list_subnets.return_value = fake_neutron_subnets_response
        join_request = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
            'SandboxKey': utils.get_sandbox_key(fake_container_id),
            'Options': {},
        }
        response = self.app.post('/NetworkDriver.Join',
                                 content_type='application/json',
                                 data=jsonutils.dumps(join_request))

        fake_neutron_v4_subnet = fake_subnets_dict_by_id[
            fake_neutron_v4_subnet_id]
        fake_neutron_v6_subnet = fake_subnets_dict_by_id[
            fake_neutron_v6_subnet_id]
        expected_response = {
            'Gateway': fake_neutron_v4_subnet['gateway_ip'],
            'GatewayIPv6': fake_neutron_v6_subnet['gateway_ip'],
            'InterfaceName': {
                'DstPrefix': config.CONF.binding.veth_dst_prefix,
                'SrcName': fake_iface_name,
            },
            'StaticRoutes': [],
            'DisableGatewayService': True
        }

        self.assertEqual(200, response.status_code)

        decoded_json = jsonutils.loads(response.data)
        mock_list_networks.assert_any_call(tags=t)
        mock_get_container_iface_name.assert_called_with(
            fake_neutron_ports_response['ports'][0])
        mock_list_ports.assert_called_with(tags=port_tags)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id)

        self.assertEqual(expected_response, decoded_json)

    @mock.patch.object(driver_utils, 'get_veth_pair_names')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch(
        'kuryr_libnetwork.controllers.DEFAULT_DRIVER.get_container_iface_name')
    def test_network_driver_join_multiple_subnets(
            self, mock_get_container_iface_name,
            mock_list_subnets, mock_list_ports, mock_list_networks,
            mock_get_veth_pair_names):
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_container_id = lib_utils.get_hash()
        fake_address_v4 = "10.2.0.3"
        fake_address_v6 = "fe80::f816:3eff:fe20:57c4"

        fake_neutron_net_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_net_id)
        te = t + ',' + utils.existing_net_tag(fake_docker_net_id)

        def mock_network(*args, **kwargs):
            if kwargs['tags'] == te:
                return self._get_fake_list_network(
                    fake_neutron_net_id,
                    check_existing=True)
            elif kwargs['tags'] == t:
                return self._get_fake_list_network(
                    fake_neutron_net_id)
        mock_list_networks.side_effect = mock_network
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_subnetpool_id = uuidutils.generate_uuid()
        port_tags = utils.make_port_tags(fake_docker_endpoint_id)
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id_2 = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id_2 = uuidutils.generate_uuid()
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_DOWN,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            fake_address_v4, fake_address_v6)

        fake_subnet_v4_1 = self._get_fake_v4_subnet(
            fake_neutron_net_id,
            name="subnet1",
            subnet_v4_id=fake_neutron_v4_subnet_id,
            cidr="10.2.0.0/24",
            subnetpool_id=fake_neutron_subnetpool_id)
        fake_subnet_v4_2 = self._get_fake_v4_subnet(
            fake_neutron_net_id,
            name="subnet2",
            subnet_v4_id=fake_neutron_v4_subnet_id_2,
            cidr="10.2.1.0/24",
            subnetpool_id=fake_neutron_subnetpool_id)
        fake_subnet_v6_1 = self._get_fake_v6_subnet(
            fake_neutron_net_id,
            name="subnet_v6_1",
            subnet_v6_id=fake_neutron_v6_subnet_id,
            cidr="fe80::/64",
            subnetpool_id=fake_neutron_subnetpool_id)
        fake_subnet_v6_2 = self._get_fake_v6_subnet(
            fake_neutron_net_id,
            name="subnet_v6_2",
            subnet_v6_id=fake_neutron_v6_subnet_id_2,
            cidr="fe81::/64",
            subnetpool_id=fake_neutron_subnetpool_id)
        fake_neutron_subnets = [
            fake_subnet_v4_1['subnet'],
            fake_subnet_v4_2['subnet'],
            fake_subnet_v6_1['subnet'],
            fake_subnet_v6_2['subnet']
        ]
        fake_neutron_subnets_response = {"subnets": fake_neutron_subnets}
        fake_iface_name = 'fake-name'

        mock_get_container_iface_name.return_value = fake_iface_name

        fake_subnets_dict_by_id = {subnet['id']: subnet
                                   for subnet in fake_neutron_subnets}

        mock_list_ports.return_value = fake_neutron_ports_response
        mock_list_subnets.return_value = fake_neutron_subnets_response
        join_request = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
            'SandboxKey': utils.get_sandbox_key(fake_container_id),
            'Options': {},
        }
        response = self.app.post('/NetworkDriver.Join',
                                 content_type='application/json',
                                 data=jsonutils.dumps(join_request))

        fake_neutron_v4_subnet = fake_subnets_dict_by_id[
            fake_neutron_v4_subnet_id]
        fake_neutron_v6_subnet = fake_subnets_dict_by_id[
            fake_neutron_v6_subnet_id]
        expected_response = {
            'Gateway': fake_neutron_v4_subnet['gateway_ip'],
            'GatewayIPv6': fake_neutron_v6_subnet['gateway_ip'],
            'InterfaceName': {
                'DstPrefix': config.CONF.binding.veth_dst_prefix,
                'SrcName': fake_iface_name,
            },
            'StaticRoutes': [],
            'DisableGatewayService': True
        }

        self.assertEqual(200, response.status_code)

        decoded_json = jsonutils.loads(response.data)
        mock_list_networks.assert_any_call(tags=t)
        mock_get_container_iface_name.assert_called_with(
            fake_neutron_ports_response['ports'][0])
        mock_list_ports.assert_called_with(tags=port_tags)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id)

        self.assertEqual(expected_response, decoded_json)

    @mock.patch.object(driver_utils, 'get_veth_pair_names')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch(
        'kuryr_libnetwork.controllers.DEFAULT_DRIVER.get_container_iface_name')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(True, False)
    def test_network_driver_join_with_static_route_return(self,
            mock_use_tags, mock_app,
            mock_get_container_iface_name,
            mock_list_subnets, mock_list_ports, mock_list_networks,
            mock_get_veth_pair_names):
        mock_app.tag = mock_use_tags
        fake_neutron_net_id = uuidutils.generate_uuid()

        fake_v4_subnet_id = uuidutils.generate_uuid()
        fake_v6_subnet_id = uuidutils.generate_uuid()
        fake_host_routes = [{"destination": "192.168.2.0/24",
                             "nexthop": "192.168.1.1"}]

        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id,
            docker_endpoint_id="fake_id",
            subnet_v4_id=fake_v4_subnet_id,
            host_routes=fake_host_routes)
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id,
            docker_endpoint_id="fake_id",
            subnet_v6_id=fake_v6_subnet_id)

        fake_existing_subnets_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v6_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_existing_subnets_response

        fake_docker_net_id = lib_utils.get_hash()
        if mock_app.tag:
            t = utils.make_net_tags(fake_docker_net_id)

        fake_neutron_existing_network_response = {
            'networks':
            [
                {
                    "status": "ACTIVE",
                    "subnets": fake_existing_subnets_response["subnets"],
                    "admin_state_up": True,
                    "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                    "router:external": False,
                    "segments": [],
                    "shared": False,
                    "id": fake_neutron_net_id
                }
            ]
        }
        mock_list_networks.return_value = (
            fake_neutron_existing_network_response)

        fake_iface_name = 'fake-name'
        mock_get_container_iface_name.return_value = fake_iface_name

        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_container_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_DOWN,
            fake_v4_subnet_id, fake_v6_subnet_id)
        mock_list_ports.return_value = fake_neutron_ports_response

        join_request = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
            'SandboxKey': utils.get_sandbox_key(fake_container_id),
            'Options': {},
        }
        response = self.app.post('/NetworkDriver.Join',
                                 content_type='application/json',
                                 data=jsonutils.dumps(join_request))

        expected_response = {
            'Gateway': fake_v4_subnet['subnet']['gateway_ip'],
            'GatewayIPv6': fake_v6_subnet['subnet']['gateway_ip'],
            'InterfaceName': {
                'DstPrefix': config.CONF.binding.veth_dst_prefix,
                'SrcName': fake_iface_name,
            },
            'StaticRoutes': [
                {'NextHop':
                 fake_v4_subnet['subnet']['host_routes'][0]['nexthop'],
                 'Destination':
                 fake_v4_subnet['subnet']['host_routes'][0]['destination'],
                 'RouteType': constants.ROUTE_TYPE['NEXTHOP']}],
            'DisableGatewayService': True
        }

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        if mock_app.tag:
            mock_list_networks.assert_any_call(tags=t)
        else:
            mock_list_networks.assert_any_call(name=fake_docker_net_id)

        mock_get_container_iface_name.assert_called_with(
            fake_neutron_ports_response['ports'][0])
        if mock_app.tag:
            port_tags = utils.make_port_tags(fake_docker_endpoint_id)
            mock_list_ports.assert_called_with(tags=port_tags)
        else:
            port_name = utils.get_neutron_port_name(fake_docker_endpoint_id)
            mock_list_ports.assert_called_once_with(name=port_name)
        mock_list_subnets.assert_called_with(network_id=fake_neutron_net_id)
        self.assertEqual(expected_response, decoded_json)

    def test_network_driver_leave(self):
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()
        leave_request = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
        }
        response = self.app.post('/NetworkDriver.Leave',
                                 content_type='application/json',
                                 data=jsonutils.dumps(leave_request))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    def test_network_driver_allocate_network(self):
        docker_network_id = lib_utils.get_hash()
        allocate_network_request = {
            'NetworkID': docker_network_id,
            'IPv4Data': [{
                'AddressSpace': 'foo',
                'Pool': '192.168.42.0/24',
                'Gateway': '192.168.42.1/24',
            }],
            'IPv6Data': [],
            'Options': {}
        }

        response = self.app.post('/NetworkDriver.AllocateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(
                                     allocate_network_request))
        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual({'Options': {}}, decoded_json)

    def test_network_driver_free_network(self):
        docker_network_id = lib_utils.get_hash()
        free_network_request = {'NetworkID': docker_network_id}

        response = self.app.post('/NetworkDriver.FreeNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(free_network_request))
        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)
