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
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import constants as const
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


@ddt.ddt
class TestKuryrNetworkPreExisting(base.TestKuryrBase):

    def _ids(self):
        docker_network_id = lib_utils.get_hash()
        fake_neutron_net_id = "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
        fake_response = {
            'networks':
            [
                {
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
            ]
        }
        return docker_network_id, fake_neutron_net_id, fake_response

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (True), (False))
    def test_create_network_pre_existing(self, use_tags,
            mock_tag, mock_list_subnetpools, mock_list_networks,
            mock_add_tag, mock_update_network,
            mock_list_subnets, mock_create_subnet):
        if not use_tags:
            mock_tag.tag = use_tags

        docker_network_id, fake_neutron_net_id, fake_response = self._ids()
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()

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
                const.NETWORK_GENERIC_OPTIONS: {
                    const.NEUTRON_UUID_OPTION: fake_neutron_net_id
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
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]
        mock_list_networks.return_value = fake_response

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'
        mock_list_subnets.return_value = fake_existing_subnets_response

        fake_v4_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v4),
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': mock_tag.enable_dhcp,
                'gateway_ip': '192.168.42.1',
                'subnetpool_id': fake_kuryr_v4_subnetpool_id
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id,
            fake_kuryr_subnetpool_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)
        fake_cidr_v6 = 'fe80::/64'
        fake_v6_subnet_request = {
            "subnets": [{
                'name': utils.make_subnet_name(fake_cidr_v6),
                'network_id': fake_neutron_net_id,
                'ip_version': 6,
                'cidr': fake_cidr_v6,
                'enable_dhcp': mock_tag.enable_dhcp,
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

        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_networks.assert_called_with(id=fake_neutron_net_id)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)
        mock_create_subnet.assert_any_call(fake_v4_subnet_request)
        mock_create_subnet.assert_any_call(fake_v6_subnet_request)
        if mock_tag.tag:
            tags = utils.create_net_tags(docker_network_id)
            for tag in tags:
                mock_add_tag.assert_any_call('networks',
                    fake_neutron_net_id, tag)
            mock_add_tag.assert_any_call('networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
        else:
            mock_update_network.assert_called_with(
                fake_neutron_net_id, {'network':
                {'name': docker_network_id}})

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_extension')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True), (False))
    def test_create_network_and_subnet_pre_existing_add_tag_for_subnet(
            self, use_tags, mock_tag, mock_show_extension,
            mock_list_subnetpools, mock_list_networks,
            mock_add_tag, mock_update_network,
            mock_list_subnets):
        if use_tags:
            mock_tag.tag = use_tags

        fake_tag_extension = {
            "extension":
            {"alias": "tag", "updated": "mock_time",
             "name": "Tag support", "links": [],
             "description": "mock tag on resources ['subnet', 'network']."}}
        mock_show_extension.return_value = fake_tag_extension

        docker_network_id, fake_neutron_net_id, fake_response = self._ids()

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
                const.NETWORK_GENERIC_OPTIONS: {
                    const.NEUTRON_UUID_OPTION: fake_neutron_net_id
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
        mock_list_subnetpools.side_effect = [
            {'subnetpools': kuryr_v4_subnetpools['subnetpools']},
            {'subnetpools': kuryr_v6_subnetpools['subnetpools']}
        ]

        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v6_id = uuidutils.generate_uuid()
        fake_cidr_v4 = '192.168.42.0/24'
        fake_cidr_v6 = 'fe80::/64'
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id,
            docker_endpoint_id="fake_id",
            subnet_v4_id=subnet_v4_id,
            subnetpool_id=fake_kuryr_v4_subnetpool_id,
            tag_subnetpool_id=False,
            cidr=fake_cidr_v4)
        fake_v6_subnet = self._get_fake_v6_subnet(
            fake_neutron_net_id,
            docker_endpoint_id="fake_id",
            subnet_v6_id=subnet_v6_id,
            subnetpool_id=fake_kuryr_v6_subnetpool_id,
            cidr=fake_cidr_v6)

        fake_existing_subnets_response = [
            {'subnets': [fake_v4_subnet['subnet']]},
            {'subnets': [fake_v6_subnet['subnet']]}
        ]

        mock_list_subnets.side_effect = fake_existing_subnets_response
        fake_response['networks'][0]['subnets'].append(subnet_v4_id)
        fake_response['networks'][0]['subnets'].append(subnet_v6_id)
        mock_list_networks.return_value = fake_response

        def mock_exception(*args, **kwargs):
            if 'subnet' not in kwargs['extension']['description']:
                return n_exceptions.NotFound

        mock_add_tag.side_effect = mock_exception(**fake_tag_extension)
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_any_call(name=fake_v4_pool_name)
        mock_list_subnetpools.assert_any_call(name=fake_v6_pool_name)
        mock_list_networks.assert_called_with(id=fake_neutron_net_id)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_list_subnets.assert_any_call(
            network_id=fake_neutron_net_id,
            cidr=fake_cidr_v6)

        if mock_tag.tag:
            tags = utils.create_net_tags(docker_network_id)
            for tag in tags:
                mock_add_tag.assert_any_call(
                    'networks', fake_neutron_net_id, tag)
            mock_add_tag.assert_any_call('networks', fake_neutron_net_id,
                utils.existing_net_tag(docker_network_id))
            mock_add_tag.assert_any_call('subnets',
                                         subnet_v4_id,
                                         fake_kuryr_v4_subnetpool_id)
            mock_add_tag.assert_any_call('subnets',
                                         subnet_v6_id,
                                         fake_kuryr_v6_subnetpool_id)
        else:
            mock_update_network.assert_called_with(
                fake_neutron_net_id, {'network':
                {'name': docker_network_id}})

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (True), (False))
    def test_delete_network_pre_existing_neutron_kuryr_subnets_pre_created(
            self, use_tags,
            mock_tag, mock_list_networks, mock_remove_tag,
            mock_delete_subnet, mock_delete_network, mock_list_subnets):
        if not use_tags:
            mock_tag.tag = use_tags

        docker_network_id, fake_neutron_net_id, _ = self._ids()
        # fake pre-existed kuryr subnet
        kuryr_subnet_v4_id = uuidutils.generate_uuid()
        kuryr_fake_cidr_v4 = '192.168.4.0/24'
        kuryr_fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id=kuryr_subnet_v4_id,
            subnetpool_id=uuidutils.generate_uuid(),
            cidr=kuryr_fake_cidr_v4,
            name=utils.make_subnet_name(kuryr_fake_cidr_v4))

        # fake pre-existed neutron subnet
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id=neutron_subnet_v4_id,
            name='fake_name')

        fake_existing_subnets_response = {
            "subnets": [
                kuryr_fake_v4_subnet['subnet'],
                neutron_fake_v4_subnet['subnet']
            ]
        }

        if mock_tag.tag:
            t = utils.make_net_tags(docker_network_id)
            te = t + ',' + utils.existing_net_tag(docker_network_id)
            tags = utils.create_net_tags(docker_network_id)
            tags += [utils.existing_net_tag(docker_network_id)]
        else:
            fake_existing_subnets_response = {
                "subnets": []
            }
            mock_delete_network.return_value = None

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
                    "id": fake_neutron_net_id,
                    "tags": tags if mock_tag.tag else [],
                }
            ]
        }

        mock_list_networks.return_value = (
            fake_neutron_existing_network_response)
        mock_list_subnets.return_value = fake_existing_subnets_response

        data = {'NetworkID': docker_network_id}
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        if mock_tag.tag:
            mock_list_networks.assert_any_call(tags=te)
            for tag in tags:
                mock_remove_tag.assert_any_call('networks',
                    fake_neutron_net_id, tag)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
            mock_delete_subnet.assert_called_once_with(kuryr_subnet_v4_id)
            self.assertEqual(1, mock_delete_subnet.call_count)
        else:
            mock_list_networks.assert_any_call(name=docker_network_id)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
            mock_delete_network.assert_called_with(fake_neutron_net_id)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (True), (False))
    def test_delete_network_pre_existing_neutron_subnets_pre_created(
            self, use_tags,
            mock_tag, mock_list_networks, mock_remove_tag,
            mock_delete_network, mock_list_subnets):
        if not use_tags:
            mock_tag.tag = use_tags

        docker_network_id, fake_neutron_net_id, _ = self._ids()

        # fake pre-existed neutron subnet
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id=neutron_subnet_v4_id,
            name='fake_name')

        fake_existing_subnets_response = {
            "subnets": [
                neutron_fake_v4_subnet['subnet']
            ]
        }

        if mock_tag.tag:
            t = utils.make_net_tags(docker_network_id)
            te = t + ',' + utils.existing_net_tag(docker_network_id)
            tags = utils.create_net_tags(docker_network_id)
            tags += [utils.existing_net_tag(docker_network_id)]
        else:
            fake_existing_subnets_response = {
                "subnets": []
            }
            mock_delete_network.return_value = None

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
                    "id": fake_neutron_net_id,
                    "tags": tags if mock_tag.tag else [],
                }
            ]
        }

        mock_list_networks.return_value = (
            fake_neutron_existing_network_response)
        mock_list_subnets.return_value = fake_existing_subnets_response

        data = {'NetworkID': docker_network_id}
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        if mock_tag.tag:
            mock_list_networks.assert_any_call(tags=te)
            for tag in tags:
                mock_remove_tag.assert_any_call('networks',
                    fake_neutron_net_id, tag)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
        else:
            mock_list_networks.assert_any_call(name=docker_network_id)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
            mock_delete_network.assert_called_with(fake_neutron_net_id)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (True), (False))
    def test_delete_network_pre_existing_kuryr_subnets_pre_created(
            self, use_tags,
            mock_tag, mock_list_networks, mock_remove_tag,
            mock_delete_subnet, mock_delete_network, mock_list_subnets):
        if not use_tags:
            mock_tag.tag = use_tags

        docker_network_id, fake_neutron_net_id, _ = self._ids()
        # fake pre-existed kuryr subnet
        kuryr_subnet_v4_id = uuidutils.generate_uuid()
        kuryr_fake_cidr_v4 = '192.168.4.0/24'
        kuryr_fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id=kuryr_subnet_v4_id,
            subnetpool_id=uuidutils.generate_uuid(),
            cidr=kuryr_fake_cidr_v4,
            name=utils.make_subnet_name(kuryr_fake_cidr_v4))

        fake_existing_subnets_response = {
            "subnets": [
                kuryr_fake_v4_subnet['subnet']
            ]
        }

        if mock_tag.tag:
            t = utils.make_net_tags(docker_network_id)
            te = t + ',' + utils.existing_net_tag(docker_network_id)
            tags = utils.create_net_tags(docker_network_id)
            tags += [utils.existing_net_tag(docker_network_id)]
        else:
            fake_existing_subnets_response = {
                "subnets": []
            }
            mock_delete_network.return_value = None

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
                    "id": fake_neutron_net_id,
                    "tags": tags if mock_tag.tag else [],
                }
            ]
        }

        mock_list_networks.return_value = (
            fake_neutron_existing_network_response)
        mock_list_subnets.return_value = fake_existing_subnets_response

        data = {'NetworkID': docker_network_id}
        response = self.app.post('/NetworkDriver.DeleteNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        if mock_tag.tag:
            mock_list_networks.assert_any_call(tags=te)
            for tag in tags:
                mock_remove_tag.assert_any_call('networks',
                    fake_neutron_net_id, tag)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
            mock_delete_subnet.assert_called_once_with(kuryr_subnet_v4_id)
        else:
            mock_list_networks.assert_any_call(name=docker_network_id)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
            mock_delete_network.assert_called_with(fake_neutron_net_id)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)
