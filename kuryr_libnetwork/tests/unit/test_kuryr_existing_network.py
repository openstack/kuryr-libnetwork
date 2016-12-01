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
                    "id": fake_neutron_net_id
                }
            ]
        }
        return docker_network_id, fake_neutron_net_id, fake_response

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnet')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (True), (False))
    def test_create_network_pre_existing(self, use_tags,
            mock_tag, mock_list_networks, mock_add_tag,
            mock_update_network, mock_list_subnets,
            mock_create_subnet):
        if not use_tags:
            mock_tag.tag = use_tags

        docker_network_id, fake_neutron_net_id, fake_response = self._ids()

        mock_list_networks.return_value = fake_response

        fake_existing_subnets_response = {
            "subnets": []
        }
        fake_cidr_v4 = '192.168.42.0/24'
        mock_list_subnets.return_value = fake_existing_subnets_response

        fake_subnet_request = {
            "subnets": [{
                'name': fake_cidr_v4,
                'network_id': fake_neutron_net_id,
                'ip_version': 4,
                'cidr': fake_cidr_v4,
                'enable_dhcp': mock_tag.enable_dhcp,
                'gateway_ip': '192.168.42.1',
            }]
        }
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            fake_neutron_net_id, subnet_v4_id,
            name=fake_cidr_v4, cidr=fake_cidr_v4)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_create_subnet.return_value = fake_subnet_response

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
        response = self.app.post('/NetworkDriver.CreateNetwork',
                                 content_type='application/json',
                                 data=jsonutils.dumps(network_request))

        self.assertEqual(200, response.status_code)
        mock_list_networks.assert_called_with(id=fake_neutron_net_id)
        mock_list_subnets.assert_called_with(
            network_id=fake_neutron_net_id,
            cidr=fake_cidr_v4)
        mock_create_subnet.assert_called_with(fake_subnet_request)
        if mock_tag.tag:
            tags = utils.create_net_tags(docker_network_id)
            for tag in tags:
                mock_add_tag.assert_any_call('networks',
                    fake_neutron_net_id, tag)
            mock_add_tag.assert_any_call('networks', fake_neutron_net_id,
                const.KURYR_EXISTING_NEUTRON_NET)
        else:
            mock_update_network.assert_called_with(
                fake_neutron_net_id, {'network':
                {'name': docker_network_id}})

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_network')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data(
        (True), (False))
    def test_delete_network_pre_existing(self, use_tags,
            mock_tag, mock_list_networks, mock_remove_tag,
            mock_delete_network, mock_list_subnets):
        if not use_tags:
            mock_tag.tag = use_tags

        docker_network_id, fake_neutron_net_id, fake_response = self._ids()
        mock_list_networks.return_value = fake_response

        if mock_tag.tag:
            t = utils.make_net_tags(docker_network_id)
            te = t + ',' + const.KURYR_EXISTING_NEUTRON_NET
            tags = utils.create_net_tags(docker_network_id)
        else:
            fake_existing_subnets_response = {
                "subnets": []
            }
            mock_list_subnets.return_value = fake_existing_subnets_response
            mock_delete_network.return_value = None

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
            mock_remove_tag.assert_any_call('networks',
                fake_neutron_net_id, const.KURYR_EXISTING_NEUTRON_NET)
        else:
            mock_list_networks.assert_any_call(name=docker_network_id)
            mock_list_subnets.assert_called_with(
                network_id=fake_neutron_net_id)
            mock_delete_network.assert_called_with(fake_neutron_net_id)

        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(const.SCHEMA['SUCCESS'], decoded_json)
