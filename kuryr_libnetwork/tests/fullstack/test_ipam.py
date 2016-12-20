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

from kuryr.lib import constants as lib_const
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.tests.fullstack import kuryr_base
from kuryr_libnetwork import utils


class IpamTest(kuryr_base.KuryrBaseTest):
    """Test Container IPAM related operations

    Test container IPAM operations(request/release pool|address)
    """

    def test_container_ipam_release_address(self):
        # pre-created Neutron network and subnet
        neutron_net_name = lib_utils.get_random_string(8)
        neutron_network = self.neutron_client.create_network(
            {'network': {'name': neutron_net_name,
                         "admin_state_up": True}})
        neutron_subnet_name = lib_utils.get_random_string(8)
        subnet_param = [{
            'name': neutron_subnet_name,
            'network_id': neutron_network['network']['id'],
            'ip_version': 4,
            'cidr': "10.10.0.0/24",
            'enable_dhcp': True,
        }]
        self.neutron_client.create_subnet({'subnets': subnet_param})

        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.10.0.0/16",
                    "IPRange": "10.10.0.0/24",
                    "Gateway": "10.10.0.1"
                }
            ]
        }

        # Create docker network using existing Neutron network
        options = {'neutron.net.name': neutron_net_name}
        container_net_name = lib_utils.get_random_string(8)
        container_net = self.docker_client.create_network(
            name=container_net_name,
            driver='kuryr',
            options=options,
            ipam=fake_ipam)
        container_net_id = container_net.get('Id')
        try:
            networks = self.neutron_client.list_networks(
                tags=utils.make_net_tags(container_net_id))
        except Exception as e:
            self.docker_client.remove_network(container_net_id)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])
        self.assertEqual(1, len(networks['networks']))

        # Boot a container, and connect to the docker network.
        container_name = lib_utils.get_random_string(8)
        container = self.docker_client.create_container(
            image='kuryr/busybox',
            command='/bin/sleep 600',
            hostname='kuryr_test_container',
            name=container_name)
        warn_msg = container.get('Warning')
        container_id = container.get('Id')
        self.assertIsNone(warn_msg, 'Warn in creating container')
        self.assertIsNotNone(container_id, 'Create container id must not '
                                           'be None')
        self.docker_client.start(container=container_id)
        self.docker_client.connect_container_to_network(container_id,
                                                        container_net_id)
        try:
            ports = self.neutron_client.list_ports(
                network_id=neutron_network['network']['id'])
        except Exception as e:
            self.docker_client.disconnect_container_from_network(
                container_id,
                container_net_id)
            message = ("Failed to list neutron ports: %s")
            self.fail(message % e.args[0])

        # A dhcp port gets created as well; dhcp is enabled by default
        self.assertEqual(2, len(ports['ports']))
        # Find the kuryr port
        kuryr_port_param = {"network_id": neutron_network['network']['id'],
                            "device_owner": lib_const.DEVICE_OWNER}
        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        self.assertEqual(1, len(kuryr_ports['ports']))

        # Disconnect container from network, this release ip address.
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)
        ports = self.neutron_client.list_ports(
            network_id=neutron_network['network']['id'])
        self.assertEqual(1, len(ports['ports']))
        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        self.assertEqual(0, len(kuryr_ports['ports']))

        # Cleanup resources
        self.docker_client.stop(container=container_id)
        self.docker_client.remove_network(container_net_id)
        self.neutron_client.delete_network(neutron_network['network']['id'])
