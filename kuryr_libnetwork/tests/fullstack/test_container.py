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

from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.tests.fullstack import kuryr_base
from kuryr_libnetwork import utils


class ContainerTest(kuryr_base.KuryrBaseTest):
    """Test Container related operations

    Test container connect/disconnect from docker to Neutron
    """
    def setUp(self):
        super(ContainerTest, self).setUp()

        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.3.0.0/16",
                    "IPRange": "10.3.0.0/24",
                    "Gateway": "10.3.0.1"
                }
            ]
        }
        net_name = lib_utils.get_random_string(8)
        res = self.docker_client.create_network(name=net_name,
                                                driver='kuryr',
                                                ipam=fake_ipam)
        self.net_id = res.get('Id')

        try:
            networks = self.neutron_client.list_networks(
                tags=utils.make_net_tags(self.net_id))
        except Exception as e:
            self.docker_client.remove_network(self.net_id)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])
        self.assertEqual(1, len(networks['networks']))
        self.neutron_net_id = networks['networks'][0]['id']

    def tearDown(self):
        self.docker_client.remove_network(self.net_id)
        networks = self.neutron_client.list_networks(
            tags=utils.make_net_tags(self.net_id))
        self.assertEqual(0, len(networks['networks']))
        super(ContainerTest, self).tearDown()

    def test_connect_disconnect_container(self):
        # Test if support connect/disconnect operations
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
                                                        self.net_id)
        try:
            ports = self.neutron_client.list_ports(
                network_id=self.neutron_net_id)
        except Exception as e:
            self.docker_client.disconnect_container_from_network(
                container_id,
                self.net_id)
            message = ("Failed to list neutron ports: %s")
            self.fail(message % e.args[0])
        # A dhcp port gets created as well; dhcp is enabled by default
        self.assertEqual(2, len(ports['ports']))
        self.docker_client.disconnect_container_from_network(container_id,
                                                             self.net_id)
        ports = self.neutron_client.list_ports(
            network_id=self.neutron_net_id)
        self.assertEqual(1, len(ports['ports']))
        self.docker_client.stop(container=container_id)

        # TODO(banix) Stopping the container is enough for the
        # container to get disconnected from the network. Therefore,
        # the following is not necessary for this test. The problem
        # with removing container is not related to the networking
        # but we should find out how the container can be removed.
        # self.docker_client.remove_container(container=container_id,
        #                                     force=True)
