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
from kuryr_libnetwork import constants
from kuryr_libnetwork.tests.fullstack import kuryr_base
from kuryr_libnetwork import utils


class NetworkTest(kuryr_base.KuryrBaseTest):
    """Test Networks operation

    Test networks creation/deletion from docker to Neutron
    """
    def test_create_delete_network_with_kuryr_driver(self):
        """Create and Delete docker network with Kuryr

           This method creates a docker network with Kuryr driver
           and tests it was created in Neutron.
           It then deletes the docker network and tests that it was
           deleted from Neutron.
        """
        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.0.0.0/16",
                    "IPRange": "10.0.0.0/24",
                    "Gateway": "10.0.0.1"
                }
            ]
        }
        net_name = lib_utils.get_random_string(8)
        res = self.docker_client.create_network(name=net_name, driver='kuryr',
                                                ipam=fake_ipam)
        net_id = res['Id']
        try:
            network = self.neutron_client.list_networks(
                tags=utils.make_net_tags(net_id))
        except Exception as e:
            self.docker_client.remove_network(net_id)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])
        self.assertEqual(1, len(network['networks']))
        self.docker_client.remove_network(net_id)
        network = self.neutron_client.list_networks(
            tags=utils.make_net_tags(net_id))
        self.assertEqual(0, len(network['networks']))

    def test_create_delete_dualstack_network_with_kuryr_driver(self):
        """Create and Delete docker dual-stack network with Kuryr

           This method creates a docker network with Kuryr driver
           and tests it was created in Neutron.
           It then deletes the docker network and tests that it was
           deleted from Neutron.
        """
        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.4.0.0/16",
                    "IPRange": "10.4.0.0/24",
                    "Gateway": "10.4.0.1"
                },
                {
                    "Subnet": "2001:db8:a0b:12f0::/64",
                    "IPRange": "2001:db8:a0b:12f0::/64",
                    "Gateway": "2001:db8:a0b:12f0::1"
                }
            ]
        }
        net_name = lib_utils.get_random_string(8)
        res = self.docker_client.create_network(name=net_name,
                                                driver='kuryr',
                                                enable_ipv6=True,
                                                ipam=fake_ipam)
        net_id = res['Id']
        try:
            network = self.neutron_client.list_networks(
                tags=utils.make_net_tags(net_id))
        except Exception as e:
            self.docker_client.remove_network(net_id)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])
        self.assertEqual(1, len(network['networks']))
        neutron_netid = network['networks'][0]['id']
        subnets = self.neutron_client.list_subnets(
            network_id=neutron_netid)
        self.assertEqual(2, len(subnets['subnets']))
        subnet_version = []
        subnet_name = []
        for subnet in subnets['subnets']:
            subnet_version.append(subnet['ip_version'])
            subnet_name.append(subnet['name'])
        self.assertIn(4, subnet_version)
        self.assertIn(6, subnet_version)
        self.assertIn(
            constants.SUBNET_NAME_PREFIX + '10.4.0.0/24',
            subnet_name)
        self.assertIn(
            constants.SUBNET_NAME_PREFIX + '2001:db8:a0b:12f0::/64',
            subnet_name)
        self.docker_client.remove_network(net_id)
        network = self.neutron_client.list_networks(
            tags=utils.make_net_tags(net_id))
        self.assertEqual(0, len(network['networks']))
        subnets = self.neutron_client.list_subnets(
            network_id=neutron_netid)
        self.assertEqual(0, len(subnets['subnets']))

    def test_create_delete_network_without_kuryr_driver(self):
        """Create and Delete docker network without Kuryr

           This method create a docker network with the default
           docker driver, It tests that it was created correctly, but
           not added to Neutron
        """
        net_name = lib_utils.get_random_string(8)
        res = self.docker_client.create_network(name=net_name)
        net_id = res['Id']
        network = self.neutron_client.list_networks(
            tags=utils.make_net_tags(net_id))
        self.assertEqual(0, len(network['networks']))
        docker_networks = self.docker_client.networks()
        network_found = False
        for docker_net in docker_networks:
            if docker_net['Id'] == net_id:
                network_found = True
        self.assertTrue(network_found)
        self.docker_client.remove_network(net_id)

    def test_create_network_with_same_name(self):
        """Create docker network with same name

           Create two docker networks with same name,
           delete them and see that neutron networks are
           deleted as well
        """
        fake_ipam_1 = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.1.0.0/16",
                    "IPRange": "10.1.0.0/24",
                    "Gateway": "10.1.0.1"
                }
            ]
        }
        fake_ipam_2 = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.2.0.0/16",
                    "IPRange": "10.2.0.0/24",
                    "Gateway": "10.2.0.1"
                }
            ]
        }
        net_name = lib_utils.get_random_string(8)
        res = self.docker_client.create_network(name=net_name, driver='kuryr',
                                                ipam=fake_ipam_1)
        net_id1 = res['Id']

        res = self.docker_client.create_network(name=net_name, driver='kuryr',
                                                ipam=fake_ipam_2)
        net_id2 = res['Id']
        try:
            network = self.neutron_client.list_networks(
                tags=utils.make_net_tags(net_id1))
            self.assertEqual(1, len(network['networks']))
            network = self.neutron_client.list_networks(
                tags=utils.make_net_tags(net_id2))
            self.assertEqual(1, len(network['networks']))
        except Exception as e:
            self.docker_client.remove_network(net_id1)
            self.docker_client.remove_network(net_id2)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])
        self.docker_client.remove_network(net_id1)
        self.docker_client.remove_network(net_id2)
        network = self.neutron_client.list_networks(
            tags=utils.make_net_tags(net_id1))
        self.assertEqual(0, len(network['networks']))
        network = self.neutron_client.list_networks(
            tags=utils.make_net_tags(net_id2))
        self.assertEqual(0, len(network['networks']))
