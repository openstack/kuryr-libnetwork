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
from kuryr_libnetwork import constants as const
from kuryr_libnetwork.tests.fullstack import kuryr_base
from kuryr_libnetwork import utils


class IpamTest(kuryr_base.KuryrBaseTest):
    """Test Container IPAM related operations

    Test container IPAM operations(request/release pool|address)
    """

    def test_container_ipam_request_release_pool(self):
        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.11.0.0/16",
                    "IPRange": "10.11.0.0/24",
                    "Gateway": "10.11.0.1"
                }
            ]
        }

        container_net_name = lib_utils.get_random_string(8)
        container_net = self.docker_client.create_network(
            name=container_net_name,
            driver='kuryr',
            ipam=fake_ipam)
        container_net_id = container_net.get('Id')
        try:
            networks = self.neutron_client.list_networks(
                tags=utils.make_net_tags(container_net_id))
        except Exception as e:
            self.docker_client.remove_network(container_net_id)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])

        # Currently we cannot get IPAM pool from docker client.
        pool_name = "kuryrPool-" + "10.11.0.0/24"
        subnetpools = self.neutron_client.list_subnetpools(name=pool_name)
        self.assertEqual(1, len(subnetpools['subnetpools']))

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
            self.neutron_client.list_ports(
                network_id=networks['networks'][0]['id'])
        except Exception as e:
            self.docker_client.disconnect_container_from_network(
                container_id,
                container_net_id)
            message = ("Failed to list neutron ports: %s")
            self.fail(message % e.args[0])

        # Disconnect container from network, this release ip address.
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)

        # Delete docker network, if no endpoint, will release the pool
        # and delete the subnetpool in Neutron.
        self.docker_client.stop(container=container_id)
        self.docker_client.remove_network(container_net_id)
        subnetpools = self.neutron_client.list_subnetpools(name=pool_name)
        self.assertEqual(0, len(subnetpools['subnetpools']))

    def test_container_ipam_request_address(self):
        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.12.0.0/16",
                    "IPRange": "10.12.0.0/24",
                    "Gateway": "10.12.0.1"
                }
            ]
        }

        container_net_name = lib_utils.get_random_string(8)
        container_net = self.docker_client.create_network(
            name=container_net_name,
            driver='kuryr',
            ipam=fake_ipam)
        container_net_id = container_net.get('Id')
        try:
            networks = self.neutron_client.list_networks(
                tags=utils.make_net_tags(container_net_id))
        except Exception as e:
            self.docker_client.remove_network(container_net_id)
            message = ("Failed to list neutron networks: %s")
            self.fail(message % e.args[0])

        # Currently we cannot get IPAM pool from docker client.
        pool_name = "kuryrPool-" + "10.12.0.0/24"
        subnetpools = self.neutron_client.list_subnetpools(name=pool_name)
        self.assertEqual(1, len(subnetpools['subnetpools']))

        subnets = self.neutron_client.list_subnets(
            network_id=networks['networks'][0]['id'],
            cidr="10.12.0.0/24")
        self.assertEqual(1, len(subnets['subnets']))

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
                network_id=networks['networks'][0]['id'])
        except Exception as e:
            self.docker_client.disconnect_container_from_network(
                container_id,
                container_net_id)
            message = ("Failed to list neutron ports: %s")
            self.fail(message % e.args[0])

        # DHCP port and container endpoint
        self.assertEqual(2, len(ports['ports']))
        # Find the kuryr port
        kuryr_port_param = {"network_id": networks['networks'][0]['id']}
        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        kuryr_port = [port for port in kuryr_ports['ports'] if
                      (lib_const.DEVICE_OWNER in port['tags'] or
                       port['name'] ==
                       utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(1, len(kuryr_port))

        # Disconnect container from network, this release ip address.
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)
        # Cleanup resources
        self.docker_client.stop(container=container_id)
        self.docker_client.remove_network(container_net_id)

    def test_container_ipam_release_address(self):
        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.13.0.0/16",
                    "IPRange": "10.13.0.0/24",
                    "Gateway": "10.13.0.1"
                }
            ]
        }

        container_net_name = lib_utils.get_random_string(8)
        container_net = self.docker_client.create_network(
            name=container_net_name,
            driver='kuryr',
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
                network_id=networks['networks'][0]['id'])
        except Exception as e:
            self.docker_client.disconnect_container_from_network(
                container_id,
                container_net_id)
            message = ("Failed to list neutron ports: %s")
            self.fail(message % e.args[0])

        # A dhcp port gets created as well; dhcp is enabled by default
        self.assertEqual(2, len(ports['ports']))
        # Find the kuryr port
        kuryr_port_param = {"network_id": networks['networks'][0]['id']}
        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        kuryr_port = [port for port in kuryr_ports['ports'] if
                      (lib_const.DEVICE_OWNER in port['tags'] or
                       port['name'] ==
                       utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(1, len(kuryr_port))

        # Disconnect container from network, this release ip address.
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)
        ports = self.neutron_client.list_ports(
            network_id=networks['networks'][0]['id'])
        # DHCP port leave behind.
        self.assertEqual(1, len(ports['ports']))

        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        kuryr_port = [port for port in kuryr_ports['ports'] if
                      (lib_const.DEVICE_OWNER in port['tags'] or
                       port['name'] ==
                       utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(0, len(kuryr_port))

        # Cleanup resources
        self.docker_client.stop(container=container_id)
        self.docker_client.remove_network(container_net_id)

    def test_container_ipam_release_address_with_existing_network(self):
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
        kuryr_port_param = {"network_id": neutron_network['network']['id']}
        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        kuryr_port = [port for port in kuryr_ports['ports'] if
                      (lib_const.DEVICE_OWNER in port['tags'] or
                       port['name'] ==
                       utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(1, len(kuryr_port))
        # Disconnect container from network, this release ip address.
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)
        ports = self.neutron_client.list_ports(
            network_id=neutron_network['network']['id'])
        self.assertEqual(1, len(ports['ports']))
        kuryr_ports = self.neutron_client.list_ports(
            **kuryr_port_param)
        kuryr_port = [port for port in kuryr_ports['ports'] if
                      (lib_const.DEVICE_OWNER in port['tags'] or
                       port['name'] ==
                       utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(0, len(kuryr_port))

        # Cleanup resources
        self.docker_client.stop(container=container_id)
        self.docker_client.remove_network(container_net_id)
        self.neutron_client.delete_network(neutron_network['network']['id'])

    def test_container_ipam_request_address_with_existing_port(self):
        # pre-created Neutron network and subnet and port
        neutron_net_name = lib_utils.get_random_string(8)
        neutron_network = self.neutron_client.create_network(
            {'network': {'name': neutron_net_name,
                         "admin_state_up": True}})
        neutron_subnet_name = lib_utils.get_random_string(8)
        subnet_param = [{
            'name': neutron_subnet_name,
            'network_id': neutron_network['network']['id'],
            'ip_version': 4,
            'cidr': "10.14.0.0/24",
        }]
        neutron_subnet = self.neutron_client.create_subnet(
            {'subnets': subnet_param})
        neutron_v6_subnet_name = lib_utils.get_random_string(8)
        v6_subnet_param = [{
            'name': neutron_v6_subnet_name,
            'network_id': neutron_network['network']['id'],
            'ip_version': 6,
            'cidr': "fe81::/64",
        }]
        neutron_v6_subnet = self.neutron_client.create_subnet(
            {'subnets': v6_subnet_param})
        existing_neutron_port = self.neutron_client.create_port(
            {'port': {'network_id': neutron_network['network']['id']}})
        fixed_ips = {fip['subnet_id']: fip['ip_address']
                     for fip in existing_neutron_port['port']['fixed_ips']}
        ipv4_address = fixed_ips[neutron_subnet['subnets'][0]['id']]
        ipv6_address = fixed_ips[neutron_v6_subnet['subnets'][0]['id']]

        fake_ipam = {
            "Driver": "kuryr",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.14.0.0/24",
                    "Gateway": "10.14.0.1"
                },
                {
                    "Subnet": "fe81::/64",
                    "Gateway": "fe81::1"
                },
            ]
        }

        # Create docker network using existing Neutron network
        options = {'neutron.net.name': neutron_net_name}
        container_net_name = lib_utils.get_random_string(8)
        container_net = self.docker_client.create_network(
            name=container_net_name,
            driver='kuryr',
            enable_ipv6=True,
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
        self.docker_client.connect_container_to_network(
            container_id, container_net_id, ipv4_address=ipv4_address,
            ipv6_address=ipv6_address)
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
        # Find the existing neutron port
        neutron_port_param = {"network_id": neutron_network['network']['id']}
        neutron_ports = self.neutron_client.list_ports(
            **neutron_port_param)
        neutron_port = [port for port in neutron_ports['ports'] if
                        (const.KURYR_EXISTING_NEUTRON_PORT in port['tags'] or
                         port['name'] ==
                         utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(1, len(neutron_port))
        # Disconnect container from network.
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)
        ports = self.neutron_client.list_ports(
            network_id=neutron_network['network']['id'])
        self.assertEqual(2, len(ports['ports']))
        neutron_ports = self.neutron_client.list_ports(
            **neutron_port_param)
        neutron_port = [port for port in neutron_ports['ports'] if
                        (const.KURYR_EXISTING_NEUTRON_PORT in port['tags'] or
                         port['name'] ==
                         utils.get_neutron_port_name(port['device_id']))]
        self.assertEqual(0, len(neutron_port))

        # Cleanup resources
        self.docker_client.stop(container=container_id)
        self.docker_client.remove_network(container_net_id)
        self.neutron_client.delete_port(existing_neutron_port['port']['id'])
        self.neutron_client.delete_subnet(neutron_subnet['subnets'][0]['id'])
        self.neutron_client.delete_subnet(
            neutron_v6_subnet['subnets'][0]['id'])
        self.neutron_client.delete_network(neutron_network['network']['id'])

    def test_container_ipam_release_address_with_existing_port_same_ip(self):
        ipv4_address = "10.15.0.10"

        # pre-created the first Neutron network and subnet and port
        neutron_net_name = lib_utils.get_random_string(8)
        neutron_network = self.neutron_client.create_network(
            {'network': {'name': neutron_net_name,
                         "admin_state_up": True}})
        neutron_subnet_name = lib_utils.get_random_string(8)
        subnet_param = [{
            'name': neutron_subnet_name,
            'network_id': neutron_network['network']['id'],
            'ip_version': 4,
            'cidr': "10.15.0.0/24",
        }]
        neutron_subnet = self.neutron_client.create_subnet(
            {'subnets': subnet_param})
        existing_neutron_port = self.neutron_client.create_port(
            {'port': {'network_id': neutron_network['network']['id'],
                      'fixed_ips': [{'ip_address': ipv4_address}]}})
        fake_ipam = {
            "Driver": "kuryr",
            "Options": {
                'neutron.subnet.name': neutron_subnet_name
            },
            "Config": [
                {
                    "Subnet": "10.15.0.0/24",
                    "Gateway": "10.15.0.1"
                }
            ]
        }
        # Create docker network using existing Neutron network
        options = {'neutron.net.name': neutron_net_name,
                   'neutron.subnet.name': neutron_subnet_name}
        container_net_name = lib_utils.get_random_string(8)
        container_net = self.docker_client.create_network(
            name=container_net_name,
            driver='kuryr',
            options=options,
            ipam=fake_ipam)
        container_net_id = container_net.get('Id')

        # pre-created the second Neutron network and subnet and port
        neutron_net_name2 = lib_utils.get_random_string(8)
        neutron_network2 = self.neutron_client.create_network(
            {'network': {'name': neutron_net_name2,
                         "admin_state_up": True}})
        neutron_subnet_name2 = lib_utils.get_random_string(8)
        subnet_param2 = [{
            'name': neutron_subnet_name2,
            'network_id': neutron_network2['network']['id'],
            'ip_version': 4,
            'cidr': "10.15.0.0/24",
        }]
        neutron_subnet2 = self.neutron_client.create_subnet(
            {'subnets': subnet_param2})
        existing_neutron_port2 = self.neutron_client.create_port(
            {'port': {'network_id': neutron_network2['network']['id'],
                      'fixed_ips': [{'ip_address': ipv4_address}]}})
        fake_ipam2 = {
            "Driver": "kuryr",
            "Options": {
                'neutron.subnet.name': neutron_subnet_name2
            },
            "Config": [
                {
                    "Subnet": "10.15.0.0/24",
                    "Gateway": "10.15.0.1"
                }
            ]
        }
        # Create docker network using existing Neutron network
        options = {'neutron.net.name': neutron_net_name2,
                   'neutron.subnet.name': neutron_subnet_name2}
        container_net_name2 = lib_utils.get_random_string(8)
        container_net2 = self.docker_client.create_network(
            name=container_net_name2,
            driver='kuryr',
            options=options,
            ipam=fake_ipam2)
        container_net_id2 = container_net2.get('Id')

        # Boot the first container, and connect to the first docker network.
        endpoint_config = self.docker_client.create_endpoint_config(
            ipv4_address=ipv4_address)
        network_config = self.docker_client.create_networking_config({
            container_net_id: endpoint_config})
        container_name = lib_utils.get_random_string(8)
        container = self.docker_client.create_container(
            image='kuryr/busybox',
            command='/bin/sleep 600',
            hostname='kuryr_test_container',
            name=container_name,
            networking_config=network_config)
        container_id = container.get('Id')
        self.docker_client.start(container=container_id)

        # Boot the second container, and connect to the second docker network.
        endpoint_config = self.docker_client.create_endpoint_config(
            ipv4_address=ipv4_address)
        network_config = self.docker_client.create_networking_config({
            container_net_id2: endpoint_config})
        container_name2 = lib_utils.get_random_string(8)
        container2 = self.docker_client.create_container(
            image='kuryr/busybox',
            command='/bin/sleep 600',
            hostname='kuryr_test_container2',
            name=container_name2,
            networking_config=network_config)
        container_id2 = container2.get('Id')
        self.docker_client.start(container=container_id2)

        # Assert both existing neutron ports active
        for port_id in (existing_neutron_port['port']['id'],
                        existing_neutron_port2['port']['id']):
            utils.wait_for_port_active(
                self.neutron_client, port_id, 60)
            neutron_port = self.neutron_client.show_port(port_id)
            self.assertEqual('ACTIVE', neutron_port['port']['status'])

        # Disconnect the first container from network and
        # assert the first neutron port is down and the second is still active
        self.docker_client.disconnect_container_from_network(container_id,
                                                             container_net_id)
        existing_neutron_port = self.neutron_client.show_port(
            existing_neutron_port['port']['id'])
        self.assertEqual('DOWN', existing_neutron_port['port']['status'])
        existing_neutron_port2 = self.neutron_client.show_port(
            existing_neutron_port2['port']['id'])
        self.assertEqual('ACTIVE', existing_neutron_port2['port']['status'])

        # Disconnect the second container from network and
        # assert both neutron ports are down.
        self.docker_client.disconnect_container_from_network(container_id2,
                                                             container_net_id2)
        for port_id in (existing_neutron_port['port']['id'],
                        existing_neutron_port2['port']['id']):
            neutron_port = self.neutron_client.show_port(port_id)
            self.assertEqual('DOWN', neutron_port['port']['status'])

        # Cleanup resources
        self.docker_client.stop(container=container_id)
        self.docker_client.stop(container=container_id2)
        self.docker_client.remove_network(container_net_id)
        self.docker_client.remove_network(container_net_id2)
        self.neutron_client.delete_port(existing_neutron_port['port']['id'])
        self.neutron_client.delete_port(existing_neutron_port2['port']['id'])
        self.neutron_client.delete_subnet(neutron_subnet['subnets'][0]['id'])
        self.neutron_client.delete_subnet(neutron_subnet2['subnets'][0]['id'])
        self.neutron_client.delete_network(neutron_network['network']['id'])
        self.neutron_client.delete_network(neutron_network2['network']['id'])
