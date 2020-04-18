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

from oslo_utils import uuidutils

from kuryr.lib import binding
from kuryr.lib.binding.drivers import utils
from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.port_driver.drivers import nested
from kuryr_libnetwork.tests.unit import base

mock_interface = mock.MagicMock()


class TestNestedDriver(base.TestKuryrBase):
    """Unit tests for the NestedDriver port driver"""

    def test_get_supported_bindings(self):
        nested_driver = nested.NestedDriver()
        bindings = nested_driver.get_supported_bindings()
        self.assertEqual(bindings, nested.NestedDriver.BINDING_DRIVERS)

    @mock.patch('kuryr_libnetwork.config.CONF')
    @mock.patch.object(nested.NestedDriver, '_get_port_from_host_iface')
    def test_get_default_network_id(self, mock_get_port_from_host, mock_conf):
        mock_conf.binding.link_iface = 'eth0'

        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()

        fake_vm_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)['port']
        mock_get_port_from_host.return_value = fake_vm_port

        nested_driver = nested.NestedDriver()
        host_network_id = nested_driver.get_default_network_id()
        mock_get_port_from_host.assert_called_with('eth0')
        self.assertEqual(host_network_id, fake_vm_port['network_id'])

    @mock.patch('kuryr_libnetwork.config.CONF')
    @mock.patch.object(binding, 'port_bind')
    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(nested.NestedDriver, '_get_port_from_host_iface')
    def test_create_host_iface(
            self, mock_get_port_from_host,
            mock_update_port, mock_port_bind, mock_conf):
        mock_conf.binding.link_iface = 'eth0'

        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_vm_port_id = uuidutils.generate_uuid()

        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9')['port']
        fake_neutron_port['mac_address'] = 'fa:16:3e:20:57:c3'
        fake_vm_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_vm_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.2', 'fe80::f816:3eff:fe20:57c4')['port']
        fake_vm_port['allowed_address_pairs'] = [
            {'ip_address': '192.168.1.2',
             'mac_address': fake_vm_port['mac_address']},
            {'ip_address': 'fe80::f816:3eff:fe20:57c4',
             'mac_address': fake_vm_port['mac_address']}]
        updated_allowed_pairs = fake_vm_port['allowed_address_pairs']
        updated_allowed_pairs.extend([
            {'ip_address': '192.168.1.3',
             'mac_address': fake_neutron_port['mac_address']},
            {'ip_address': 'fe80::f816:3eff:fe1c:36a9',
             'mac_address': fake_neutron_port['mac_address']}])

        fake_subnets = self._get_fake_subnets(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)['subnets']

        fake_network = mock.sentinel.binding_network
        fake_exec_response = ('fake_stdout', '')
        mock_port_bind.return_value = ('fake_host_ifname',
            'fake_container_ifname', fake_exec_response)
        mock_get_port_from_host.return_value = fake_vm_port

        nested_driver = nested.NestedDriver()
        response = nested_driver.create_host_iface(fake_endpoint_id,
            fake_neutron_port, fake_subnets, fake_network)

        mock_get_port_from_host.assert_called_with('eth0')
        mock_port_bind.assert_called_with(fake_endpoint_id,
            fake_neutron_port, fake_subnets, fake_network, fake_vm_port)
        mock_update_port.assert_called_with(
            fake_vm_port['id'],
            {'port': {
                'allowed_address_pairs': updated_allowed_pairs
            }})

        self.assertEqual(response, fake_exec_response)

    @mock.patch('kuryr_libnetwork.config.CONF')
    @mock.patch.object(binding, 'port_unbind')
    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(nested.NestedDriver, '_get_port_from_host_iface')
    def test_delete_host_iface(
            self, mock_get_port_from_host,
            mock_update_port, mock_port_unbind, mock_conf):
        mock_conf.binding.link_iface = 'eth0'

        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_vm_port_id = uuidutils.generate_uuid()

        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id, fake_neutron_port_id,
            lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9')['port']
        fake_neutron_port['mac_address'] = 'fa:16:3e:20:57:c3'
        fake_vm_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_vm_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.2', 'fe80::f816:3eff:fe20:57c4')['port']
        fake_vm_port['allowed_address_pairs'] = [
            {'ip_address': '192.168.1.3',
             'mac_address': fake_neutron_port['mac_address']},
            {'ip_address': 'fe80::f816:3eff:fe1c:36a9',
             'mac_address': fake_neutron_port['mac_address']}]
        updated_allowed_pairs = [
            {'ip_address': '192.168.1.2',
             'mac_address': fake_vm_port['mac_address']},
            {'ip_address': 'fe80::f816:3eff:fe20:57c4',
             'mac_address': fake_vm_port['mac_address']}]
        fake_vm_port['allowed_address_pairs'].extend(updated_allowed_pairs)

        fake_unbind_response = ('fake_stdout', '')
        mock_get_port_from_host.return_value = fake_vm_port
        mock_port_unbind.return_value = fake_unbind_response

        nested_driver = nested.NestedDriver()
        response = nested_driver.delete_host_iface(fake_endpoint_id,
                                                   fake_neutron_port)

        mock_get_port_from_host.assert_called_with('eth0')
        mock_update_port.assert_called_with(
            fake_vm_port['id'],
            {'port': {
                'allowed_address_pairs': updated_allowed_pairs
            }})
        mock_port_unbind.assert_called_with(fake_endpoint_id,
                                            fake_neutron_port)

        self.assertEqual(response, fake_unbind_response)

    @mock.patch.object(utils, 'get_veth_pair_names',
        return_value=("fake_host_ifname", "fake_container_name"))
    def test_get_container_iface_name(self, mock_get_pair_names):
        nested_driver = nested.NestedDriver()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            uuidutils.generate_uuid(), uuidutils.generate_uuid(),
            fake_neutron_port_id)['port']
        response = nested_driver.get_container_iface_name(fake_neutron_port)
        mock_get_pair_names.assert_called_with(fake_neutron_port_id)
        self.assertEqual(response, "fake_container_name")


class TestNestedDriverFailures(base.TestKuryrFailures):
    """Unit tests for the NestedDriver port driver failures"""

    @mock.patch.object(nested.NestedDriver, '_get_port_from_host_iface')
    def test_create_host_iface(self, mock_get_port_from_host):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()

        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE)['port']

        nested_driver = nested.NestedDriver()
        self.assertRaises(exceptions.KuryrException,
            nested_driver.create_host_iface, fake_endpoint_id,
            fake_neutron_port, None)
