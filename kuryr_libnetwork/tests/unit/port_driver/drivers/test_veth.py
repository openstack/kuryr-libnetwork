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
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.port_driver.drivers import veth
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils as libnet_utils


class TestVethDriver(base.TestKuryrBase):
    """Unit tests for veth driver"""

    def test_get_supported_bindings(self):
        veth_driver = veth.VethDriver()
        supported_bindings = veth_driver.get_supported_bindings()
        self.assertEqual(supported_bindings, veth.VethDriver.BINDING_DRIVERS)

    def test_get_default_network_id(self):
        veth_driver = veth.VethDriver()
        host_network = veth_driver.get_default_network_id()
        self.assertIsNone(host_network)

    @mock.patch.object(binding, 'port_bind')
    def test_create_host_iface(self, mock_port_bind):
        veth_driver = veth.VethDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()

        fake_subnets = self._get_fake_subnets(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        fake_network = mock.sentinel.binding_network
        fake_exec_response = ('fake_stdout', '')
        mock_port_bind.return_value = ('fake_host_ifname',
            'fake_container_ifname', fake_exec_response)

        response = veth_driver.create_host_iface(fake_endpoint_id,
            fake_neutron_port, fake_subnets, fake_network)
        mock_port_bind.assert_called_with(fake_endpoint_id,
            fake_neutron_port, fake_subnets, fake_network)
        self.assertEqual(response, fake_exec_response)

    @mock.patch.object(binding, 'port_unbind')
    def test_delete_host_iface(self, mock_port_unbind):
        veth_driver = veth.VethDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port = uuidutils.generate_uuid()
        fake_unbind_response = ('fake_stdout', '')
        mock_port_unbind.return_value = fake_unbind_response

        response = veth_driver.delete_host_iface(fake_endpoint_id,
                                                 fake_neutron_port)
        mock_port_unbind.assert_called_with(fake_endpoint_id,
                                            fake_neutron_port)
        self.assertEqual(response, fake_unbind_response)

    @mock.patch.object(utils, 'get_veth_pair_names',
       return_value=('fake_host_ifname', 'fake_container_ifname'))
    def test_get_container_iface_name(self, mock_get_veth_pair_names):
        veth_driver = veth.VethDriver()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            uuidutils.generate_uuid(), uuidutils.generate_uuid(),
            fake_neutron_port_id)['port']
        response = veth_driver.get_container_iface_name(fake_neutron_port)
        mock_get_veth_pair_names.assert_called_with(fake_neutron_port_id)
        self.assertEqual(response, "fake_container_ifname")

    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(libnet_utils, 'get_neutron_port_name')
    def test_update_port_with_mac_address(self, mock_get_port_name,
                                          mock_update_port):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_mac_address1 = 'fa:16:3e:20:57:c3'
        fake_mac_address2 = 'fa:16:3e:20:57:c4'
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9',
            fake_mac_address1,
            admin_state_up=False, binding_host='')['port']
        fake_port_name = '-'.join([fake_endpoint_id, lib_utils.PORT_POSTFIX])
        mock_get_port_name.return_value = fake_port_name

        veth_driver = veth.VethDriver()
        veth_driver.update_port(fake_neutron_port, fake_endpoint_id,
                                fake_mac_address2)

        mock_get_port_name.assert_called_with(fake_endpoint_id)
        expected_update_port = {
            'port': {
                'device_owner': lib_const.DEVICE_OWNER,
                'binding:host_id': lib_utils.get_hostname(),
                'mac_address': fake_mac_address2,
                'admin_state_up': True,
            }
        }
        mock_update_port.assert_called_with(fake_neutron_port_id,
                                            expected_update_port)

    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(libnet_utils, 'get_neutron_port_name')
    def test_update_port_with_no_mac_address(self, mock_get_port_name,
                                             mock_update_port):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9',
            admin_state_up=False, binding_host='')['port']
        fake_port_name = '-'.join([fake_endpoint_id, lib_utils.PORT_POSTFIX])
        mock_get_port_name.return_value = fake_port_name

        veth_driver = veth.VethDriver()
        veth_driver.update_port(fake_neutron_port, fake_endpoint_id, '')

        mock_get_port_name.assert_called_with(fake_endpoint_id)
        expected_update_port = {
            'port': {
                'device_owner': lib_const.DEVICE_OWNER,
                'binding:host_id': lib_utils.get_hostname(),
                'admin_state_up': True,
            }
        }
        mock_update_port.assert_called_with(fake_neutron_port_id,
                                            expected_update_port)

    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(libnet_utils, 'get_neutron_port_name')
    def test_update_port_with_device_id(self, mock_get_port_name,
                                        mock_update_port):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_mac_address1 = 'fa:16:3e:20:57:c3'
        fake_mac_address2 = 'fa:16:3e:20:57:c4'
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9',
            fake_mac_address1,
            admin_state_up=False, binding_host='')['port']
        fake_neutron_port.pop('device_id')
        fake_port_name = '-'.join([fake_endpoint_id, lib_utils.PORT_POSTFIX])
        mock_get_port_name.return_value = fake_port_name

        veth_driver = veth.VethDriver()
        veth_driver.update_port(fake_neutron_port, fake_endpoint_id,
                                fake_mac_address2)

        mock_get_port_name.assert_called_with(fake_endpoint_id)
        expected_update_port = {
            'port': {
                'device_owner': lib_const.DEVICE_OWNER,
                'binding:host_id': lib_utils.get_hostname(),
                'device_id': fake_endpoint_id,
                'mac_address': fake_mac_address2,
                'admin_state_up': True,
            }
        }
        mock_update_port.assert_called_with(fake_neutron_port_id,
                                            expected_update_port)

    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(libnet_utils, 'get_neutron_port_name')
    def test_update_port_with_no_changes(self, mock_get_port_name,
                                         mock_update_port):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9',
            binding_host=lib_utils.get_hostname())['port']
        fake_port_name = '-'.join([fake_endpoint_id, lib_utils.PORT_POSTFIX])
        mock_get_port_name.return_value = fake_port_name

        veth_driver = veth.VethDriver()
        veth_driver.update_port(fake_neutron_port, fake_endpoint_id, '')

        mock_get_port_name.assert_called_with(fake_endpoint_id)
        mock_update_port.assert_not_called()
