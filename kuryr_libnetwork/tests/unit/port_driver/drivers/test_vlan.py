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
from kuryr.lib import segmentation_type_drivers as seg_driver
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.port_driver.drivers import vlan
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils as libnet_utils

mock_interface = mock.MagicMock()


class TestVlanDriver(base.TestKuryrBase):
    """Unit tests for the VlanDriver port driver"""

    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    def test_get_supported_bindings(self, mock_trunk_port, mock_vlan_check):
        mock_trunk_port.return_value = None
        mock_vlan_check.return_value = None
        vlan_driver = vlan.VlanDriver()
        bindings = vlan_driver.get_supported_bindings()
        self.assertEqual(bindings, vlan.VlanDriver.BINDING_DRIVERS)

    @mock.patch('kuryr_libnetwork.config.CONF')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch.object(binding, 'port_bind')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_segmentation_id')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    def test_create_host_iface(self, mock_get_port_from_host,
                               mock_segmentation_id,
                               mock_port_bind, mock_vlan_check, mock_conf):
        mock_vlan_check.return_value = None
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

        fake_subnets = self._get_fake_subnets(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)['subnets']

        fake_network = mock.sentinel.binding_network
        mock_conf.binding.link_iface = 'eth0'
        fake_exec_response = ('fake_stdout', '')
        fake_segmentation_id = 1
        mock_port_bind.return_value = ('fake_host_ifname',
            'fake_container_ifname', fake_exec_response)
        mock_segmentation_id.return_value = fake_segmentation_id
        mock_get_port_from_host.return_value = fake_vm_port

        vlan_driver = vlan.VlanDriver()

        response = vlan_driver.create_host_iface(fake_endpoint_id,
            fake_neutron_port, fake_subnets, fake_network)

        mock_get_port_from_host.assert_called_with(
            mock_conf.binding.link_iface)
        mock_port_bind.assert_called_with(fake_endpoint_id,
            fake_neutron_port, fake_subnets, fake_network, fake_vm_port,
            fake_segmentation_id)
        mock_segmentation_id.assert_called_with(fake_neutron_port['id'])

        self.assertEqual(response, fake_exec_response)

    @mock.patch('kuryr_libnetwork.config.CONF')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._release_segmentation_id')
    @mock.patch.object(binding, 'port_unbind')
    @mock.patch('kuryr_libnetwork.app.neutron.trunk_remove_subports')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    def test_delete_host_iface(self, mock_get_port_from_host,
                               mock_trunk_remove_subports, mock_port_unbind,
                               mock_release_seg_id, mock_vlan_check,
                               mock_conf):
        mock_vlan_check.return_value = None
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_trunk_id = uuidutils.generate_uuid()
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
            '192.168.1.2', 'fe80::f816:3eff:fe20:57c4', 'fa:16:3e:20:57:c3',
            None, fake_neutron_trunk_id)['port']
        fake_vm_port['allowed_address_pairs'] = [
            {'ip_address': '192.168.1.3',
             'mac_address': fake_neutron_port['mac_address']},
            {'ip_address': 'fe80::f816:3eff:fe1c:36a9',
             'mac_address': fake_neutron_port['mac_address']}]

        mock_conf.binding.link_iface = 'eth0'
        fake_unbind_response = ('fake_stdout', '')
        mock_get_port_from_host.return_value = fake_vm_port
        mock_port_unbind.return_value = fake_unbind_response

        vlan_driver = vlan.VlanDriver()

        response = vlan_driver.delete_host_iface(fake_endpoint_id,
                                                 fake_neutron_port)

        mock_get_port_from_host.assert_called_with(
            mock_conf.binding.link_iface)
        mock_port_unbind.assert_called_with(fake_endpoint_id,
                                            fake_neutron_port)
        mock_trunk_remove_subports.assert_called_with(fake_neutron_trunk_id,
            {'sub_ports': [{
                'port_id': fake_neutron_port_id
            }]})
        mock_release_seg_id.assert_called_with(fake_neutron_port_id)

        self.assertEqual(response, fake_unbind_response)

    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    @mock.patch.object(utils, 'get_veth_pair_names',
        return_value=("fake_host_ifname", "fake_container_name"))
    def test_get_container_iface_name(self, mock_get_pair_names,
                                      mock_trunk_port, mock_vlan_check):
        mock_trunk_port.return_value = None
        mock_vlan_check.return_value = None
        vlan_driver = vlan.VlanDriver()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            uuidutils.generate_uuid(), uuidutils.generate_uuid(),
            fake_neutron_port_id)['port']
        response = vlan_driver.get_container_iface_name(fake_neutron_port)
        mock_get_pair_names.assert_called_with(fake_neutron_port_id)
        self.assertEqual(response, "fake_container_name")

    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    @mock.patch('kuryr_libnetwork.app.neutron.trunk_add_subports')
    def test_attach_subport(self, mock_trunk_add_subports, mock_trunk_port,
                            mock_vlan_check):
        mock_trunk_port.return_value = None
        mock_vlan_check.return_value = None

        fake_neutron_trunk_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_segmentation_id = 1
        fake_subport = [
            {
                'segmentation_id': fake_segmentation_id,
                'port_id': fake_neutron_port_id,
                'segmentation_type': 'vlan'
            }
        ]

        vlan_driver = vlan.VlanDriver()

        vlan_driver._attach_subport(fake_neutron_trunk_id,
                                    fake_neutron_port_id,
                                    fake_segmentation_id)
        mock_trunk_add_subports.assert_called_with(fake_neutron_trunk_id,
                                                   {'sub_ports': fake_subport})

    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    @mock.patch.object(seg_driver, 'allocate_segmentation_id')
    def test_get_segmentation_id(self, mock_alloc_seg_id, mock_trunk_port,
                                 mock_vlan_check):
        mock_trunk_port.return_value = None
        mock_vlan_check.return_value = None
        fake_neutron_port1_id = uuidutils.generate_uuid()
        fake_neutron_port2_id = uuidutils.generate_uuid()
        mock_alloc_seg_id.side_effect = [1, 2]

        vlan_driver = vlan.VlanDriver()

        response = vlan_driver._get_segmentation_id(fake_neutron_port1_id)
        mock_alloc_seg_id.assert_called_once()
        self.assertEqual(response, 1)

        mock_alloc_seg_id.reset_mock()
        response = vlan_driver._get_segmentation_id(fake_neutron_port1_id)
        mock_alloc_seg_id.assert_not_called()
        self.assertEqual(response, 1)

        response = vlan_driver._get_segmentation_id(fake_neutron_port2_id)
        mock_alloc_seg_id.assert_called_once()
        self.assertEqual(response, 2)

    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._check_for_vlan_ids')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    @mock.patch('kuryr_libnetwork.app.neutron.update_port')
    @mock.patch.object(libnet_utils, 'get_neutron_port_name')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._attach_subport')
    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_segmentation_id')
    def test_update_port(self, mock_get_seg_id, mock_attach_subport,
                         mock_get_port_name, mock_update_port,
                         mock_get_port_from_host, mock_vlan_check):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_trunk_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_vm_port_id = uuidutils.generate_uuid()

        fake_neutron_mac_address1 = 'fa:16:3e:20:57:c3'
        fake_neutron_mac_address2 = 'fa:16:3e:20:57:c4'
        fake_vm_mac_address = 'fa:16:3e:20:57:c5'
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.3', 'fe80::f816:3eff:fe1c:36a9',
            fake_neutron_mac_address1,
            binding_host='', admin_state_up=False)['port']
        fake_vm_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_vm_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id,
            '192.168.1.2', 'fe80::f816:3eff:fe20:57c4', fake_vm_mac_address,
            None, fake_neutron_trunk_id)['port']
        fake_segmentation_id = 1
        fake_port_name = 'port1'

        mock_get_seg_id.return_value = fake_segmentation_id
        mock_get_port_name.return_value = fake_port_name
        mock_get_port_from_host.return_value = fake_vm_port
        mock_vlan_check.return_value = None

        vlan_driver = vlan.VlanDriver()

        vlan_driver.update_port(fake_neutron_port, fake_endpoint_id,
                                fake_neutron_mac_address2)

        mock_get_seg_id.assert_called_with(fake_neutron_port_id)

        mock_get_port_name.assert_called_with(fake_endpoint_id)

        mock_attach_subport.assert_called_with(fake_neutron_trunk_id,
                                               fake_neutron_port_id,
                                               fake_segmentation_id)

        mock_update_port.assert_called_with(fake_neutron_port_id,
                {'port': {
                    'device_owner': lib_const.DEVICE_OWNER,
                    'binding:host_id': lib_utils.get_hostname(),
                    'mac_address': fake_neutron_mac_address2,
                    'admin_state_up': True,
                }})


class TestVlanDriverFailures(base.TestKuryrFailures):
    """Unit tests for the VlanDriver port driver failures"""

    @mock.patch('kuryr_libnetwork.port_driver.drivers.vlan'
                '.VlanDriver._get_port_from_host_iface')
    def test_create_host_iface(self, mock_get_port_from_host):
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_net_id = uuidutils.generate_uuid()

        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE)['port']

        vlan_driver = vlan.VlanDriver()
        self.assertRaises(exceptions.KuryrException,
            vlan_driver.create_host_iface, fake_endpoint_id,
            fake_neutron_port, None)
