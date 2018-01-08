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

import glob
import mock
import os

from oslo_utils import uuidutils

from kuryr.lib import binding
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.port_driver.drivers import sriov
from kuryr_libnetwork.tests.unit import base


class TestSriovDriver(base.TestKuryrBase):
    """Unit tests for veth driver"""

    def test_get_supported_bindings(self):
        sriov_driver = sriov.SriovDriver()
        supported_bindings = sriov_driver.get_supported_bindings()
        self.assertEqual(supported_bindings, sriov.SriovDriver.BINDING_DRIVERS)

    @mock.patch.object(os, 'readlink')
    @mock.patch.object(glob, 'iglob')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(binding, 'port_bind')
    def test_create_host_iface(self, mock_port_bind, mock_listdir,
                               mock_iglob, mock_readlink):
        sriov_driver = sriov.SriovDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, uuidutils.generate_uuid(),
            fake_neutron_port_id,
            binding_profile={'pci_slot': '0000:0a:00.1'})['port']
        fake_subnets = mock.sentinel.binding_subnets
        fake_pf_ifname = 'eth3'
        mock_listdir.return_value = [fake_pf_ifname]
        mock_iglob.return_value = [
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn3',
        ]
        mock_readlink.return_value = '../../0000:0a:00.1'
        fake_exec_response = ('fake_stdout', '')
        mock_port_bind.return_value = ('fake_host_ifname',
            'fake_container_ifname', fake_exec_response)

        response = sriov_driver.create_host_iface(fake_endpoint_id,
            fake_neutron_port, fake_subnets)
        self.assertEqual(response, fake_exec_response)
        mock_port_bind.assert_called_with(fake_endpoint_id,
            fake_neutron_port, fake_subnets,
            pf_ifname=fake_pf_ifname, vf_num='3',
            driver='kuryr.lib.binding.drivers.hw_veb')
        mock_listdir.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/net')
        mock_iglob.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn*')
        mock_readlink.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn3')

    @mock.patch.object(os, 'readlink')
    @mock.patch.object(glob, 'iglob')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(binding, 'port_bind')
    def test_create_host_iface_pf_not_found(
            self, mock_port_bind, mock_listdir, mock_iglob, mock_readlink):
        sriov_driver = sriov.SriovDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, uuidutils.generate_uuid(),
            fake_neutron_port_id,
            binding_profile={'pci_slot': '0000:0a:00.1'})['port']
        fake_subnets = mock.sentinel.binding_subnets
        mock_listdir.side_effect = OSError('No such file or directory')

        self.assertRaises(exceptions.KuryrException,
                          sriov_driver.create_host_iface,
                          fake_endpoint_id, fake_neutron_port, fake_subnets)
        mock_port_bind.assert_not_called()
        mock_listdir.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/net')
        mock_iglob.assert_not_called()
        mock_readlink.assert_not_called()

    @mock.patch.object(os, 'readlink')
    @mock.patch.object(glob, 'iglob')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(binding, 'port_bind')
    def test_create_host_iface_vf_num_not_found(
            self, mock_port_bind, mock_listdir, mock_iglob, mock_readlink):
        sriov_driver = sriov.SriovDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, uuidutils.generate_uuid(),
            fake_neutron_port_id,
            binding_profile={'pci_slot': '0000:0a:00.1'})['port']
        fake_subnets = mock.sentinel.binding_subnets
        fake_pf_ifname = 'eth3'
        mock_listdir.return_value = [fake_pf_ifname]
        mock_iglob.return_value = [
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn3',
        ]
        mock_readlink.return_value = '../../0000:0a:00.2'

        self.assertRaises(exceptions.KuryrException,
                          sriov_driver.create_host_iface,
                          fake_endpoint_id, fake_neutron_port, fake_subnets)
        mock_port_bind.assert_not_called()
        mock_listdir.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/net')
        mock_iglob.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn*')
        mock_readlink.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn3')

    @mock.patch.object(os, 'readlink')
    @mock.patch.object(glob, 'iglob')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(binding, 'port_unbind')
    def test_delete_host_iface(self, mock_port_unbind, mock_listdir,
                               mock_iglob, mock_readlink):
        sriov_driver = sriov.SriovDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, uuidutils.generate_uuid(),
            fake_neutron_port_id,
            binding_profile={'pci_slot': '0000:0a:00.1'})['port']
        fake_pf_ifname = 'eth3'
        mock_listdir.return_value = [fake_pf_ifname]
        mock_iglob.return_value = [
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn3',
        ]
        mock_readlink.return_value = '../../0000:0a:00.1'
        fake_unbind_response = ('fake_stdout', '')
        mock_port_unbind.return_value = fake_unbind_response

        response = sriov_driver.delete_host_iface(fake_endpoint_id,
                                                  fake_neutron_port)
        self.assertEqual(response, fake_unbind_response)
        mock_port_unbind.assert_called_with(fake_endpoint_id,
            fake_neutron_port, pf_ifname=fake_pf_ifname,
            vf_num='3', driver='kuryr.lib.binding.drivers.hw_veb')
        mock_listdir.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/net')
        mock_iglob.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn*')
        mock_readlink.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/physfn/virtfn3')

    @mock.patch.object(os, 'listdir')
    def test_get_container_iface_name(self, mock_listdir):
        sriov_driver = sriov.SriovDriver()
        fake_endpoint_id = lib_utils.get_hash()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_port = self._get_fake_port(
            fake_endpoint_id, uuidutils.generate_uuid(),
            fake_neutron_port_id,
            binding_profile={'pci_slot': '0000:0a:00.1'})['port']
        fake_vf_ifname = 'vf01'
        mock_listdir.return_value = [fake_vf_ifname]
        response = sriov_driver.get_container_iface_name(fake_neutron_port)
        self.assertEqual(response, fake_vf_ifname)
        mock_listdir.assert_called_with(
            '/sys/bus/pci/devices/0000:0a:00.1/net')
