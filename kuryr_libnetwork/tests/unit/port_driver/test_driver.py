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

from oslo_utils import importutils

from kuryr.lib import exceptions
from kuryr_libnetwork.port_driver import driver
from kuryr_libnetwork.tests.unit import base


@ddt.ddt
class TestDriver(base.TestKuryrBase):
    """Unit tests for driver loading"""

    @mock.patch.object(driver, '_verify_binding_driver_compatibility')
    @mock.patch.object(driver, '_verify_port_driver_compliancy')
    @mock.patch.object(importutils, 'import_object')
    @mock.patch.object(driver, '_parse_port_driver_config')
    def test_get_driver_instance(
            self, mock_parse_config, mock_import_object,
            mock_verify_compliancy, mock_verify_compatibility):
        module = 'kuryr_libnetwork.port_driver.drivers.veth'
        mock_parse_config.return_value = (module, 'veth', 'VethDriver')
        fake_driver = mock.Mock(spec=driver.Driver)
        mock_import_object.return_value = fake_driver

        response_driver = driver.get_driver_instance()
        mock_parse_config.assert_called_once()
        mock_import_object.assert_called_once_with(module + '.VethDriver')
        mock_verify_compliancy.assert_called_once_with(fake_driver, 'veth')
        mock_verify_compatibility.assert_called_once_with(fake_driver, 'veth')
        self.assertEqual(response_driver, fake_driver)

    @mock.patch('kuryr_libnetwork.config.CONF')
    @ddt.data('kuryr_libnetwork.port_driver.drivers.veth', 'veth')
    def test__parse_port_driver_config(self, port_driver_value, mock_conf):
        mock_conf.default_port_driver = port_driver_value

        module, name, classname = driver._parse_port_driver_config()
        self.assertEqual(module, 'kuryr_libnetwork.port_driver.drivers.veth')
        self.assertEqual(name, 'veth')
        self.assertEqual(classname, 'VethDriver')

    def test__verify_port_driver_compliancy(self):
        fake_driver = mock.Mock(spec=driver.Driver)
        ret = driver._verify_port_driver_compliancy(fake_driver, 'driver')
        self.assertIsNone(ret)

    @mock.patch('kuryr_libnetwork.config.CONF')
    def test__verify_binding_driver_compatibility(self, mock_conf):
        mock_conf.binding.enabled_drivers = ['veth']
        fake_driver = mock.Mock(spec=driver.Driver)
        fake_driver.get_supported_bindings.return_value = ('veth',)

        ret = driver._verify_binding_driver_compatibility(fake_driver, 'veth')
        fake_driver.get_supported_bindings.assert_called_once()
        self.assertIsNone(ret)

    @mock.patch('kuryr_libnetwork.config.CONF')
    def test__verify_binding_driver_compatibility_multi_drivers(
            self, mock_conf):
        mock_conf.binding.enabled_drivers = ['veth', 'sriov']
        fake_driver = mock.Mock(spec=driver.Driver)
        fake_driver.get_supported_bindings.return_value = ('sriov',)

        ret = driver._verify_binding_driver_compatibility(fake_driver, 'sriov')
        fake_driver.get_supported_bindings.assert_called_once()
        self.assertIsNone(ret)


class TestNestedDriverFailures(base.TestKuryrFailures):
    """Unit tests for driver loading failures"""

    @mock.patch('kuryr_libnetwork.config.CONF')
    def test__parse_port_driver_config_empty(self, mock_conf):
        mock_conf.default_port_driver = ''

        self.assertRaisesRegex(exceptions.KuryrException,
            "No port driver provided", driver._parse_port_driver_config)

    @mock.patch.object(importutils, 'import_object', side_effect=ImportError)
    def test_get_driver_instance_import_error(self, mock_import_object):
        self.assertRaises(exceptions.KuryrException,
            driver.get_driver_instance)

    def test__verify_port_driver_compliancy(self):
        class InvalidDriver(object):
            pass

        self.assertRaises(exceptions.KuryrException,
            driver._verify_port_driver_compliancy, InvalidDriver(), 'invalid')

    @mock.patch('kuryr_libnetwork.config.CONF')
    def test__verify_binding_driver_compatibility_not_compatible(self, m_conf):
        m_conf.binding.enabled_drivers = ['macvlan']
        message = r"Configuration file error: port driver 'veth' is not " \
                  r"compatible with binding driver '\['macvlan'\]'"

        fake_driver = mock.Mock(spec=driver.Driver)
        fake_driver.get_supported_bindings.return_value = ('veth',)
        self.assertRaisesRegex(exceptions.KuryrException, message,
            driver._verify_binding_driver_compatibility, fake_driver, 'veth')

    @mock.patch('kuryr_libnetwork.config.CONF')
    def test__verify_binding_driver_compatibility_not_compatible_multi_drivers(
            self, m_conf):
        m_conf.binding.enabled_drivers = ['macvlan', 'sriov']
        message = r"Configuration file error: port driver 'veth' is not " \
                  r"compatible with binding driver '\['macvlan'\, 'sriov']'"

        fake_driver = mock.Mock(spec=driver.Driver)
        fake_driver.get_supported_bindings.return_value = ('veth',)
        self.assertRaisesRegex(exceptions.KuryrException, message,
            driver._verify_binding_driver_compatibility, fake_driver, 'veth')

    @mock.patch('kuryr_libnetwork.config.CONF')
    def test__verify_binding_driver_compatibility_not_supported(self, m_conf):
        m_conf.binding.enabled_drivers = ['ipvlan']
        message = r"Configuration file error: binding driver " \
                  r"'\['ipvlan'\]' is currently not supported " \
                  r"with 'nested' port driver"

        fake_driver = mock.Mock(spec=driver.Driver)
        fake_driver.get_supported_bindings.return_value = ('ipvlan',)
        self.assertRaisesRegex(exceptions.KuryrException, message,
            driver._verify_binding_driver_compatibility, fake_driver, 'nested')
