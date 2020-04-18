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

from kuryr.lib import exceptions
from kuryr_libnetwork.port_driver import base as d_base
from kuryr_libnetwork.tests.unit import base


class TestBaseDriver(d_base.BaseNestedDriver):
    def get_default_network_id(self):
        pass

    def create_host_iface(self, endpoint_id, neutron_port, subnets,
                          network=None):
        pass

    def delete_host_iface(self, endpoint_id, neutron_port):
        pass

    def get_container_iface_name(self, neutron_port):
        pass

    def get_supported_bindings(self):
        pass

    def update_port(self, neutron_port_id, endpoint_id):
        pass


@ddt.ddt
class TestBaseNestedDriver(base.TestKuryrBase):
    """Unit tests for the BaseNestedDriver port driver"""

    @mock.patch('kuryr_libnetwork.app.neutron.list_ports')
    @mock.patch('kuryr.lib.binding.drivers.utils.get_ipdb')
    @ddt.data(('fa:16:3e:20:57:c3'), (None))
    def test__get_port_from_host_iface(self, addr, m_get_ipdb, m_list_ports):
        m_ip = mock.MagicMock()
        m_iface = mock.MagicMock()
        port = mock.sentinel.port
        ports = {'ports': [port]}

        m_get_ipdb.return_value = m_ip
        m_ip.interfaces.get.return_value = m_iface
        m_iface.get.return_value = addr
        m_list_ports.return_value = ports

        base_driver = TestBaseDriver()
        if addr:
            response = base_driver._get_port_from_host_iface('iface')
            self.assertEqual(port, response)
            m_list_ports.assert_called_with(mac_address=addr)
        else:
            self.assertRaises(exceptions.KuryrException,
                base_driver._get_port_from_host_iface, 'iface')


class TestBaseNestedDriverFailures(base.TestKuryrFailures):
    """Unit tests for the BaseNestedDriver port driver failures"""

    @mock.patch('kuryr.lib.binding.drivers.utils.get_ipdb')
    def test__get_port_from_host_iface(self, m_get_ipdb):
        m_ip = mock.MagicMock()
        m_get_ipdb.return_value = m_ip
        m_ip.interfaces.get.return_value = {}

        base_driver = TestBaseDriver()
        self.assertRaises(exceptions.KuryrException,
            base_driver._get_port_from_host_iface, '')
