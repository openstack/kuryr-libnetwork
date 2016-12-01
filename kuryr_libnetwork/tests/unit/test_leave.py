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

import ddt
import mock
from oslo_concurrency import processutils
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from werkzeug import exceptions as w_exceptions

from kuryr.lib import binding
from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import constants
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


@ddt.ddt
class TestKuryrLeaveFailures(base.TestKuryrFailures):
    """Unit tests for the failures for unbinding a Neutron port."""
    def _invoke_leave_request(self, docker_network_id,
                              docker_endpoint_id):
        data = {
            'NetworkID': docker_network_id,
            'EndpointID': docker_endpoint_id,
        }
        response = self.app.post('/NetworkDriver.Leave',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        return response

    @mock.patch.object(binding, 'port_unbind')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    @ddt.data(exceptions.VethDeletionFailure,
              processutils.ProcessExecutionError)
    def test_leave_unbinding_failure(self, GivenException,
            mock_list_networks, mock_list_ports, mock_port_unbind):
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        t = utils.make_net_tags(fake_docker_network_id)
        mock_list_networks.return_value = self._get_fake_list_network(
            fake_neutron_network_id)
        neutron_port_name = utils.get_neutron_port_name(
            fake_docker_endpoint_id)
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        mock_list_ports.return_value = fake_neutron_ports_response
        fake_neutron_port = fake_neutron_ports_response['ports'][0]

        fake_message = "fake message"
        fake_exception = GivenException(fake_message)
        mock_port_unbind.side_effect = fake_exception
        response = self._invoke_leave_request(
            fake_docker_network_id, fake_docker_endpoint_id)

        self.assertEqual(
            w_exceptions.InternalServerError.code, response.status_code)
        mock_list_networks.assert_called_with(tags=t)
        mock_list_ports.assert_called_with(name=neutron_port_name)
        mock_port_unbind.assert_called_with(fake_docker_endpoint_id,
            fake_neutron_port)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertIn(fake_message, decoded_json['Err'])

    def test_leave_bad_request(self):
        fake_docker_network_id = lib_utils.get_hash()
        invalid_docker_endpoint_id = 'id-should-be-hexdigits'

        response = self._invoke_leave_request(
            fake_docker_network_id, invalid_docker_endpoint_id)

        self.assertEqual(w_exceptions.BadRequest.code, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        # TODO(tfukushima): Add the better error message validation.
        self.assertIn(invalid_docker_endpoint_id, decoded_json['Err'])
        self.assertIn('EndpointID', decoded_json['Err'])

    @mock.patch.object(binding, 'port_unbind')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_networks')
    def test_leave_unbinding(self, mock_list_networks,
            mock_list_ports, mock_port_unbind):
        fake_docker_network_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()

        fake_unbinding_response = ('fake stdout', '')
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        fake_neutron_port = fake_neutron_ports_response['ports'][0]

        t = utils.make_net_tags(fake_docker_network_id)
        neutron_port_name = utils.get_neutron_port_name(
            fake_docker_endpoint_id)
        mock_list_networks.return_value = self._get_fake_list_network(
            fake_neutron_network_id)
        mock_list_ports.return_value = fake_neutron_ports_response
        mock_port_unbind.return_value = fake_unbinding_response
        response = self._invoke_leave_request(
            fake_docker_network_id, fake_docker_endpoint_id)

        self.assertEqual(200, response.status_code)
        mock_list_networks.assert_called_with(tags=t)
        mock_list_ports.assert_called_with(name=neutron_port_name)
        mock_port_unbind.assert_called_with(fake_docker_endpoint_id,
            fake_neutron_port)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)
