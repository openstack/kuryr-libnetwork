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

from collections import defaultdict
from itertools import groupby
from operator import itemgetter
from unittest import mock

import ddt
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from kuryr.lib import constants as lib_const
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import config
from kuryr_libnetwork import constants
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils

PORT = 77
SINGLE_PORT = 100
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17


@ddt.ddt
class TestExternalConnectivityKuryr(base.TestKuryrBase):
    """The unitests for external connectivity

    This test class is used to test programming and revoking external
    connectivity for containers.  Tests cover containers which already have
    a security group (perhaps the default security group set up by Neutron)
    associated with their ports in addition to those without any such
    security groups. Tests also cover adding more than one port to the
    list of exposed ports.
    """
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.create_security_group_rule')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.create_security_group')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @ddt.data((False, 1), (True, 1), (False, 2), (True, 2))
    @ddt.unpack
    def test_network_driver_program_external_connectivity(self, existing_sg,
            num_ports, mock_list_ports, mock_create_security_group,
            mock_create_security_group_rule, mock_show_port,
            mock_update_port):
        config.CONF.set_override('process_external_connectivity', True)
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        neutron_port_name = utils.get_neutron_port_name(
            fake_docker_endpoint_id)
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        if existing_sg:
            fake_neutron_existing_sec_group_id = uuidutils.generate_uuid()
            fake_neutron_ports_response['ports'][0]['security_groups'] = [
                fake_neutron_existing_sec_group_id]

        mock_list_ports.return_value = fake_neutron_ports_response

        sec_group = {
            'name': utils.get_sg_expose_name(fake_neutron_port_id),
            'description': 'Docker exposed ports created by Kuryr.'
        }
        fake_neutron_sec_group_id = lib_utils.get_hash()
        fake_neutron_sec_group_response = {'security_group':
                                           {'id': fake_neutron_sec_group_id}}
        mock_create_security_group.return_value = (
            fake_neutron_sec_group_response)

        proto_port_dict = defaultdict(list)
        for i in range(num_ports):
            proto_port_dict[constants.PROTOCOLS[PROTOCOL_TCP]].append(PORT + i)
            proto_port_dict[constants.PROTOCOLS[PROTOCOL_UDP]].append(PORT + i)
        proto_port_dict[constants.PROTOCOLS[PROTOCOL_UDP]].append(SINGLE_PORT)

        for proto, port_list in proto_port_dict.items():
            for key, group in groupby(enumerate(sorted(port_list)),
                                      lambda ix: ix[0] - ix[1]):
                port_range_list = list(map(itemgetter(1), group))

                port_range_min = min(port_range_list)
                port_range_max = max(port_range_list)
                sec_group_rule = {
                    'security_group_id': fake_neutron_sec_group_id,
                    'direction': 'ingress',
                    'port_range_min': port_range_min,
                    'port_range_max': port_range_max,
                    'protocol': proto
                }

        sgs = [fake_neutron_sec_group_id]
        if existing_sg:
            sgs.append(fake_neutron_existing_sec_group_id)
        mock_show_port.return_value = {'port':
            fake_neutron_ports_response['ports'][0]}

        port_opt = []
        for i in range(num_ports):
            port_opt.append({u'Port': PORT + i, u'Proto': PROTOCOL_TCP})
            port_opt.append({u'Port': PORT + i, u'Proto': PROTOCOL_UDP})
        port_opt.append({u'Port': SINGLE_PORT, u'Proto': PROTOCOL_UDP})
        options = {'com.docker.network.endpoint.exposedports':
                   port_opt,
                   'com.docker.network.portmap':
                   []}
        data = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
            'Options': options,
        }
        response = self.app.post('/NetworkDriver.ProgramExternalConnectivity',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_update_port.assert_called_with(fake_neutron_port_id,
                                {'port': {'security_groups': sgs}})
        mock_show_port.assert_called_with(fake_neutron_port_id)
        mock_create_security_group_rule.assert_called_with(
            {'security_group_rule': sec_group_rule})
        mock_create_security_group.assert_called_with(
            {'security_group': sec_group})
        mock_list_ports.assert_called_with(name=neutron_port_name)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.create_security_group_rule')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.create_security_group')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @ddt.data((False, 1), (True, 1), (False, 2), (True, 2))
    @ddt.unpack
    def test_network_driver_program_external_connectivity_disabled(
            self, existing_sg,
            num_ports, mock_list_ports, mock_create_security_group,
            mock_create_security_group_rule, mock_show_port,
            mock_update_port):
        config.CONF.set_override('process_external_connectivity', False)
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        port_opt = []
        for i in range(num_ports):
            port_opt.append({u'Port': PORT + i, u'Proto': PROTOCOL_TCP})
            port_opt.append({u'Port': PORT + i, u'Proto': PROTOCOL_UDP})
        port_opt.append({u'Port': SINGLE_PORT, u'Proto': PROTOCOL_UDP})
        options = {'com.docker.network.endpoint.exposedports':
                   port_opt,
                   'com.docker.network.portmap':
                   []}
        data = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
            'Options': options,
        }
        response = self.app.post('/NetworkDriver.ProgramExternalConnectivity',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_update_port.assert_not_called()
        mock_show_port.assert_not_called()
        mock_create_security_group_rule.assert_not_called()
        mock_create_security_group.assert_not_called()
        mock_list_ports.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.delete_security_group')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.list_security_groups')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @ddt.data((False, False), (False, True), (True, False), (True, True))
    @ddt.unpack
    def test_network_driver_revoke_external_connectivity(self, existing_sg,
            removing_sg, mock_list_ports, mock_list_security_groups,
            mock_delete_security_groups, mock_show_port,
            mock_update_port):
        config.CONF.set_override('process_external_connectivity', True)
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        fake_neutron_net_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_neutron_sec_group_id = lib_utils.get_hash()
        neutron_port_name = utils.get_neutron_port_name(
            fake_docker_endpoint_id)
        fake_neutron_v4_subnet_id = uuidutils.generate_uuid()
        fake_neutron_v6_subnet_id = uuidutils.generate_uuid()
        fake_neutron_ports_response = self._get_fake_ports(
            fake_docker_endpoint_id, fake_neutron_net_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            fake_neutron_v4_subnet_id, fake_neutron_v6_subnet_id)
        if existing_sg:
            fake_neutron_existing_sec_group_id = uuidutils.generate_uuid()
            fake_neutron_ports_response['ports'][0]['security_groups'] = [
                fake_neutron_sec_group_id, fake_neutron_existing_sec_group_id]
        else:
            fake_neutron_ports_response['ports'][0]['security_groups'] = [
                fake_neutron_sec_group_id]
        if removing_sg:
            fake_neutron_sec_group_response = {
                'security_groups': [{'id': fake_neutron_sec_group_id}]}
        else:
            fake_neutron_sec_group_response = {
                'security_groups': []}

        mock_list_ports.return_value = fake_neutron_ports_response
        mock_list_security_groups.return_value = (
            fake_neutron_sec_group_response)
        mock_show_port.return_value = {'port':
            fake_neutron_ports_response['ports'][0]}

        if existing_sg:
            sgs = [fake_neutron_existing_sec_group_id]
        else:
            sgs = []
        data = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
        }
        response = self.app.post('/NetworkDriver.RevokeExternalConnectivity',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_ports.assert_called_with(name=neutron_port_name)
        if removing_sg:
            mock_list_security_groups.assert_called_with(
                name=utils.get_sg_expose_name(fake_neutron_port_id))
            mock_delete_security_groups.assert_called_with(
                fake_neutron_sec_group_id)
            mock_show_port.assert_called_with(fake_neutron_port_id)
            mock_update_port.assert_called_with(fake_neutron_port_id,
                            {'port': {'security_groups': sgs}})
        else:
            mock_list_security_groups.assert_called_with(
                name=utils.get_sg_expose_name(fake_neutron_port_id))
            mock_delete_security_groups.assert_not_called()
            mock_show_port.assert_not_called()
            mock_update_port.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_port')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.delete_security_group')
    @mock.patch(
        'kuryr_libnetwork.controllers.app.neutron.list_security_groups')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @ddt.data((False, False), (False, True), (True, False), (True, True))
    @ddt.unpack
    def test_network_driver_revoke_external_connectivity_disabled(
            self, existing_sg,
            removing_sg, mock_list_ports, mock_list_security_groups,
            mock_delete_security_groups, mock_show_port,
            mock_update_port):
        config.CONF.set_override('process_external_connectivity', False)
        fake_docker_net_id = lib_utils.get_hash()
        fake_docker_endpoint_id = lib_utils.get_hash()

        data = {
            'NetworkID': fake_docker_net_id,
            'EndpointID': fake_docker_endpoint_id,
        }
        response = self.app.post('/NetworkDriver.RevokeExternalConnectivity',
                                 content_type='application/json',
                                 data=jsonutils.dumps(data))

        self.assertEqual(200, response.status_code)
        mock_list_ports.assert_not_called()
        mock_list_security_groups.assert_not_called()
        mock_delete_security_groups.assert_not_called()
        mock_show_port.assert_not_called()
        mock_update_port.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(constants.SCHEMA['SUCCESS'], decoded_json)
