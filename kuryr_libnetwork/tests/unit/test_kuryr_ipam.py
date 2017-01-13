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
from oslo_serialization import jsonutils
from oslo_utils import uuidutils
from werkzeug import exceptions as w_exceptions

from kuryr.lib import constants as lib_const
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import config
from kuryr_libnetwork import constants as const
from kuryr_libnetwork.tests.unit import base
from kuryr_libnetwork import utils


FAKE_IP4_CIDR = '10.0.0.0/16'


@ddt.ddt
class TestKuryrIpam(base.TestKuryrBase):
    """Basic unit tests for libnetwork remote IPAM driver URI endpoints.

    This test class covers the following HTTP methods and URIs as described in
    the remote IPAM driver specification as below:

      https://github.com/docker/libnetwork/blob/9bf339f27e9f5c7c922036706c9bcc410899f249/docs/ipam.md  # noqa

    - POST /IpamDriver.GetDefaultAddressSpaces
    - POST /IpamDriver.RequestPool
    - POST /IpamDriver.ReleasePool
    - POST /IpamDriver.RequestAddress
    - POST /IpamDriver.ReleaseAddress
    """
    @ddt.data(
        ('/IpamDriver.GetDefaultAddressSpaces',
         {"LocalDefaultAddressSpace":
          config.CONF.local_default_address_space,
          "GlobalDefaultAddressSpace":
          config.CONF.global_default_address_space}),
        ('/IpamDriver.GetCapabilities',
         {"RequiresMACAddress": False}))
    @ddt.unpack
    def test_remote_ipam_driver_endpoint(self, endpoint, expected):
        response = self.app.post(endpoint)
        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(expected, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_ipam_driver_request_pool_with_user_pool(self,
            mock_list_subnets, mock_list_subnetpools, mock_create_subnetpool):
        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet
        pool_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': 16,
            'prefixes': [FAKE_IP4_CIDR]}

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = pool_name
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = {'subnetpools': []}
        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }

        mock_create_subnetpool.return_value = fake_subnetpool_response

        fake_request = {
            'AddressSpace': '',
            'Pool': FAKE_IP4_CIDR,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {},
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(cidr=FAKE_IP4_CIDR)
        mock_list_subnetpools.assert_called_with(name=fake_name)
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_ipam_driver_request_pool_with_pool_name_option(self,
            mock_list_subnets, mock_create_subnetpool):
        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = 'fake_pool_name'
        new_subnetpool = {
            'name': fake_name,
            'default_prefixlen': 16,
            'prefixes': [FAKE_IP4_CIDR]}

        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }

        mock_create_subnetpool.return_value = fake_subnetpool_response

        fake_request = {
            'AddressSpace': '',
            'Pool': FAKE_IP4_CIDR,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {'neutron.pool.name': 'fake_pool_name'},
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(cidr=FAKE_IP4_CIDR)
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_pool_with_default_v6pool(self,
            mock_list_subnetpools):
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = 'kuryr6'
        kuryr_subnetpools = self._get_fake_v6_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=['fe80::/64'])
        mock_list_subnetpools.return_value = {
            'subnetpools': kuryr_subnetpools['subnetpools']}

        fake_request = {
            'AddressSpace': '',
            'Pool': '',
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {},
            'V6': True
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(name=fake_name)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_extension')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True), (False))
    def test_ipam_driver_release_pool(self,
                                      use_tags,
                                      mock_tag,
                                      mock_show_extension,
                                      mock_list_subnetpools,
                                      mock_list_subnets,
                                      mock_remove_tag,
                                      mock_delete_subnetpool):
        mock_tag.tag = use_tags
        fake_tag_extension = {
            "extension":
            {"alias": "tag", "updated": "mock_time",
             "name": "Tag support", "links": [],
             "description": "mock tag on resources ['subnet', 'network']."}}
        mock_show_extension.return_value = fake_tag_extension

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_subnetpool_name = lib_utils.get_neutron_subnetpool_name(
            FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_subnetpool_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        mock_delete_subnetpool.return_value = {}

        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id
        }
        response = self.app.post('/IpamDriver.ReleasePool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        if mock_tag.tag:
            mock_show_extension.assert_called_with("tag")
            mock_list_subnetpools.assert_called_with(
                id=fake_kuryr_subnetpool_id)
            mock_list_subnets.assert_called_with(
                cidr=FAKE_IP4_CIDR)
            mock_remove_tag.assert_called_with('subnets',
                                               subnet_v4_id,
                                               fake_kuryr_subnetpool_id)
        mock_delete_subnetpool.assert_called_with(fake_kuryr_subnetpool_id)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address(self,
            mock_list_subnetpools, mock_list_subnets,
            mock_create_port):
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        # faking create_port
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address="10.0.0.5")
        port_request = {
            'name': 'kuryr-unbound-port',
            'admin_state_up': True,
            'network_id': neutron_network_id,
            'binding:host_id': lib_utils.get_hostname(),
        }
        fixed_ips = port_request['fixed_ips'] = []
        fixed_ip = {'subnet_id': subnet_v4_id}
        fixed_ips.append(fixed_ip)

        mock_create_port.return_value = fake_port
        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            cidr=FAKE_IP4_CIDR)
        mock_create_port.assert_called_with({'port': port_request})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.5/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_when_subnet_not_exist(self,
            mock_list_subnetpools, mock_list_subnets):
        requested_address = '10.0.0.5'

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        fake_subnet_response = {'subnets': []}
        mock_list_subnets.return_value = fake_subnet_response

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': requested_address,
            'Options': {}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(cidr=FAKE_IP4_CIDR)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(requested_address + '/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @ddt.data((False), (True))
    def test_ipam_driver_request_specific_address(self, existing_port,
            mock_list_subnetpools, mock_list_subnets,
            mock_list_ports, mock_update_port, mock_create_port):
        requested_address = '10.0.0.5'
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        # faking update_port or create_port
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address=requested_address)

        fixed_ip_existing = [('subnet_id=%s' % subnet_v4_id)]
        if existing_port:
            fake_existing_port = fake_port['port']
            fake_existing_port['binding:host_id'] = ''
            fake_existing_port['binding:vif_type'] = 'unbound'
            fake_ports_response = {'ports': [fake_existing_port]}
        else:
            fake_ports_response = {'ports': []}

        fixed_ip_existing.append('ip_address=%s' % requested_address)
        mock_list_ports.return_value = fake_ports_response

        if existing_port:
            update_port = {
                'admin_state_up': True,
                'binding:host_id': lib_utils.get_hostname(),
            }
            mock_update_port.return_value = fake_port

        else:
            port_request = {
                'name': 'kuryr-unbound-port',
                'admin_state_up': True,
                'network_id': neutron_network_id,
                'binding:host_id': lib_utils.get_hostname(),
            }
            fixed_ips = port_request['fixed_ips'] = []
            fixed_ip = {'subnet_id': subnet_v4_id,
                        'ip_address': requested_address}
            fixed_ips.append(fixed_ip)
            mock_create_port.return_value = fake_port

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': requested_address,
            'Options': {}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            cidr=FAKE_IP4_CIDR)
        mock_list_ports.assert_called_with(
            fixed_ips=fixed_ip_existing)
        if existing_port:
            mock_update_port.assert_called_with(fake_neutron_port_id,
                {'port': update_port})
        else:
            mock_create_port.assert_called_with({'port': port_request})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(requested_address + '/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_overlapping_cidr_in_neutron(self,
            mock_list_subnetpools, mock_list_subnets, mock_create_port):
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id2 = uuidutils.generate_uuid()

        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        neutron_network_id2 = uuidutils.generate_uuid()
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_subnet_v4_id2 = uuidutils.generate_uuid()

        # Fake existing Neutron subnets
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, neutron_subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)

        fake_v4_subnet2 = self._get_fake_v4_subnet(
            neutron_network_id2, docker_endpoint_id, neutron_subnet_v4_id2,
            subnetpool_id=fake_kuryr_subnetpool_id2,
            cidr=FAKE_IP4_CIDR)

        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet2['subnet'],
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response
        # faking create_port
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = self._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id,
            neutron_subnet_v4_id=neutron_subnet_v4_id,
            neutron_subnet_v4_address="10.0.0.5")
        mock_create_port.return_value = fake_port
        port_request = {
            'name': 'kuryr-unbound-port',
            'admin_state_up': True,
            'network_id': neutron_network_id,
            'binding:host_id': lib_utils.get_hostname(),
        }
        port_request['fixed_ips'] = []
        fixed_ip = {'subnet_id': neutron_subnet_v4_id}
        port_request['fixed_ips'].append(fixed_ip)

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            cidr=FAKE_IP4_CIDR)
        mock_create_port.assert_called_with(
            {'port': port_request})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.5/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_overlapping_cidr_no_subnet_tags(self,
            mock_list_subnetpools, mock_list_subnets, mock_create_port):
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id2 = uuidutils.generate_uuid()

        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        neutron_network_id2 = uuidutils.generate_uuid()
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_subnet_v4_id2 = uuidutils.generate_uuid()

        # Fake existing Neutron subnets
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, neutron_subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        # Making existing Neutron subnet has no tag attribute
        del fake_v4_subnet['subnet']['tags']

        fake_v4_subnet2 = self._get_fake_v4_subnet(
            neutron_network_id2, docker_endpoint_id, neutron_subnet_v4_id2,
            subnetpool_id=fake_kuryr_subnetpool_id2,
            cidr=FAKE_IP4_CIDR)
        # Making existing Neutron subnet has no tag attribute
        del fake_v4_subnet2['subnet']['tags']

        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet2['subnet'],
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(w_exceptions.InternalServerError.code,
                         response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            cidr=FAKE_IP4_CIDR)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertIn(fake_kuryr_subnetpool_id, decoded_json['Err'])
        self.assertIn(FAKE_IP4_CIDR, decoded_json['Err'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_overlapping_cidr_in_kuryr(self,
            mock_list_subnetpools, mock_list_subnets, mock_create_port):
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id2 = uuidutils.generate_uuid()

        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        neutron_network_id2 = uuidutils.generate_uuid()
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_subnet_v4_id2 = uuidutils.generate_uuid()

        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, neutron_subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR,
            name=utils.make_subnet_name(FAKE_IP4_CIDR))

        fake_v4_subnet2 = self._get_fake_v4_subnet(
            neutron_network_id2, docker_endpoint_id, neutron_subnet_v4_id2,
            subnetpool_id=fake_kuryr_subnetpool_id2,
            cidr=FAKE_IP4_CIDR,
            name=utils.make_subnet_name(FAKE_IP4_CIDR))

        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet2['subnet'],
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response
        # faking create_port
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = self._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id,
            neutron_subnet_v4_id=neutron_subnet_v4_id,
            neutron_subnet_v4_address="10.0.0.5")
        mock_create_port.return_value = fake_port
        port_request = {
            'name': 'kuryr-unbound-port',
            'admin_state_up': True,
            'network_id': neutron_network_id,
            'binding:host_id': lib_utils.get_hostname(),
        }
        port_request['fixed_ips'] = []
        fixed_ip = {'subnet_id': neutron_subnet_v4_id}
        port_request['fixed_ips'].append(fixed_ip)

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            cidr=FAKE_IP4_CIDR)
        mock_create_port.assert_called_with(
            {'port': port_request})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.5/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_for_same_gateway(self,
            mock_list_subnetpools, mock_list_subnets):
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()

        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_v4_subnet['subnet'].update(gateway_ip='10.0.0.1')
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '10.0.0.1',
            'Options': {
                const.REQUEST_ADDRESS_TYPE: const.NETWORK_GATEWAY_OPTIONS
            }
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(cidr=FAKE_IP4_CIDR)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.1/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_for_different_gateway(self,
            mock_list_subnetpools, mock_list_subnets):
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = lib_utils.get_neutron_subnetpool_name(FAKE_IP4_CIDR)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_v4_subnet['subnet'].update(gateway_ip='10.0.0.1')
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '10.0.0.5',  # Different with existed gw ip
            'Options': {
                const.REQUEST_ADDRESS_TYPE: const.NETWORK_GATEWAY_OPTIONS
            }
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(500, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(cidr=FAKE_IP4_CIDR)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        err_message = ("Requested gateway {0} does not match with "
                       "gateway {1} in existed network.").format(
                       '10.0.0.5', '10.0.0.1')
        self.assertEqual({'Err': err_message}, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_release_address(self,
            mock_list_subnetpools, mock_list_subnets, mock_list_ports,
            mock_delete_port):
        # faking list_subnetpools
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = str('-'.join(['kuryrPool', FAKE_IP4_CIDR]))
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR], name=fake_name)
        mock_list_subnetpools.return_value = kuryr_subnetpools

        # faking list_subnets
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            docker_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response

        fake_ip4 = '10.0.0.5'
        # faking list_ports and delete_port
        neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address=fake_ip4,
            device_owner=lib_const.DEVICE_OWNER)

        fake_port['port']['fixed_ips'] = [
            {'subnet_id': subnet_v4_id, 'ip_address': fake_ip4}
        ]

        list_port_response = {'ports': [fake_port['port']]}
        mock_list_ports.return_value = list_port_response

        mock_delete_port.return_value = {}

        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': fake_ip4
        }
        response = self.app.post('/IpamDriver.ReleaseAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            cidr=FAKE_IP4_CIDR)
        mock_list_ports.assert_called_with(
            device_owner=lib_const.DEVICE_OWNER)
        mock_delete_port.assert_called_with(
            fake_port['port']['id'])
