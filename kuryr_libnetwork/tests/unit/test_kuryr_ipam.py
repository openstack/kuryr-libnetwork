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

import ipaddress
from unittest import mock


import ddt
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
FAKE_IP6_CIDR = 'fe80::/64'


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
         {"RequiresMACAddress": True}))
    @ddt.unpack
    def test_remote_ipam_driver_endpoint(self, endpoint, expected):
        response = self.app.post(endpoint)
        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(expected, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @ddt.data((FAKE_IP4_CIDR), (FAKE_IP6_CIDR))
    def test_ipam_driver_request_pool_with_existing_subnet_id(self,
            pool_cidr, mock_list_subnetpools,
            mock_create_subnetpool, mock_add_tag):
        neutron_subnet_v4_id = uuidutils.generate_uuid()

        pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)
        prefixlen = ipaddress.ip_network(str(pool_cidr)).prefixlen
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': prefixlen,
            'prefixes': [pool_cidr],
            'shared': False}

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = pool_name
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        mock_list_subnetpools.return_value = {'subnetpools': []}
        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }

        mock_create_subnetpool.return_value = fake_subnetpool_response

        fake_request = {
            'AddressSpace': '',
            'Pool': pool_cidr,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {
                'neutron.subnet.uuid': neutron_subnet_v4_id
            },
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            name=pool_name, tags=[str(neutron_subnet_v4_id)])
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        mock_add_tag.assert_called_once_with(
            'subnetpools', fake_kuryr_subnetpool_id, neutron_subnet_v4_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @ddt.data((FAKE_IP4_CIDR), (FAKE_IP6_CIDR))
    def test_ipam_driver_request_pool_with_existing_subnet_id_and_shared(self,
            pool_cidr, mock_list_subnetpools,
            mock_create_subnetpool, mock_add_tag):
        neutron_subnet_v4_id = uuidutils.generate_uuid()

        pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)
        prefixlen = ipaddress.ip_network(str(pool_cidr)).prefixlen
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': prefixlen,
            'prefixes': [pool_cidr],
            'shared': True}

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = pool_name
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        mock_list_subnetpools.return_value = {'subnetpools': []}
        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }

        mock_create_subnetpool.return_value = fake_subnetpool_response

        fake_request = {
            'AddressSpace': '',
            'Pool': pool_cidr,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {
                'neutron.subnet.uuid': neutron_subnet_v4_id,
                'neutron.net.shared': True
            },
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            name=pool_name, tags=[str(neutron_subnet_v4_id)])
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        mock_add_tag.assert_called_once_with(
            'subnetpools', fake_kuryr_subnetpool_id, neutron_subnet_v4_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @ddt.data((FAKE_IP4_CIDR), (FAKE_IP6_CIDR))
    def test_ipam_driver_request_pool_with_existing_subnet_name(self,
            pool_cidr, mock_list_subnets, mock_list_subnetpools,
            mock_create_subnetpool, mock_add_tag):
        # faking list_subnets
        docker_endpoint_id = lib_utils.get_hash()
        neutron_network_id = uuidutils.generate_uuid()
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_subnet_v4_name = utils.make_subnet_name(FAKE_IP4_CIDR)

        # Faking existing Neutron subnets
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id,
            subnet_v4_id=neutron_subnet_v4_id,
            cidr=FAKE_IP4_CIDR, name=neutron_subnet_v4_name)

        fake_subnets = {
            'subnets': [
                fake_v4_subnet['subnet'],
            ]
        }

        mock_list_subnets.return_value = fake_subnets
        pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)
        prefixlen = ipaddress.ip_network(str(pool_cidr)).prefixlen
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': prefixlen,
            'prefixes': [pool_cidr],
            'shared': False}

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = pool_name
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        mock_list_subnetpools.return_value = {'subnetpools': []}
        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }

        mock_create_subnetpool.return_value = fake_subnetpool_response

        fake_request = {
            'AddressSpace': '',
            'Pool': pool_cidr,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {
                'neutron.subnet.name': neutron_subnet_v4_name
            },
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(name=neutron_subnet_v4_name)
        mock_list_subnetpools.assert_called_with(
            name=pool_name, tags=[str(neutron_subnet_v4_id)])
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        mock_add_tag.assert_called_once_with(
            'subnetpools', fake_kuryr_subnetpool_id, neutron_subnet_v4_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @ddt.data((FAKE_IP4_CIDR), (FAKE_IP6_CIDR))
    def test_ipam_driver_request_pool_with_user_pool(self, pool_cidr,
            mock_list_subnets, mock_list_subnetpools, mock_create_subnetpool):
        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet
        pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)
        prefixlen = ipaddress.ip_network(str(pool_cidr)).prefixlen
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': prefixlen,
            'prefixes': [pool_cidr],
            'shared': False}

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = pool_name
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
        mock_list_subnetpools.return_value = {'subnetpools': []}
        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }

        mock_create_subnetpool.return_value = fake_subnetpool_response

        fake_request = {
            'AddressSpace': '',
            'Pool': pool_cidr,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {},
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(cidr=pool_cidr)
        mock_list_subnetpools.assert_called_with(name=fake_name)
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True, FAKE_IP4_CIDR), (True, FAKE_IP6_CIDR),
              (False, FAKE_IP4_CIDR), (False, FAKE_IP6_CIDR))
    @ddt.unpack
    def test_ipam_driver_request_pool_with_pool_name_option(self,
            use_tag_ext, pool_cidr, mock_app, mock_list_subnets,
            mock_list_subnetpools, mock_add_tag):
        mock_app.tag_ext = use_tag_ext
        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_name = 'fake_pool_name'
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
            options = {
                const.NEUTRON_POOL_NAME_OPTION: fake_name}
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr],
                name=fake_name)
            options = {
                const.NEUTRON_V6_POOL_NAME_OPTION: fake_name}
        mock_list_subnetpools.return_value = kuryr_subnetpools

        fake_request = {
            'AddressSpace': '',
            'Pool': pool_cidr,
            'SubPool': pool_cidr,
            'Options': options,
            'V6': False if pool_cidr == FAKE_IP4_CIDR else True
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(cidr=pool_cidr)
        if mock_app.tag_ext:
            mock_add_tag.assert_called_once_with(
                'subnetpools', fake_kuryr_subnetpool_id,
                const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)
        else:
            mock_add_tag.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True, FAKE_IP4_CIDR), (True, FAKE_IP6_CIDR),
              (False, FAKE_IP4_CIDR), (False, FAKE_IP6_CIDR))
    @ddt.unpack
    def test_ipam_driver_request_pool_with_pool_id_option(self,
            use_tag_ext, pool_cidr, mock_app, mock_list_subnets,
            mock_list_subnetpools, mock_add_tag):
        mock_app.tag_ext = use_tag_ext
        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr])
            options = {
                const.NEUTRON_POOL_UUID_OPTION: fake_kuryr_subnetpool_id}
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[pool_cidr])
            options = {
                const.NEUTRON_V6_POOL_UUID_OPTION: fake_kuryr_subnetpool_id}
        mock_list_subnetpools.return_value = kuryr_subnetpools

        fake_request = {
            'AddressSpace': '',
            'Pool': pool_cidr,
            'SubPool': pool_cidr,
            'Options': options,
            'V6': False if pool_cidr == FAKE_IP4_CIDR else True
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(cidr=pool_cidr)
        if mock_app.tag_ext:
            mock_add_tag.assert_called_once_with(
                'subnetpools', fake_kuryr_subnetpool_id,
                const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)
        else:
            mock_add_tag.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_kuryr_subnetpool_id, decoded_json['PoolID'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True, FAKE_IP4_CIDR), (True, FAKE_IP6_CIDR),
              (False, FAKE_IP4_CIDR), (False, FAKE_IP6_CIDR))
    @ddt.unpack
    def test_ipam_driver_request_pool_with_unmatched_cidr(self,
            use_tag_ext, pool_cidr, mock_app, mock_list_subnets,
            mock_list_subnetpools, mock_create_subnetpool, mock_add_tag):
        mock_app.tag_ext = use_tag_ext
        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet
        subnet_ip4_cidr = '10.0.0.0/24'
        subnet_ip6_cidr = 'fe80::/68'
        if pool_cidr == FAKE_IP4_CIDR:
            subnet_cidr = subnet_ip4_cidr
        else:
            subnet_cidr = subnet_ip6_cidr
        pool_name = lib_utils.get_neutron_subnetpool_name(subnet_cidr)
        prefixlen = ipaddress.ip_network(str(subnet_cidr)).prefixlen
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': prefixlen,
            'prefixes': [subnet_cidr],
            'shared': False}

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_existing_subnetpool_id = uuidutils.generate_uuid()
        if pool_cidr == FAKE_IP4_CIDR:
            kuryr_subnetpools = self._get_fake_v4_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[subnet_ip4_cidr])
            existing_subnetpools = self._get_fake_v4_subnetpools(
                fake_existing_subnetpool_id, prefixes=[pool_cidr])
            options = {
                const.NEUTRON_POOL_UUID_OPTION: fake_existing_subnetpool_id}
        else:
            kuryr_subnetpools = self._get_fake_v6_subnetpools(
                fake_kuryr_subnetpool_id, prefixes=[subnet_ip6_cidr])
            existing_subnetpools = self._get_fake_v6_subnetpools(
                fake_existing_subnetpool_id, prefixes=[pool_cidr])
            options = {
                const.NEUTRON_V6_POOL_UUID_OPTION: fake_existing_subnetpool_id}
        mock_list_subnetpools.side_effect = [
            existing_subnetpools,
            {'subnetpools': []}
        ]

        fake_subnetpool_response = {
            'subnetpool': kuryr_subnetpools['subnetpools'][0]
        }
        mock_create_subnetpool.return_value = fake_subnetpool_response

        if pool_cidr == FAKE_IP4_CIDR:
            subnet_cidr = subnet_ip4_cidr
            fake_request = {
                'AddressSpace': '',
                'Pool': subnet_cidr,
                'SubPool': subnet_cidr,
                'Options': options,
                'V6': False,
            }
        else:
            subnet_cidr = subnet_ip6_cidr
            fake_request = {
                'AddressSpace': '',
                'Pool': subnet_cidr,
                'SubPool': subnet_cidr,
                'Options': options,
                'V6': True,
            }
        response = self.app.post('/IpamDriver.RequestPool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(cidr=subnet_cidr)
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        if mock_app.tag_ext:
            mock_add_tag.assert_called_once_with(
                'subnetpools', fake_existing_subnetpool_id,
                const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)
        else:
            mock_add_tag.assert_not_called()
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
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True), (False))
    def test_ipam_driver_release_pool(self,
                                      use_tag_ext,
                                      mock_app,
                                      mock_list_subnetpools,
                                      mock_list_subnets,
                                      mock_remove_tag,
                                      mock_delete_subnetpool):
        mock_app.tag_ext = use_tag_ext

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
        if mock_app.tag_ext:
            mock_list_subnetpools.assert_called_with(
                id=fake_kuryr_subnetpool_id)
            mock_list_subnets.assert_any_call(
                cidr=FAKE_IP4_CIDR)
            mock_remove_tag.assert_called_with('subnets',
                                               subnet_v4_id,
                                               fake_kuryr_subnetpool_id)
        mock_delete_subnetpool.assert_called_with(fake_kuryr_subnetpool_id)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((True), (False))
    def test_ipam_driver_release_pool_with_pool_name_option(
            self, use_tag_ext, mock_app, mock_list_subnetpools,
            mock_list_subnets, mock_remove_tag):
        mock_app.tag_ext = use_tag_ext

        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_subnetpool_name = 'fake_pool_name'
        fake_tags = []
        if mock_app.tag_ext:
            fake_tags.append(const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)
        kuryr_subnetpools = self._get_fake_v4_subnetpools(
            fake_kuryr_subnetpool_id, prefixes=[FAKE_IP4_CIDR],
            name=fake_subnetpool_name, tags=fake_tags)
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

        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id
        }
        response = self.app.post('/IpamDriver.ReleasePool',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        if mock_app.tag_ext:
            mock_list_subnetpools.assert_called_with(
                id=fake_kuryr_subnetpool_id)
            mock_list_subnets.assert_called_with(
                cidr=FAKE_IP4_CIDR)
            mock_remove_tag.assert_any_call('subnets',
                                            subnet_v4_id,
                                            fake_kuryr_subnetpool_id)
            mock_remove_tag.assert_any_call(
                'subnetpools', fake_kuryr_subnetpool_id,
                const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)

    @mock.patch('kuryr_libnetwork.controllers._neutron_port_add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_request_address(self, use_tag_ext, mock_app,
            mock_list_subnets, mock_create_port, mock_port_add_tag):
        mock_app.tag_ext = use_tag_ext
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
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
        fake_mac_address = 'fa:16:3e:ca:59:88'
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address="10.0.0.5",
            neutron_mac_address=fake_mac_address)
        port_request = {
            'name': const.KURYR_UNBOUND_PORT,
            'admin_state_up': True,
            'network_id': neutron_network_id,
        }
        fixed_ips = port_request['fixed_ips'] = []
        fixed_ip = {'subnet_id': subnet_v4_id}
        fixed_ips.append(fixed_ip)

        mock_create_port.return_value = fake_port
        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: fake_mac_address}
        }
        mock_port_add_tag.return_value = None
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_create_port.assert_called_with({'port': port_request})
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.5/16', decoded_json['Address'])
        if mock_app.tag_ext:
            mock_port_add_tag.assert_called()
        else:
            mock_port_add_tag.assert_not_called()

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_request_address_when_subnet_not_exist(self,
            mock_list_subnetpools, mock_list_subnets):
        requested_address = '10.0.0.5'
        fake_mac_address = 'fa:16:3e:ca:59:88'
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
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: fake_mac_address}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(500, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(cidr=FAKE_IP4_CIDR)

    @mock.patch('kuryr_libnetwork.controllers._neutron_port_add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_request_specific_address(self,
            use_tag_ext, mock_app, mock_list_subnets, mock_list_ports,
            mock_update_port, mock_create_port, mock_port_add_tag):
        mock_app.tag_ext = use_tag_ext
        # faking list_subnets
        neutron_network_id = uuidutils.generate_uuid()
        docker_endpoint_id = lib_utils.get_hash()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
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
        requested_address = '10.0.0.5'
        fake_mac_address = 'fa:16:3e:ca:59:88'
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address=requested_address,
            neutron_mac_address=fake_mac_address)

        fixed_ip_existing = [('subnet_id=%s' % subnet_v4_id)]
        fixed_ip_existing.append('ip_address=%s' % requested_address)
        fake_ports_response = {'ports': []}
        mock_list_ports.return_value = fake_ports_response

        port_request = {
            'name': const.KURYR_UNBOUND_PORT,
            'admin_state_up': True,
            'network_id': neutron_network_id,
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
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: fake_mac_address}
        }
        mock_port_add_tag.return_value = None
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_list_ports.assert_has_calls([
            mock.call(fixed_ips=fixed_ip_existing),
            mock.call(
                mac_address=fake_mac_address,
                fixed_ips='subnet_id=%s' % fake_v4_subnet['subnet']['id'])])
        mock_create_port.assert_called_with({'port': port_request})
        if mock_app.tag_ext:
            mock_port_add_tag.assert_called()
        else:
            mock_port_add_tag.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(requested_address + '/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers._neutron_port_add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_request_specific_address_existing_port(self,
            use_tag_ext, mock_app, mock_list_subnets, mock_list_ports,
            mock_create_port, mock_port_add_tag):
        mock_app.tag_ext = use_tag_ext
        # faking list_subnets
        neutron_network_id = uuidutils.generate_uuid()
        docker_endpoint_id = lib_utils.get_hash()
        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v6_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_v6_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_v6_subnet = self._get_fake_v6_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v6_id,
            subnetpool_id=fake_kuryr_subnetpool_v6_id,
            cidr=FAKE_IP6_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        fake_subnet_response_v6 = {
            'subnets': [
                fake_v6_subnet['subnet']
            ]
        }
        mock_list_subnets.side_effect = [
            fake_subnet_response, fake_subnet_response_v6]

        # faking update_port or create_port
        requested_address = '10.0.0.5'
        requested_address_v6 = 'fe80::6'
        requested_mac_address = 'fa:16:3e:86:a0:fe'
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id, subnet_v6_id,
            neutron_subnet_v4_address=requested_address,
            neutron_subnet_v6_address=requested_address_v6,
            neutron_mac_address=requested_mac_address)

        fixed_ip_existing = [('subnet_id=%s' % subnet_v4_id)]
        fixed_ipv6_existing = [('subnet_id=%s' % subnet_v6_id)]
        fixed_ip_existing.append('ip_address=%s' % requested_address)
        fixed_ipv6_existing.append('ip_address=%s' % requested_address_v6)
        fake_existing_port = dict(fake_port['port'])
        fake_existing_port['binding:host_id'] = ''
        fake_existing_port['binding:vif_type'] = 'unbound'
        fake_ports_response = {'ports': [fake_existing_port]}
        fake_existing_port_2 = dict(fake_port['port'])
        fake_existing_port_2['name'] = const.NEUTRON_UNBOUND_PORT
        fake_existing_port_2['binding:host_id'] = lib_utils.get_hostname()
        fake_ports_response_2 = {'ports': [fake_existing_port_2]}
        mock_list_ports.side_effect = [
            fake_ports_response, fake_ports_response_2]

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': requested_address,
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: requested_mac_address}
        }
        mock_port_add_tag.return_value = None
        response = self.app.post('/IpamDriver.RequestAddress',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(requested_address + '/16', decoded_json['Address'])

        fake_request_2 = {
            'PoolID': fake_kuryr_subnetpool_v6_id,
            'Address': requested_address_v6,
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: requested_mac_address}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request_2))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(requested_address_v6 + '/64', decoded_json['Address'])

        mock_list_subnets.assert_has_calls([
            mock.call(subnetpool_id=fake_kuryr_subnetpool_id),
            mock.call(subnetpool_id=fake_kuryr_subnetpool_v6_id)])
        mock_list_ports.assert_has_calls([
            mock.call(fixed_ips=fixed_ip_existing),
            mock.call(fixed_ips=fixed_ipv6_existing)])
        if mock_app.tag_ext:
            self.assertEqual(2, mock_port_add_tag.call_count)
        else:
            self.assertEqual(0, mock_port_add_tag.call_count)

    @mock.patch('kuryr_libnetwork.controllers._neutron_port_add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_request_specific_mac_address_existing_port(self,
            use_tag_ext, mock_app, mock_list_subnets, mock_list_ports,
            mock_create_port, mock_port_add_tag):
        mock_app.tag_ext = use_tag_ext
        # faking list_subnets
        neutron_network_id = uuidutils.generate_uuid()
        docker_endpoint_id = lib_utils.get_hash()
        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v6_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_v6_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_v6_subnet = self._get_fake_v6_subnet(
            neutron_network_id, docker_endpoint_id, subnet_v6_id,
            subnetpool_id=fake_kuryr_subnetpool_v6_id,
            cidr=FAKE_IP6_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        fake_subnet_response_v6 = {
            'subnets': [
                fake_v6_subnet['subnet']
            ]
        }
        mock_list_subnets.side_effect = [
            fake_subnet_response, fake_subnet_response_v6]

        # faking update_port or create_port
        fake_address = '10.0.0.5'
        fake_address_v6 = 'fe80::6'
        requested_mac_address = 'fa:16:3e:86:a0:fe'
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id, subnet_v6_id,
            neutron_subnet_v4_address=fake_address,
            neutron_subnet_v6_address=fake_address_v6,
            neutron_mac_address=requested_mac_address)

        fixed_ip_existing = [('subnet_id=%s' % subnet_v4_id)]
        fixed_ipv6_existing = [('subnet_id=%s' % subnet_v6_id)]
        fixed_ip_existing.append('ip_address=%s' % fake_address)
        fixed_ipv6_existing.append('ip_address=%s' % fake_address_v6)
        fake_existing_port = dict(fake_port['port'])
        fake_existing_port['binding:host_id'] = ''
        fake_existing_port['binding:vif_type'] = 'unbound'
        fake_ports_response = {'ports': [fake_existing_port]}
        fake_existing_port_2 = dict(fake_port['port'])
        fake_existing_port_2['name'] = const.NEUTRON_UNBOUND_PORT
        fake_existing_port_2['binding:host_id'] = lib_utils.get_hostname()
        fake_ports_response_2 = {'ports': [fake_existing_port_2]}
        mock_list_ports.side_effect = [
            fake_ports_response, fake_ports_response_2]

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: requested_mac_address}
        }
        mock_port_add_tag.return_value = None
        response = self.app.post('/IpamDriver.RequestAddress',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_address + '/16', decoded_json['Address'])

        fake_request_2 = {
            'PoolID': fake_kuryr_subnetpool_v6_id,
            'Address': '',
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: requested_mac_address}
        }
        response = self.app.post('/IpamDriver.RequestAddress',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request_2))

        self.assertEqual(200, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual(fake_address_v6 + '/64', decoded_json['Address'])

        mock_list_subnets.assert_has_calls([
            mock.call(subnetpool_id=fake_kuryr_subnetpool_id),
            mock.call(subnetpool_id=fake_kuryr_subnetpool_v6_id)])
        mock_list_ports.assert_has_calls([
            mock.call(mac_address=requested_mac_address,
                      fixed_ips='subnet_id=%s' % subnet_v4_id),
            mock.call(mac_address=requested_mac_address,
                      fixed_ips='subnet_id=%s' % subnet_v6_id)])
        if mock_app.tag_ext:
            self.assertEqual(2, mock_port_add_tag.call_count)
        else:
            self.assertEqual(0, mock_port_add_tag.call_count)

    @mock.patch('kuryr_libnetwork.controllers._neutron_port_add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_request_address_overlapping_cidr_in_neutron(self,
            use_tag_ext, mock_app, mock_list_subnetpools, mock_list_subnets,
            mock_create_port, mock_port_add_tag):
        mock_app.tag_ext = use_tag_ext
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
            cidr=FAKE_IP4_CIDR, name=utils.make_subnet_name(FAKE_IP4_CIDR),
            tags=[fake_kuryr_subnetpool_id])

        fake_v4_subnet2 = self._get_fake_v4_subnet(
            neutron_network_id2, docker_endpoint_id, neutron_subnet_v4_id2,
            cidr=FAKE_IP4_CIDR, name=utils.make_subnet_name(FAKE_IP4_CIDR),
            tags=[fake_kuryr_subnetpool_id2])

        fake_subnet_response = {
            'subnets': []
        }
        fake_subnet_response2 = {
            'subnets': [
                fake_v4_subnet2['subnet'],
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.side_effect = [
            fake_subnet_response, fake_subnet_response2]
        # faking create_port
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_mac_address = 'fa:16:3e:86:a0:fe'
        fake_port = self._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id,
            neutron_subnet_v4_id=neutron_subnet_v4_id,
            neutron_subnet_v4_address="10.0.0.5",
            neutron_mac_address=fake_mac_address)
        mock_create_port.return_value = fake_port
        port_request = {
            'name': const.KURYR_UNBOUND_PORT,
            'admin_state_up': True,
            'network_id': neutron_network_id,
        }
        port_request['fixed_ips'] = []
        fixed_ip = {'subnet_id': neutron_subnet_v4_id}
        port_request['fixed_ips'].append(fixed_ip)

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: fake_mac_address}
        }
        mock_port_add_tag.return_value = None
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
        if mock_app.tag_ext:
            mock_port_add_tag.assert_called()
        else:
            mock_port_add_tag.assert_not_called()
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
            'subnets': []
        }
        fake_subnet_response2 = {
            'subnets': [
                fake_v4_subnet2['subnet'],
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.side_effect = [
            fake_subnet_response, fake_subnet_response2]

        # Testing container ip allocation
        fake_mac_address = 'fa:16:3e:86:a0:fe'
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: fake_mac_address}
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

    @mock.patch('kuryr_libnetwork.controllers._neutron_port_add_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_request_address_overlapping_cidr_in_kuryr(
            self, use_tag_ext, mock_app, mock_list_subnetpools,
            mock_list_subnets, mock_create_port, mock_port_add_tag):
        mock_app.tag_ext = use_tag_ext
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
        neutron_network_id2 = uuidutils.generate_uuid()
        neutron_subnet_v4_id = uuidutils.generate_uuid()
        neutron_subnet_v4_id2 = uuidutils.generate_uuid()

        fake_v4_subnet = self._get_fake_v4_subnet(
            neutron_network_id, docker_endpoint_id, neutron_subnet_v4_id,
            cidr=FAKE_IP4_CIDR,
            name=utils.make_subnet_name(FAKE_IP4_CIDR))

        fake_v4_subnet2 = self._get_fake_v4_subnet(
            neutron_network_id2, docker_endpoint_id, neutron_subnet_v4_id2,
            cidr=FAKE_IP4_CIDR,
            name=utils.make_subnet_name(FAKE_IP4_CIDR))

        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet'],
                fake_v4_subnet2['subnet'],
            ]
        }
        mock_list_subnets.return_value = fake_subnet_response
        # faking create_port
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_mac_address = 'fa:16:3e:86:a0:fe'
        fake_port = self._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id,
            neutron_subnet_v4_id=neutron_subnet_v4_id,
            neutron_subnet_v4_address="10.0.0.5",
            neutron_mac_address=fake_mac_address)
        mock_create_port.return_value = fake_port
        port_request = {
            'name': const.KURYR_UNBOUND_PORT,
            'admin_state_up': True,
            'network_id': neutron_network_id,
        }
        port_request['fixed_ips'] = []
        fixed_ip = {'subnet_id': neutron_subnet_v4_id}
        port_request['fixed_ips'].append(fixed_ip)

        # Testing container ip allocation
        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': '',  # Querying for container address
            'Options': {const.DOCKER_MAC_ADDRESS_OPTION: fake_mac_address}
        }
        mock_port_add_tag.return_value = None
        response = self.app.post('/IpamDriver.RequestAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnetpools.assert_called_with(
            id=fake_kuryr_subnetpool_id)
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_create_port.assert_called_with(
            {'port': port_request})
        if mock_app.tag_ext:
            mock_port_add_tag.assert_called()
        else:
            mock_port_add_tag.assert_not_called()
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.5/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_ipam_driver_request_address_for_same_gateway(self,
            mock_list_subnets):
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
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
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertEqual('10.0.0.1/16', decoded_json['Address'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_ipam_driver_request_address_for_different_gateway(self,
            mock_list_subnets):
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
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
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        err_message = ("Requested gateway {0} does not match with "
                       "gateway {1} in existed network.").format(
                           '10.0.0.5', '10.0.0.1')
        self.assertEqual({'Err': err_message}, decoded_json)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    def test_ipam_driver_release_address(self,
            mock_list_subnets, mock_list_ports, mock_delete_port):
        # faking list_subnets
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        subnet_v4_id = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            docker_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR,
            name=utils.make_subnet_name(FAKE_IP4_CIDR))
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
            device_owner=lib_const.DEVICE_OWNER,
            tags=lib_const.DEVICE_OWNER)

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
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_list_ports.assert_called()
        mock_delete_port.assert_called_with(
            fake_port['port']['id'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_ipam_driver_release_address_w_existing_subnet(self,
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
            'subnets': []
        }
        fake_subnet_response2 = {
            'subnets': [
                fake_v4_subnet['subnet']
            ]
        }
        mock_list_subnets.side_effect = [
            fake_subnet_response, fake_subnet_response2]

        fake_ip4 = '10.0.0.5'
        # faking list_ports and delete_port
        neutron_network_id = uuidutils.generate_uuid()
        fake_neutron_port_id = uuidutils.generate_uuid()
        fake_port = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address=fake_ip4,
            device_owner=lib_const.DEVICE_OWNER,
            tags=lib_const.DEVICE_OWNER)

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
        mock_list_ports.assert_called()
        mock_delete_port.assert_called_with(
            fake_port['port']['id'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    def test_ipam_driver_release_address_w_existing_port(self,
            mock_app, mock_list_subnets, mock_list_ports, mock_delete_port,
            mock_update_port, mock_remove_tag):
        # TODO(hongbin): Current implementation still delete existing ports
        # if tag extension is not enabled. This needs to be fixed and test
        # case needs to be added after.
        mock_app.tag_ext = True
        # faking list_subnets
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
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
            device_owner=lib_const.DEVICE_OWNER,
            tags=const.KURYR_EXISTING_NEUTRON_PORT)

        fake_port['port']['fixed_ips'] = [
            {'subnet_id': subnet_v4_id, 'ip_address': fake_ip4}
        ]

        list_port_response = {'ports': [fake_port['port']]}
        mock_list_ports.return_value = list_port_response

        fake_request = {
            'PoolID': fake_kuryr_subnetpool_id,
            'Address': fake_ip4
        }
        response = self.app.post('/IpamDriver.ReleaseAddress',
                                content_type='application/json',
                                data=jsonutils.dumps(fake_request))

        self.assertEqual(200, response.status_code)
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_list_ports.assert_called()
        expect_updated_port = {'device_owner': '',
                               'device_id': '', 'binding:host_id': ''}
        mock_update_port.assert_called_with(fake_port['port']['id'],
                                            {'port': expect_updated_port})
        mock_delete_port.assert_not_called()
        mock_remove_tag.assert_called_with('ports',
                                           fake_port['port']['id'],
                                           const.KURYR_EXISTING_NEUTRON_PORT)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    @ddt.data((False), (True))
    def test_ipam_driver_release_address_w_same_ip_and_cidr(
            self, use_tag_ext, mock_app, mock_list_subnets, mock_list_ports,
            mock_delete_port):
        # It checks only the kuryr port is removed even if the other port
        # has the same IP and belongs to a subnet with the same subnetpool_id
        # faking list_subnets
        mock_app.tag_ext = use_tag_ext
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        # faking list_subnets
        docker_network_id = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        no_kuryr_endpoint_id = lib_utils.get_hash()
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
        fake_port_no_kuryr = base.TestKuryrBase._get_fake_port(
            no_kuryr_endpoint_id, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id,
            neutron_subnet_v4_address=fake_ip4)
        fake_port_no_kuryr['port']['name'] = 'port0'

        if use_tag_ext:
            fake_port['port']['tags'] = [lib_const.DEVICE_OWNER]
        fake_port['port']['fixed_ips'] = [
            {'subnet_id': subnet_v4_id, 'ip_address': fake_ip4}
        ]
        fake_port_no_kuryr['port']['fixed_ips'] = [
            {'subnet_id': subnet_v4_id, 'ip_address': fake_ip4}
        ]

        list_port_response = {'ports': [fake_port['port'],
                                        fake_port_no_kuryr['port']]}
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
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_list_ports.assert_called()
        mock_delete_port.assert_called_once_with(
            fake_port['port']['id'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.remove_tag')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.update_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.delete_port')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_ports')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app')
    def test_ipam_driver_release_address_w_existing_port_w_same_ip_and_cidr(
            self, mock_app, mock_list_subnets, mock_list_ports,
            mock_delete_port, mock_update_port, mock_remove_tag):
        # TODO(hongbin): Current implementation still delete existing ports
        # if tag extension is not enabled. This needs to be fixed and test
        # case needs to be added after.
        mock_app.tag_ext = True
        fake_kuryr_subnetpool_id = uuidutils.generate_uuid()
        fake_kuryr_subnetpool_id2 = uuidutils.generate_uuid()
        # faking list_subnets
        docker_network_id = lib_utils.get_hash()
        docker_network_id2 = lib_utils.get_hash()
        docker_endpoint_id = lib_utils.get_hash()
        docker_endpoint_id2 = lib_utils.get_hash()
        subnet_v4_id = uuidutils.generate_uuid()
        subnet_v4_id2 = uuidutils.generate_uuid()
        fake_v4_subnet = self._get_fake_v4_subnet(
            docker_network_id, docker_endpoint_id, subnet_v4_id,
            subnetpool_id=fake_kuryr_subnetpool_id,
            cidr=FAKE_IP4_CIDR)
        fake_v4_subnet2 = self._get_fake_v4_subnet(
            docker_network_id2, docker_endpoint_id2, subnet_v4_id2,
            subnetpool_id=fake_kuryr_subnetpool_id2,
            cidr=FAKE_IP4_CIDR)
        fake_subnet_response = {
            'subnets': [
                fake_v4_subnet['subnet'], fake_v4_subnet2['subnet']
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
            device_owner=lib_const.DEVICE_OWNER,
            tags=[const.KURYR_EXISTING_NEUTRON_PORT])
        fake_port2 = base.TestKuryrBase._get_fake_port(
            docker_endpoint_id2, neutron_network_id,
            fake_neutron_port_id, lib_const.PORT_STATUS_ACTIVE,
            subnet_v4_id2,
            neutron_subnet_v4_address=fake_ip4,
            device_owner=lib_const.DEVICE_OWNER,
            tags=[const.KURYR_EXISTING_NEUTRON_PORT])

        fake_port['port']['fixed_ips'] = [
            {'subnet_id': subnet_v4_id, 'ip_address': fake_ip4}
        ]
        fake_port2['port']['fixed_ips'] = [
            {'subnet_id': subnet_v4_id2, 'ip_address': fake_ip4}
        ]

        list_port_response = {'ports': [fake_port['port'],
                                        fake_port2['port']]}
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
        mock_list_subnets.assert_called_with(
            subnetpool_id=fake_kuryr_subnetpool_id)
        mock_list_ports.assert_called()
        expect_updated_port = {'device_owner': '',
                               'device_id': '', 'binding:host_id': ''}
        mock_update_port.assert_called_once_with(fake_port['port']['id'],
                                            {'port': expect_updated_port})
        mock_delete_port.assert_not_called()
        mock_remove_tag.assert_called_once_with('ports',
                                           fake_port['port']['id'],
                                           const.KURYR_EXISTING_NEUTRON_PORT)
