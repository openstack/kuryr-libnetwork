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
from neutronclient.common import exceptions
from oslo_serialization import jsonutils

from kuryr.lib import utils as lib_utils
from kuryr_libnetwork.tests.unit import base


@ddt.ddt
class TestIpamRequestPoolFailures(base.TestKuryrFailures):
    """Unit tests for testing request pool failures.

    This test covers error responses listed in the spec:
    https://docs.openstack.org/api-ref/network/v2/index.html#subnet-pools-extension-subnetpools # noqa
    """
    def _invoke_create_request(self, pool):
        fake_request = {
            'AddressSpace': '',
            'Pool': pool,
            'SubPool': '',  # In the case --ip-range is not given
            'Options': {},
            'V6': False
        }
        response = self.app.post('/IpamDriver.RequestPool',
                                 content_type='application/json',
                                 data=jsonutils.dumps(fake_request))
        return response

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.create_subnetpool')
    @ddt.data(exceptions.Unauthorized, exceptions.Forbidden,
              exceptions.NotFound)
    def test_request_pool_create_failures(self, GivenException,
            mock_create_subnetpool, mock_list_subnetpools, mock_list_subnets):
        pool_name = lib_utils.get_neutron_subnetpool_name("10.0.0.0/16")
        new_subnetpool = {
            'name': pool_name,
            'default_prefixlen': 16,
            'prefixes': ['10.0.0.0/16'],
            'shared': False}

        fake_subnet = {"subnets": []}
        mock_list_subnets.return_value = fake_subnet

        fake_subnet_pools = {'subnetpools': []}
        mock_list_subnetpools.return_value = fake_subnet_pools

        mock_create_subnetpool.side_effect = GivenException
        pool = '10.0.0.0/16'
        response = self._invoke_create_request(pool)

        self.assertEqual(GivenException.status_code, response.status_code)
        mock_list_subnets.assert_called_with(cidr='10.0.0.0/16')
        mock_list_subnetpools.assert_called_with(name=pool_name)
        mock_create_subnetpool.assert_called_with(
            {'subnetpool': new_subnetpool})
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertEqual(
            {'Err': GivenException.message}, decoded_json)

    def test_request_pool_bad_request_failure(self):
        pool = 'pool-should-be-cidr'
        response = self._invoke_create_request(pool)

        self.assertEqual(400, response.status_code)
        decoded_json = jsonutils.loads(response.data)
        self.assertIn('Err', decoded_json)
        self.assertIn(pool, decoded_json['Err'])
        self.assertIn('Pool', decoded_json['Err'])

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnets')
    @mock.patch('kuryr_libnetwork.controllers.app.neutron.list_subnetpools')
    def test_request_pool_list_subnetpool_failure(self,
                        mock_list_subnetpools, mock_list_subnets):
        fake_subnet = {"subnets": []}
        fake_pool_name = lib_utils.get_neutron_subnetpool_name("10.0.0.0/16")
        mock_list_subnets.return_value = fake_subnet

        ex = exceptions.Unauthorized
        mock_list_subnetpools.side_effect = ex

        pool = '10.0.0.0/16'
        response = self._invoke_create_request(pool)
        mock_list_subnets.assert_called_with(cidr='10.0.0.0/16')
        mock_list_subnetpools.assert_called_with(name=fake_pool_name)
        self.assertEqual(ex.status_code, response.status_code)
