#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import ddt
import mock
import os
from six.moves.urllib import parse
import sys

from neutronclient.common import exceptions as n_exceptions

from kuryr.lib import exceptions
from kuryr_libnetwork import config
from kuryr_libnetwork import controllers
from kuryr_libnetwork.server import start
from kuryr_libnetwork.tests.unit import base


@ddt.ddt
class ConfigurationTest(base.TestKuryrBase):

    def test_defaults(self):
        basepath = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                '../../..'))
        self.assertEqual(basepath,
                         config.CONF.pybasedir)
        self.assertEqual('/usr/libexec/kuryr',
                         config.CONF.bindir)
        self.assertEqual('http://127.0.0.1:23750',
                         config.CONF.kuryr_uri)

        self.assertEqual('kuryr',
                         config.CONF.neutron.default_subnetpool_v4)

        self.assertEqual('kuryr6',
                         config.CONF.neutron.default_subnetpool_v6)

        self.assertEqual('kuryr_libnetwork.port_driver.drivers.veth',
                         config.CONF.port_driver)

    @mock.patch('kuryr_libnetwork.controllers.check_for_neutron_tag_support')
    @mock.patch('kuryr_libnetwork.controllers.check_for_neutron_ext_support')
    @mock.patch('kuryr_libnetwork.controllers.neutron_client')
    @mock.patch('kuryr_libnetwork.app.run')
    def test_start(self, mock_run, mock_neutron_client,
                   mock_check_neutron_ext_support,
                   mock_check_for_neutron_tag_support):
        with mock.patch.object(sys, 'argv', ['prog']):
            start()
        kuryr_uri = parse.urlparse(config.CONF.kuryr_uri)
        mock_neutron_client.assert_called_once()
        mock_check_neutron_ext_support.assert_called_once()
        mock_check_for_neutron_tag_support.assert_called_once_with()
        mock_run.assert_called_once_with(kuryr_uri.hostname, 23750,
            ssl_context=None)

    def test_check_for_neutron_ext_support_with_ex(self):
        with mock.patch.object(controllers.app.neutron,
                            'show_extension') as mock_extension:
            ext_alias = "subnet_allocation"
            err = n_exceptions.NotFound.status_code
            ext_not_found_ex = n_exceptions.NeutronClientException(
                status_code=err,
                message="")
            mock_extension.side_effect = ext_not_found_ex
            ex = exceptions.MandatoryApiMissing
            self.assertRaises(ex, controllers.check_for_neutron_ext_support)
            mock_extension.assert_called_once_with(ext_alias)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_extension')
    def test_check_for_neutron_tag_support_with_modern_ext(self,
                                                           mock_extension):
        controllers.check_for_neutron_tag_support()
        mock_extension.assert_called_once_with('standard-attr-tag')
        self.assertTrue(controllers.app.tag)
        self.assertTrue(controllers.app.tag_ext)

    @mock.patch('kuryr_libnetwork.controllers.app.neutron.show_extension')
    @ddt.data({'tag': True, 'tag-ext': True},
              {'tag': True, 'tag-ext': False},
              {'tag': False, 'tag-ext': True},
              {'tag': False, 'tag-ext': False})
    def test_check_for_neutron_tag_support_with_legacy_ext(self, ext_matrix,
                                                           mock_extension):
        err = n_exceptions.NotFound.status_code
        ext_not_found_ex = n_exceptions.NeutronClientException(
            status_code=err,
            message="")

        def mock_fn(ext):
            if not ext_matrix.get(ext, False):
                raise ext_not_found_ex

        mock_extension.side_effect = mock_fn
        controllers.check_for_neutron_tag_support()
        mock_extension.assert_any_call('standard-attr-tag')
        mock_extension.assert_any_call('tag')
        mock_extension.assert_any_call('tag-ext')

        self.assertEqual(controllers.app.tag, ext_matrix['tag'])
        self.assertEqual(controllers.app.tag_ext, ext_matrix['tag-ext'])
