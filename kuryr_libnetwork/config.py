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

"""
Routines for configuring Kuryr
"""

import os

from oslo_config import cfg
from oslo_log import log
import pbr.version

from kuryr.lib._i18n import _
from kuryr.lib import config as lib_config

core_opts = [
    cfg.StrOpt('pybasedir',
               default=os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                    '../')),
               help=_('Directory where Kuryr python module is installed.')),
    cfg.StrOpt('kuryr_uri',
               default=os.environ.get('OS_KURYR_URI',
                                      'http://127.0.0.1:23750'),
               help=_('Kuryr URL for accessing Kuryr through json rpc.')),
    cfg.StrOpt('capability_scope',
               default=os.environ.get('CAPABILITY_SCOPE', 'local'),
               choices=['local', 'global'],
               help=_('Kuryr plugin scope reported to libnetwork.')),
    cfg.StrOpt('local_default_address_space',
               default='no_address_space',
               help=_('There is no address-space by default in neutron')),
    cfg.StrOpt('global_default_address_space',
               default='no_address_space',
               help=_('There is no address-space by default in neutron')),
    cfg.StrOpt('port_driver',
               default='kuryr_libnetwork.port_driver.drivers.veth',
               deprecated_for_removal=True,
               help=_('Default driver for the desired deployment model')),
    cfg.StrOpt('default_port_driver',
               default='kuryr_libnetwork.port_driver.drivers.veth',
               help=_('Default driver for the desired deployment model')),
    cfg.ListOpt('enabled_port_drivers',
                default=['kuryr_libnetwork.port_driver.drivers.veth'],
                help=_('Available port drivers')),
    cfg.BoolOpt('process_external_connectivity',
                default=True,
                help=_('Do processing external connectivity')),
    cfg.StrOpt('ssl_cert_file',
               default='/var/lib/kuryr/certs/cert.pem',
               help=_('This option allows setting absolute path'
                    'to the SSL certificate')),
    cfg.StrOpt('ssl_key_file',
               default='/var/lib/kuryr/certs/key.pem',
               help=_('This option allows setting absolute path'
                     'to the SSL private key')),
    cfg.BoolOpt('enable_ssl',
                default=False,
                help=_('Enable SSL for Kuryr'))
]

CONF = cfg.CONF
CONF.register_opts(core_opts)

CONF.register_opts(lib_config.core_opts)
CONF.register_opts(lib_config.binding_opts, 'binding')
lib_config.register_neutron_opts(CONF)

# Setting oslo.log options for logging.
log.register_options(CONF)


def init(args, **kwargs):
    cfg.CONF(
        args=args,
        project='kuryr',
        version=pbr.version.VersionInfo('kuryr-libnetwork').version_string(),
        **kwargs)
