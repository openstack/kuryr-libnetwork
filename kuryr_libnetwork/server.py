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
import os
import sys

from oslo_log import log
from six.moves.urllib import parse

from kuryr_libnetwork import app
from kuryr_libnetwork import config
from kuryr_libnetwork import controllers


def configure_app():
    config.init(sys.argv[1:])
    log.setup(config.CONF, 'kuryr')
    controllers.neutron_client()
    controllers.check_for_neutron_ext_support()
    controllers.check_for_neutron_ext_tag()
    controllers.load_default_subnet_pools()
    controllers.load_port_driver()


def start():
    configure_app()
    kuryr_uri = parse.urlparse(config.CONF.kuryr_uri)
    app.run(kuryr_uri.hostname, kuryr_uri.port)


if __name__ == '__main__':
    sys.exit(start())
elif 'UWSGI_ORIGINAL_PROC_NAME' in os.environ:
    # The module is being loaded by uWSGI to get the Flask app running under
    # it. This allows Neutron to be set, since uWSGI does not run 'start',
    # which would trigger the embedded Flask wsgi development server.
    configure_app()
