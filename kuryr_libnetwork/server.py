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

import sys

from oslo_log import log
from six.moves.urllib import parse

from kuryr_libnetwork import app
from kuryr_libnetwork.common import config
from kuryr_libnetwork import controllers


def start():
    config.init(sys.argv[1:])
    controllers.neutron_client()
    controllers.check_for_neutron_ext_support()
    controllers.check_for_neutron_ext_tag()

    log.setup(config.CONF, 'Kuryr')
    kuryr_uri = parse.urlparse(config.CONF.kuryr_uri)
    app.run(kuryr_uri.hostname, kuryr_uri.port)


if __name__ == '__main__':
    start()
