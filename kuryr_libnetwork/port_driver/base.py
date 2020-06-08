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

import abc

from kuryr.lib.binding.drivers import utils
from kuryr.lib import exceptions
from kuryr_libnetwork import app
from kuryr_libnetwork import config
from kuryr_libnetwork.port_driver import driver


class BaseNestedDriver(driver.Driver, metaclass=abc.ABCMeta):
    """Driver for container-in-VM deployments with MACVLAN and IPVLAN."""

    def __init__(self):
        self.link_iface = config.CONF.binding.link_iface

    def _get_port_from_host_iface(self, ifname):
        """Returns the Neutron port associated to ifname or raises otherwise.

        Returns the Neutron port associated to ifname if such port exists, a
        exceptions.KuryrException if it does not,
        n_exceptions.NeutronClientException on errors.

        :returns: a Neutron port dictionary as returned by
                  python-neutronclient or None
        :raises: exceptions.KuryrException
                 neutronclient.common.exceptions.NeutronClientException
        """
        ip = utils.get_ipdb()

        mac_address = ip.interfaces.get(ifname, {}).get('address', None)
        if mac_address:
            ports = app.neutron.list_ports(mac_address=mac_address)
            if ports['ports']:
                return ports['ports'][0]

        raise exceptions.KuryrException("Cannot find a Neutron port "
            "associated to interface name {0}".format(ifname))

    def get_container_iface_name(self, neutron_port):
        """Returns interface name of a container in the default namespace.

        :param neutron_port: The neutron port
        :returns: interface name as string.
        """
        _, container_iface_name = utils.get_veth_pair_names(neutron_port['id'])
        return container_iface_name
