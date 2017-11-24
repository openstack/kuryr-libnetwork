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

from neutronclient.common import exceptions as n_exceptions
from oslo_log import log

from kuryr.lib import binding
from kuryr.lib import exceptions

from kuryr_libnetwork import app
from kuryr_libnetwork.port_driver import base

LOG = log.getLogger(__name__)


class NestedDriver(base.BaseNestedDriver):
    """Driver for container-in-VM deployments with MACVLAN and IPVLAN."""

    BINDING_DRIVERS = ('macvlan', 'ipvlan')

    def __init__(self):
        super(NestedDriver, self).__init__()

    def get_supported_bindings(self):
        """Returns a tuple of supported binding driver names for the driver.

        :returns: a tuple of strings
        """
        return self.BINDING_DRIVERS

    def get_default_network_id(self):
        """Returns a Neutron network ID as per driver logic, if any.

        Nested Endpoints need to join the same network as their Master
        interface, this function will return its Neutron network UUID for the
        Endpoint to join or throw in case of failure.

        :returns: the Neutron network UUID as a string
        :raises: exceptions.KuryrException
        """
        vm_port = self._get_port_from_host_iface(self.link_iface)

        return vm_port['network_id']

    def create_host_iface(self, endpoint_id, neutron_port, subnets,
                          network=None):
        """Instantiates a host interface and binds it to the host.

        A host linked interface will be created for the specific Neutron port
        by delegating to the pre-selected kuryr-lib driver.
        This driver will also add the IP and MAC address pairs of the Endpoint
        to the allowed_address_pairs list of the Neutron port associated to the
        underlying host interface.

        :param endpoint_id:  the ID of the endpoint as string
        :param neutron_port: the container Neutron port dictionary as returned
                             by python-neutronclient
        :param subnets:      an iterable of all the Neutron subnets which the
                             endpoint is trying to join
        :param network:      the Neutron network which the endpoint is trying
                             to join
        :returns: the tuple of stdout and stderr returned by
                  processutils.execute invoked
                  with the executable script for binding
        :raises: exceptions.VethCreationFailure,
                 exceptions.KuryrException,
                 n_exceptions.NeutronClientException,
                 processutils.ProcessExecutionError
        """
        container_mac = neutron_port['mac_address']
        container_ips = neutron_port['fixed_ips']

        if not container_ips:  # The MAC address should be mandatory, no check
            raise exceptions.KuryrException(
                "Neutron port {0} does not have fixed_ips."
                .format(neutron_port['id']))

        vm_port = self._get_port_from_host_iface(self.link_iface)

        _, _, (stdout, stderr) = binding.port_bind(
            endpoint_id, neutron_port, subnets, network, vm_port)
        self._add_to_allowed_address_pairs(vm_port, container_ips,
                                           container_mac)

        return (stdout, stderr)

    def delete_host_iface(self, endpoint_id, neutron_port):
        """Deletes a host interface after unbinding it from the host.

        The host Slave interface associated to the Neutron port will be deleted
        by delegating to the selected kuryr-lib driver.
        This driver will also remove the IP and MAC address pairs of the
        Endpoint to the allowed_address_pairs list of the Neutron port
        associated to the underlying host interface.

        :param endpoint_id:  the ID of the endpoint as string
        :param neutron_port: a port dictionary returned from
                             python-neutronclient
        :returns: the tuple of stdout and stderr returned
                  by processutils.execute invoked with the executable script
                  for unbinding
        :raises: exceptions.VethDeletionFailure,
                 exceptions.KuryrException,
                 n_exceptions.NeutronClientException,
                 processutils.ProcessExecutionError,
        """
        vm_port = self._get_port_from_host_iface(self.link_iface)
        container_ips = neutron_port['fixed_ips']

        self._remove_from_allowed_address_pairs(vm_port, container_ips)
        return binding.port_unbind(endpoint_id, neutron_port)

    def _add_to_allowed_address_pairs(self, port, ip_addresses,
                                      mac_address=None):
        address_pairs = port['allowed_address_pairs']
        for ip_entry in ip_addresses:
            pair = {'ip_address': ip_entry['ip_address']}
            if mac_address:
                pair['mac_address'] = mac_address
            address_pairs.append(pair)

        self._update_port_address_pairs(port['id'], address_pairs)

    def _remove_from_allowed_address_pairs(self, port, ip_addresses):
        address_pairs = port['allowed_address_pairs']
        filter = frozenset(ip_entry['ip_address'] for ip_entry in ip_addresses)
        updated_address_pairs = []

        # filter allowed IPs by copying
        for address_pair in address_pairs:
            if address_pair['ip_address'] in filter:
                continue
            updated_address_pairs.append(address_pair)

        self._update_port_address_pairs(port['id'], updated_address_pairs)

    def _update_port_address_pairs(self, port_id, address_pairs):
        try:
            app.neutron.update_port(
                port_id,
                {
                    'port': {
                        'allowed_address_pairs': address_pairs
                    }
                })
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during updating Neutron "
                      "port %(port_id)s: %(ex)s", port_id, ex)
            raise
