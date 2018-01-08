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

from kuryr.lib import binding
from kuryr.lib.binding.drivers import utils

from kuryr_libnetwork.port_driver import driver


class VethDriver(driver.Driver):
    """Driver supporting veth on Bare Metal"""

    BINDING_DRIVERS = ('veth',)

    def get_supported_bindings(self):
        """Returns a tuple of supported binding driver names for the driver.

        :returns: a tuple of strings
        """
        return self.BINDING_DRIVERS

    def get_default_network_id(self):
        """Returns a Neutron network ID as per driver logic, if any.

        This driver does not make use of any specific network and will thus
        return None.

        :returns: None
        """
        return None

    def create_host_iface(self, endpoint_id, neutron_port, subnets,
                          network=None):
        """Instantiates a host interface and bind it to the host.

        The interface type will be veth and bound to a virtual bridge.

        :param endpoint_id:  the ID of the endpoint as string
        :param neutron_port: the container Neutron port dictionary as returned
                             by python-neutronclient
        :param subnets:      an iterable of all the Neutron subnets which the
                             endpoint is trying to join
        :param network:      the Neutron network which the endpoint is trying
                             to join
        :returns: the tuple of stdout and stderr returned by
                  processutils.execute invoked with the executable script for
                  unbinding
        :raises: kuryr.lib.exceptions.VethCreationFailure,
                 kuryr.lib.exceptions.BindingNotSupportedFailure
                 processutils.ProcessExecutionError
        """
        _, _, (stdout, stderr) = binding.port_bind(
            endpoint_id, neutron_port, subnets, network)
        return (stdout, stderr)

    def delete_host_iface(self, endpoint_id, neutron_port):
        """Deletes a host interface after unbinding it from the host.

        The host veth interface associated to the Neutron port will be unbound
        from its vitual bridge and deleted by delegating to the selected
        kuryr-lib driver.

        :param endpoint_id:  the ID of the endpoint as string
        :param neutron_port: a port dictionary returned from
               python-neutronclient
        :returns: the tuple of stdout and stderr returned by
                  processutils.execute invoked with the executable script for
                  unbinding
        :raises: kuryr.lib.exceptions.VethDeletionFailure,
                 processutils.ProcessExecutionError
        """
        return binding.port_unbind(endpoint_id, neutron_port)

    def get_container_iface_name(self, neutron_port):
        """Returns interface name of a container in the default namespace.

        :param neutron_port_id: The neutron port
        :returns: interface name as string
        """
        _, container_iface_name = utils.get_veth_pair_names(neutron_port['id'])
        return container_iface_name
