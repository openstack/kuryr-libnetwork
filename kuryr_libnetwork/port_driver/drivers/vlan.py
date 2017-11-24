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
from kuryr.lib import segmentation_type_drivers as seg_driver

from kuryr_libnetwork import app
from kuryr_libnetwork.port_driver import base

LOG = log.getLogger(__name__)


class VlanDriver(base.BaseNestedDriver):
    """Driver for container-in-VM deployments with Trunk Ports."""

    BINDING_DRIVERS = ('vlan',)

    def __init__(self):
        super(VlanDriver, self).__init__()

        self.port_vlan_dic = {}
        self.trunk_port = self._get_port_from_host_iface(self.link_iface)
        self._check_for_vlan_ids()

    def _check_for_vlan_ids(self):
        """Gathers information about vlans already in use."""
        for subport in self.trunk_port['trunk_details']['sub_ports']:
            self.port_vlan_dic[subport['port_id']] = subport['segmentation_id']

    def get_supported_bindings(self):
        """Returns a tuple of supported binding driver names for the driver.

        :returns: a tuple of strings
        """
        return self.BINDING_DRIVERS

    def get_default_network_id(self):
        """Returns a Neutron network ID as per driver logic, if any.

        :returns: the Neutron network UUID as a string
        :raises: exceptions.KuryrException
        """
        return None

    def update_port(self, port, endpoint_id, interface_mac):
        segmentation_id = self._get_segmentation_id(port['id'])
        self._attach_subport(self.trunk_port['trunk_details']['trunk_id'],
                             port['id'],
                             segmentation_id)
        return super(VlanDriver, self).update_port(port, endpoint_id,
                                                   interface_mac)

    def create_host_iface(self, endpoint_id, neutron_port, subnets,
                          network=None):
        """Instantiates a host interface and binds it to the host.

        A host linked interface will be created for the specific Neutron port
        by delegating to the pre-selected kuryr-lib driver.
        This driver will attach the port to the trunk port as a subport by
        using a segmentation id available.

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
        container_ips = neutron_port['fixed_ips']

        if not container_ips:
            raise exceptions.KuryrException(
                "Neutron port {0} does not have fixed_ips."
                .format(neutron_port['id']))

        vm_port = self._get_port_from_host_iface(self.link_iface)

        segmentation_id = self._get_segmentation_id(neutron_port['id'])

        _, _, (stdout, stderr) = binding.port_bind(
            endpoint_id, neutron_port, subnets, network, vm_port,
            segmentation_id)

        return (stdout, stderr)

    def delete_host_iface(self, endpoint_id, neutron_port):
        """Deletes a host interface after unbinding it from the host.

        The host Slave interface associated to the Neutron port will be deleted
        by delegating to the selected kuryr-lib driver.
        This driver will also remove the subport attached to the trunk port
        and will release its segmentation id

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

        stdout, stderr = binding.port_unbind(endpoint_id, neutron_port)

        subports = [{'port_id': neutron_port['id']}]
        try:
            app.neutron.trunk_remove_subports(
                vm_port['trunk_details']['trunk_id'],
                {'sub_ports': subports})
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during subport deletion "
                      "%(port_id)s: %(ex)s",
                      {'port_id': neutron_port['id'], 'ex': ex})
            raise
        self._release_segmentation_id(neutron_port['id'])
        return stdout, stderr

    def _attach_subport(self, trunk_id, port_id, segmentation_id):
        subport = [
            {
                'segmentation_id': segmentation_id,
                'port_id': port_id,
                'segmentation_type': 'vlan'
            }
        ]
        try:
            app.neutron.trunk_add_subports(trunk_id, {'sub_ports': subport})
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened adding subport %(port_id)s "
                      "to trunk port %(trunk_id)s: %(ex)s",
                      port_id, trunk_id, ex)
            raise

    def _get_segmentation_id(self, id):
        if id in self.port_vlan_dic.keys():
            return self.port_vlan_dic[id]
        seg_id = seg_driver.allocate_segmentation_id(
            self.port_vlan_dic.values())
        self.port_vlan_dic[id] = seg_id
        return seg_id

    def _release_segmentation_id(self, id):
        seg_driver.release_segmentation_id(id)
        del self.port_vlan_dic[id]

    def _get_port_vlan(self, port_id):
        return self.port_vlan_dic[port_id]
