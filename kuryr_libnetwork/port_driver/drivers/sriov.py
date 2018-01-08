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

import glob
import os
import re

from kuryr.lib import binding
from kuryr.lib import exceptions

from kuryr_libnetwork import constants as const
from kuryr_libnetwork.port_driver import driver


def get_ifname_by_pci_address(pci_addr, pf_interface=False):
    """Get the interface name based on a VF's pci address.

    The returned interface name is either the parent PF's or that of the VF
    itself based on the argument of pf_interface.
    """
    dev_path = _get_sysfs_netdev_path(pci_addr, pf_interface)
    try:
        dev_info = os.listdir(dev_path)
        return dev_info.pop()
    except Exception:
        raise exceptions.KuryrException(
            "PCI device %s not found" % pci_addr)


def _get_sysfs_netdev_path(pci_addr, pf_interface):
    """Get the sysfs path based on the PCI address of the device.

    Assumes a networking device - will not check for the existence of the path.
    """
    if pf_interface:
        return "/sys/bus/pci/devices/%s/physfn/net" % pci_addr
    return "/sys/bus/pci/devices/%s/net" % pci_addr


def get_vf_num_by_pci_address(pci_addr):
    """Get the VF number based on a VF's pci address

    A VF is associated with an VF number, which ip link command uses to
    configure it. This number can be obtained from the PCI device filesystem.
    """
    VIRTFN_RE = re.compile("virtfn(\d+)")
    virtfns_path = "/sys/bus/pci/devices/%s/physfn/virtfn*" % (pci_addr)
    vf_num = None
    try:
        for vf_path in glob.iglob(virtfns_path):
            if re.search(pci_addr, os.readlink(vf_path)):
                t = VIRTFN_RE.search(vf_path)
                vf_num = t.group(1)
                break
    except Exception:
        pass
    if vf_num is None:
        raise exceptions.KuryrException(
            "PCI device %s not found" % pci_addr)
    return vf_num


class SriovDriver(driver.Driver):
    """Driver supporting SR-IOV on Bare Metal"""

    BINDING_DRIVERS = ('hw_veb',)

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
        :raises: kuryr.lib.exceptions.BindingNotSupportedFailure
                 processutils.ProcessExecutionError
        """
        binding_driver = 'kuryr.lib.binding.drivers.hw_veb'
        pci_addr = neutron_port[const.BINDING_PROFILE]['pci_slot']
        pf_ifname = get_ifname_by_pci_address(pci_addr,
                                              pf_interface=True)
        vf_num = get_vf_num_by_pci_address(pci_addr)
        _, _, (stdout, stderr) = binding.port_bind(
            endpoint_id, neutron_port, subnets, pf_ifname=pf_ifname,
            vf_num=vf_num, driver=binding_driver)
        return (stdout, stderr)

    def delete_host_iface(self, endpoint_id, neutron_port):
        """Deletes a host interface after unbinding it from the host.

        The host veth interface associated to the Neutron port will be unbound
        from its vitual bridge and deleted by delegating to the selected
        kuryr-lib driver.

        :param endpoint_id:  the ID of the Docker container as string
        :param neutron_port: a port dictionary returned from
               python-neutronclient
        :returns: the tuple of stdout and stderr returned by
                  processutils.execute invoked with the executable script for
                  unbinding
        :raises: processutils.ProcessExecutionError
        """
        binding_driver = 'kuryr.lib.binding.drivers.hw_veb'
        pci_addr = neutron_port[const.BINDING_PROFILE]['pci_slot']
        pf_ifname = get_ifname_by_pci_address(pci_addr,
                                              pf_interface=True)
        vf_num = get_vf_num_by_pci_address(pci_addr)
        return binding.port_unbind(endpoint_id, neutron_port,
                                   pf_ifname=pf_ifname,
                                   vf_num=vf_num, driver=binding_driver)

    def get_container_iface_name(self, neutron_port):
        """Returns interface name of a container in the default namespace.

        :param neutron_port_id: The ID of a neutron port as string
        :returns: interface name as string
        """
        pci_addr = neutron_port[const.BINDING_PROFILE]['pci_slot']
        vf_ifname = get_ifname_by_pci_address(pci_addr)
        return vf_ifname
