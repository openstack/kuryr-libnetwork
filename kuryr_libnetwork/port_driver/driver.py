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
import six

from oslo_log import log
from oslo_utils import importutils

from neutronclient.common import exceptions as n_exceptions

from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import app
from kuryr_libnetwork import config
from kuryr_libnetwork import utils as libnet_utils

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface class for port drivers.

    In order to create compliant implementations subclasses must be named with
    the 'Driver' suffix.
    """

    @abc.abstractmethod
    def get_default_network_id(self):
        """Returns a Neutron network ID as per driver logic, if any.

        Endpoints associated to certain type of drivers might need to join a
        specific, possibly pre-existing, network to be able to work correctly.
        For these drivers a Neutron network ID is returned or an exception
        raised if failed, None returned in all the other cases.

        :returns: the Neutron network UUID as a string when available or None
        :raises: exceptions.KuryrException
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def create_host_iface(self, endpoint_id, neutron_port, subnets,
                          network=None):
        """Instantiates a host interface and binds it to the host.

        A host interface will be created for the specific Neutron port and
        bound to the related network subsystem on the host by delegating to the
        pre-selected kuryr-lib driver.

        :param endpoint_id:  the ID of the endpoint as string
        :param neutron_port: the container Neutron port dictionary as returned
                             by python-neutronclient
        :param subnets:      an iterable of all the Neutron subnets which the
                             endpoint is trying to join
        :param network:      the Neutron network which the endpoint is trying
                             to join
        :returns: the tuple of stdout and stderr returned by
                  processutils.execute invoked with the executable script for
                  binding
        :raises: exceptions.VethCreationFailure,
                 exceptions.BindingNotSupportedFailure
                 exceptions.KuryrException,
                 neutronclient.common.NeutronClientException,
                 processutils.ProcessExecutionError
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def delete_host_iface(self, endpoint_id, neutron_port):
        """Deletes a host interface after unbinding it from the host.

        The host interface associated to the Neutron port will be unbound from
        its network subsystem and deleted by delegating to the selected
        kuryr-lib driver.

        :param endpoint_id:  the ID of the Docker container as string
        :param neutron_port: a port dictionary returned from
                             python-neutronclient
        :returns: the tuple of stdout and stderr returned by
                  processutils.execute invoked with the executable script for
                  unbinding
        :raises: exceptions.VethDeletionFailure,
                 exceptions.KuryrException,
                 neutronclient.common.NeutronClientException,
                 processutils.ProcessExecutionError
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_container_iface_name(self, neutron_port):
        """Returns interface name of a container in the default namespace.

        :param neutron_port: The neutron port
        :returns: interface name as string
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_supported_bindings(self):
        """Returns a tuple of supported binding driver names for the driver.

        :returns: a tuple of strings
        """
        raise NotImplementedError()

    def update_port(self, port, endpoint_id, interface_mac, tags=True):
        """Updates port information and performs extra driver-specific actions.

        It returns the updated port dictionary after the required actions
        performed depending on the binding driver.

        :param port: a neutron port dictionary returned from
                             python-neutronclient
        :param endpoint_id:  the ID of the endpoint as string
        :param interface_mac: the MAC address of the endpoint
        :returns: the updated Neutron port id dictionary as returned by
                  python-neutronclient
        """
        try:
            updated_port = {}
            hostname = lib_utils.get_hostname()
            if port['binding:host_id'] != hostname:
                updated_port['binding:host_id'] = hostname
                updated_port['device_owner'] = lib_const.DEVICE_OWNER
            if port['admin_state_up'] is not True:
                updated_port['admin_state_up'] = True
            if not tags:
                # rename the port if tagging is not supported
                updated_port['name'] = libnet_utils.get_neutron_port_name(
                    endpoint_id)
            if not port.get('device_id'):
                updated_port['device_id'] = endpoint_id
            if interface_mac and port['mac_address'] != interface_mac:
                updated_port['mac_address'] = interface_mac
            if updated_port:
                port = app.neutron.update_port(port['id'],
                                               {'port': updated_port})['port']
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during updating a "
                      "Neutron port: %s", ex)
            raise
        return port

    def __str__(self):
        return self.__class__.__name__


def get_driver_instance(name=None):
    """Instantiate a driver instance accordingly to the file configuration.

    :returns: a Driver instance
    :raises: exceptions.KuryrException
    """
    if name:
        module, name, classname = _parse_port_driver_config(name)
    else:
        module, name, classname = _parse_port_driver_config()

    if (module not in config.CONF.enabled_port_drivers and
            name not in config.CONF.enabled_port_drivers):
        raise exceptions.KuryrException("No port driver available")

    # TODO(apuimedo): switch to the openstack/stevedore plugin system
    try:
        driver = importutils.import_object("{0}.{1}".format(module, classname))
    except ImportError as ie:
        raise exceptions.KuryrException(
            "Cannot load port driver '{0}': {1}".format(module, ie))

    _verify_port_driver_compliancy(driver, name)
    _verify_binding_driver_compatibility(driver, name)

    return driver


def _parse_port_driver_config(config_value=None):
    """Read the port driver related config value and parse it.

    :returns: the provided full module path as per config file, the name of the
             driver/module and the class name of the Driver class inside it
    """
    if config_value is None:
        config_value = config.CONF.default_port_driver
    config_tokens = config_value.rsplit('.', 1)
    if len(config_tokens) == 1:  # not a path, just a name
        name = config_tokens[0]
        if len(name) == 0:
            raise exceptions.KuryrException("No port driver provided")
        else:
            # Attempt to use the name only by prepending the default location
            module = "kuryr_libnetwork.port_driver.drivers." + name
    else:
        module = config_value
        name = config_tokens[1]

    classname = name.capitalize() + 'Driver'

    return module, name, classname


def _verify_port_driver_compliancy(driver, port_driver_name):
    if not issubclass(driver.__class__, Driver):
        raise exceptions.KuryrException("Cannot load port driver '{0}': "
            "driver is not compliant with the {1} interface"
            .format(port_driver_name, Driver.__name__))


def _verify_binding_driver_compatibility(driver, port_driver_name):
    binding_drivers_names = []
    for binding_driver in config.CONF.binding.enabled_drivers:
        tokens = binding_driver.rsplit('.', 1)
        binding_driver_name = tokens[0] if len(tokens) == 1 else tokens[1]
        binding_drivers_names.append(binding_driver_name.lower())

    # TODO(mchiappe): find a clean way to test the binding driver
    # is also loadable before we start
    supported_bindings = driver.get_supported_bindings()

    if not set(binding_drivers_names) & set(supported_bindings):
        raise exceptions.KuryrException("Configuration file error: "
            "port driver '{0}' is not compatible with binding driver '{1}'"
            .format(port_driver_name, binding_drivers_names))

    # Temporarily ban IPVLAN, to be removed in the future
    if 'ipvlan' in binding_drivers_names:
        raise exceptions.KuryrException("Configuration file error: "
            "binding driver '{0}' is currently not supported with '{1}' "
            "port driver".format(binding_drivers_names, port_driver_name))
