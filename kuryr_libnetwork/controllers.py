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


from collections import defaultdict
import flask
import ipaddress
from itertools import groupby
import jsonschema
import math
from operator import itemgetter
import time

from neutronclient.common import exceptions as n_exceptions
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import strutils

from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils

from kuryr_libnetwork import app
from kuryr_libnetwork import config
from kuryr_libnetwork import constants as const
from kuryr_libnetwork.port_driver import driver
from kuryr_libnetwork import schemata
from kuryr_libnetwork import utils

LOG = log.getLogger(__name__)

MANDATORY_NEUTRON_EXTENSION = "subnet_allocation"
TAG_NEUTRON_EXTENSION = "tag"
TAG_EXT_NEUTRON_EXTENSION = "tag-ext"
TAG_STANDARD_NEUTRON_EXTENSION = 'standard-attr-tag'
SUBNET_POOLS_V4 = []
SUBNET_POOLS_V6 = []
DEFAULT_DRIVER = driver.get_driver_instance()
try:
    SRIOV_DRIVER = driver.get_driver_instance(name='sriov')
except exceptions.KuryrException:
    SRIOV_DRIVER = None
VNIC_TYPES_DRIVERS_MAPPING = {
    const.VNIC_TYPE_NORMAL: DEFAULT_DRIVER,
    const.VNIC_TYPE_DIRECT: SRIOV_DRIVER,
    const.VNIC_TYPE_MACVTAP: SRIOV_DRIVER,
    const.VNIC_TYPE_DIRECT_PHYSICAL: SRIOV_DRIVER,
}


def get_neutron_client():
    """Creates the Neutron client for communicating with Neutron."""
    return lib_utils.get_neutron_client()


def neutron_client():
    if not hasattr(app, 'neutron'):
        app.neutron = get_neutron_client()
        app.enable_dhcp = cfg.CONF.neutron.enable_dhcp
        app.vif_plug_is_fatal = cfg.CONF.neutron.vif_plugging_is_fatal
        app.vif_plug_timeout = cfg.CONF.neutron.vif_plugging_timeout
        app.neutron.format = 'json'


def check_for_neutron_ext_support():
    """Validates for mandatory extension support availability in neutron."""
    max_attempts = 8
    for attempt in range(max_attempts):
        try:
            app.neutron.show_extension(MANDATORY_NEUTRON_EXTENSION)
            break
        except n_exceptions.NeutronClientException as e:
            if e.status_code == n_exceptions.NotFound.status_code:
                raise exceptions.MandatoryApiMissing(
                    "Neutron extension with alias '{0}' not found"
                                .format(MANDATORY_NEUTRON_EXTENSION))
            elif attempt == max_attempts - 1:
                raise
            else:
                LOG.error("Error happened during retrieving neutron "
                          "extensions")
        except Exception as e:
            if attempt == max_attempts - 1:
                raise
            else:
                LOG.error("Error happened during retrieving neutron "
                          "extensions: %s", e)
        backoff = int(math.pow(2, attempt) - 1)
        time.sleep(backoff)


def check_for_neutron_tag_support():
    """Validates tagging extensions availability in Neutron.

    Checks if either tag, tag-ext or standard-attr-tag is available and sets
    ``app`` properties accordingly.
    """

    app.tag_ext = True
    app.tag = True

    # Check for modern extension first.
    try:
        app.neutron.show_extension(TAG_STANDARD_NEUTRON_EXTENSION)
    except n_exceptions.NeutronClientException:
        pass
    else:
        # Okay, this means we have functionality of both tag and tag_ext,
        # we're good to go!
        return

    # Fallback to legacy extensions.
    for ext in (TAG_NEUTRON_EXTENSION, TAG_EXT_NEUTRON_EXTENSION):
        try:
            app.neutron.show_extension(ext)
        except n_exceptions.NeutronClientException as e:
            ext_param = ext.replace('-', '_')  # identifiers cannot have '-'
            setattr(app, ext_param, False)
            if e.status_code == n_exceptions.NotFound.status_code:
                LOG.warning("Neutron extension %s not supported. "
                            "Continue without using them.", ext)


def load_default_subnet_pools():
    """Load the default subnetpools."""
    global SUBNET_POOLS_V4
    global SUBNET_POOLS_V6
    SUBNET_POOLS_V4 = [cfg.CONF.neutron.default_subnetpool_v4]
    SUBNET_POOLS_V6 = [cfg.CONF.neutron.default_subnetpool_v6]


def load_port_driver():
    app.driver = DEFAULT_DRIVER
    LOG.debug("Using port driver '%s'", str(app.driver))


def get_driver(port):
    vnic_type = port.get('binding:vnic_type', const.VNIC_TYPE_NORMAL)
    driver = VNIC_TYPES_DRIVERS_MAPPING.get(vnic_type)
    if driver is None:
        raise exceptions.KuryrException(
            "No port driver available for VNIC type %s" % vnic_type)
    return driver


def _cache_default_subnetpool_ids(app):
    """Caches IDs of the default subnetpools as app.DEFAULT_POOL_IDS."""
    if not hasattr(app, 'DEFAULT_POOL_IDS'):
        default_subnetpool_id_set = set()
        try:
            subnetpool_names = SUBNET_POOLS_V4 + SUBNET_POOLS_V6
            for subnetpool_name in subnetpool_names:
                subnetpools = app.neutron.list_subnetpools(
                    name=subnetpool_name)
                for subnetpool in subnetpools['subnetpools']:
                    default_subnetpool_id_set.add(subnetpool['id'])
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during retrieving the default"
                      " subnet pools: %s", ex)
        app.DEFAULT_POOL_IDS = frozenset(default_subnetpool_id_set)


def _get_networks_by_attrs(**attrs):
    networks = app.neutron.list_networks(**attrs)
    if len(networks.get('networks', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron networks exist for the params {0}"
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return networks['networks']


def _get_subnets_by_attrs(**attrs):
    subnets = app.neutron.list_subnets(**attrs)
    return subnets['subnets']


def _get_ports_by_attrs(**attrs):
    ports = app.neutron.list_ports(**attrs)
    if len(ports.get('ports', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron ports exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return ports['ports']


def _get_subnetpools_by_attrs(**attrs):
    subnetpools = app.neutron.list_subnetpools(**attrs)
    if len(subnetpools.get('subnetpools', [])) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron subnetspool exist for the params {0} "
            .format(', '.join(['{0}={1}'.format(k, v)
                               for k, v in attrs.items()])))
    return subnetpools['subnetpools']


def _get_subnets_by_interface_cidr(neutron_network_id,
                                   interface_cidr):
    iface = ipaddress.ip_interface(str(interface_cidr))
    subnets = _get_subnets_by_attrs(
        network_id=neutron_network_id, cidr=str(iface.network))
    if len(subnets) > 2:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron subnets exist for the network_id={0}"
            "and cidr={1}"
            .format(neutron_network_id, iface.network))
    return subnets


def _get_subnet_by_name(subnet_name):
    subnets_by_name = _get_subnets_by_attrs(name=subnet_name)
    if not subnets_by_name:
        raise exceptions.NoResourceException(
            "The subnet doesn't exist for the name {0}"
            .format(subnets_by_name))
    elif len(subnets_by_name) > 1:
        raise exceptions.DuplicatedResourceException(
            "Multiple Neutron subnets exist for name {0}"
            .format(subnet_name))
    return subnets_by_name[0]['id']


def _get_neutron_port_from_docker_endpoint(endpoint_id):
    port_name = utils.get_neutron_port_name(endpoint_id)
    filtered_ports = app.neutron.list_ports(name=port_name)
    num_ports = len(filtered_ports.get('ports', []))
    if num_ports == 1:
        return filtered_ports['ports'][0]['id']


def _get_neutron_port_status_from_docker_endpoint(endpoint_id):
    response_port_status = {}
    neutron_port_identifier = _make_port_identifier(endpoint_id)
    filtered_ports = _get_ports_by_identifier(neutron_port_identifier)
    if filtered_ports:
        response_port_status['status'] = filtered_ports[0]['status']
    return response_port_status


def _process_interface_address(port_dict, subnets_dict_by_id,
                               response_interface):
    subnet_id = port_dict['subnet_id']
    subnet = subnets_dict_by_id[subnet_id]
    iface = ipaddress.ip_interface(str(subnet['cidr']))
    address_key = 'Address' if iface.version == 4 else 'AddressIPv6'
    response_interface[address_key] = str(iface)


def _create_port(endpoint_id, neutron_network_id, interface_mac, fixed_ips):
    port = {
        'name': utils.get_neutron_port_name(endpoint_id),
        'admin_state_up': True,
        'network_id': neutron_network_id,
        'device_owner': lib_const.DEVICE_OWNER,
        'device_id': endpoint_id,
        'binding:host_id': lib_utils.get_hostname(),
        'fixed_ips': fixed_ips
    }
    if interface_mac:
        port['mac_address'] = interface_mac
    try:
        rcvd_port = app.neutron.create_port({'port': port})
    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened during creating a"
                  " Neutron port: %s", ex)
        raise
    return rcvd_port['port']


def _get_fixed_ips_by_interface_cidr(subnets, interface_cidrv4,
                                     interface_cidrv6, fixed_ips):
    for subnet in subnets:
        fixed_ip = [('subnet_id=%s' % subnet['id'])]
        if interface_cidrv4 or interface_cidrv6:
            if subnet['ip_version'] == 4 and interface_cidrv4:
                iface = ipaddress.ip_interface(str(interface_cidrv4))
            elif subnet['ip_version'] == 6 and interface_cidrv6:
                iface = ipaddress.ip_interface(str(interface_cidrv6))
            if str(subnet['cidr']) != str(iface.network):
                continue
            fixed_ip.append('ip_address=%s' % iface.ip)
        fixed_ips.extend(fixed_ip)


def _create_or_update_port(neutron_network_id, endpoint_id,
                           interface_cidrv4, interface_cidrv6, interface_mac):
    subnets = []
    fixed_ips = []
    response_port = []

    subnetsv4 = subnetsv6 = []
    if interface_cidrv4:
        subnetsv4 = _get_subnets_by_interface_cidr(
            neutron_network_id, interface_cidrv4)
    if interface_cidrv6:
        subnetsv6 = _get_subnets_by_interface_cidr(
            neutron_network_id, interface_cidrv6)
    subnets = subnetsv4 + subnetsv6
    if not len(subnets):
        raise exceptions.NoResourceException(
            "No subnet exist for the cidrs {0} and {1} "
            .format(interface_cidrv4, interface_cidrv6))
    if len(subnets) > 2:
        raise exceptions.DuplicatedResourceException(
            "Multiple subnets exist for the cidrs {0} and {1}"
            .format(interface_cidrv4, interface_cidrv6))

    _get_fixed_ips_by_interface_cidr(subnets, interface_cidrv4,
                                     interface_cidrv6, fixed_ips)
    filtered_ports = app.neutron.list_ports(fixed_ips=fixed_ips)
    num_port = len(filtered_ports.get('ports', []))
    if not num_port:
        fixed_ips = (
            lib_utils.get_dict_format_fixed_ips_from_kv_format(fixed_ips))
        response_port = _create_port(endpoint_id, neutron_network_id,
                                     interface_mac, fixed_ips)
    elif num_port == 1:
        port = filtered_ports['ports'][0]
        port_driver = get_driver(port)
        response_port = port_driver.update_port(port, endpoint_id,
                                                interface_mac,
                                                tags=app.tag)
        _neutron_port_add_tags(port, endpoint_id)
    # For the container boot from dual-net, request_address will
    # create two ports(v4 and v6 address), we should only allow one
    # for port bind.
    # There are two cases:
    # 1. User specifies an existing port with v4 address only.
    #    In this case, Kuryr creates the v6 port in ipam_request_address.
    #    We will bind the v4 port and remove the v6 port.
    # 2. Users doesn't specify a port. In this case Kuryr creates
    #    the v4 and v6 ports in ipam_request_address and
    #    we will delete both ports then re-create a dual-port.
    elif num_port == 2:
        response_port = None
        for port in filtered_ports.get('ports', []):
            port_name = port.get('name')
            if str(port_name).startswith(const.KURYR_UNBOUND_PORT):
                app.neutron.delete_port(port['id'])
            else:
                port_driver = get_driver(port)
                response_port = port_driver.update_port(port, endpoint_id,
                                                        interface_mac,
                                                        tags=app.tag)
                _neutron_port_add_tags(port, endpoint_id)
        if not response_port:
            fixed_ips = (
                lib_utils.get_dict_format_fixed_ips_from_kv_format(fixed_ips))
            response_port = _create_port(endpoint_id, neutron_network_id,
                                         interface_mac, fixed_ips)
    else:
        raise exceptions.DuplicatedResourceException(
            "Multiple ports exist for the cidrs {0} and {1}"
            .format(interface_cidrv4, interface_cidrv6))

    return response_port, subnets


def _neutron_net_add_tag(net, tag):
    _neutron_add_tag('networks', net, tag)


def _neutron_net_add_tags(net, tag, tags=True):
    if tags:
        tags = utils.create_net_tags(tag)
        for tag in tags:
            _neutron_net_add_tag(net, tag)


def _neutron_net_remove_tag(net, tag):
    _neutron_remove_tag('networks', net, tag)


def _neutron_net_remove_tags(net, tag):
    tags = utils.create_net_tags(tag)
    for tag in tags:
        _neutron_net_remove_tag(net, tag)


def _neutron_subnetpool_add_tag(pool, tag):
    _neutron_add_tag('subnetpools', pool, tag)


def _neutron_subnetpool_remove_tag(pool, tag):
    _neutron_remove_tag('subnetpools', pool, tag)


def _neutron_subnet_add_tag(subnet, tag):
    _neutron_add_tag('subnets', subnet, tag)


def _neutron_subnet_remove_tag(subnet, tag):
    _neutron_remove_tag('subnets', subnet, tag)


def _neutron_port_add_tag(port, tag):
    _neutron_add_tag('ports', port, tag)


def _neutron_port_add_tags(port, tag):
    if app.tag:
        tags = utils.create_port_tags(tag)
        for tag in tags:
            _neutron_port_add_tag(port, tag)


def _neutron_port_remove_tag(port, tag):
    _neutron_remove_tag('ports', port, tag)


def _neutron_port_remove_tags(port, tag):
    if app.tag:
        tags = utils.create_port_tags(tag)
        for tag in tags:
            _neutron_port_remove_tag(port, tag)


def _neutron_add_tag(resource_type, resource, tag):
    if tag not in resource['tags']:
        try:
            app.neutron.add_tag(resource_type, resource['id'], tag)
        except n_exceptions.NotFound:
            LOG.warning("Neutron tags extension for given "
                        "resource type is not supported, "
                        "cannot add tag to %s.", resource_type)


def _neutron_remove_tag(resource_type, resource, tag):
    if tag in resource['tags']:
        app.neutron.remove_tag(resource_type, resource['id'], tag)


def _make_net_identifier(network_id, tags=True):
    if tags:
        return utils.make_net_tags(network_id)
    return network_id


def _get_networks_by_identifier(identifier):
    if app.tag:
        return _get_networks_by_attrs(tags=identifier)
    return _get_networks_by_attrs(name=identifier)


def _make_port_identifier(endpoint_id):
    if app.tag:
        return utils.make_port_tags(endpoint_id)
    return utils.get_neutron_port_name(endpoint_id)


def _get_ports_by_identifier(identifier):
    if app.tag:
        return _get_ports_by_attrs(tags=identifier)
    return _get_ports_by_attrs(name=identifier)


def _program_expose_ports(options, port_id):
    exposed_ports = options.get(const.DOCKER_EXPOSED_PORTS_OPTION)
    if not exposed_ports:
        return

    sec_group = {
        'name': utils.get_sg_expose_name(port_id),
        'description': 'Docker exposed ports created by Kuryr.'
    }
    try:
        sg = app.neutron.create_security_group({'security_group': sec_group})
        sg_id = sg['security_group']['id']

    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened during creating a "
                  "Neutron security group: %s", ex)
        raise exceptions.ExportPortFailure(
            ("Could not create required security group {0} "
             "for setting up exported port ").format(sec_group))

    proto_port_dict = defaultdict(list)
    for exposed in exposed_ports:
        port = exposed['Port']
        proto = exposed['Proto']
        try:
            proto = const.PROTOCOLS[proto]
            proto_port_dict[proto].append(port)
        except KeyError:
            # This should not happen as Docker client catches such errors
            LOG.error("Unrecognizable protocol %s", proto)
            app.neutron.delete_security_group(sg_id)
            raise exceptions.ExportPortFailure(
                ("Bad protocol number for exposed port. Deleting "
                 "the security group {0}.").format(sg_id))

    for proto, port_list in proto_port_dict.items():
        # Sort the port range list
        for key, group in groupby(enumerate(sorted(port_list)),
                                  lambda ix: ix[0] - ix[1]):
            port_range_list = list(map(itemgetter(1), group))

            port_range_min = min(port_range_list)
            port_range_max = max(port_range_list)
            sec_group_rule = {
                'security_group_id': sg_id,
                'direction': 'ingress',
                'port_range_min': port_range_min,
                'port_range_max': port_range_max,
                'protocol': proto
            }

            try:
                app.neutron.create_security_group_rule({'security_group_rule':
                                                        sec_group_rule})
            except n_exceptions.NeutronClientException as ex:
                LOG.error("Error happened during creating a "
                          "Neutron security group "
                          "rule: %s", ex)
                app.neutron.delete_security_group(sg_id)
                raise exceptions.ExportPortFailure(
                    ("Could not create required security group rules {0} "
                     "for setting up exported port ").format(sec_group_rule))

    try:
        sgs = [sg_id]
        port = app.neutron.show_port(port_id)
        port = port.get('port')
        if port:
            existing_sgs = port.get('security_groups')
            if existing_sgs:
                sgs = sgs + existing_sgs

        app.neutron.update_port(port_id,
                                {'port': {'security_groups': sgs}})
    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened during updating a "
                  "Neutron port: %s", ex)
        app.neutron.delete_security_group(sg_id)
        raise exceptions.ExportPortFailure(
            ("Could not update port with required security groups{0} "
             "for setting up exported port ").format(sgs))


def _get_cidr_from_subnetpool(**kwargs):
    pools = _get_subnetpools_by_attrs(**kwargs)
    if pools:
        pool = pools[0]
        pool_id = pool['id']
        prefixes = pool['prefixes']
        if len(prefixes) > 1:
            LOG.warning("More than one prefixes present. "
                        "Picking first one.")

        return ipaddress.ip_network(str(prefixes[0])), pool_id
    else:
        raise exceptions.NoResourceException(
            "No subnetpools with {0} is found."
            .format(kwargs))


def revoke_expose_ports(port_id):
    sgs = app.neutron.list_security_groups(
        name=utils.get_sg_expose_name(port_id))
    sgs = sgs.get('security_groups')
    if not sgs:
        return
    removing_sgs = [sg['id'] for sg in sgs]

    existing_sgs = []
    port = app.neutron.show_port(port_id)
    port = port.get('port')
    if port:
        existing_sgs = port.get('security_groups')
        for sg in removing_sgs:
            if sg in existing_sgs:
                existing_sgs.remove(sg)
        try:
            app.neutron.update_port(port_id,
                                    {'port':
                                     {'security_groups': existing_sgs}})
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during updating a "
                      "Neutron port with a new list of "
                      "security groups: {0}".format(ex))
    try:
        for sg in removing_sgs:
            app.neutron.delete_security_group(sg)
    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened during deleting a "
                  "Neutron security group: {0}".format(ex))


def _create_kuryr_subnet(pool_cidr, subnet_cidr, pool_id, network_id, gateway):
    new_kuryr_subnet = [{
        'name': utils.make_subnet_name(pool_cidr),
        'network_id': network_id,
        'ip_version': subnet_cidr.version,
        'cidr': str(subnet_cidr),
        'enable_dhcp': app.enable_dhcp,
    }]
    new_kuryr_subnet[0]['subnetpool_id'] = pool_id
    if gateway:
        new_kuryr_subnet[0]['gateway_ip'] = gateway

    subnets = app.neutron.create_subnet({'subnets': new_kuryr_subnet})
    if app.tag_ext:
        for subnet in subnets['subnets']:
            _neutron_subnet_add_tag(subnet, pool_id)
    LOG.debug("Created kuryr subnet %s", new_kuryr_subnet)


def _create_kuryr_subnetpool(pool_cidr, pool_tag, shared):
    pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)

    kwargs = {'name': pool_name}
    if pool_tag:
        kwargs['tags'] = [pool_tag]
    pools = _get_subnetpools_by_attrs(**kwargs)
    if len(pools):
        raise exceptions.KuryrException(
            "Another pool with same cidr exist. ipam and network"
            " options not used to pass pool name")

    cidr = ipaddress.ip_network(str(pool_cidr))
    new_subnetpool = {
        'name': pool_name,
        'default_prefixlen': cidr.prefixlen,
        'prefixes': [pool_cidr],
        'shared': shared
    }
    LOG.info("Creating subnetpool with the given pool CIDR")
    created_subnetpool_response = app.neutron.create_subnetpool(
        {'subnetpool': new_subnetpool})
    pool = created_subnetpool_response['subnetpool']
    if pool_tag:
        _neutron_subnetpool_add_tag(pool, pool_tag)
    return pool


@app.route('/Plugin.Activate', methods=['POST'])
def plugin_activate():
    """Returns the list of the implemented drivers.

    This function returns the list of the implemented drivers defaults to
    ``[NetworkDriver, IpamDriver]`` in the handshake of the remote driver,
     which happens right before the first request against Kuryr.

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#handshake  # noqa
    """
    LOG.debug("Received /Plugin.Activate")
    return flask.jsonify(const.SCHEMA['PLUGIN_ACTIVATE'])


@app.route('/NetworkDriver.GetCapabilities', methods=['POST'])
def plugin_scope():
    """Returns the capability as the remote network driver.

    This function returns the capability of the remote network driver, which is
    ``global`` or ``local`` and defaults to ``local``. With ``global``
    capability, the network information is shared among multipe Docker daemons
    if the distributed store is appropriately configured.

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#set-capability  # noqa
    """
    LOG.debug("Received /NetworkDriver.GetCapabilities")
    capabilities = {'Scope': cfg.CONF.capability_scope}
    return flask.jsonify(capabilities)


@app.route('/NetworkDriver.DiscoverNew', methods=['POST'])
def network_driver_discover_new():
    """The callback function for the DiscoverNew notification.

    The DiscoverNew notification includes the type of the
    resource that has been newly discovered and possibly other
    information associated with the resource.

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#discovernew-notification  # noqa
    """
    LOG.debug("Received /NetworkDriver.DiscoverNew")
    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.DiscoverDelete', methods=['POST'])
def network_driver_discover_delete():
    """The callback function for the DiscoverDelete notification.

    The DiscoverDelete notification includes the type of the
    resource that has been deleted and possibly other
    information associated with the resource.

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#discoverdelete-notification  # noqa
    """
    LOG.debug("Received /NetworkDriver.DiscoverDelete")
    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.AllocateNetwork', methods=['POST'])
def network_driver_allocate_network():
    """Allocate network specific resources passing network id and network specific config.

    Libnetwork miss this API in their doc.
    https://github.com/docker/libnetwork/issues/1699

    See the following like for more detail about the spec:

      https://github.com/docker/libnetwork/blob/master/driverapi/driverapi.go # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for "
              "/NetworkDriver.AllocateNetwork", json_data)
    # Note(limao): This API will only called in docker swarm mode
    # The returned options are passed to CreateNetwork.
    return flask.jsonify({'Options': json_data.get('Options')})


@app.route('/NetworkDriver.FreeNetwork', methods=['POST'])
def network_driver_free_network():
    """Free network specific resources associated with a given network id.

    Libnetwork miss this API in their doc.
    https://github.com/docker/libnetwork/issues/1699

    See the following like for more detail about the spec:

      https://github.com/docker/libnetwork/blob/master/driverapi/driverapi.go # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for "
              "/NetworkDriver.FreeNetwork", json_data)
    # Note(limao): This API will only called in docker swarm mode,
    #              we do not have network resource to free right now,
    #              so just return SUCCESS.
    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.CreateNetwork', methods=['POST'])
def network_driver_create_network():
    """Creates a new Neutron Network which name is the given NetworkID.

    This function takes the following JSON data and delegates the actual
    network creation to the Neutron client. libnetwork's NetworkID is used as
    the name of Network in Neutron. ::

        {
            "NetworkID": string,
            "IPv4Data" : [{
                "AddressSpace": string,
                "Pool": ipv4-cidr-string,
                "Gateway" : ipv4-address,
                "AuxAddresses": {
                    "<identifier1>" : "<ipv4-address1>",
                    "<identifier2>" : "<ipv4-address2>",
                    ...
                }
            }, ...],
            "IPv6Data" : [{
                "AddressSpace": string,
                "Pool": ipv6-cidr-string,
                "Gateway" : ipv6-address,
                "AuxAddresses": {
                    "<identifier1>" : "<ipv6-address1>",
                    "<identifier2>" : "<ipv6-address2>",
                    ...
                }
            }, ...],
            "Options": {
                ...
            }
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#create-network  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for"
              " /NetworkDriver.CreateNetwork", json_data)
    jsonschema.validate(json_data, schemata.NETWORK_CREATE_SCHEMA)
    container_net_id = json_data['NetworkID']
    neutron_network_name = utils.make_net_name(container_net_id, tags=app.tag)
    v4_pool_cidr = None
    v6_pool_cidr = None
    v4_gateway_ip = ''
    v6_gateway_ip = ''

    def _get_gateway_ip(ip_data):
        gateway_ip = ''
        if 'Gateway' in ip_data:
            gateway_cidr = ip_data['Gateway']
            gateway_ip = gateway_cidr.split('/')[0]
        return gateway_ip

    if json_data['IPv4Data']:
        v4_pool_cidr = json_data['IPv4Data'][0]['Pool']
        v4_gateway_ip = _get_gateway_ip(json_data['IPv4Data'][0])

    if json_data['IPv6Data']:
        v6_pool_cidr = json_data['IPv6Data'][0]['Pool']
        v6_gateway_ip = _get_gateway_ip(json_data['IPv6Data'][0])

    neutron_uuid = None
    neutron_name = None
    v4_pool_name = ''
    v4_pool_id = ''
    v6_pool_name = ''
    v6_pool_id = ''
    v4_subnet_name = ''
    v4_subnet_id = ''
    v6_subnet_name = ''
    v6_subnet_id = ''
    shared = False
    options = json_data.get('Options')
    if options:
        generic_options = options.get(const.NETWORK_GENERIC_OPTIONS)
        if generic_options:
            v4_subnet_id = generic_options.get(
                const.NEUTRON_SUBNET_UUID_OPTION)
            v4_subnet_name = generic_options.get(
                const.NEUTRON_SUBNET_NAME_OPTION)
            v6_subnet_id = generic_options.get(
                const.NEUTRON_V6_SUBNET_UUID_OPTION)
            v6_subnet_name = generic_options.get(
                const.NEUTRON_V6_SUBNET_NAME_OPTION)
            neutron_uuid = generic_options.get(const.NEUTRON_UUID_OPTION)
            neutron_name = generic_options.get(const.NEUTRON_NAME_OPTION)
            v4_pool_name = generic_options.get(const.NEUTRON_POOL_NAME_OPTION)
            v6_pool_name = generic_options.get(
                const.NEUTRON_V6_POOL_NAME_OPTION)
            v4_pool_id = generic_options.get(
                const.NEUTRON_POOL_UUID_OPTION)
            v6_pool_id = generic_options.get(
                const.NEUTRON_V6_POOL_UUID_OPTION)
            shared = strutils.bool_from_string(generic_options.get(
                const.NEUTRON_SHARED_OPTION, 'False'))

    def _get_pool_id(pool_name, pool_cidr, pool_tags):
        pool_id = ''
        kwargs = {}
        if pool_tags:
            kwargs['tags'] = pool_tags
        if not pool_name and pool_cidr:
            pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)
        if pool_name:
            kwargs['name'] = pool_name
            pools = _get_subnetpools_by_attrs(**kwargs)
            if pools:
                pool_id = pools[0]['id']
            else:
                raise exceptions.KuryrException(
                    ("Specified pool name({0}) does not "
                     "exist.").format(pool_name))
        return pool_id

    def _verify_pool_id(pool_id):
        pools = _get_subnetpools_by_attrs(id=pool_id)
        if not pools:
            raise exceptions.KuryrException(
                ("Specified pool id({0}) does not "
                 "exist.").format(pool_id))
    if v4_subnet_name and not v4_subnet_id:
        v4_subnet_id = _get_subnet_by_name(v4_subnet_name)
    if v4_pool_id:
        _verify_pool_id(v4_pool_id)
    else:
        v4_pool_tags = [v4_subnet_id] if v4_subnet_id else None
        v4_pool_id = _get_pool_id(v4_pool_name, v4_pool_cidr, v4_pool_tags)

    if v6_subnet_name and not v6_subnet_id:
        v6_subnet_id = _get_subnet_by_name(v6_subnet_name)
    if v6_pool_id:
        _verify_pool_id(v6_pool_id)
    else:
        v6_pool_tags = [v6_subnet_id] if v6_subnet_id else None
        v6_pool_id = _get_pool_id(v6_pool_name, v6_pool_cidr, v6_pool_tags)

    # let the user override the driver default
    if not neutron_uuid and not neutron_name:
        try:
            neutron_uuid = app.driver.get_default_network_id()
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Failed to retrieve the default driver "
                      "network due to Neutron error: %s", ex)
            raise

    if not neutron_uuid and not neutron_name:
        network = app.neutron.create_network(
            {'network': {'name': neutron_network_name,
                         "admin_state_up": True,
                         'shared': shared}})['network']
        network_id = network['id']
        _neutron_net_add_tags(network, container_net_id,
                              tags=app.tag)

        LOG.info("Created a new network with name "
                 "%(neutron_network_name)s successfully: %(network)s",
                 {'neutron_network_name': neutron_network_name,
                  'network': network})
    else:
        try:
            if neutron_uuid:
                networks = _get_networks_by_attrs(id=neutron_uuid)
                specified_network = neutron_uuid
            else:
                networks = _get_networks_by_attrs(name=neutron_name)
                specified_network = neutron_name
            if not networks:
                raise exceptions.KuryrException(
                    ("Specified network id/name({0}) does not "
                     "exist.").format(specified_network))
            network = networks[0]
            network_id = network['id']
            network_shared = networks[0]['shared']
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during listing "
                      "Neutron networks: %s", ex)
            raise
        if app.tag:
            _neutron_net_add_tags(network, container_net_id, tags=app.tag)
            _neutron_net_add_tag(network,
                                 utils.existing_net_tag(container_net_id))
        else:
            network = app.neutron.update_network(
                neutron_uuid, {'network': {'name': neutron_network_name}})
            LOG.info("Updated the network with new name "
                     "%(neutron_network_name)s successfully: %(network)s",
                     {'neutron_network_name': neutron_network_name,
                      'network': network})
        if network_shared != shared:
            raise exceptions.ConflictConfigOption(
                'Network %(network_id)s had option '
                'shared=%(network_shared)s, conflict with the given option '
                'shared=%(shared)s', {
                    'network_id': network_id,
                    'network_shared': network_shared,
                    'shared': shared
                })
        LOG.info("Using existing network %s "
                 "successfully", specified_network)

    def _get_existing_neutron_subnets(pool_cidr, network_id):
        cidr = None
        subnets = []
        if pool_cidr:
            cidr = ipaddress.ip_network(str(pool_cidr))
            subnets = _get_subnets_by_attrs(network_id=network_id,
                                            cidr=str(cidr))
        if len(subnets) > 1:
            raise exceptions.DuplicatedResourceException(
                "Multiple Neutron subnets exist for the network_id={0}"
                "and cidr={1}".format(network_id, cidr))
        return cidr, subnets

    v4_cidr, v4_subnets = _get_existing_neutron_subnets(v4_pool_cidr,
                                                        network_id)
    v6_cidr, v6_subnets = _get_existing_neutron_subnets(v6_pool_cidr,
                                                        network_id)

    def _add_tag_for_existing_subnet(subnet, pool_id):
        if len(subnet) == 1:
            _neutron_subnet_add_tag(subnet[0], pool_id)

    # This will add a subnetpool_id(created by kuryr) tag
    # for existing Neutron subnets.
    if app.tag_ext:
        _add_tag_for_existing_subnet(v4_subnets, v4_pool_id)
        _add_tag_for_existing_subnet(v6_subnets, v6_pool_id)

    if not v4_subnets and v4_pool_cidr:
        _create_kuryr_subnet(v4_pool_cidr, v4_cidr, v4_pool_id,
                             network_id, v4_gateway_ip)
    if not v6_subnets and v6_pool_cidr:
        _create_kuryr_subnet(v6_pool_cidr, v6_cidr, v6_pool_id,
                             network_id, v6_gateway_ip)

    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.DeleteNetwork', methods=['POST'])
def network_driver_delete_network():
    """Delete the Neutron Network with name as the given NetworkID.

    This function takes the following JSON data and delegates the actual
    network deletion to the Neutron client. ::

        {
            "NetworkID": string
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#delete-network  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for"
              " /NetworkDriver.DeleteNetwork", json_data)
    jsonschema.validate(json_data, schemata.NETWORK_DELETE_SCHEMA)

    container_net_id = json_data['NetworkID']
    neutron_network_identifier = _make_net_identifier(container_net_id,
                                                      tags=app.tag)
    if app.tag:
        existing_network_identifier = neutron_network_identifier + ','
        existing_network_identifier += utils.existing_net_tag(container_net_id)
        try:
            existing_networks = _get_networks_by_identifier(
                existing_network_identifier)
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during listing "
                      "Neutron networks: %s", ex)
            raise

        if existing_networks:
            LOG.warning("Network is a pre existing Neutron "
                        "network, not deleting in Neutron. "
                        "removing tags: %s", existing_network_identifier)
            neutron_net = existing_networks[0]
            neutron_net_id = neutron_net['id']
            _neutron_net_remove_tags(neutron_net, container_net_id)
            _neutron_net_remove_tag(neutron_net,
                                    utils.existing_net_tag(container_net_id))
            # Delete subnets created by kuryr
            filtered_subnets = _get_subnets_by_attrs(
                network_id=neutron_net_id)
            for subnet in filtered_subnets:
                try:
                    subnet_name = subnet.get('name')
                    if str(subnet_name).startswith(const.SUBNET_NAME_PREFIX):
                        app.neutron.delete_subnet(subnet['id'])
                except n_exceptions.Conflict:
                    LOG.error("Subnet %s is in use, "
                              "can't be deleted.", subnet['id'])
                except n_exceptions.NeutronClientException as ex:
                    LOG.error("Error happened during deleting a "
                              "subnet created by kuryr: %s", ex)
            return flask.jsonify(const.SCHEMA['SUCCESS'])

    try:
        filtered_networks = _get_networks_by_identifier(
            neutron_network_identifier)
    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened during listing "
                  "Neutron networks: %s", ex)
        raise

    if not filtered_networks:
        LOG.warning("Network with identifier %s cannot be found",
                    neutron_network_identifier)
    else:
        neutron_network_id = filtered_networks[0]['id']
        filtered_subnets = _get_subnets_by_attrs(
            network_id=neutron_network_id)
        if len(filtered_subnets) > 2:  # subnets for IPv4 and/or IPv6
            raise exceptions.DuplicatedResourceException(
                "Multiple Neutron subnets exist for the network_id={0} "
                .format(neutron_network_id))
        for subnet in filtered_subnets:
            try:
                subnetpool_id = subnet.get('subnetpool_id', None)

                _cache_default_subnetpool_ids(app)

                if subnetpool_id not in app.DEFAULT_POOL_IDS:
                    # If the subnet to be deleted has any port, when some ports
                    # are referring to the subnets in other words,
                    # delete_subnet throws an exception, SubnetInUse that
                    # extends Conflict. This can happen when the multiple
                    # Docker endpoints are created with the same subnet CIDR
                    # and it's totally the normal case. So we'd just log that
                    # and continue to proceed.
                    app.neutron.delete_subnet(subnet['id'])
            except n_exceptions.Conflict:
                LOG.error("Subnet, %s, is in use. Network can't "
                          "be deleted.", subnet['id'])
                raise
            except n_exceptions.NeutronClientException as ex:
                LOG.error("Error happened during deleting a "
                          "Neutron subnets: %s", ex)
                raise

        try:
            app.neutron.delete_network(neutron_network_id)
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during deleting a "
                      "Neutron network: %s", ex)
            raise
        LOG.info("Deleted the network with ID %s "
                 "successfully", neutron_network_id)
    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.CreateEndpoint', methods=['POST'])
def network_driver_create_endpoint():
    """Creates new Neutron Subnets and a Port with the given EndpointID.

    This function takes the following JSON data and delegates the actual
    endpoint creation to the Neutron client mapping it into Subnet and Port. ::

        {
            "NetworkID": string,
            "EndpointID": string,
            "Options": {
                ...
            },
            "Interface": {
                "Address": string,
                "AddressIPv6": string,
                "MacAddress": string
            }
        }

    Then the following JSON response is returned. ::

        {
            "Interface": {
                "Address": string,
                "AddressIPv6": string,
                "MacAddress": string
            }
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#create-endpoint  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for "
              "/NetworkDriver.CreateEndpoint", json_data)
    jsonschema.validate(json_data, schemata.ENDPOINT_CREATE_SCHEMA)

    endpoint_id = json_data['EndpointID']
    neutron_network_identifier = _make_net_identifier(json_data['NetworkID'],
                                                      tags=app.tag)
    filtered_networks = _get_networks_by_identifier(neutron_network_identifier)

    if not filtered_networks:
        return flask.jsonify({
            'Err': "Neutron net associated with identifier {0} doesn't exist."
            .format(neutron_network_identifier)
        })
    else:
        neutron_network_id = filtered_networks[0]['id']
        interface = json_data['Interface'] or {}  # Workaround for null
        interface_cidrv4 = interface.get('Address', '')
        interface_cidrv6 = interface.get('AddressIPv6', '')
        interface_mac = interface.get('MacAddress', '')
        if not interface_cidrv4 and not interface_cidrv6:
            return flask.jsonify({
                'Err': "Interface address v4 or v6 not provided."
            })
        neutron_port, subnets = _create_or_update_port(
            neutron_network_id, endpoint_id, interface_cidrv4,
            interface_cidrv6, interface_mac)
        try:
            port_driver = get_driver(neutron_port)
            (stdout, stderr) = port_driver.create_host_iface(
                endpoint_id, neutron_port, subnets, filtered_networks[0])
            LOG.debug(stdout)
            if stderr:
                LOG.error(stderr)
        except (exceptions.VethCreationFailure,
                exceptions.BindingNotSupportedFailure) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Preparing the veth '
                          'pair was failed: %s.', ex)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error('Could not bind the Neutron port to '
                          'the veth endpoint.')
        except (exceptions.KuryrException,
                n_exceptions.NeutronClientException) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to set up the interface: %s', ex)

        if app.vif_plug_is_fatal:
            port_active = utils.wait_for_port_active(
                app.neutron, neutron_port['id'], app.vif_plug_timeout)
            if not port_active:
                neutron_port_name = neutron_port['name']
                raise exceptions.InactiveResourceException(
                    "Neutron port {0} did not become active on time."
                    .format(neutron_port_name))

        response_interface = {}
        created_fixed_ips = neutron_port['fixed_ips']
        subnets_dict_by_id = {subnet['id']: subnet
                              for subnet in subnets}

        if not interface_mac:
            response_interface['MacAddress'] = neutron_port['mac_address']

        vnic_type = neutron_port.get('binding:vnic_type')
        if vnic_type in const.VNIC_TYPES_SRIOV:
            response_interface.pop('MacAddress', None)

        if not (interface_cidrv4 or interface_cidrv6):
            if 'ip_address' in neutron_port:
                _process_interface_address(
                    neutron_port, subnets_dict_by_id, response_interface)
            for fixed_ip in created_fixed_ips:
                _process_interface_address(
                    fixed_ip, subnets_dict_by_id, response_interface)

        LOG.debug("Response JSON data %s for /NetworkDriver.CreateEndpoint",
                  {'Interface': response_interface})
        return flask.jsonify({'Interface': response_interface})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def network_driver_endpoint_operational_info():
    """Return Neutron Port status with the given EndpointID.

    This function takes the following JSON data and delegates the actual
    endpoint query to the Neutron client mapping it into Port status. ::

        {
            "NetworkID": string,
            "EndpointID": string
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#endpoint-operational-info  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for "
              "/NetworkDriver.EndpointOperInfo", json_data)
    jsonschema.validate(json_data, schemata.ENDPOINT_INFO_SCHEMA)

    endpoint_id = json_data['EndpointID']
    response_port_status = (
        _get_neutron_port_status_from_docker_endpoint(endpoint_id))

    LOG.debug("Response JSON data %s for /NetworkDriver.EndpointOperInfo",
              {'Value': response_port_status})
    return flask.jsonify({'Value': response_port_status})


@app.route('/NetworkDriver.DeleteEndpoint', methods=['POST'])
def network_driver_delete_endpoint():
    """Deletes Neutron Subnets and a Port with the given EndpointID.

    This function takes the following JSON data and delegates the actual
    endpoint deletion to the Neutron client mapping it into Subnet and Port. ::

        {
            "NetworkID": string,
            "EndpointID": string
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#delete-endpoint  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for"
              " /NetworkDriver.DeleteEndpoint", json_data)
    jsonschema.validate(json_data, schemata.ENDPOINT_DELETE_SCHEMA)

    neutron_network_identifier = _make_net_identifier(json_data['NetworkID'],
                                                      tags=app.tag)
    endpoint_id = json_data['EndpointID']
    filtered_networks = _get_networks_by_identifier(neutron_network_identifier)

    if not filtered_networks:
        return flask.jsonify({
            'Err': "Neutron net associated with identifier {0} doesn't exit."
            .format(neutron_network_identifier)
        })
    else:
        neutron_port_identifier = _make_port_identifier(endpoint_id)
        filtered_ports = _get_ports_by_identifier(neutron_port_identifier)
        if not filtered_ports:
            raise exceptions.NoResourceException(
                "The port doesn't exist for the identifier {0}"
                .format(neutron_port_identifier))
        neutron_port = filtered_ports[0]

        try:
            port_driver = get_driver(neutron_port)
            stdout, stderr = port_driver.delete_host_iface(
                endpoint_id, neutron_port)
            LOG.debug(stdout)
            if stderr:
                LOG.error(stderr)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error('Could not unbind the Neutron port from'
                          'the veth endpoint.')
        except exceptions.VethDeletionFailure:
            with excutils.save_and_reraise_exception():
                LOG.error('Cleaning the veth pair up was failed.')
        except (exceptions.KuryrException,
                n_exceptions.NeutronClientException) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error('Error while removing the interface: %s', ex)

        _neutron_port_remove_tags(neutron_port, endpoint_id)

    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.Join', methods=['POST'])
def network_driver_join():
    """Binds a Neutron Port to a network interface attached to a container.

    This function takes the following JSON data, creates a veth pair, put one
    end inside of the container and binds another end to the Neutron Port
    specified in the request. ::

        {
            "NetworkID": string,
            "EndpointID": string,
            "SandboxKey": string,
            "Options": {
                ...
            }
        }

    If the binding is succeeded, the following JSON response is returned.::

        {
            "InterfaceName": {
                SrcName: string,
                DstPrefix: string
            },
            "Gateway": string,
            "GatewayIPv6": string,
            "StaticRoutes": [{
                "Destination": string,
                "RouteType": int,
                "NextHop": string,
            }, ...]
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/remote.md#join  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for /NetworkDriver.Join", json_data)
    jsonschema.validate(json_data, schemata.JOIN_SCHEMA)

    neutron_network_identifier = _make_net_identifier(json_data['NetworkID'],
                                                      tags=app.tag)
    endpoint_id = json_data['EndpointID']
    filtered_networks = _get_networks_by_identifier(neutron_network_identifier)

    if not filtered_networks:
        return flask.jsonify({
            'Err': "Neutron net associated with identifier {0} doesn't exit."
            .format(neutron_network_identifier)
        })
    else:
        neutron_network_id = filtered_networks[0]['id']

        neutron_port_identifier = _make_port_identifier(endpoint_id)
        filtered_ports = _get_ports_by_identifier(neutron_port_identifier)
        if not filtered_ports:
            raise exceptions.NoResourceException(
                "The port doesn't exist for the identifier {0}"
                .format(neutron_port_identifier))
        neutron_port = filtered_ports[0]
        all_subnets = _get_subnets_by_attrs(network_id=neutron_network_id)
        kuryr_subnets = []
        for subnet in all_subnets:
            subnet_name = subnet.get('name')
            if str(subnet_name).startswith(const.SUBNET_NAME_PREFIX):
                kuryr_subnets.append(subnet)
        if len(kuryr_subnets) > 2:
            raise exceptions.DuplicatedResourceException(
                "Multiple Kuryr subnets exist for the network_id={0} "
                .format(neutron_network_id))

        port_driver = get_driver(neutron_port)
        iface_name = port_driver.get_container_iface_name(neutron_port)

        join_response = {
            "InterfaceName": {
                "SrcName": iface_name,
                "DstPrefix": config.CONF.binding.veth_dst_prefix
            },
            "StaticRoutes": [],
            "DisableGatewayService": True,
        }

        for subnet in all_subnets:
            for fixed_ip in neutron_port['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    if subnet['ip_version'] == 4:
                        join_response['Gateway'] = subnet.get('gateway_ip', '')
                    else:
                        join_response['GatewayIPv6'] = subnet.get(
                            'gateway_ip', '')

            # NOTE: kuryr-libnetwork do not support a connected route
            host_routes = subnet.get('host_routes', [])
            for host_route in host_routes:
                static_route = {
                    'Destination': host_route['destination'],
                    'RouteType': const.ROUTE_TYPE['NEXTHOP'],
                    'NextHop': host_route['nexthop']
                }
                join_response['StaticRoutes'].append(static_route)

        LOG.debug("Response JSON data %s for /NetworkDriver.Join",
                  join_response)
        return flask.jsonify(join_response)


@app.route('/NetworkDriver.Leave', methods=['POST'])
def network_driver_leave():
    """Unbinds a Neutron Port to a network interface attached to a container.

    This function takes the following JSON data and delete the veth pair
    corresponding to the given info. ::

        {
            "NetworkID": string,
            "EndpointID": string
        }
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for"
              " /NetworkDriver.Leave", json_data)
    jsonschema.validate(json_data, schemata.LEAVE_SCHEMA)

    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.ProgramExternalConnectivity', methods=['POST'])
def network_driver_program_external_connectivity():
    """Provides external connectivity for a given container.

    Performs the necessary programming to allow the external connectivity
    dictated by the specified options

    See the following link for more details about the spec:
      https://github.com/docker/libnetwork/blob/master/driverapi/driverapi.go
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for"
              " /NetworkDriver.ProgramExternalConnectivity", json_data)
    if not cfg.CONF.process_external_connectivity:
        return flask.jsonify(const.SCHEMA['SUCCESS'])

    # TODO(banix): Add support for exposed ports
    port = _get_neutron_port_from_docker_endpoint(json_data['EndpointID'])
    if port:
        _program_expose_ports(json_data['Options'], port)

    # TODO(banix): Add support for published ports
    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/NetworkDriver.RevokeExternalConnectivity', methods=['POST'])
def network_driver_revoke_external_connectivity():
    """Removes external connectivity for a given container.

    Performs the necessary programming to remove the external connectivity
    of a container

    See the following link for more details about the spec:
      https://github.com/docker/libnetwork/blob/master/driverapi/driverapi.go
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for"
              " /NetworkDriver.RevokeExternalConnectivity", json_data)
    if not cfg.CONF.process_external_connectivity:
        return flask.jsonify(const.SCHEMA['SUCCESS'])

    # TODO(banix): Add support for removal of exposed ports
    port = _get_neutron_port_from_docker_endpoint(json_data['EndpointID'])
    if port:
        revoke_expose_ports(port)

    # TODO(banix): Add support for removal of published ports
    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/IpamDriver.GetCapabilities', methods=['POST'])
def ipam_get_capabilities():
    """Provides the IPAM driver capabilities.

    This function is called during the registration of the IPAM driver.

    See the following link for more details about the spec:
      https://github.com/docker/libnetwork/blob/master/docs/ipam.md#getcapabilities  # noqa
    """
    LOG.debug("Received /IpamDriver.GetCapabilities")
    capabilities = {'RequiresMACAddress': True}
    return flask.jsonify(capabilities)


@app.route('/IpamDriver.GetDefaultAddressSpaces', methods=['POST'])
def ipam_get_default_address_spaces():
    """Provides the default address spaces for the IPAM.

    This function is called after the registration of the IPAM driver and
    the plugin set the returned values as the default address spaces for the
    IPAM. The address spaces can be configured in the config file.

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/ipam.md#getdefaultaddressspaces  # noqa
    """
    LOG.debug("Received /IpamDriver.GetDefaultAddressSpaces")
    address_spaces = {
        'LocalDefaultAddressSpace': cfg.CONF.local_default_address_space,
        'GlobalDefaultAddressSpace': cfg.CONF.global_default_address_space}
    return flask.jsonify(address_spaces)


@app.route('/IpamDriver.RequestPool', methods=['POST'])
def ipam_request_pool():
    """Creates a new Neutron subnetpool from the given request.

    This funciton takes the following JSON data and delegates the subnetpool
    creation to the Neutron client. ::

        {
            "AddressSpace": string
            "Pool":         string
            "SubPool":      string
            "Options":      map[string]string
            "V6":           bool
        }

    Then the following JSON response is returned. ::

        {
            "PoolID": string
            "Pool":   string
            "Data":   map[string]string
        }

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/ipam.md#requestpool  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for /IpamDriver.RequestPool",
              json_data)
    jsonschema.validate(json_data, schemata.REQUEST_POOL_SCHEMA)
    requested_pool = json_data['Pool']
    requested_subpool = json_data['SubPool']
    v6 = json_data['V6']
    subnet_cidr = ''
    pool_name = ''
    pool_id = ''
    subnet_id = ''
    subnet_name = ''
    shared = False
    options = json_data.get('Options')
    if options:
        shared = strutils.bool_from_string(options.get(
            const.NEUTRON_SHARED_OPTION, 'False'))
        if v6:
            subnet_name = options.get(const.NEUTRON_V6_SUBNET_NAME_OPTION)
            subnet_id = options.get(const.NEUTRON_V6_SUBNET_UUID_OPTION)
            pool_name = options.get(const.NEUTRON_V6_POOL_NAME_OPTION)
            pool_id = options.get(const.NEUTRON_V6_POOL_UUID_OPTION)
        else:
            subnet_name = options.get(const.NEUTRON_SUBNET_NAME_OPTION)
            subnet_id = options.get(const.NEUTRON_SUBNET_UUID_OPTION)
            pool_name = options.get(const.NEUTRON_POOL_NAME_OPTION)
            pool_id = options.get(const.NEUTRON_POOL_UUID_OPTION)
    if requested_pool:
        if requested_subpool:
            cidr = ipaddress.ip_network(str(requested_subpool))
        else:
            cidr = ipaddress.ip_network(str(requested_pool))
        subnet_cidr = str(cidr)
        if not subnet_id and subnet_name:
            subnet_id = _get_subnet_by_name(subnet_name)
        elif not subnet_id and not subnet_name:
            subnets_by_cidr = _get_subnets_by_attrs(cidr=subnet_cidr)
            if len(subnets_by_cidr):
                LOG.warning("There is already existing subnet for the "
                            "same cidr. Please check and specify pool name "
                            "in Options.")
        if not pool_name and not pool_id:
            pool_id = _create_kuryr_subnetpool(subnet_cidr,
                                               subnet_id,
                                               shared)['id']
        else:
            if pool_id:
                existing_pools = _get_subnetpools_by_attrs(id=pool_id)
            else:
                existing_pools = _get_subnetpools_by_attrs(name=pool_name)
            if not existing_pools:
                raise exceptions.KuryrException(
                    ("Specified subnetpool id/name({0}) does not "
                     "exist.").format(pool_id or pool_name))

            pool_id = existing_pools[0]['id']
            if app.tag_ext:
                _neutron_subnetpool_add_tag(
                    existing_pools[0], const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)
            prefixes = existing_pools[0]['prefixes']
            pool_cidr = ipaddress.ip_network(str(prefixes[0]))
            if pool_cidr == cidr:
                if shared != existing_pools[0]['shared']:
                    raise exceptions.ConflictConfigOption(
                        'There is already existing subnet pool '
                        'with %(cidr)s but with shared = %(shared)s',
                        {'cidr': cidr,
                         'shared': existing_pools[0]['shared']})
                LOG.info("Using existing Neutron subnetpool %s successfully",
                         pool_id)
            else:
                pool_id = _create_kuryr_subnetpool(subnet_cidr,
                                                   subnet_id,
                                                   shared)['id']
    else:
        if v6:
            default_pool_list = SUBNET_POOLS_V6
        else:
            default_pool_list = SUBNET_POOLS_V4
        pool_name = default_pool_list[0]
        subnet_cidr, pool_id = _get_cidr_from_subnetpool(name=pool_name)
        subnet_cidr = str(subnet_cidr)

    req_pool_res = {'PoolID': pool_id,
                    'Pool': subnet_cidr}
    LOG.debug("Response JSON data %s for /IpamDriver.RequestPool",
              req_pool_res)
    return flask.jsonify(req_pool_res)


@app.route('/IpamDriver.RequestAddress', methods=['POST'])
def ipam_request_address():
    """Allocates the IP address in the given request.

    This function takes the following JSON data and add the given IP address in
    the allocation_pools attribute of the subnet. ::

        {
            "PoolID":  string
            "Address": string
            "Options": map[string]string
        }

    Then the following response is returned. ::

        {
            "Address": string
            "Data":    map[string]string
        }

    See the following link for more details about the spec:

    https://github.com/docker/libnetwork/blob/master/docs/ipam.md#requestaddress  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for "
              "/IpamDriver.RequestAddress", json_data)
    jsonschema.validate(json_data, schemata.REQUEST_ADDRESS_SCHEMA)
    pool_id = json_data['PoolID']
    req_address = json_data['Address']
    req_mac_address = ''
    is_gateway = False
    allocated_address = ''
    subnet = {}
    # Check if the port is gateway
    options = json_data.get('Options')
    if options:
        req_mac_address = options.get(const.DOCKER_MAC_ADDRESS_OPTION)
        request_address_type = options.get(const.REQUEST_ADDRESS_TYPE)
        if request_address_type == const.NETWORK_GATEWAY_OPTIONS:
            is_gateway = True

    # check if any subnet with matching subnetpool_id is present
    subnets_by_poolid = _get_subnets_by_attrs(subnetpool_id=pool_id)
    if subnets_by_poolid:
        if len(subnets_by_poolid) == 1:
            subnet = subnets_by_poolid[0]
            subnet_cidr = ipaddress.ip_network(str(subnet['cidr']))
        else:
            pool_cidr, _ = _get_cidr_from_subnetpool(id=pool_id)
            for tmp_subnet in subnets_by_poolid:
                subnet_cidr = ipaddress.ip_network(
                    str(tmp_subnet['cidr']))
                if pool_cidr == subnet_cidr:
                    subnet = tmp_subnet
                    break
    else:
        # check if any subnet with matching cidr is present
        subnet_cidr, _ = _get_cidr_from_subnetpool(id=pool_id)
        subnets_by_cidr = _get_subnets_by_attrs(
            cidr=str(subnet_cidr))
        if len(subnets_by_cidr) > 1:
            for tmp_subnet in subnets_by_cidr:
                if tmp_subnet.get('tags') is not None:
                    if pool_id in tmp_subnet.get('tags'):
                        subnet = tmp_subnet
                else:
                    LOG.warning("subnetpool tag for Neutron "
                                "subnet %s is missing, cannot "
                                "gets the correct subnet.",
                                tmp_subnet['id'])
        elif len(subnets_by_cidr) == 1:
            subnet = subnets_by_cidr[0]

    if not any(subnet) and not is_gateway:
        raise exceptions.KuryrException(
            ("Subnet with pool {0} does not exist.").format(pool_id))

    if any(subnet):
        if is_gateway:
            # check if request gateway ip same with existed gateway ip
            existed_gateway_ip = subnet.get('gateway_ip', '')
            if not req_address:
                if subnet['ip_version'] == 4:
                    allocated_address = "0.0.0.0/0"
                else:
                    allocated_address = "::/0"
            elif req_address == existed_gateway_ip:
                allocated_address = '{}/{}'.format(req_address,
                                                   subnet_cidr.prefixlen)
            else:
                raise exceptions.GatewayConflictFailure(
                    "Requested gateway {0} does not match with "
                    "gateway {1} in existed "
                    "network.".format(req_address, existed_gateway_ip))
        else:
            # allocating address for container port
            neutron_network_id = subnet['network_id']
            try:
                port = {
                    'name': const.KURYR_UNBOUND_PORT,
                    'admin_state_up': True,
                    'network_id': neutron_network_id,
                }
                fixed_ips = port['fixed_ips'] = []
                fixed_ip = {'subnet_id': subnet['id']}
                filtered_ports = []
                if req_address:
                    fixed_ip['ip_address'] = req_address
                    fixed_ip_existing = [('subnet_id=%s' % subnet['id'])]
                    fixed_ip_existing.append('ip_address='
                                             '%s' % str(req_address))
                    filtered_ports = app.neutron.list_ports(
                        fixed_ips=fixed_ip_existing).get('ports', [])
                if not filtered_ports:
                    filtered_ports = app.neutron.list_ports(
                        fixed_ips='subnet_id=%s' % subnet['id'],
                        mac_address=req_mac_address).get('ports', [])

                num_ports = len(filtered_ports)
                fixed_ips.append(fixed_ip)

                if num_ports:
                    created_port = filtered_ports[0]
                    # REVISIT(yedongcan) For tag-ext extension not
                    # supported, the Neutron existing port still can not
                    # be deleted in ipam_release_address.
                    if app.tag_ext:
                        _neutron_port_add_tag(
                            created_port,
                            const.KURYR_EXISTING_NEUTRON_PORT)
                else:
                    created_port_resp = app.neutron.create_port({'port': port})
                    created_port = created_port_resp['port']
                    if app.tag_ext:
                        _neutron_port_add_tag(created_port,
                                              lib_const.DEVICE_OWNER)

                LOG.debug("created port %s", created_port)
                fixed_ips = created_port['fixed_ips']
                fixed_ips = [ip for ip in fixed_ips
                             if ip['subnet_id'] == subnet['id']]
                allocated_address = (req_address or
                                     fixed_ips[0]['ip_address'])
                allocated_address = '{}/{}'.format(allocated_address,
                                                   subnet_cidr.prefixlen)
            except n_exceptions.NeutronClientException as ex:
                LOG.error("Error happened during ip allocation on "
                          "Neutron side: %s", ex)
                raise
    else:
        # Auxiliary address or gw_address is received at network creation time.
        # This address cannot be reserved with neutron at this time as subnet
        # is not created yet. In /NetworkDriver.CreateNetwork this address will
        # be reserved with neutron.
        if req_address:
            allocated_address = '{}/{}'.format(req_address,
                                               subnet_cidr.prefixlen)

    LOG.debug("Response JSON data %s for /IpamDriver.RequestAddress",
              {'Address': allocated_address})
    return flask.jsonify({'Address': allocated_address})


@app.route('/IpamDriver.ReleasePool', methods=['POST'])
def ipam_release_pool():
    """Deletes a new Neutron subnetpool from the given reuest.

    This function takes the following JSON data and delegates the subnetpool
    deletion to the Neutron client. ::

       {
           "PoolID": string
       }

    Then the following JSON response is returned. ::

       {}

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/ipam.md#releasepool  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for /IpamDriver.ReleasePool",
              json_data)
    jsonschema.validate(json_data, schemata.RELEASE_POOL_SCHEMA)
    pool_id = json_data['PoolID']

    # Remove subnetpool_id tag from Neutron existing subnet.
    if app.tag_ext:
        subnet_cidr, _ = _get_cidr_from_subnetpool(id=pool_id)
        subnets_by_cidr = _get_subnets_by_attrs(
            cidr=str(subnet_cidr))
        for tmp_subnet in subnets_by_cidr:
            if pool_id in tmp_subnet.get('tags', []):
                _neutron_subnet_remove_tag(tmp_subnet, pool_id)
                break

    pools = _get_subnetpools_by_attrs(id=pool_id)
    if pools:
        pool_name = pools[0]['name']
        if app.tag_ext:
            tags = pools[0].get('tags', [])
            if const.KURYR_EXISTING_NEUTRON_SUBNETPOOL in tags:
                _neutron_subnetpool_remove_tag(
                    pools[0], const.KURYR_EXISTING_NEUTRON_SUBNETPOOL)
                LOG.debug('Skip the cleanup since this is an existing Neutron '
                          'subnetpool.')
                return flask.jsonify(const.SCHEMA['SUCCESS'])
        elif not pool_name.startswith(cfg.CONF.subnetpool_name_prefix):
            LOG.debug('Skip the cleanup since this is an existing Neutron '
                      'subnetpool.')
            return flask.jsonify(const.SCHEMA['SUCCESS'])

    # Delete subnets created by kuryr
    filtered_subnets = _get_subnets_by_attrs(
        subnetpool_id=pool_id)
    for subnet in filtered_subnets:
        try:
            subnet_name = subnet.get('name')
            if str(subnet_name).startswith(const.SUBNET_NAME_PREFIX):
                app.neutron.delete_subnet(subnet['id'])
        except n_exceptions.Conflict:
            LOG.error("Subnet %s is in use, "
                      "can't be deleted.", subnet['id'])
        except n_exceptions.NeutronClientException as ex:
            LOG.error("Error happened during deleting a "
                      "subnet created by kuryr: %s", ex)

    try:
        app.neutron.delete_subnetpool(pool_id)
    except n_exceptions.Conflict:
        LOG.info("The subnetpool with ID %s is still in use."
                 " It can't be deleted for now.", pool_id)
    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened during deleting a "
                  "Neutron subnetpool: %s", ex)
        raise

    return flask.jsonify(const.SCHEMA['SUCCESS'])


@app.route('/IpamDriver.ReleaseAddress', methods=['POST'])
def ipam_release_address():
    """Deallocates the IP address in the given request.

    This function takes the following JSON data and remove the given IP address
    from the allocation_pool attribute of the subnet. ::

        {
            "PoolID": string
            "Address": string
        }

    Then the following response is returned. ::

        {}

    See the following link for more details about the spec:

      https://github.com/docker/libnetwork/blob/master/docs/ipam.md#releaseaddress  # noqa
    """
    json_data = flask.request.get_json(force=True)
    LOG.debug("Received JSON data %s for /IpamDriver.ReleaseAddress",
              json_data)
    jsonschema.validate(json_data, schemata.RELEASE_ADDRESS_SCHEMA)
    pool_id = json_data['PoolID']
    rel_address = json_data['Address']
    # check if any subnet with matching subnetpool_id is present
    subnets = _get_subnets_by_attrs(subnetpool_id=pool_id)
    if not len(subnets):
        # check if any subnet with matching cidr is present
        subnet_cidr = str(_get_cidr_from_subnetpool(id=pool_id)[0])
        subnets = _get_subnets_by_attrs(cidr=subnet_cidr)
    if not len(subnets):
        LOG.info("Subnet already deleted.")
        return flask.jsonify(const.SCHEMA['SUCCESS'])
    if app.tag_ext:
        subnets = [subnet
                   for subnet in subnets
                   if pool_id in subnet.get('tags') or []]

    iface = ipaddress.ip_interface(str(rel_address))
    rel_ip_address = str(iface.ip)
    try:
        fixed_ip = 'ip_address=' + str(rel_ip_address)
        all_ports = app.neutron.list_ports(fixed_ips=fixed_ip)
        for port in all_ports['ports']:
            tags = port.get('tags', [])
            if ((tags and lib_const.DEVICE_OWNER in tags) or
                    (not tags and port['name'] ==
                        utils.get_neutron_port_name(port['device_id']))):
                for tmp_subnet in subnets:
                    if (port['fixed_ips'][0]['subnet_id'] == tmp_subnet['id']):
                        app.neutron.delete_port(port['id'])
            elif tags and const.KURYR_EXISTING_NEUTRON_PORT in tags:
                updated_port = {'device_owner': '',
                                'binding:host_id': ''}
                if port['name'].startswith(port['device_id']):
                    updated_port["device_id"] = ''
                for subnet in subnets:
                    if (port['fixed_ips'][0]['subnet_id'] == subnet['id']):
                        app.neutron.update_port(
                            port['id'], {'port': updated_port})
                        _neutron_port_remove_tag(
                            port, const.KURYR_EXISTING_NEUTRON_PORT)
    except n_exceptions.NeutronClientException as ex:
        LOG.error("Error happened while fetching "
                  "and deleting port, %s", ex)
        raise

    return flask.jsonify(const.SCHEMA['SUCCESS'])
