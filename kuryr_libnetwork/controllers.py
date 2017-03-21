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
from operator import itemgetter
import six
import time

from neutronclient.common import exceptions as n_exceptions
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils

from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils
from kuryr.lib._i18n import _LE, _LI, _LW
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
SUBNET_POOLS_V4 = []
SUBNET_POOLS_V6 = []


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
    try:
        app.neutron.show_extension(MANDATORY_NEUTRON_EXTENSION)
    except n_exceptions.NeutronClientException as e:
        if e.status_code == n_exceptions.NotFound.status_code:
            raise exceptions.MandatoryApiMissing(
                            "Neutron extension with alias '{0}' not found"
                            .format(MANDATORY_NEUTRON_EXTENSION))


def check_for_neutron_tag_support(ext_name):
    """Validates tag and tag-ext extension support availability in Neutron."""
    if ext_name == TAG_EXT_NEUTRON_EXTENSION:
        ext_rename = "tag_ext"
    else:
        ext_rename = ext_name
    setattr(app, ext_rename, True)
    try:
        app.neutron.show_extension(ext_name)
    except n_exceptions.NeutronClientException as e:
        setattr(app, ext_rename, False)
        if e.status_code == n_exceptions.NotFound.status_code:
            LOG.warning(_LW("Neutron extension %s not supported. "
                            "Continue without using them."), ext_name)


def load_default_subnet_pools():
    """Load the default subnetpools."""
    global SUBNET_POOLS_V4
    global SUBNET_POOLS_V6
    SUBNET_POOLS_V4 = [cfg.CONF.neutron.default_subnetpool_v4]
    SUBNET_POOLS_V6 = [cfg.CONF.neutron.default_subnetpool_v6]


def load_port_driver():
    app.driver = driver.get_driver_instance()
    LOG.debug("Using port driver '%s'", str(app.driver))


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
            LOG.error(_LE("Error happened during retrieving the default"
                          " subnet pools: %s"), ex)
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
    iface = ipaddress.ip_interface(six.text_type(interface_cidr))
    subnets = _get_subnets_by_attrs(
        network_id=neutron_network_id, cidr=six.text_type(iface.network))
    if len(subnets) > 2:
        raise exceptions.DuplicatedResourceException(
                "Multiple Neutron subnets exist for the network_id={0}"
                "and cidr={1}"
                .format(neutron_network_id, iface.network))
    return subnets


def _get_neutron_port_from_docker_endpoint(endpoint_id):
    port_name = utils.get_neutron_port_name(endpoint_id)
    filtered_ports = app.neutron.list_ports(name=port_name)
    num_ports = len(filtered_ports.get('ports', []))
    if num_ports == 1:
        return filtered_ports['ports'][0]['id']


def _get_neutron_port_status_from_docker_endpoint(endpoint_id):
    response_port_status = {}
    port_name = utils.get_neutron_port_name(endpoint_id)
    filtered_ports = _get_ports_by_attrs(name=port_name)
    if filtered_ports:
        response_port_status['status'] = filtered_ports[0]['status']
    return response_port_status


def _process_interface_address(port_dict, subnets_dict_by_id,
                               response_interface):
    subnet_id = port_dict['subnet_id']
    subnet = subnets_dict_by_id[subnet_id]
    iface = ipaddress.ip_interface(six.text_type(subnet['cidr']))
    address_key = 'Address' if iface.version == 4 else 'AddressIPv6'
    response_interface[address_key] = six.text_type(iface)


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
        LOG.error(_LE("Error happened during creating a"
                      " Neutron port: %s"), ex)
        raise
    return rcvd_port['port']


def _get_fixed_ips_by_interface_cidr(subnets, interface_cidrv4,
                                     interface_cidrv6, fixed_ips):
    for subnet in subnets:
        fixed_ip = [('subnet_id=%s' % subnet['id'])]
        if interface_cidrv4 or interface_cidrv6:
            if subnet['ip_version'] == 4 and interface_cidrv4:
                iface = ipaddress.ip_interface(six.text_type(interface_cidrv4))
            elif subnet['ip_version'] == 6 and interface_cidrv6:
                iface = ipaddress.ip_interface(six.text_type(interface_cidrv6))
            if six.text_type(subnet['cidr']) != six.text_type(iface.network):
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
        response_port = app.driver.update_port(port, endpoint_id,
                                               interface_mac)
    # For the container boot from dual-net, request_address will
    # create two ports(v4 and v6 address), we should only allow one
    # for port bind.
    elif num_port == 2:
        for port in filtered_ports.get('ports', []):
            port_name = port.get('name')
            if str(port_name).startswith(const.KURYR_UNBOUND_PORT):
                app.neutron.delete_port(port['id'])
        fixed_ips = (
            lib_utils.get_dict_format_fixed_ips_from_kv_format(fixed_ips))
        response_port = _create_port(endpoint_id, neutron_network_id,
            interface_mac, fixed_ips)
    else:
        raise exceptions.DuplicatedResourceException(
            "Multiple ports exist for the cidrs {0} and {1}"
            .format(interface_cidrv4, interface_cidrv6))

    return response_port, subnets


def _neutron_net_add_tag(netid, tag):
    _neutron_add_tag('networks', netid, tag)


def _neutron_net_add_tags(netid, tag, tags=True):
    if tags:
        tags = utils.create_net_tags(tag)
        for tag in tags:
            _neutron_net_add_tag(netid, tag)


def _neutron_net_remove_tag(netid, tag):
    _neutron_remove_tag('networks', netid, tag)


def _neutron_net_remove_tags(netid, tag):
    tags = utils.create_net_tags(tag)
    for tag in tags:
        _neutron_net_remove_tag(netid, tag)


def _neutron_subnet_add_tag(subnetid, tag):
    _neutron_add_tag('subnets', subnetid, tag)


def _neutron_subnet_remove_tag(subnetid, tag):
    _neutron_remove_tag('subnets', subnetid, tag)


def _neutron_port_add_tag(portid, tag):
    _neutron_add_tag('ports', portid, tag)


def _neutron_port_remove_tag(portid, tag):
    _neutron_remove_tag('ports', portid, tag)


def _neutron_add_tag(resource_type, resource_id, tag):
    try:
        app.neutron.add_tag(resource_type, resource_id, tag)
    except n_exceptions.NotFound:
        LOG.warning(_LW("Neutron tags extension for given "
                        "resource type is not supported, "
                        "cannot add tag to %s."), resource_type)


def _neutron_remove_tag(resource_type, resource_id, tag):
    app.neutron.remove_tag(resource_type, resource_id, tag)


def _make_net_identifier(network_id, tags=True):
    if tags:
        return utils.make_net_tags(network_id)
    return network_id


def _get_networks_by_identifier(identifier):
    if app.tag:
        return _get_networks_by_attrs(tags=identifier)
    return _get_networks_by_attrs(name=identifier)


def _port_active(neutron_port_id, vif_plug_timeout):
    port_active = False
    tries = 0
    while True:
        try:
            port = app.neutron.show_port(neutron_port_id)
        except n_exceptions.NeutronClientException as ex:
            LOG.error(_LE('Could not get the port %s to check '
                          'its status'), ex)
        else:
            if port['port']['status'] == lib_const.PORT_STATUS_ACTIVE:
                port_active = True
        if port_active or (vif_plug_timeout > 0 and tries >= vif_plug_timeout):
            break
        LOG.debug('Waiting for port %s to become ACTIVE', neutron_port_id)
        tries += 1
        time.sleep(1)

    return port_active


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
        LOG.error(_LE("Error happened during creating a "
                      "Neutron security group: %s"), ex)
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
            LOG.error(_LE("Unrecognizable protocol %s"), proto)
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
                LOG.error(_LE("Error happened during creating a "
                              "Neutron security group "
                              "rule: %s"), ex)
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
        LOG.error(_LE("Error happened during updating a "
                      "Neutron port: %s"), ex)
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
            LOG.warning(_LW("More than one prefixes present. "
                            "Picking first one."))

        return ipaddress.ip_network(six.text_type(prefixes[0])), pool_id
    else:
        raise exceptions.NoResourceException(
            "No subnetpools with {0} is found."
            .format(kwargs))


def _update_existing_port(existing_port, fixed_ip):
    host = existing_port.get('binding:host_id')
    vif_type = existing_port.get('binding:vif_type')
    if not host and vif_type == 'unbound':
        updated_port = {
            'name': const.NEUTRON_UNBOUND_PORT,
            'admin_state_up': True,
            'binding:host_id': lib_utils.get_hostname(),
        }
        updated_port_resp = app.neutron.update_port(
            existing_port['id'],
            {'port': updated_port})
        existing_port = updated_port_resp['port']
    else:
        port_name = existing_port.get('name', '')
        if (str(port_name) != const.NEUTRON_UNBOUND_PORT or
                len(existing_port['fixed_ips']) <= 1 or
                host != lib_utils.get_hostname()):
            raise exceptions.AddressInUseException(
                "Requested ip address {0} already belongs to "
                "a bound Neutron port: {1}".format(fixed_ip,
                existing_port['id']))

    return existing_port


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
            LOG.error(_LE("Error happened during updating a "
                          "Neutron port with a new list of "
                          "security groups: {0}").format(ex))
    try:
        for sg in removing_sgs:
            app.neutron.delete_security_group(sg)
    except n_exceptions.NeutronClientException as ex:
        LOG.error(_LE("Error happened during deleting a "
                      "Neutron security group: {0}").format(ex))


def _create_kuryr_subnet(pool_cidr, subnet_cidr, pool_id, network_id, gateway):
    new_kuryr_subnet = [{
        'name': utils.make_subnet_name(pool_cidr),
        'network_id': network_id,
        'ip_version': subnet_cidr.version,
        'cidr': six.text_type(subnet_cidr),
        'enable_dhcp': app.enable_dhcp,
    }]
    new_kuryr_subnet[0]['subnetpool_id'] = pool_id
    if gateway:
        new_kuryr_subnet[0]['gateway_ip'] = gateway

    app.neutron.create_subnet({'subnets': new_kuryr_subnet})
    LOG.debug("Created kuryr subnet %s", new_kuryr_subnet)


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
    options = json_data.get('Options')
    if options:
        generic_options = options.get(const.NETWORK_GENERIC_OPTIONS)
        if generic_options:
            neutron_uuid = generic_options.get(const.NEUTRON_UUID_OPTION)
            neutron_name = generic_options.get(const.NEUTRON_NAME_OPTION)
            v4_pool_name = generic_options.get(const.NEUTRON_POOL_NAME_OPTION)
            v6_pool_name = generic_options.get(
                const.NEUTRON_V6_POOL_NAME_OPTION)
            v4_pool_id = generic_options.get(
                const.NEUTRON_POOL_UUID_OPTION)
            v6_pool_id = generic_options.get(
                const.NEUTRON_V6_POOL_UUID_OPTION)

    def _get_pool_id(pool_name, pool_cidr):
        pool_id = ''
        if not pool_name and pool_cidr:
            pool_name = lib_utils.get_neutron_subnetpool_name(pool_cidr)
        if pool_name:
            pools = _get_subnetpools_by_attrs(name=pool_name)
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

    if v4_pool_id:
        _verify_pool_id(v4_pool_id)
    else:
        v4_pool_id = _get_pool_id(v4_pool_name, v4_pool_cidr)
    if v6_pool_id:
        _verify_pool_id(v6_pool_id)
    else:
        v6_pool_id = _get_pool_id(v6_pool_name, v6_pool_cidr)

    # let the user override the driver default
    if not neutron_uuid and not neutron_name:
        try:
            neutron_uuid = app.driver.get_default_network_id()
        except n_exceptions.NeutronClientException as ex:
            LOG.error(_LE("Failed to retrieve the default driver "
                          "network due to Neutron error: %s"), ex)
            raise

    if not neutron_uuid and not neutron_name:
        network = app.neutron.create_network(
            {'network': {'name': neutron_network_name,
                         "admin_state_up": True}})
        network_id = network['network']['id']
        _neutron_net_add_tags(network['network']['id'], container_net_id,
                              tags=app.tag)

        LOG.info(_LI("Created a new network with name "
                     "%(neutron_network_name)s successfully: %(network)s"),
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
            network_id = networks[0]['id']
        except n_exceptions.NeutronClientException as ex:
            LOG.error(_LE("Error happened during listing "
                          "Neutron networks: %s"), ex)
            raise
        if app.tag:
            _neutron_net_add_tags(network_id, container_net_id, tags=app.tag)
            _neutron_net_add_tag(network_id, const.KURYR_EXISTING_NEUTRON_NET)
        else:
            network = app.neutron.update_network(
                neutron_uuid, {'network': {'name': neutron_network_name}})
            LOG.info(_LI("Updated the network with new name "
                         "%(neutron_network_name)s successfully: %(network)s"),
                     {'neutron_network_name': neutron_network_name,
                      'network': network})
        LOG.info(_LI("Using existing network %s "
                     "successfully"), specified_network)

    def _get_existing_neutron_subnets(pool_cidr, network_id):
        cidr = None
        subnets = []
        if pool_cidr:
            cidr = ipaddress.ip_network(six.text_type(pool_cidr))
            subnets = _get_subnets_by_attrs(network_id=network_id,
                                            cidr=six.text_type(cidr))
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
            _neutron_subnet_add_tag(subnet[0]['id'], pool_id)

    # This will add a subnetpool_id(created by kuryr) tag
    # for existing Neutron subnets.
    if app.tag:
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
        existing_network_identifier += const.KURYR_EXISTING_NEUTRON_NET
        try:
            existing_networks = _get_networks_by_identifier(
                existing_network_identifier)
        except n_exceptions.NeutronClientException as ex:
            LOG.error(_LE("Error happened during listing "
                          "Neutron networks: %s"), ex)
            raise

        if existing_networks:
            LOG.warning(_LW("Network is a pre existing Neutron "
                            "network, not deleting in Neutron. "
                            "removing tags: %s"), existing_network_identifier)
            neutron_net_id = existing_networks[0]['id']
            _neutron_net_remove_tags(neutron_net_id, container_net_id)
            _neutron_net_remove_tag(neutron_net_id,
                                    const.KURYR_EXISTING_NEUTRON_NET)
            # Delete subnets created by kuryr
            filtered_subnets = _get_subnets_by_attrs(
                network_id=neutron_net_id)
            for subnet in filtered_subnets:
                try:
                    subnet_name = subnet.get('name')
                    if str(subnet_name).startswith(const.SUBNET_NAME_PREFIX):
                        app.neutron.delete_subnet(subnet['id'])
                except n_exceptions.Conflict as ex:
                    LOG.error(_LE("Subnet %s is in use, "
                                  "can't be deleted."), subnet['id'])
                except n_exceptions.NeutronClientException as ex:
                    LOG.error(_LE("Error happened during deleting a "
                                  "subnet created by kuryr: %s"), ex)
            return flask.jsonify(const.SCHEMA['SUCCESS'])

    try:
        filtered_networks = _get_networks_by_identifier(
            neutron_network_identifier)
    except n_exceptions.NeutronClientException as ex:
        LOG.error(_LE("Error happened during listing "
                      "Neutron networks: %s"), ex)
        raise

    if not filtered_networks:
        LOG.warning(_LW("Network with identifier %s cannot be found"),
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
            except n_exceptions.Conflict as ex:
                LOG.error(_LE("Subnet, %s, is in use. Network can't "
                              "be deleted."), subnet['id'])
                raise
            except n_exceptions.NeutronClientException as ex:
                LOG.error(_LE("Error happened during deleting a "
                              "Neutron subnets: %s"), ex)
                raise

        try:
            app.neutron.delete_network(neutron_network_id)
        except n_exceptions.NeutronClientException as ex:
            LOG.error(_LE("Error happened during deleting a "
                          "Neutron network: %s"), ex)
            raise
        LOG.info(_LI("Deleted the network with ID %s "
                     "successfully"), neutron_network_id)
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
            (stdout, stderr) = app.driver.create_host_iface(
                endpoint_id, neutron_port, subnets, filtered_networks[0])
            LOG.debug(stdout)
            if stderr:
                LOG.error(stderr)
        except (exceptions.VethCreationFailure,
                exceptions.BindingNotSupportedFailure) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Preparing the veth '
                              'pair was failed: %s.'), ex)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Could not bind the Neutron port to '
                              'the veth endpoint.'))
        except (exceptions.KuryrException,
                n_exceptions.NeutronClientException) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Failed to set up the interface: %s'), ex)

        if app.vif_plug_is_fatal:
            port_active = _port_active(neutron_port['id'],
                                       app.vif_plug_timeout)
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

        if not (interface_cidrv4 or interface_cidrv6):
            if 'ip_address' in neutron_port:
                _process_interface_address(
                    neutron_port, subnets_dict_by_id, response_interface)
            for fixed_ip in created_fixed_ips:
                _process_interface_address(
                    fixed_ip, subnets_dict_by_id, response_interface)

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
        neutron_port_name = utils.get_neutron_port_name(endpoint_id)
        filtered_ports = _get_ports_by_attrs(name=neutron_port_name)
        if not filtered_ports:
            raise exceptions.NoResourceException(
                "The port doesn't exist for the name {0}"
                .format(neutron_port_name))
        neutron_port = filtered_ports[0]

        try:
            stdout, stderr = app.driver.delete_host_iface(
                endpoint_id, neutron_port)
            LOG.debug(stdout)
            if stderr:
                LOG.error(stderr)
        except processutils.ProcessExecutionError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Could not unbind the Neutron port from'
                              'the veth endpoint.'))
        except exceptions.VethDeletionFailure:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Cleaning the veth pair up was failed.'))
        except (exceptions.KuryrException,
                n_exceptions.NeutronClientException) as ex:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error while removing the interface: %s'), ex)

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

        neutron_port_name = utils.get_neutron_port_name(endpoint_id)
        filtered_ports = _get_ports_by_attrs(name=neutron_port_name)
        if not filtered_ports:
            raise exceptions.NoResourceException(
                "The port doesn't exist for the name {0}"
                .format(neutron_port_name))
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

        iface_name = app.driver.get_container_iface_name(neutron_port['id'])

        join_response = {
            "InterfaceName": {
                "SrcName": iface_name,
                "DstPrefix": config.CONF.binding.veth_dst_prefix
            },
            "StaticRoutes": []
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
    capabilities = {'RequiresMACAddress': False}
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
    pools = []
    options = json_data.get('Options')
    if options:
        if v6:
            pool_name = options.get(const.NEUTRON_V6_POOL_NAME_OPTION)
            pool_id = options.get(const.NEUTRON_V6_POOL_UUID_OPTION)
        else:
            pool_name = options.get(const.NEUTRON_POOL_NAME_OPTION)
            pool_id = options.get(const.NEUTRON_POOL_UUID_OPTION)
    if requested_pool:
        LOG.info(_LI("Creating subnetpool with the given pool CIDR"))
        if requested_subpool:
            cidr = ipaddress.ip_network(six.text_type(requested_subpool))
        else:
            cidr = ipaddress.ip_network(six.text_type(requested_pool))
        subnet_cidr = six.text_type(cidr)
        subnets_by_cidr = _get_subnets_by_attrs(cidr=subnet_cidr)
        if len(subnets_by_cidr):
            LOG.warning(_LW("There is already existing subnet for the "
                            "same cidr. Please check and specify pool name "
                            "in Options."))
        if not pool_name and not pool_id:
            pool_name = lib_utils.get_neutron_subnetpool_name(subnet_cidr)
            pools = _get_subnetpools_by_attrs(name=pool_name)
            if len(pools):
                raise exceptions.KuryrException(
                       "Another pool with same cidr exist. ipam and network"
                       " options not used to pass pool name")

            new_subnetpool = {
                'name': pool_name,
                'default_prefixlen': cidr.prefixlen,
                'prefixes': [subnet_cidr]}
            created_subnetpool_response = app.neutron.create_subnetpool(
                {'subnetpool': new_subnetpool})
            pool = created_subnetpool_response['subnetpool']
            pool_id = pool['id']
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
            LOG.info(_LI("Using existing Neutron subnetpool %s successfully"),
                     pool_id)
    else:
        if v6:
            default_pool_list = SUBNET_POOLS_V6
        else:
            default_pool_list = SUBNET_POOLS_V4
        pool_name = default_pool_list[0]
        subnet_cidr, pool_id = _get_cidr_from_subnetpool(name=pool_name)
        subnet_cidr = six.text_type(subnet_cidr)

    req_pool_res = {'PoolID': pool_id,
                    'Pool': subnet_cidr}
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
    is_gateway = False
    allocated_address = ''
    subnet = {}
    # Check if the port is gateway
    options = json_data.get('Options')
    if options:
        request_address_type = options.get(const.REQUEST_ADDRESS_TYPE)
        if request_address_type == const.NETWORK_GATEWAY_OPTIONS:
            is_gateway = True

    # check if any subnet with matching subnetpool_id is present
    subnets_by_poolid = _get_subnets_by_attrs(subnetpool_id=pool_id)
    if subnets_by_poolid:
        if len(subnets_by_poolid) == 1:
            subnet = subnets_by_poolid[0]
            subnet_cidr = ipaddress.ip_network(six.text_type(subnet['cidr']))
        else:
            pool_cidr, _ = _get_cidr_from_subnetpool(id=pool_id)
            for tmp_subnet in subnets_by_poolid:
                subnet_cidr = ipaddress.ip_network(
                    six.text_type(tmp_subnet['cidr']))
                if pool_cidr == subnet_cidr:
                    subnet = tmp_subnet
                    break
    else:
        # check if any subnet with matching cidr is present
        subnet_cidr, _ = _get_cidr_from_subnetpool(id=pool_id)
        subnets_by_cidr = _get_subnets_by_attrs(
            cidr=six.text_type(subnet_cidr))
        if len(subnets_by_cidr) > 1:
            for tmp_subnet in subnets_by_cidr:
                if tmp_subnet.get('tags') is not None:
                    if pool_id in tmp_subnet.get('tags'):
                        subnet = tmp_subnet
                else:
                    LOG.warning(_LW("subnetpool tag for Neutron "
                                    "subnet %s is missing, cannot "
                                    "gets the correct subnet."),
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
            if req_address == existed_gateway_ip:
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
                num_ports = 0
                if req_address:
                    fixed_ip['ip_address'] = req_address
                    fixed_ip_existing = [('subnet_id=%s' % subnet['id'])]
                    fixed_ip_existing.append('ip_address='
                                             '%s' % str(req_address))
                    filtered_ports = app.neutron.list_ports(
                        fixed_ips=fixed_ip_existing)
                    num_ports = len(filtered_ports.get('ports', []))
                fixed_ips.append(fixed_ip)

                if num_ports:
                    existing_port = filtered_ports['ports'][0]
                    created_port = _update_existing_port(existing_port,
                                                         fixed_ip)
                    # REVISIT(yedongcan) For tag-ext extension not
                    # supported, the Neutron existing port still can not
                    # be deleted in ipam_release_address.
                    if app.tag_ext:
                        _neutron_port_add_tag(
                            created_port['id'],
                            const.KURYR_EXISTING_NEUTRON_PORT)
                else:
                    created_port_resp = app.neutron.create_port({'port': port})
                    created_port = created_port_resp['port']
                    if app.tag_ext:
                        _neutron_port_add_tag(created_port['id'],
                                              lib_const.DEVICE_OWNER)

                LOG.debug("created port %s", created_port)
                allocated_address = (req_address or
                    created_port['fixed_ips'][0]['ip_address'])
                allocated_address = '{}/{}'.format(allocated_address,
                                                   subnet_cidr.prefixlen)
            except n_exceptions.NeutronClientException as ex:
                LOG.error(_LE("Error happened during ip allocation on "
                              "Neutron side: %s"), ex)
                raise
    else:
        # Auxiliary address or gw_address is received at network creation time.
        # This address cannot be reserved with neutron at this time as subnet
        # is not created yet. In /NetworkDriver.CreateNetwork this address will
        # be reserved with neutron.
        if req_address:
            allocated_address = '{}/{}'.format(req_address,
                                               subnet_cidr.prefixlen)

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
            cidr=six.text_type(subnet_cidr))
        for tmp_subnet in subnets_by_cidr:
            if pool_id in tmp_subnet.get('tags', []):
                _neutron_subnet_remove_tag(tmp_subnet['id'], pool_id)
                break

    pools = _get_subnetpools_by_attrs(id=pool_id)
    if pools:
        pool_name = pools[0]['name']
        if not pool_name.startswith(cfg.CONF.subnetpool_name_prefix):
            LOG.debug('Skip the cleanup since this is an existing Neutron '
                      'subnetpool.')
            return flask.jsonify(const.SCHEMA['SUCCESS'])

    try:
        app.neutron.delete_subnetpool(pool_id)
    except n_exceptions.Conflict as ex:
        LOG.info(_LI("The subnetpool with ID %s is still in use."
                     " It can't be deleted for now."), pool_id)
    except n_exceptions.NeutronClientException as ex:
        LOG.error(_LE("Error happened during deleting a "
                      "Neutron subnetpool: %s"), ex)
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
        subnet_cidr = six.text_type(_get_cidr_from_subnetpool(id=pool_id)[0])
        subnets = _get_subnets_by_attrs(cidr=subnet_cidr)
    if not len(subnets):
        LOG.info(_LI("Subnet already deleted."))
        return flask.jsonify(const.SCHEMA['SUCCESS'])

    iface = ipaddress.ip_interface(six.text_type(rel_address))
    rel_ip_address = six.text_type(iface.ip)
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
                updated_port = {'name': '', 'device_owner': '',
                                'device_id': '', 'binding:host_id': ''}
                app.neutron.update_port(port['id'], {'port': updated_port})
                _neutron_port_remove_tag(port['id'],
                                         const.KURYR_EXISTING_NEUTRON_PORT)
    except n_exceptions.NeutronClientException as ex:
        LOG.error(_LE("Error happened while fetching "
                      "and deleting port, %s"), ex)
        raise

    return flask.jsonify(const.SCHEMA['SUCCESS'])
