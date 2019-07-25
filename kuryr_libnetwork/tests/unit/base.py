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

import mock
import netaddr

from neutronclient.v2_0 import client
from oslotest import base

from kuryr.lib import constants as lib_const
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import app
from kuryr_libnetwork import controllers
from kuryr_libnetwork.port_driver import driver
from kuryr_libnetwork import utils


TOKEN = 'testtoken'
ENDURL = 'localurl'


class TestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setUp(self):
        super(TestCase, self).setUp()
        app.config['DEBUG'] = True
        app.config['TESTING'] = True
        self.app = app.test_client()
        self.app.neutron = client.Client(token=TOKEN, endpoint_url=ENDURL)
        app.driver = mock.Mock(spec=driver.Driver)
        app.tag = True
        app.tag_ext = True


class TestKuryrBase(TestCase):
    """Base class for all Kuryr unittests."""

    def setUp(self):
        super(TestKuryrBase, self).setUp()
        controllers.neutron_client()
        controllers.load_default_subnet_pools()
        self.app.neutron.format = 'json'
        if hasattr(app, 'DEFAULT_POOL_IDS'):
            del app.DEFAULT_POOL_IDS

    @staticmethod
    def _get_fake_list_network(neutron_network_id, check_existing=False):
        if check_existing:
            no_networks_response = {
                "networks": []}
            return no_networks_response
        fake_list_response = {
            "networks": [{
                "status": "ACTIVE",
                "subnets": [],
                "admin_state_up": True,
                "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
                "router:external": False,
                "segments": [],
                "shared": False,
                "id": neutron_network_id
            }]
        }
        return fake_list_response

    @staticmethod
    def _get_fake_v4_subnetpools(subnetpool_id, prefixes=["192.168.1.0/24"],
                                 name="kuryr", tags=None):
        # The following fake response is retrieved from the Neutron doc:
        #   http://developer.openstack.org/api-ref-networking-v2-ext.html#listSubnetPools  # noqa
        if tags is None:
            tags = []
        v4_subnetpools = {
            "subnetpools": [{
                "min_prefixlen": "24",
                "address_scope_id": None,
                "default_prefixlen": "24",
                "id": subnetpool_id,
                "max_prefixlen": "24",
                "name": name,
                "default_quota": None,
                "tenant_id": "9fadcee8aa7c40cdb2114fff7d569c08",
                "prefixes": prefixes,
                "ip_version": 4,
                "shared": False,
                "tags": tags
            }]
        }

        return v4_subnetpools

    @staticmethod
    def _get_fake_v6_subnetpools(subnetpool_id, prefixes=['fe80::/64'],
                                 name="kuryr6", tags=None):
        # The following fake response is retrieved from the Neutron doc:
        #   http://developer.openstack.org/api-ref-networking-v2-ext.html#listSubnetPools  # noqa
        if tags is None:
            tags = []
        v6_subnetpools = {
            "subnetpools": [{
                "min_prefixlen": "64",
                "address_scope_id": None,
                "default_prefixlen": "64",
                "id": subnetpool_id,
                "max_prefixlen": "64",
                "name": name,
                "default_quota": None,
                "tenant_id": "9fadcee8aa7c40cdb2114fff7d569c08",
                "prefixes": prefixes,
                "ip_version": 6,
                "shared": False,
                "tags": tags,
            }]
        }

        return v6_subnetpools

    @staticmethod
    def _get_fake_subnets(docker_endpoint_id, neutron_network_id,
                          fake_neutron_subnet_v4_id,
                          fake_neutron_subnet_v6_id):
        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-subnet  # noqa
        fake_subnet_response = {
            "subnets": [
                {"name": '-'.join([docker_endpoint_id, '192.168.1.0']),
                "network_id": neutron_network_id,
                "tenant_id": "c1210485b2424d48804aad5d39c61b8f",
                "allocation_pools": [{"start": "192.168.1.2",
                                      "end": "192.168.1.254"}],
                "gateway_ip": "192.168.1.1",
                "ip_version": 4,
                "cidr": "192.168.1.0/24",
                "id": fake_neutron_subnet_v4_id,
                "enable_dhcp": True,
                "subnetpool_id": ''},
                {"name": '-'.join([docker_endpoint_id, 'fe80::']),
                "network_id": neutron_network_id,
                "tenant_id": "c1210485b2424d48804aad5d39c61b8f",
                "allocation_pools": [{"start": "fe80::f816:3eff:fe20:57c4",
                                      "end": "fe80::ffff:ffff:ffff:ffff"}],
                "gateway_ip": "fe80::f816:3eff:fe20:57c3",
                "ip_version": 6,
                "cidr": "fe80::/64",
                "id": fake_neutron_subnet_v6_id,
                "enable_dhcp": True,
                "subnetpool_id": ''}
            ]
        }
        return fake_subnet_response

    @staticmethod
    def _get_fake_port(docker_endpoint_id, neutron_network_id,
                       neutron_port_id,
                       neutron_port_status=lib_const.PORT_STATUS_DOWN,
                       neutron_subnet_v4_id=None,
                       neutron_subnet_v6_id=None,
                       neutron_subnet_v4_address="192.168.1.2",
                       neutron_subnet_v6_address="fe80::f816:3eff:fe20:57c4",
                       neutron_mac_address="fa:16:3e:20:57:c3",
                       device_owner=None,
                       neutron_trunk_id=None,
                       tags=None,
                       name=None,
                       binding_profile=None,
                       binding_host=None,
                       admin_state_up=True):
        # The following fake response is retrieved from the Neutron doc:
        #   https://docs.openstack.org/api-ref/network/v2/index.html#create-port  # noqa
        if not name:
            name = utils.get_neutron_port_name(docker_endpoint_id)
        fake_port = {
            'port': {
                "status": neutron_port_status,
                "name": name,
                "allowed_address_pairs": [],
                "admin_state_up": admin_state_up,
                "network_id": neutron_network_id,
                "tenant_id": "d6700c0c9ffa4f1cb322cd4a1f3906fa",
                "device_owner": device_owner,
                "mac_address": neutron_mac_address,
                "fixed_ips": [],
                "id": neutron_port_id,
                "security_groups": [],
                "device_id": docker_endpoint_id,
                "tags": tags
            }
        }

        if binding_profile is not None:
            fake_port['port']['binding:profile'] = binding_profile

        if binding_host is not None:
            fake_port['port']['binding:host_id'] = binding_host

        if neutron_subnet_v4_id:
            fake_port['port']['fixed_ips'].append({
                "subnet_id": neutron_subnet_v4_id,
                "ip_address": neutron_subnet_v4_address
            })
        if neutron_subnet_v6_id:
            fake_port['port']['fixed_ips'].append({
                "subnet_id": neutron_subnet_v6_id,
                "ip_address": neutron_subnet_v6_address
            })
        if neutron_trunk_id:
            fake_port['port']['trunk_details'] = {'trunk_id': neutron_trunk_id}

        return fake_port

    @classmethod
    def _get_fake_ports(cls, docker_endpoint_id, neutron_network_id,
                        fake_neutron_port_id, neutron_port_status,
                        fake_neutron_subnet_v4_id, fake_neutron_subnet_v6_id,
                        neutron_subnet_v4_address="192.168.1.2",
                        neutron_subnet_v6_address="fe80::f816:3eff:fe20:57c4",
                        tags=None):
        fake_port = cls._get_fake_port(
            docker_endpoint_id, neutron_network_id,
            fake_neutron_port_id, neutron_port_status,
            fake_neutron_subnet_v4_id, fake_neutron_subnet_v6_id,
            neutron_subnet_v4_address, neutron_subnet_v6_address,
            tags=tags)
        fake_port = fake_port['port']
        fake_ports = {
            'ports': [
                fake_port
            ]
        }

        return fake_ports

    @staticmethod
    def _get_fake_v4_subnet(neutron_network_id, docker_endpoint_id=None,
                            subnet_v4_id=None, subnetpool_id=None,
                            cidr='192.168.1.0/24', tag_subnetpool_id=True,
                            name=None, host_routes=None, tags=None):
        if host_routes is None:
            host_routes = []
        if not name:
            name = str('-'.join([docker_endpoint_id,
                                str(netaddr.IPNetwork(cidr).network)]))
        if not tags:
            tags = []
        gateway_ip = netaddr.IPNetwork(cidr).network + 1
        start_v4_ip = gateway_ip + 1
        end_v4_ip = netaddr.IPNetwork(cidr).broadcast - 1
        fake_v4_subnet = {
            'subnet': {
                "name": name,
                "network_id": neutron_network_id,
                "tenant_id": "c1210485b2424d48804aad5d39c61b8f",
                "allocation_pools": [{
                    "start": str(start_v4_ip),
                    "end": str(end_v4_ip)
                }],
                "gateway_ip": str(gateway_ip),
                "ip_version": 4,
                "cidr": cidr,
                "id": subnet_v4_id,
                "enable_dhcp": True,
                "subnetpool_id": '',
                "host_routes": host_routes,
                "tags": tags
            }
        }
        if subnetpool_id:
            fake_v4_subnet['subnet'].update(subnetpool_id=subnetpool_id)
            if tag_subnetpool_id:
                fake_v4_subnet['subnet'].get('tags').append(subnetpool_id)

        return fake_v4_subnet

    @staticmethod
    def _get_fake_v6_subnet(docker_network_id, docker_endpoint_id=None,
                            subnet_v6_id=None, subnetpool_id=None,
                            cidr='fe80::/64', name=None, tags=None):
        if not name:
            name = str('-'.join([docker_endpoint_id, 'fe80::']))
        if not tags:
            tags = []
        gateway_ip = netaddr.IPNetwork(cidr).network + 1
        start_ip = gateway_ip + 1
        end_ip = netaddr.IPNetwork(cidr).broadcast - 1
        fake_v6_subnet = {
            'subnet': {
                "name": name,
                "network_id": docker_network_id,
                "tenant_id": "c1210485b2424d48804aad5d39c61b8f",
                "allocation_pools": [{
                    "start": str(start_ip),
                    "end": str(end_ip)
                }],
                "gateway_ip": str(gateway_ip),
                "ip_version": 6,
                "cidr": cidr,
                "id": subnet_v6_id,
                "enable_dhcp": True,
                "tags": tags,
            }
        }
        if subnetpool_id:
            fake_v6_subnet['subnet'].update(subnetpool_id=subnetpool_id)

        return fake_v6_subnet

    @staticmethod
    def _get_fake_port_request(
            neutron_network_id, docker_endpoint_id,
            neutron_subnetv4_id, neutron_subnetv6_id):
        fake_port_request = {
            'port': {
                'name': utils.get_neutron_port_name(docker_endpoint_id),
                'admin_state_up': True,
                "binding:host_id": lib_utils.get_hostname(),
                'device_owner': lib_const.DEVICE_OWNER,
                'device_id': docker_endpoint_id,
                'fixed_ips': [{
                    'subnet_id': neutron_subnetv4_id,
                    'ip_address': '192.168.1.2'
                }, {
                    'subnet_id': neutron_subnetv6_id,
                    'ip_address': 'fe80::f816:3eff:fe20:57c4'
                }],
                'mac_address': "fa:16:3e:20:57:c3",
                'network_id': neutron_network_id
            }
        }
        return fake_port_request

    @staticmethod
    def _get_fake_port_map(
            neutron_network_id, docker_endpoint_id,
            neutron_subnetv4_id, neutron_subnetv6_id):
        fake_port = {
            "port": {
                "status": "DOWN",
                "name": utils.get_neutron_port_name(docker_endpoint_id),
                "allowed_address_pairs": [],
                "admin_state_up": True,
                "binding:host_id": lib_utils.get_hostname(),
                "network_id": neutron_network_id,
                "tenant_id": "d6700c0c9ffa4f1cb322cd4a1f3906fa",
                'device_owner': lib_const.DEVICE_OWNER,
                'device_id': docker_endpoint_id,
                "mac_address": "fa:16:3e:20:57:c3",
                'fixed_ips': [{
                    'subnet_id': neutron_subnetv4_id,
                    'ip_address': '192.168.1.2'
                }, {
                    'subnet_id': neutron_subnetv6_id,
                    'ip_address': 'fe80::f816:3eff:fe20:57c4'
                }],
                "id": "65c0ee9f-d634-4522-8954-51021b570b0d",
                "security_groups": [],
                "device_id": ""
            }
        }
        return fake_port


class TestKuryrFailures(TestKuryrBase):
    """Unitests for checking if Kuryr handles the failures appropriately."""
