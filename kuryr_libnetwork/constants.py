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


SCHEMA = {
    "PLUGIN_ACTIVATE": {"Implements": ["NetworkDriver", "IpamDriver"]},
    "SUCCESS": {}
}

# Routes are given a RouteType of 0 and a value for NextHop;
ROUTE_TYPE = {
    "NEXTHOP": 0
}

PROTOCOLS = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp'
}

NET_NAME_PREFIX = 'kuryr-net-'
SUBNET_NAME_PREFIX = 'kuryr-subnet-'
NEUTRON_ID_LH_OPTION = 'kuryr.net.uuid.lh'
NEUTRON_ID_UH_OPTION = 'kuryr.net.uuid.uh'

DOCKER_EXPOSED_PORTS_OPTION = 'com.docker.network.endpoint.exposedports'
DOCKER_MAC_ADDRESS_OPTION = 'com.docker.network.endpoint.macaddress'
KURYR_EXISTING_NEUTRON_NET = 'kuryr.net.existing'
KURYR_EXISTING_NEUTRON_SUBNETPOOL = 'kuryr.subnetpool.existing'
KURYR_EXISTING_NEUTRON_PORT = 'kuryr.port.existing'
NETWORK_GATEWAY_OPTIONS = 'com.docker.network.gateway'
NETWORK_GENERIC_OPTIONS = 'com.docker.network.generic'
NEUTRON_NAME_OPTION = 'neutron.net.name'
NEUTRON_SHARED_OPTION = 'neutron.net.shared'
NEUTRON_SUBNET_NAME_OPTION = 'neutron.subnet.name'
NEUTRON_SUBNET_UUID_OPTION = 'neutron.subnet.uuid'
NEUTRON_V6_SUBNET_NAME_OPTION = 'neutron.subnet.v6.name'
NEUTRON_V6_SUBNET_UUID_OPTION = 'neutron.subnet.v6.uuid'
NEUTRON_POOL_NAME_OPTION = 'neutron.pool.name'
NEUTRON_POOL_UUID_OPTION = 'neutron.pool.uuid'
NEUTRON_V6_POOL_NAME_OPTION = 'neutron.pool.v6.name'
NEUTRON_V6_POOL_UUID_OPTION = 'neutron.pool.v6.uuid'
NEUTRON_UUID_OPTION = 'neutron.net.uuid'
REQUEST_ADDRESS_TYPE = 'RequestAddressType'
KURYR_UNBOUND_PORT = 'kuryr-unbound-port'
NEUTRON_UNBOUND_PORT = 'neutron-unbound-port'
BINDING_PROFILE = 'binding:profile'

# Define supported virtual NIC types.
VNIC_TYPE_NORMAL = 'normal'
VNIC_TYPE_DIRECT = 'direct'
VNIC_TYPE_MACVTAP = 'macvtap'
VNIC_TYPE_DIRECT_PHYSICAL = 'direct-physical'

# Define list of virtual NIC types.
VNIC_TYPES_SRIOV = (VNIC_TYPE_DIRECT, VNIC_TYPE_MACVTAP,
                    VNIC_TYPE_DIRECT_PHYSICAL)
