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
KURYR_EXISTING_NEUTRON_NET = 'kuryr.net.existing'
KURYR_EXISTING_NEUTRON_PORT = 'kuryr.port.existing'
NETWORK_GATEWAY_OPTIONS = 'com.docker.network.gateway'
NETWORK_GENERIC_OPTIONS = 'com.docker.network.generic'
NEUTRON_NAME_OPTION = 'neutron.net.name'
NEUTRON_POOL_NAME_OPTION = 'neutron.pool.name'
NEUTRON_POOL_UUID_OPTION = 'neutron.pool.uuid'
NEUTRON_V6_POOL_NAME_OPTION = 'neutron.pool.v6.name'
NEUTRON_V6_POOL_UUID_OPTION = 'neutron.pool.v6.uuid'
NEUTRON_UUID_OPTION = 'neutron.net.uuid'
REQUEST_ADDRESS_TYPE = 'RequestAddressType'
KURYR_UNBOUND_PORT = 'kuryr-unbound-port'
NEUTRON_UNBOUND_PORT = 'neutron-unbound-port'
