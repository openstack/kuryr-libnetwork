# Copyright 2016: IBM Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from rally.common import logging
from rally.task import atomic
from rally_openstack import scenario

LOG = logging.getLogger(__name__)


class KuryrScenario(scenario.OpenStackScenario):
    """Base class for Kuryr scenarios with basic atomic actions."""

    @atomic.action_timer("kuryr.list_networks")
    def _list_networks(self, network_list_args):
        """Return user networks list.

        :param network_list_args: network list options
        """
        LOG.debug("Running the list_networks scenario")
        names = network_list_args.get('names')
        ids = network_list_args.get('ids')
        return self.docker_client.networks(names, ids)

    @atomic.action_timer("kuryr.create_network")
    def _create_network(self, is_kuryr=True, network_create_args=None):
        """Create network with kuryr or without kuryr.

        :param network_create_args: dict: name, driver and others
        :returns: dict of the created network reference object
        """
        name = self.generate_random_name()
        if is_kuryr:
            ipam = {
                "Driver": "kuryr",
                "Options": {},
                "Config": [
                    {
                        "Subnet": "20.0.0.0/24",
                        "IPRange": "20.0.0.0/24",
                        "Gateway": "20.0.0.1"
                    }
                ]
            }
            return self.docker_client.create_network(name=name,
                                      driver='kuryr',
                                      ipam=ipam,
                                      options=network_create_args)
        else:
            return self.docker_client.create_network(name=name,
                                      options=network_create_args)

    @atomic.action_timer("kuryr.delete_network")
    def _delete_network(self, network):
        """Delete Kuryr network.

        :param network: Network object
        """
        self.docker_client.remove_network(network['Id'])

    @atomic.action_timer("kuryr.start_container")
    def _start_container(self, container_create_args=None):
        """Start Container on docker network."""
        network_config = self.docker_client.create_networking_config(
            {self.context.get("netname"):
             self.docker_client.create_endpoint_config()})
        container = self.docker_client.create_container(
            image='kuryr/busybox',
            command='/bin/sleep 600',
            networking_config=network_config)
        container_id = container.get('Id')
        self.docker_client.start(container=container_id)
        return container_id

    @atomic.action_timer("kuryr.stop_container")
    def _stop_container(self, container_id):
        """Stop Container."""
        self.docker_client.stop(container=container_id)

    @atomic.action_timer("kuryr.remove_container")
    def _remove_container(self, container_id):
        self.docker_client.remove_container(container=container_id,
                                            force=True)
