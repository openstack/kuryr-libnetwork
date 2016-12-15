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

import utils

from rally.plugins.openstack import scenario


class Kuryr(utils.KuryrScenario):
    """Benchmark scenarios for Kuryr."""

    def __init__(self, context=None, admin_clients=None, clients=None):
        super(Kuryr, self).__init__(context, admin_clients, clients)

    @scenario.configure(context={"cleanup": ["kuryr"]})
    def list_networks(self, network_list_args=None):
        """List the networks.

        Measure the "docker network ls" command performance under kuryr.

        This will call the docker client API to list networks

        TODO (baohua):
        1. may support tenant/user in future.
        2. validation.required_services add KURYR support

        :param network_list_args: dict: names, ids
        """
        self._list_networks(network_list_args or {})

    @scenario.configure(context={"cleanup": ["kuryr"]})
    def create_and_delete_networks_with_kuryr(self, network_create_args=None):
        """Create and delete a network with kuryr.

        Measure the "docker network create" and "docker network rm" command
        performance with kuryr driver.

        :param network_create_args: dict as options to create the network
        """
        network = self._create_network(is_kuryr=True,
                       network_create_args=network_create_args or {})
        self._delete_network(network)

    @scenario.configure(context={"cleanup": ["kuryr"]})
    def create_and_delete_networks_without_kuryr(self,
                                                 network_create_args=None):
        """Create and delete a network without kuryr.

        Measure the "docker network create" and "docker network rm" command
        performance with default driver.

        :param network_create_args: dict as options to create the network
        """
        network = self._create_network(is_kuryr=False,
                       network_create_args=network_create_args or {})
        self._delete_network(network)

    @scenario.configure(context={"cleanup": ["kuryr"]})
    def start_and_stop_containers(self, container_create_args=None):
        """Start and stop container on docker network.

        Measure the "docker run" , "docker stop", "docker rm"
        command performance.
        """
        container_id = self._start_container(container_create_args or {})
        self._stop_container(container_id)
        # TODO(yedongcan) We will hit the Docker bug:
        # "Unable to remove filesystem - device or resource busy"
        # Temporary workaround is disable remove_container here.
        # self._remove_container(container_id)
