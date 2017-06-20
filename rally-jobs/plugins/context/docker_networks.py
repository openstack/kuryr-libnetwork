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

import docker

from rally.common import logging
from rally import consts
from rally.task import context

LOG = logging.getLogger(__name__)


@context.configure(name="docker_network", order=1000)
class DockerNetworkContext(context.Context):
    """Create a kuryr or non-kuryr docker network as context"""

    CONFIG_SCHEMA = {
        "type": "object",
        "$schema": consts.JSON_SCHEMA,
        "additionalProperties": False,
        "properties": {
            "is_kuryr": {
                "type": "boolean"
            },
            "Subnet": {
                "type": "string"
            },
            "IPRange": {
                "type": "string"
            },
            "Gateway": {
                "type": "string"
            }
        }
    }
    DEFAULT_CONFIG = {
        "is_kuryr": True,
        "Subnet": "50.0.0.0/24",
        "IPRange": "50.0.0.0/24",
        "Gateway": "50.0.0.1"
    }

    def setup(self):
        """Create kuryr or non-kuryr docker network, and prepare image cache"""
        try:
            docker_client = docker.APIClient(base_url="tcp://0.0.0.0:2375")

            if self.config["is_kuryr"]:
                ipam = {
                    "Driver": "kuryr",
                    "Options": {},
                    "Config": [
                        {
                            "Subnet": self.config.get("Subnet"),
                            "IPRange": self.config.get("IPRange"),
                            "Gateway": self.config.get("Gateway")
                        }
                    ]
                }
                res = docker_client.create_network(name="kuryr_network",
                                                   driver="kuryr",
                                                   ipam=ipam)
                self.context["netid"] = res.get("Id")
                self.context["netname"] = "kuryr_network"
            else:
                res = docker_client.create_network(name="docker_network")
                self.context["netid"] = res.get("Id")
                self.context["netname"] = "docker_network"
            LOG.debug("Container network id is '%s'" % self.context["netid"])
        except Exception as e:
            msg = "Can't create docker network: %s" % e.message
            if logging.is_debug():
                LOG.exception(msg)
            else:
                LOG.warning(msg)

    def cleanup(self):
        """Clean up network"""
        try:
            self.docker_client.remove_network(self.context["netid"])
            LOG.debug("Docker network '%s' deleted" % self.context["netid"])
        except Exception as e:
            msg = "Can't delete docker network: %s" % e.message
            if logging.is_debug():
                LOG.exception(msg)
            else:
                LOG.warning(msg)
