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

import os
import sys
import time
import traceback

import flask
import jsonschema

from neutronclient.common import exceptions as n_exceptions
from oslo_concurrency import processutils
from oslo_log import log
from werkzeug import exceptions as w_exceptions

from kuryr.lib import constants as lib_const
from kuryr.lib import exceptions
from kuryr.lib import utils as lib_utils
from kuryr_libnetwork import constants as const


LOG = log.getLogger(__name__)
SG_POSTFIX = 'exposed_ports'


# Return all errors as JSON. From http://flask.pocoo.org/snippets/83/
def make_json_app(import_name, **kwargs):
    """Creates a JSON-oriented Flask app.

    All error responses that you don't specifically manage yourself will have
    application/json content type, and will contain JSON that follows the
    libnetwork remote driver protocol.


    { "Err": "405: Method Not Allowed" }


    See:
      - https://github.com/docker/libnetwork/blob/3c8e06bc0580a2a1b2440fe0792fbfcd43a9feca/docs/remote.md#errors  # noqa
    """
    app = flask.Flask(import_name, **kwargs)

    @app.errorhandler(exceptions.KuryrException)
    @app.errorhandler(n_exceptions.NeutronClientException)
    @app.errorhandler(jsonschema.ValidationError)
    @app.errorhandler(processutils.ProcessExecutionError)
    def make_json_error(ex):
        LOG.error("Unexpected error happened: %s", ex)
        traceback.print_exc(file=sys.stderr)
        response = flask.jsonify({"Err": str(ex)})
        response.status_code = w_exceptions.InternalServerError.code
        if isinstance(ex, w_exceptions.HTTPException):
            response.status_code = ex.code
        elif isinstance(ex, n_exceptions.NeutronClientException):
            response.status_code = ex.status_code
        elif isinstance(ex, jsonschema.ValidationError):
            response.status_code = w_exceptions.BadRequest.code
        content_type = 'application/vnd.docker.plugins.v1+json; charset=utf-8'
        response.headers['Content-Type'] = content_type
        return response

    for code in w_exceptions.default_exceptions:
        app.register_error_handler(code, make_json_error)

    return app


def get_sandbox_key(container_id):
    """Returns a sandbox key constructed with the given container ID.

    :param container_id: the ID of the Docker container as string
    :returns: the constructed sandbox key as string
    """
    return os.path.join(lib_utils.DOCKER_NETNS_BASE, container_id[:12])


def get_neutron_port_name(docker_endpoint_id):
    """Returns a Neutron port name.

    :param docker_endpoint_id: the EndpointID
    :returns: the Neutron port name formatted appropriately
    """
    return '-'.join([docker_endpoint_id, lib_utils.PORT_POSTFIX])


def get_sg_expose_name(port_id):
    """Returns a Neutron security group name.

    :param port_id: The Neutron port id to create a security group for
    :returns: the Neutron security group name formatted appropriately
    """
    return '-'.join([port_id, SG_POSTFIX])


def create_net_tags(tag):
    tags = []
    tags.append(const.NEUTRON_ID_LH_OPTION + ':' + tag[:32])
    if len(tag) > 32:
        tags.append(const.NEUTRON_ID_UH_OPTION + ':' + tag[32:64])

    return tags


def existing_net_tag(netid):
    return const.KURYR_EXISTING_NEUTRON_NET + ':' + netid[:12]


def make_net_tags(tag):
    tags = create_net_tags(tag)
    return ','.join(map(str, tags))


def make_net_name(netid, tags=True):
    if tags:
        return const.NET_NAME_PREFIX + netid[:8]
    return netid


def make_subnet_name(pool_cidr):
    return const.SUBNET_NAME_PREFIX + pool_cidr


def create_port_tags(tag):
    tags = []
    tags.append(const.NEUTRON_ID_LH_OPTION + ':' + tag[:32])
    if len(tag) > 32:
        tags.append(const.NEUTRON_ID_UH_OPTION + ':' + tag[32:64])

    return tags


def make_port_tags(tag):
    tags = create_port_tags(tag)
    return ','.join(map(str, tags))


def wait_for_port_active(neutron_client, neutron_port_id, vif_plug_timeout):
    port_active = False
    tries = 0
    while True:
        try:
            port = neutron_client.show_port(neutron_port_id)
        except n_exceptions.NeutronClientException as ex:
            LOG.error('Could not get the port %s to check '
                      'its status', ex)
        else:
            if port['port']['status'] == lib_const.PORT_STATUS_ACTIVE:
                port_active = True
        if port_active or (vif_plug_timeout > 0 and
                           tries >= vif_plug_timeout):
            break
        LOG.debug('Waiting for port %s to become ACTIVE', neutron_port_id)
        tries += 1
        time.sleep(1)

    return port_active
