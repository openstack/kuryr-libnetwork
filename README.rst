========================
Team and repository tags
========================

.. image:: https://governance.openstack.org/tc/badges/kuryr-libnetwork.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

.. Change things from this point on

================
kuryr-libnetwork
================

.. image:: https://raw.githubusercontent.com/openstack/kuryr/master/doc/images/kuryr_logo.png
    :alt: Kuryr mascot
    :align: center


Docker for OpenStack Neutron

Kuryr-libnetwork is `Kuryr's <https://github.com/openstack/kuryr>`_ Docker
libnetwork driver that uses Neutron to provide networking services. It provides
containerised images for the common Neutron plugins.

This repo provides libnetwork specific functionalities such as handler methods
for libnetwork apis. All the logic/utilities that can be shared among
different container networking frameworks such as Docker's libnetwork,
K8s's CNI and so on, is maintained in separate Kuryr repo as a common library.


* Free software: Apache license
* Documentation: https://docs.openstack.org/kuryr-libnetwork/latest/
* Source: http://git.openstack.org/cgit/openstack/kuryr-libnetwork
* Bugs: http://bugs.launchpad.net/kuryr-libnetwork

Features
--------

* Docker libnetwork remote driver

* Docker libnetwork IPAM driver

* Support for Linux Bridge, Open vSwitch, Midonet, and IOvisor port bindings

* Support for using existing Neutron networks::

    docker network create -d kuryr --ipam-driver=kuryr --subnet=10.10.0.0/24 --gateway=10.10.0.1 \
       -o neutron.net.uuid=d98d1259-03d1-4b45-9b86-b039cba1d90d mynet

    docker network create -d kuryr --ipam-driver=kuryr --subnet=10.10.0.0/24 --gateway=10.10.0.1 \
       -o neutron.net.name=my_neutron_net mynet

* Support for using existing Neutron ports::

    docker run -it --net=kuryr_net --ip=10.0.0.5 ubuntu

    if a port in the corresponding subnet with the requested ip address
    already exists and it is unbound, that port is used for the
    container.

* Support for the Docker "expose" option::

    docker run --net=my_kuryr_net --expose=1234-1238/udp -it ubuntu

    This feature is implemented by using Neutron security groups.

Getting it running with a service container
-------------------------------------------

Prerequisites
~~~~~~~~~~~~~

The necessary components for an operating environment to run Kuryr are:

* Keystone (preferably configured with Keystone v3),
* Neutron (preferably mitaka or newer),
* DB management system such as MySQL or Mariadb (for Neutron and Keystone),
* Neutron agents for the vendor you choose,
* Rabbitmq if the Neutron agents for your vendor require it,
* Docker 1.9+

Building the container
~~~~~~~~~~~~~~~~~~~~~~

The Dockerfile in the root of this repository can be used to generate a wsgi
Kuryr Libnetwork server container with docker build::

    docker build -t your_docker_username/libnetwork:latest .

Additionally, you can pull the upstream container::

    docker pull kuryr/libnetwork:latest

Note that you can also specify the tag of a stable release for the above
command instead of *latest*.

How to run the container
~~~~~~~~~~~~~~~~~~~~~~~~

First we prepare Docker to find the driver::

    sudo mkdir -p /usr/lib/docker/plugins/kuryr
    sudo curl -o /usr/lib/docker/plugins/kuryr/kuryr.spec \
    https://raw.githubusercontent.com/openstack/kuryr-libnetwork/master/etc/kuryr.spec
    sudo service docker restart

Then we start the container::

    docker run --name kuryr-libnetwork \
      --net=host \
      --cap-add=NET_ADMIN \
      -e SERVICE_USER=admin \
      -e SERVICE_PROJECT_NAME=admin \
      -e SERVICE_PASSWORD=admin \
      -e SERVICE_DOMAIN_NAME=Default \
      -e USER_DOMAIN_NAME=Default \
      -e IDENTITY_URL=http://127.0.0.1:5000/v3 \
      -v /var/log/kuryr:/var/log/kuryr \
      -v /var/run/openvswitch:/var/run/openvswitch \
      kuryr/libnetwork

Where:

* SERVICE_USER, SERVICE_PROJECT_NAME, SERVICE_PASSWORD, SERVICE_DOMAIN_NAME,
  USER_DOMAIN_NAME are OpenStack credentials
* IDENTITY_URL is the url to the OpenStack Keystone v3 endpoint
* A volume is created so that the logs are available on the host
* NET_ADMIN capabilities are given in order to perform network operations on
  the host namespace like ovs-vsctl

Other options you can set as '-e' parameters in Docker run:

* CAPABILITY_SCOPE can be "local" or "global", the latter being for when there
  is a cluster store plugged into the docker engine.
* LOG_LEVEL for defining, for example, "DEBUG" logging messages.
* PROCESSES for defining how many kuryr processes to use to handle the
  libnetwork requests.

Note that you will probably have to change the 127.0.0.1 IDENTITY_URL address
for the address where your Keystone is running. In this case it is 127.0.0.1
because the example assumes running the container with *--net=host* on an all
in one deployment where Keystone is also binding locally.

Alternatively, if you have an existing kuryr.conf, you can use it for the
container::

    docker run --name kuryr-libnetwork \
      --net host \
      --cap-add NET_ADMIN \
      -v /etc/kuryr:/etc/kuryr:ro \
      -v /var/log/kuryr:/var/log/kuryr:rw \
      -v /var/run/openvswitch:/var/run/openvswitch:rw \
      kuryr/libnetwork


Getting it from source
----------------------

::

    $ git clone https://git.openstack.org/openstack/kuryr-libnetwork
    $ cd kuryr-libnetwork


Install prerequisites
~~~~~~~~~~~~~~~~~~~~~

::

    $ sudo pip install -r requirements.txt


Installing Kuryr's libnetwork driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Running the following will grab the requirements and install kuryr::

    $ sudo pip install .


Configuring Kuryr
~~~~~~~~~~~~~~~~~

Generate sample config, `etc/kuryr.conf.sample`, running the following::

    $ ./tools/generate_config_file_samples.sh


Rename and copy config file at required path::

    $ cp etc/kuryr.conf.sample /etc/kuryr/kuryr.conf


For using Keystone v3, edit the Neutron section in `/etc/kuryr/kuryr.conf`, replace ADMIN_PASSWORD::

    [neutron]
    auth_url = http://127.0.0.1:5000/v3/
    username = admin
    user_domain_name = Default
    password = ADMIN_PASSWORD
    project_name = service
    project_domain_name = Default
    auth_type = password


Alternatively, for using Keystone v2, edit the Neutron section in `/etc/kuryr/kuryr.conf`, replace ADMIN_PASSWORD::

    [neutron]
    auth_url = http://127.0.0.1:5000/v2.0/
    username = admin
    password = ADMIN_PASSWORD
    project_name = service
    auth_type = password


In the same file uncomment the `bindir` parameter with the path for the Kuryr
vif binding executables. For example, if you installed it on Debian or Ubuntu::

    [DEFAULT]
    bindir = /usr/local/libexec/kuryr


Running Kuryr
~~~~~~~~~~~~~

Currently, Kuryr utilizes a bash script to start the service.
Make sure that you have installed `tox` before the execution of
the following commands:

If SSL needs to be enabled follow this step or skip to next step::

    $tox -egenconfig

    Add these 3 parameters in generated file[etc/kuryr.conf.sample]:
        ssl_cert_file <Absolute Path for Cert file>
        ssl_key_file <Absolute Path for private key>
        enable_ssl <True or False>

    $export SSL_ENABLED=True

    Add the path names in [contrib/tls/kuryr.json]:
        InsecureSkipVerify <false/true>
        CAFile: <Absolute Path for CA file>
        CertFile: <Absolute Path for Cert file>
        KeyFile: <Absolute Path for private key>

    Placement of cert files:
    By default Kuryr places it certs in /var/lib/kuryr/certs directory,
    Please make sure that certs are on proper location as mentioned in kuryr.conf

    Verification of kuryr.json:
    Please make sure that your kuryr.json look similar to below sample
    with appropiate paths of certs updated, and remove older .spec files
    if any exists.
    and https configuration url::
        {
          "Name": "kuryr",
          "Addr": "https://127.0.0.1:23750",
          "TLSConfig": {
            "InsecureSkipVerify": false,
            "CAFile": "/var/lib/kuryr/certs/ca.pem",
            "CertFile": "/var/lib/kuryr/certs/cert.pem",
            "KeyFile": "/var/lib/kuryr/certs/key.pem"
          }
        }

    Optional:
    For locally generating and testing, please refer to below link:
        http://tech.paulcz.net/2016/01/secure-docker-with-tls/

Run Kuryr Server with the command below. If you have uwsgi installed this
command would run Kuryr under it. You can override this behaviour by
setting `KURYR_USE_UWSGI=False`::

    $ sudo ./scripts/run_kuryr.sh

After Kuryr starts, please restart your Docker service, e.g.::

    $ sudo service docker restart

The bash script creates the following file if it is missing:

* ``/usr/lib/docker/plugins/kuryr/kuryr.json``: Json spec file for libnetwork.

Note the root privilege is required for creating and deleting the veth pairs
with `pyroute2 <http://docs.pyroute2.org/>`_ to run.


kuryr-libnetwork docker managed pluginv2
----------------------------------------

How to build kuryr-libnetwork docker managed pluginv2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Docker Engine's `plugins system <https://docs.docker.com/engine/extend>`_
allows you to install, start, stop, and remove plugins using Docker Engine
for docker 1.13 and older.

Download kuryr-libnetwork source code, and run
contrib/docker/v2plugin/v2plugin_rootfs.sh in the top folder of
kuryr-libentwork. This script will copy config.json to the top
folder and build rootfs. ::

    $ git clone https://git.openstack.org/openstack/kuryr-libnetwork
    $ cd kuryr-libnetwork
    $ ./contrib/docker/v2plugin/v2plugin_rootfs.sh
    $ docker plugin create kuryr/libnetwork2 ./


How to use kuryr-libnetwork docker managed pluginv2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If user build pluginv2 locally, user need to enable pluginv2. ::

    $ docker plugin enable kuryr/libnetwork2

If user install pluginv2 from docker hub, the pluginv2 will be enabled
directly after install. ::

    $ docker plugin install kuryr/libnetwork2

When user create kuryr network, driver name and ipam-driver name are
kuryr/libnetwork2:latest  ::

    $ docker network create --driver=kuryr/libnetwork2:latest --ipam-driver=kuryr/libnetwork2:latest ...


How to try out nested-containers locally
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Installing OpenStack running devstack with the desired local.conf file but
   including the next to make use of OVS-firewall and enabling Trunk Ports::

    [[post-config|/$Q_PLUGIN_CONF_FILE]]

    [DEFAULT]
    service_plugins=trunk

    [securitygroup]
    firewall_driver=openvswitch

2. Launch a VM with `Neutron trunk port.
   <https://wiki.openstack.org/wiki/Neutron/TrunkPort>`

3. Inside the VM install kuryr and kuryr-libnetwork following the normal
   installation steps (see above steps at `Installing Kuryr's libnetwork
   driver`).

4. Reconfigure kuryr inside the VM to point to the neutron server and to use the
   vlan driver:

    - Configure `/etc/kuryr/kuryr.conf`::

        [binding]
        driver = kuryr.lib.binding.drivers.vlan
        link_iface = eth0 # VM vNIC

        [neutron]
        auth_url = http://KEYSTONE_SERVER_IP:5000/v3/
        username = admin
        user_domain_name = Default
        password = ADMIN_PASSWORD
        project_name = service
        project_domain_name = Default
        auth_type = password

    - Restart kuryr service inside the VM


Known nested-containers limitations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Due to the `Neutron Trunk service implementation choice  <https://github.com/openstack/neutron/blob/master/doc/source/devref/openvswitch_agent.rst#tackling-the-network-trunking-use-case>`_
   deployments with iptables hybrid security groups driver do not support
   trunk service.

2. QoS rules are not applied properly on sub-ports due to a `Neutron bug
   <https://bugs.launchpad.net/neutron/+bug/1639186>`_, i.e. nested-container
   port.


Testing Kuryr
-------------

For a quick check that Kuryr is working, create a IPv4 network::

    $ docker network create --driver kuryr --ipam-driver kuryr \
    --subnet 10.10.0.0/16 --gateway=10.10.0.1 test_v4_net
    785f8c1b5ae480c4ebcb54c1c48ab875754e4680d915b270279e4f6a1aa52283
    $ docker network ls
    NETWORK ID          NAME                   DRIVER           SCOPE
    785f8c1b5ae4        test_v4_net            kuryr            local

Or you can test with a dual-stack network::

    $ docker network create --driver kuryr --ipam-driver kuryr \
    --subnet 10.20.0.0/16 --gateway=10.20.0.1 --ipv6 --subnet 2001:db8:a0b:12f0::/64 \
    --gateway 2001:db8:a0b:12f0::1 test_net
    81e1a12eedfb168fbe73186faec4db5088aae4457244f960f38e14f4338e5760
    $ docker network ls
    NETWORK ID          NAME                DRIVER              SCOPE
    81e1a12eedfb        test_net            kuryr               local

Known IPv6 network limitations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Due to the `Docker --ipv6 tag bug <https://github.com/docker/docker/issues/28055>`_ version
1.12 and 1.13 have problem to create network only with IPv6.


Generating Documentation
------------------------


We use `Sphinx <https://pypi.org/project/Sphinx>`_ to maintain the
documentation. You can install Sphinx using pip::

    $ pip install -U Sphinx

In addition to Sphinx you will also need the following requirements
(not covered by `requirements.txt`)::

    $ pip install openstackdocstheme reno 'reno[sphinx]'

The source code of the documentation are under *doc*, you can generate the
html files using the following command. If the generation succeeds,a
*build/html* dir will be created under *doc*::

    $ cd doc
    $ make html

Now you can serve the documentation at http://localhost:8080 as a simple
website::

    $ cd build/html
    $ python -m SimpleHTTPServer 8080

Limitations
-----------

Docker 1.12 with SwarmKit (the new Swarm) does not support remote
drivers. Therefore, it cannot be used with Kuryr. This limitation is
to be removed in Docker 1.13.

To create Docker networks with subnets having same/overlapping cidr, it is
expected to pre-create Neutron subnetpool and pass the pool name for each
such network creation Docker command. Docker cli options -o and --ipam-opt
should be used to pass pool names as shown below::

    $ neutron subnetpool-create --pool-prefix 10.0.0.0/24 neutron_pool1
    $ sudo docker network create --driver=kuryr --ipam-driver=kuryr \
      --subnet 10.0.0.0/16 --gateway=10.0.0.1 --ip-range 10.0.0.0/24 \
      -o neutron.pool.name=neutron_pool1 \
      --ipam-opt=neutron.pool.name=neutron_pool1 \
      foo
      eddb51ebca09339cb17aaec05e48ffe60659ced6f3fc41b020b0eb506d364

Now Docker user creates another network with same cidr as the previous one,
i.e 10.0.0.0/16, but with different pool name, neutron_pool2::

    $ neutron subnetpool-create --pool-prefix 10.0.0.0/24 neutron_pool2
    $ sudo docker network create --driver=kuryr --ipam-driver=kuryr \
      --subnet 10.0.0.0/16 --gateway=10.0.0.1 --ip-range 10.0.0.0/24 \
      -o neutron.pool.name=neutron_pool2 \
      --ipam-opt=neutron.pool.name=neutron_pool2 \
      bar
      397badb51ebca09339cb17aaec05e48ffe60659ced6f3fc41b020b0eb506d786

Alternatively, Docker user can pass an existing pool uuid if there are multiple
pools with the same name::

    $ sudo sudo docker network create --driver=kuryr --ipam-driver=kuryr \
      --subnet 10.0.0.0/16 --gateway=10.0.0.1 --ip-range 10.0.0.0/24 \
      -o neutron.pool.uuid=2d5767a4-6c96-4522-ab1d-a06d7adc9e23 \
      --ipam-opt=neutron.pool.uuid=2d5767a4-6c96-4522-ab1d-a06d7adc9e23 \
      bar
      0aed1efbe21f6c29dc77eccd0dd17ba729274f9275070e1469230c864f9054ff


External Resources
------------------

The latest and most in-depth documentation is available at:
    <https://github.com/openstack/kuryr/tree/master/doc/source>
