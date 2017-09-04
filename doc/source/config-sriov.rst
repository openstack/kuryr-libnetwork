======
SR-IOV
======

The purpose of this page is to describe how to enable SR-IOV functionality
available in Kuryr-libnetwork. This page intends to serve as a guide for
how to configure OpenStack Networking and Kuryr-libnetwork to create SR-IOV
ports and leverage them for containers.

The basics
~~~~~~~~~~

PCI-SIG Single Root I/O Virtualization and Sharing (SR-IOV) functionality is
available in OpenStack since the Juno release. The SR-IOV specification
defines a standardized mechanism to virtualize PCIe devices. This mechanism
can virtualize a single PCIe Ethernet controller to appear as multiple PCIe
devices. Each device can be directly assigned to an instance, bypassing the
virtual switch layer. As a result, users are able to achieve low latency and
near-line wire speed.

The following terms are used throughout this document:

.. list-table::
   :header-rows: 1
   :widths: 10 90

   * - Term
     - Definition
   * - PF
     - Physical Function. The physical Ethernet controller that supports
       SR-IOV.
   * - VF
     - Virtual Function. The virtual PCIe device created from a physical
       Ethernet controller.

Using SR-IOV interfaces
~~~~~~~~~~~~~~~~~~~~~~~

In order to enable SR-IOV, the following steps are required:

#. Create Virtual Functions (Compute)
#. Configure neutron-server (Controller)
#. Enable neutron sriov-agent (Compute)
#. Configure kuryr-libnetwork (Compute)

Create Virtual Functions (Compute)
----------------------------------

Follow the session 'Create Virtual Functions' in the `networking guide
<https://docs.openstack.org/neutron/pike/admin/config-sriov.html>`_.

Configure neutron-server (Controller)
-------------------------------------

Follow the session 'Configure neutron-server' in the `networking guide
<https://docs.openstack.org/neutron/pike/admin/config-sriov.html>`_.

Enable neutron sriov-agent (Compute)
-------------------------------------

Follow the session 'Enable neutron sriov-agent' in the `networking guide
<https://docs.openstack.org/neutron/pike/admin/config-sriov.html>`_.

Configure kuryr-libnetwork (Compute)
------------------------------------

#. On every compute node running the ``kuryr-libnetwork`` service,
   edit kuryr-libnetwork config file (e.g. /etc/kuryr/kuryr.conf). Add
   ``kuryr_libnetwork.port_driver.drivers.sriov`` to
   ``enabled_port_drivers`` under ``[DEFAULT]`` and
   add ``kuryr.lib.binding.drivers.hw_veb`` to ``enabled_drivers``
   under ``[binding]``.

   .. code-block:: ini

      [DEFAULT]
      enabled_port_drivers = kuryr_libnetwork.port_driver.drivers.veth, kuryr_libnetwork.port_driver.drivers.sriov

      [binding]
      enabled_drivers = kuryr.lib.binding.drivers.veth, kuryr.lib.binding.drivers.hw_veb

#. Restart the ``kuryr-libnetwork`` service.

Launching containers with SR-IOV ports
--------------------------------------

Once configuration is complete, you can launch containers with SR-IOV ports.

#. Get the ``id`` of the network where you want the SR-IOV port to be created:

   .. code-block:: console

      $ net_id=`neutron net-show net04 | grep "\ id\ " | awk '{ print $4 }'`

#. Create a kuryr network by specifying the name of the neutron network.
   Replace ``10.10.0.0/24`` and ``10.10.0.1`` with the CIDR and gateway
   of the subnet where you want the SR-IOV port to be created:

   .. code-block:: console

      $ docker network create -d kuryr --ipam-driver=kuryr --subnet=10.10.0.0/24 --gateway=10.10.0.1 \
          -o neutron.net.uuid=$net_id kuryr_net

#. Create the SR-IOV port. ``vnic_type=direct`` is used here, but other options
   include ``normal``, ``direct-physical``, and ``macvtap``.
   The ``binding-profile`` is used by the Neutron SR-IOV driver [1].
   Replace ``physnet2``, ``1137:0047``, and ``0000:0a:00.1``
   with the correct value of the VF device:

   .. code-block:: console

      $ neutron port-create $net_id --name sriov_port --binding:vnic_type direct \
          --binding-profile '{"physical_network": "physnet2", "pci_vendor_info": "1137:0047", "pci_slot": "0000:0a:00.1"}'

#. Create the container. Specify the SR-IOV port's IP address created in step
   two:

   .. code-block:: console

      $ docker run -it --net=kuryr_net --ip=10.0.0.5 ubuntu

Reference
---------
[1] https://specs.openstack.org/openstack/neutron-specs/specs/juno/ml2-sriov-nic-switch.html
