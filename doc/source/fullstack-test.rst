==============
Fullstack test
==============

This is a guide for developers who want to run Fullstack tests in their local
machine.

Prerequisite
============

You need to deploy kuryr-libnetwork in a DevStack environment.

Clone DevStack::

    # Create a root directory for devstack if needed
    sudo mkdir -p /opt/stack
    sudo chown $USER /opt/stack

    git clone https://git.openstack.org/openstack-dev/devstack /opt/stack/devstack

We will run devstack with minimal local.conf settings required. You can use the
sample local.conf as a quick-start::

    git clone https://git.openstack.org/openstack/kuryr-libnetwork /opt/stack/kuryr-libnetwork
    cp /opt/stack/kuryr-libnetwork/devstack/local.conf.sample /opt/stack/devstack/local.conf

Run DevStack::

    cd /opt/stack/devstack
    ./stack.sh

**NOTE:** This will take a while to setup the dev environment.


Run the Fullstack test
======================

Navigate to kuryr-libnetwork directory::

    cd /opt/stack/kuryr-libnetwork

Run this command::

    tox -e fullstack


Also you can run *fullstack* test using credentials from openrc config file,
this requires you source openrc file in your DevStack or production environment.
In DevStack, you can using command "source openrc admin" in your devstack directory.
For production environment, please refer "Create OpenStack client environment scripts"
in OpenStack install guide.


Source the credential of 'admin' user::

    source /opt/stack/devstack/openrc admin

Then run command::

    tox -e fullstack
