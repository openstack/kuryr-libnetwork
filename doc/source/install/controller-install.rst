Install and configure controller node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure kuryr-libnetwork
on the controller node.

.. note::

   The installation steps for Ubuntu, openSUSE and SUSE Linux Enterprise,
   and Red Hat Enterprise Linux and CentOS are all the same.

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``kuryr`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt kuryr
        User Password:
        Repeat User Password:
        +-----------+----------------------------------+
        | Field     | Value                            |
        +-----------+----------------------------------+
        | domain_id | e0353a670a9e496da891347c589539e9 |
        | enabled   | True                             |
        | id        | ca2e175b851943349be29a328cc5e360 |
        | name      | kuryr                            |
        +-----------+----------------------------------+

   * Add the ``admin`` role to the ``kuryr`` user:

     .. code-block:: console

        $ openstack role add --project service --user kuryr admin
