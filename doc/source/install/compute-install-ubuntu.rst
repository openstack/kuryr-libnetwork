Install and configure a compute node for Ubuntu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to install and configure the Kuryr-libnetwork
for Ubuntu 16.04 (LTS).

Prerequisites
-------------

This guide assumes Docker is already installed. Refer `Get Docker
<https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/>`_
for Docker installation.

Install and configure components
--------------------------------

#. Create kuryr user and necessary directories:

   * Create user:

     .. code-block:: console

        # groupadd --system kuryr
        # useradd --home-dir "/var/lib/kuryr" \
              --create-home \
              --system \
              --shell /bin/false \
              -g kuryr \
              kuryr

   * Create directories:

     .. code-block:: console

        # mkdir -p /etc/kuryr
        # chown kuryr:kuryr /etc/kuryr

#. Clone and install kuryr-libnetwork:

   .. code-block:: console

      # apt-get install python-pip
      # cd /var/lib/kuryr
      # git clone -b stable/train https://git.openstack.org/openstack/kuryr-libnetwork.git
      # chown -R kuryr:kuryr kuryr-libnetwork
      # cd kuryr-libnetwork
      # pip install -r requirements.txt
      # python setup.py install

#. Generate a sample configuration file:

   .. code-block:: console

      # su -s /bin/sh -c "./tools/generate_config_file_samples.sh" kuryr
      # su -s /bin/sh -c "cp etc/kuryr.conf.sample \
            /etc/kuryr/kuryr.conf" kuryr

#. Edit the ``/etc/kuryr/kuryr.conf``:

   * In the ``[DEFAULT]`` section, configure the path for the Kuryr
     vif binding executables:

     .. code-block:: ini

        [DEFAULT]
        ...
        bindir = /usr/local/libexec/kuryr

   * In the ``[neutron]`` section, configure Identity service access:

     .. code-block:: ini

        [neutron]
        ...
        www_authenticate_uri = http://controller:5000
        auth_url = http://controller:5000
        username = kuryr
        user_domain_name = default
        password = KURYR_PASSWORD
        project_name = service
        project_domain_name = default
        auth_type = password

     Replace KURYR_PASSWORD with the password you chose for the kuryr user in the
     Identity service.

#. Create an upstart config, it could be named as
   ``/etc/systemd/system/kuryr-libnetwork.service``:

   .. code-block:: ini

      [Unit]
      Description = Kuryr-libnetwork - Docker network plugin for Neutron

      [Service]
      ExecStart = /usr/local/bin/kuryr-server --config-file /etc/kuryr/kuryr.conf
      CapabilityBoundingSet = CAP_NET_ADMIN

      [Install]
      WantedBy = multi-user.target

Finalize installation
---------------------

#. Enable and start the kuryr-libnetwork service:

   .. code-block:: console

      # systemctl enable kuryr-libnetwork
      # systemctl start kuryr-libnetwork

#. After Kuryr starts, please restart your Docker service:

   .. code-block:: console

      # systemctl restart docker
