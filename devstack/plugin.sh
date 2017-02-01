#!/bin/bash
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

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

echo_summary "kuryr-libnetwork's plugin.sh was called..."
ETCD_VERSION=v2.2.2

function install_etcd_data_store {

    if [ ! -f "$DEST/etcd/etcd-$ETCD_VERSION-linux-amd64/etcd" ]; then
        echo "Installing etcd server"
        mkdir $DEST/etcd
        wget https://github.com/coreos/etcd/releases/download/$ETCD_VERSION/etcd-$ETCD_VERSION-linux-amd64.tar.gz -O $DEST/etcd/etcd-$ETCD_VERSION-linux-amd64.tar.gz
        tar xzvf $DEST/etcd/etcd-$ETCD_VERSION-linux-amd64.tar.gz -C $DEST/etcd
    fi

    # Clean previous DB data
    rm -rf $DEST/etcd/db.etcd
}


function check_docker {
    if is_ubuntu; then
       dpkg -s docker-engine > /dev/null 2>&1
    else
       rpm -q docker-engine > /dev/null 2>&1 || rpm -q docker > /dev/null 2>&1
    fi
}

function create_kuryr_cache_dir {
    # Create cache dir
    sudo install -d -o "$STACK_USER" "$KURYR_AUTH_CACHE_DIR"
    if [[ ! "$KURYR_AUTH_CACHE_DIR" == "" ]]; then
        rm -f "$KURYR_AUTH_CACHE_DIR"/*
    fi

}

function create_kuryr_account {
    if is_service_enabled kuryr-libnetwork; then
        create_service_user "kuryr" "admin"
        get_or_create_service "kuryr-libnetwork" "kuryr-libnetwork" \
        "Kuryr-Libnetwork Service"
    fi
}

function configure_kuryr {
    local binding_path

    binding_path="$1"
    sudo install -d -o "$STACK_USER" "$KURYR_CONFIG_DIR"

    (cd "$KURYR_HOME" && exec ./tools/generate_config_file_samples.sh)

    cp "$KURYR_HOME/etc/kuryr.conf.sample" "$KURYR_CONFIG"

    create_kuryr_cache_dir

    # Neutron API server & Neutron plugin
    if is_service_enabled kuryr-libnetwork; then
        configure_auth_token_middleware "$KURYR_CONFIG" kuryr \
        "$KURYR_AUTH_CACHE_DIR" neutron
    fi

    iniset -sudo ${KURYR_CONFIG} DEFAULT bindir "$binding_path/libexec/kuryr"
}


# main loop
if is_service_enabled kuryr-libnetwork; then
    DISTRO_DISTUTILS_DATA_PATH=$(python -c "import distutils.dist;import distutils.command.install;inst = distutils.command.install.install(distutils.dist.Distribution());inst.finalize_options();print inst.install_data")
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Install kuryr-lib from git so we make sure we're testing
        # the latest code.
        if use_library_from_git "kuryr"; then
            git_clone_by_name "kuryr"
            setup_dev_lib "kuryr"
            # Install bind scripts
            if [ ! -d "${DISTRO_DISTUTILS_DATA_PATH}/libexec/kuryr" ]; then
                sudo mkdir -p ${DISTRO_DISTUTILS_DATA_PATH}/libexec/kuryr
            fi
            sudo cp -rf ${DEST}/kuryr/usr/libexec/kuryr/* ${DISTRO_DISTUTILS_DATA_PATH}/libexec/kuryr
        fi
        install_etcd_data_store
        setup_develop $KURYR_HOME

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then

        if [[ ! -d "${KURYR_ACTIVATOR_DIR}" ]]; then
            echo -n "${KURYR_ACTIVATOR_DIR} directory is missing. Creating it... "
            sudo mkdir -p ${KURYR_ACTIVATOR_DIR}
            echo "Done"
        fi

        if [[ ! -f "${KURYR_ACTIVATOR}" ]]; then
             echo -n "${KURYR_ACTIVATOR} is missing. Copying the default one... "
             sudo cp ${KURYR_DEFAULT_ACTIVATOR} ${KURYR_ACTIVATOR}
             echo "Done"
        fi


        create_kuryr_account
        configure_kuryr "${DISTRO_DISTUTILS_DATA_PATH}"

        # Run etcd first
        run_process etcd-server "$DEST/etcd/etcd-$ETCD_VERSION-linux-amd64/etcd --data-dir $DEST/etcd/db.etcd --advertise-client-urls http://0.0.0.0:$KURYR_ETCD_PORT  --listen-client-urls http://0.0.0.0:$KURYR_ETCD_PORT"

        # FIXME(mestery): By default, Ubuntu ships with /bin/sh pointing to
        # the dash shell.
        # ..
        # ..
        # The dots above represent a pause as you pick yourself up off the
        # floor. This means the latest version of "install_docker.sh" to load
        # docker fails because dash can't interpret some of it's bash-specific
        # things. It's a bug in install_docker.sh that it relies on those and
        # uses a shebang of /bin/sh, but that doesn't help us if we want to run
        # docker and specifically Kuryr. So, this works around that.
        sudo update-alternatives --install /bin/sh sh /bin/bash 100

        # Install docker only if it's not already installed. The following checks
        # whether the docker-engine package is already installed, as this is the
        # most common way for installing docker from binaries. In case it's been
        # manually installed, the install_docker.sh script will prompt a warning
        # if another docker executable is found
        check_docker || {
            wget http://get.docker.com -O install_docker.sh
            sudo chmod 777 install_docker.sh
            sudo sh install_docker.sh
            sudo rm install_docker.sh
        }

        # After an ./unstack it will be stopped. So it is ok if it returns exit-code == 1
        sudo service docker stop || true

        run_process docker-engine "sudo /usr/bin/docker daemon -H unix://$KURYR_DOCKER_ENGINE_SOCKET_FILE -H tcp://0.0.0.0:$KURYR_DOCKER_ENGINE_PORT --cluster-store etcd://localhost:$KURYR_ETCD_PORT"

        # We put the stack user as owner of the socket so we do not need to
        # run the Docker commands with sudo when developing.
        echo -n "Waiting for Docker to create its socket file"
        while [ ! -e "$KURYR_DOCKER_ENGINE_SOCKET_FILE" ]; do
            echo -n "."
            sleep 1
        done
        echo ""
        sudo chown "$STACK_USER":docker "$KURYR_DOCKER_ENGINE_SOCKET_FILE"

        echo "Build busybox docker image for fullstack and rally test"
        cd $DEST/kuryr-libnetwork/contrib/busybox
        sudo usermod -aG docker $STACK_USER
        sh build_image.sh
    fi

    if [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # FIXME(limao): When Kuryr start up, it need to detect if neutron support tag plugin.
        #               Kuryr will call neutron extension api to verify if neutron support tag.
        #               So Kuryr need to start after neutron-server finish load tag plugin.
        #               The process of devstack is:
        #                  ...
        #                  run_phase "stack" "post-config"
        #                  ...
        #                  start neutron-server
        #                  ...
        #                  run_phase "stack" "extra"
        #
        #               If Kuryr start up in "post-config" phase, there is no way to make sure
        #               Kuryr can start before neutron-server, so Kuryr start in "extra" phase.
        #               Bug: https://bugs.launchpad.net/kuryr/+bug/1587522
        run_process kuryr-libnetwork "sudo PYTHONPATH=$PYTHONPATH:$DEST/kuryr python $DEST/kuryr-libnetwork/scripts/run_server.py  --config-file $KURYR_CONFIG"

        neutron subnetpool-create --default-prefixlen $KURYR_POOL_PREFIX_LEN --pool-prefix $KURYR_POOL_PREFIX kuryr

    fi

    if [[ "$1" == "unstack" ]]; then
        stop_process kuryr-libnetwork
        stop_process etcd-server
        rm -rf $DEST/etcd/
        stop_process docker-engine
        # Stop process does not handle well Docker 1.12+ new multi process
        # split and doesn't kill them all. Let's leverage Docker's own pidfile
        sudo kill -s SIGTERM "$(cat /var/run/docker.pid)"
    fi
fi

# Restore xtrace
$XTRACE

