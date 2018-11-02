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

    if is_service_enabled kuryr-libnetwork; then
        configure_auth_token_middleware "$KURYR_CONFIG" kuryr \
        "$KURYR_AUTH_CACHE_DIR" neutron
        iniset $KURYR_CONFIG DEFAULT capability_scope $KURYR_CAPABILITY_SCOPE
        iniset $KURYR_CONFIG DEFAULT process_external_connectivity $KURYR_PROCESS_EXTERNAL_CONNECTIVITY
    fi

    if [[ "$ENABLE_PLUGINV2" == "True" ]]; then
        # bindir is /user/libexec/kuryr in docker image
        iniset -sudo ${KURYR_CONFIG} DEFAULT bindir "/usr/libexec/kuryr"
    else
        iniset -sudo ${KURYR_CONFIG} DEFAULT bindir "$binding_path/libexec/kuryr"
    fi
    iniset -sudo ${KURYR_CONFIG} DEFAULT debug $ENABLE_DEBUG_LOG_LEVEL
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
        if [[ ! -d "${KURYR_LOG_DIR}" ]]; then
            echo -n "${KURYR_LOG_DIR} directory is missing. Creating it... "
            sudo mkdir -p ${KURYR_LOG_DIR}
            echo "Done"
        fi
        setup_develop $KURYR_HOME

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then

        # This is needed in legacy plugin
        if [[ "$ENABLE_PLUGINV2" != "True" ]]; then
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
        fi

        create_kuryr_account
        configure_kuryr "${DISTRO_DISTUTILS_DATA_PATH}"
    fi

    if [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo "Build busybox docker image for fullstack and rally test"
        cd $DEST/kuryr-libnetwork/contrib/busybox
        sh build_image.sh

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
        if [[ "$ENABLE_PLUGINV2" == "True" ]]; then
            # Build pluginv2 rootfs
            cd $DEST/kuryr-libnetwork/
            sudo sh contrib/docker/v2plugin/v2plugin_rootfs.sh

            # Build and install pluginv2 image
            sudo docker plugin create kuryr/libnetwork2 ./

            # Enable pluginv2
            sudo docker plugin enable kuryr/libnetwork2:latest
        else
            run_process kuryr-libnetwork "$KURYR_BIN_DIR/kuryr-server --config-file $KURYR_CONFIG" "" "root"
        fi

        openstack subnet pool create --default-prefix-length $KURYR_POOL_PREFIX_LEN --pool-prefix $KURYR_POOL_PREFIX kuryr

    fi

    if [[ "$1" == "unstack" ]]; then
        if [[ "$ENABLE_PLUGINV2" == "True" ]]; then
            sudo docker plugin disable kuryr/libnetwork2:latest
        else
            stop_process kuryr-libnetwork
        fi
    fi

    if [[ "$1" == "clean" ]]; then
        sudo rm -rf $KURYR_CONFIG_DIR
    fi
fi

# Restore xtrace
$XTRACE

