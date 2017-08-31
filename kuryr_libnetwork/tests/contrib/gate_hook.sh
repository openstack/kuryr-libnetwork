#!/usr/bin/env bash

set -ex

VENV=${1:-"fullstack"}

GATE_DEST=$BASE/new
DEVSTACK_PATH=$GATE_DEST/devstack

export DEVSTACK_LOCAL_CONFIG+=$'\n'"enable_plugin devstack-plugin-container https://github.com/openstack/devstack-plugin-container"
export DEVSTACK_LOCAL_CONFIG+=$'\n'"KURYR_CONFIG_DIR=/etc/kuryr-libnetwork"

$BASE/new/devstack-gate/devstack-vm-gate.sh
