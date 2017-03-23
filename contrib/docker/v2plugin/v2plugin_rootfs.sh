#!/bin/bash
# Script to create the kuryr-libnetwork docker v2 plugin
# run this script from kuryr-libnetwork directory with contrib/docker/v2plugin/v2plugin_rootfs.sh

echo "Copy kuryr-libentwork config.json"
rm -rf ./config.json
cp contrib/docker/v2plugin/config.json ./
echo "Creating rootfs for kuryr-libnetwork v2plugin"
docker build -t kuryr-libnetwork-rootfs .
id=$(docker create kuryr-libnetwork-rootfs true)
echo "Deleting old rootfs"
rm -rf rootfs
echo "Creating new rootfs"
mkdir -p rootfs
docker export "${id}" | tar -x -C rootfs
echo "Clean up"
docker rm -vf "${id}"
docker rmi kuryr-libnetwork-rootfs
