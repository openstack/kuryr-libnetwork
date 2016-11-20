#!/bin/sh

tar cv --files-from /dev/null | docker import - scratch

sudo docker build -t kuryr/busybox .
