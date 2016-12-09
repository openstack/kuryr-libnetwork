#!/bin/sh

export OS_USER=vagrant
export HOST_IP=127.0.0.1

# run script
bash /vagrant/devstack.sh "$1"

#set environment variables for kuryr
su "$OS_USER" -c "echo 'source /vagrant/config/kuryr_rc' >> ~/.bash_profile"
