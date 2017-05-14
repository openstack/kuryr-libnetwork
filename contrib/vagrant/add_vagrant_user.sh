#!/bin/bash

echo "create user vagrant"
adduser --disabled-password --gecos "" vagrant
echo 'vagrant:vagrant' | chpasswd
ls -al /home/
echo "add sudo privilege to user vagrant"
cp /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/admin
chmod +w /etc/sudoers.d/admin
ls -al /etc/sudoers.d/
sed -i 's/ubuntu/vagrant/g' /etc/sudoers.d/admin
cat /etc/sudoers.d/admin
echo "enable ssh access for user vagrant"
mkdir /home/vagrant/.ssh
cat /home/ubuntu/.ssh/authorized_keys > /home/vagrant/.ssh/authorized_keys
chown vagrant:vagrant -R /home/vagrant/.ssh
su - vagrant -c "cat /home/vagrant/.ssh/authorized_keys"
chmod 600 /home/vagrant/.ssh/authorized_keys
ls -al /home/vagrant/.ssh
chmod 700 /home/vagrant/.ssh
ls -al /home/vagrant
