#!/bin/bash

set -e

sudo apt-get update
sudo apt-get -y install openjdk-8-jdk

sudo cp -rp /tmp/provision /opt/athenz

echo "deploying athenz-utils"
cd /opt/athenz
tar xfz athenz-utils*.tar.gz

echo "provisioning zms"
tar xfz athenz-zms*.tar.gz

echo "provisioning ui"
curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install -y -g nodemon

tar xfz athenz-ui*.tar.gz

echo "provisioning zts"
tar xfz athenz-zts*.tar.gz


