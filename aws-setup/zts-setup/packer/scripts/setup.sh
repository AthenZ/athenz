#!/usr/bin/env bash
set -xe

# install epel

sudo yum -y install epel-release
sudo yum repolist

# install aws_cli

echo "install aws"
sudo yum -y install python-pip
sudo pip install awscli
aws --version

# install openjdk

sudo yum -y install java-1.8.0-openjdk

# setup our athenz group and user

sudo groupadd athenz
sudo useradd -g athenz athenz-zts


# Copying jars, war and webdefault.xml files
sudo tar -xzf /opt/zts/tars/athenz-zts-bin.tar.gz -C /opt/zts/tars/
sudo ls -ltr /opt/zts/tars/
sudo cp -r /opt/zts/tars/athenz-zts/lib/jars/ /opt/zts/
sudo cp /opt/zts/tars/athenz-zts/etc/webdefault.xml /opt/zts/etc/
sudo cp /opt/zts/tars/athenz-zts/webapps/zts.war /opt/zts/webapps/
sudo cp -r /opt/zts/tars/athenz-zts/bin/linux/ /opt/zts/bin/

# setup our zts service

sudo mkdir /etc/zts
sudo cp /opt/zts/service/zts.service /etc/zts/zts.service
sudo systemctl enable /etc/zts/zts.service
sudo cp /opt/zts/conf/zts-user /etc/sudoers.d/

#set up aws logs

curl https://s3.amazonaws.com//aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -o /opt/zts/logs/awslogs-agent-setup.py

# make sure all files are owned by our user/group

sudo chown -R athenz-zts:athenz /opt/zts
