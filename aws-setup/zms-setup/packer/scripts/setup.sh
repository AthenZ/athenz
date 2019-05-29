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
sudo useradd -g athenz athenz-zms

# Copying jars, war and webdefault.xml files
sudo tar -xzf /opt/zms/tars/athenz-zms-bin.tar.gz -C /opt/zms/tars/
sudo ls -ltr /opt/zms/tars/
sudo cp -r /opt/zms/tars/athenz-zms/lib/jars/ /opt/zms/
sudo cp /opt/zms/tars/athenz-zms/etc/webdefault.xml /opt/zms/etc/
sudo cp /opt/zms/tars/athenz-zms/webapps/zms.war /opt/zms/webapps/
sudo cp /opt/zms/tars/athenz-zms/conf/zms_server/authorized_services.json /opt/zms/conf/zms_server/authorized_services.json
sudo cp /opt/zms/tars/athenz-zms/conf/zms_server/solution_templates.json /opt/zms/conf/zms_server/solution_templates.json
sudo cp -r /opt/zms/tars/athenz-zms/bin/linux/ /opt/zms/bin/

# setup our zms service

sudo mkdir /etc/zms
sudo cp /opt/zms/service/zms.service /etc/zms/zms.service
sudo systemctl enable /etc/zms/zms.service
sudo cp /opt/zms/conf/zms-user /etc/sudoers.d/

#set up aws logs

curl https://s3.amazonaws.com//aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -o /opt/zms/logs/awslogs-agent-setup.py

# make sure all files are owned by our user/group

sudo chown -R athenz-zms:athenz /opt/zms
