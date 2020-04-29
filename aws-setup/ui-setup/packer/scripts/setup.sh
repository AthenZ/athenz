#!/usr/bin/env bash
set -xe

# install epel

sudo yum repolist
sudo yum -y install epel-release


# install aws_cli

echo "install aws"
sudo yum -y install python-pip
sudo pip install awscli
aws --version

# install node

sudo curl --silent --location https://rpm.nodesource.com/setup_12.x | sudo bash -
sudo yum -y install --disablerepo=* --enablerepo=nodesource nodejs

# setup our athenz group and user

sudo groupadd athenz
sudo useradd -g athenz athenz-ui

# setup our ui service

sudo mkdir /etc/ui
sudo cp /opt/athenz-ui/ui.service /etc/ui/ui.service
sudo systemctl enable /etc/ui/ui.service
sudo cp /opt/athenz-ui/conf/ui-user /etc/sudoers.d/

#set up aws logs

curl https://s3.amazonaws.com//aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -o /opt/athenz-ui/logs/awslogs-agent-setup.py

# make sure all files are owned by our user/group

sudo chown -R athenz-ui:athenz /opt/athenz-ui
