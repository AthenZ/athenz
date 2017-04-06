#!/bin/bash

set -e

echo "---stopping zms---"
cd /opt/athenz/athenz-zms*
sudo -E bin/zms stop


echo "---stopping ui---"
cd /opt/athenz/athenz-ui*
export ZMS_SERVER=`hostname`
bin/athenz_ui stop

echo "---stopping zts---"
cd /opt/athenz/athenz-zts*
sudo bin/zts stop
