#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# to project root
cd ../..

# start UI
printf "\nWill start Athenz UI...\n"
docker run -d -h localhost \
  --network=host \
  -v "`pwd`/docker/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf" \
  -v "`pwd`/docker/ui/keys:/opt/athenz/ui/keys" \
  -e "ZMS_SERVER=`hostname`" \
  -e "UI_SERVER=`hostname`" \
  --name athenz-ui athenz-ui
