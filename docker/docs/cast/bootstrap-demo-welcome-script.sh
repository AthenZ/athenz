#!/usr/bin/env bash

set -u
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../../setup-scripts/common/color-print.sh

echo 'Hello~' | colored_cat b
echo "Welcome to the 'Athenz Bootstrap Demo' 😄" | colored_cat b
sleep 1.5

echo 'In this demo, we will use self-signed certificates for the setup.' | colored_cat b
sleep 1.5

echo ''
echo 'P.S. do not use self-signed certificates in your production env !!!' | colored_cat b
sleep 1.5
echo 'You should request all the certificates from your trusted CAs and put them in the pre-specified paths.' | colored_cat b
sleep 1.5
echo 'Please read through all the documents to ensure your Athenz deployment can reach your security requirement.' | colored_cat b
sleep 1.5

echo ''
echo 'The starting point is [Athenz-bootstrap.md]' | colored_cat b
sleep 1.5
echo 'It is also the starting point of this demo.' | colored_cat b
sleep 1.5

echo ''
echo "So, let's start 💪🏻" | colored_cat b
sleep 1.5

echo ''
echo 'First, confirm the prerequisites' | colored_cat b
sleep 1.5

echo '$ which keytool' | colored_cat r
which keytool | colored_cat y
echo '$ openssl version' | colored_cat r
openssl version | colored_cat y
echo '$ docker -v' | colored_cat r
docker -v | colored_cat y
sleep 1.5

echo ''
echo 'Check out the docker, nothing is running now 😭' | colored_cat b
echo '$ docker ps -a' | colored_cat r
docker ps -a | colored_cat y
sleep 1.5

echo ''
echo 'Done checking, time to go to the athenz repo' | colored_cat b
echo '$ cd ~/athenz' | colored_cat r
cd ~/athenz
sleep 1.5

echo ''
echo 'We are going run the automation shortcut, sit back and enjoy~ 🏖' | colored_cat b
