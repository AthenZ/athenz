#!/bin/sh

set -eu
set -o pipefail

cd docker

make deploy-local &
MAKE_PID=$!

wait $MAKE_PID

# change trust setting for the cert so that browser is happy ( Mac specific optional step )
# security add-trusted-cert -k $HOME/Library/Keychains/login.keychain sample/CAs/athenz_ca.der

echo "You can access UI now at https://localhost"