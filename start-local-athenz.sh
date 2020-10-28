#!/bin/sh

set -eu
set -o pipefail

cd docker

make deploy-local &
MAKE_PID=$!

wait $MAKE_PID

# convert pem cert to der format so that it can be imported into Mac login keychain
openssl x509 -outform der -in sample/CAs/athenz_ca.pem -out sample/CAs/athenz_ca.der

# change trust setting for the cert so that browser is happy ( Mac specific instructions )
# security add-trusted-cert -k $HOME/Library/Keychains/login.keychain sample/CAs/athenz_ca.der

echo "You can access UI now at https://localhost"