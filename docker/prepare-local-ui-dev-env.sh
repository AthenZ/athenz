#!/usr/bin/env bash

BASE_DIR=$(git rev-parse --show-toplevel)
cp ${BASE_DIR}/docker/ui/var/keys/*.pem ${BASE_DIR}/ui/keys
cp ${BASE_DIR}/docker/ui/var/keys/cookie-session ${BASE_DIR}/ui/keys

cp ${BASE_DIR}/docker/ui/conf/users_data.json ${BASE_DIR}/ui/src/config
cp ${BASE_DIR}/docker/ui/conf/athenz.conf  ${BASE_DIR}/ui/src/config

printf '\n'
printf 'If you are on Mac you can run the following command to add the self-signed certificate to login keychain, so that browser does not complain about it. \n'
printf "security add-trusted-cert -k %s/Library/Keychains/login.keychain ${BASE_DIR}/docker/sample/CAs/athenz_ca.der\n" "$HOME"
printf '\n'

exit 0