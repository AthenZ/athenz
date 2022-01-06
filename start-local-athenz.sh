#!/usr/bin/env bash

set -eu
set -o pipefail

cd docker

# import functions
. ./setup-scripts/common/color-print.sh

make deploy-local &
MAKE_PID=$!

wait $MAKE_PID

cat <<'EOF' | colored_cat c

#################################################
### Athenz is up!
#################################################

EOF

printf 'You can access UI now at https://localhost' | colored_cat g
printf '\n'
printf 'If you are on Mac you can run the following command to add the self-signed certificate to login keychain, so that browser does not complain about it. \n' | colored_cat y
printf 'security add-trusted-cert -k %s/Library/Keychains/login.keychain docker/sample/CAs/athenz_ca.der\n' "$HOME"
printf '\n'