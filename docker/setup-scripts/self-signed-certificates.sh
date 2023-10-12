#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ./common/color-print.sh

#################################################
### try-out-Athenz-with-self-signed-CA.md
#################################################
### WARNING: this file is just from copy-and-paste. Always update the document first.

cat <<'EOF' | colored_cat c

#################################################
### try-out-Athenz-with-self-signed-CA.md
#################################################

EOF



### ----------------------------------------------------------------
echo ''
echo '# Prepare certificates' | colored_cat r

echo '1. set up env.' | colored_cat g
BASE_DIR="$(git rev-parse --show-toplevel)"
. "${BASE_DIR}/docker/env.sh"
. "${DOCKER_DIR}/sample/env.dev.sh"

echo '2. create the self-signed CAs' | colored_cat g
bash "${DEV_CA_DIR}/create-self-signed-ca.sh"

echo '3. create self-signed Athenz domain admin user certificate' | colored_cat g
echo "your setting: DEV_DOMAIN_ADMIN=${DEV_DOMAIN_ADMIN}" | colored_cat y
bash "${DEV_DOMAIN_ADMIN_DIR}/create-self-signed-user-cert.sh"

echo '4. create ZMS server certificate' | colored_cat g
bash "${DEV_ZMS_DIR}/create-self-signed-certs.sh"

echo '5. create ZTS server certificates' | colored_cat g
bash "${DEV_ZTS_DIR}/create-self-signed-certs.sh"

echo '6. create UI server certificates' | colored_cat g
bash "${DEV_UI_DIR}/create-self-signed-certs.sh"


### ----------------------------------------------------------------
echo ''
echo '# Overwrite env.' | colored_cat r

cat <<EOF > dev-env-exports.sh
# CAs
export CA_DIR="${DEV_CA_DIR}"
export ATHENZ_CA_PATH="${DEV_ATHENZ_CA_PATH}"
export USER_CA_PATH="${DEV_USER_CA_PATH}"
export SERVICE_CA_PATH="${DEV_SERVICE_CA_PATH}"

# Athenz domain admin
export DOMAIN_ADMIN="${DEV_DOMAIN_ADMIN}"
export DOMAIN_ADMIN_DIR="${DEV_CA_DIR}"
export DOMAIN_ADMIN_CERT_KEY_PATH="${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}"
export DOMAIN_ADMIN_CERT_PATH="${DEV_DOMAIN_ADMIN_CERT_PATH}"

# Team domain admin
export TEAM_ADMIN="${DEV_TEAM_ADMIN}"
export TEAM_ADMIN_DIR="${DEV_TEAM_ADMIN_DIR}"
export TEAM_ADMIN_CERT_KEY_PATH="${DEV_TEAM_ADMIN_CERT_KEY_PATH}"
export TEAM_ADMIN_CERT_PATH="${DEV_TEAM_ADMIN_CERT_PATH}"

# ZMS
export PROD_ZMS_DIR="${DEV_ZMS_DIR}"
export ZMS_CERT_KEY_PATH="${DEV_ZMS_CERT_KEY_PATH}"
export ZMS_CERT_PATH="${DEV_ZMS_CERT_PATH}"

# ZTS
export PROD_ZTS_DIR="${DEV_ZTS_DIR}"
export ZTS_CERT_KEY_PATH="${DEV_ZTS_CERT_KEY_PATH}"
export ZTS_CERT_PATH="${DEV_ZTS_CERT_PATH}"
export ZTS_SIGNER_CERT_KEY_PATH="${DEV_ZTS_SIGNER_CERT_KEY_PATH}"
export ZTS_SIGNER_CERT_PATH="${DEV_ZTS_SIGNER_CERT_PATH}"
export ZMS_CLIENT_CERT_KEY_PATH="${DEV_ZMS_CLIENT_CERT_KEY_PATH}"
# export ZMS_CLIENT_CERT_PATH="${DEV_ZMS_CLIENT_CERT_PATH}"
export ZMS_CLIENT_CERT_PATH="${DEV_ZMS_CLIENT_CERT_BUNDLE_PATH}"

# UI
export PROD_UI_DIR="${DEV_UI_DIR}"
export UI_CERT_KEY_PATH="${DEV_UI_CERT_KEY_PATH}"
export UI_CERT_PATH="${DEV_UI_CERT_PATH}"
EOF
echo 'As shell script cannot update the env. in parent shell X_X' | colored_cat p
echo 'You will need to run the following command...' | colored_cat p
echo ". $(pwd)/dev-env-exports.sh"
echo 'Or, if you run the auto script, we will do that for you XD' | colored_cat p
