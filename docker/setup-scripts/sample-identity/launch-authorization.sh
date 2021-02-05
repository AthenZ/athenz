#!/bin/sh

# to setup-scripts directory
cd "$(dirname "$0")"

# import functions
. ../common/color-print.sh
. ../common/local-env-setup.sh

cat <<'EOF' | colored_cat c

#################################################
### launch authorization setup
#################################################

EOF

echo 'Allowing ZTS provider to launch example-service'
zms-cli -z "${ZMS_URL}/zms/v1" --key "${TEAM_ADMIN_CERT_KEY_PATH}" --cert "${TEAM_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d athenz set-domain-template zts_instance_launch_provider service=example-service