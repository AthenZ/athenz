#!/bin/sh

# to setup-scripts directory
cd "$(dirname "$0")"

# import functions
. ../common/color-print.sh
. ../common/local-env-setup.sh

cat <<'EOF' | colored_cat c

#################################################
### zts provider setup
#################################################

EOF

echo 'Setting up ZTS as provider'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-group-role providers sys.auth.zts

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy providers grant launch to providers on 'instance'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-group-role provider.sys.auth.zts sys.auth.zts

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth add-policy provider.sys.auth.zts grant launch to provider.sys.auth.zts on 'dns.zts.athenz.cloud'

zms-cli -z "${ZMS_URL}/zms/v1" --key "${DOMAIN_ADMIN_CERT_KEY_PATH}" --cert "${DOMAIN_ADMIN_CERT_PATH}" -c "${ATHENZ_CA_PATH}" \
    -d sys.auth set-service-endpoint zts class://com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider