#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# ZTS cert signer root CA
ZTS_CERT_SIGNER_X509_OUT_PATH=${ZTS_CERT_SIGNER_X509_OUT_PATH:-./docker/zts/var/keys/zts_cert_signer_cert.pem}

# ZTS truststore
ZTS_SSL_TRUSTSTORE_PATH=${ZTS_SSL_TRUSTSTORE_PATH:-./docker/zts/var/certs/zts_truststore.jks}
ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz}



# -------------------------------- ZTS --------------------------------
CERT_ALIAS='zts-cert-signer-ca'
keytool -delete -noprompt -keystore ${ZTS_SSL_TRUSTSTORE_PATH} -storepass "${ZTS_SSL_TRUSTSTORE_PASS}" -storetype JKS -alias "${CERT_ALIAS}" > /dev/null
keytool -importcert -noprompt -keystore ${ZTS_SSL_TRUSTSTORE_PATH} -storepass "${ZTS_SSL_TRUSTSTORE_PASS}" -storetype JKS -alias "${CERT_ALIAS}" -file ${ZTS_CERT_SIGNER_X509_OUT_PATH}
