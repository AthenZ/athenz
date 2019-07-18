#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# server x509 certificate path
ZMS_X509_OUT_PATH=${ZMS_X509_OUT_PATH:-./docker/zms/var/certs/zms_cert.pem}
ZTS_X509_OUT_PATH=${ZTS_X509_OUT_PATH:-./docker/zts/var/certs/zts_cert.pem}
UI_X509_OUT_PATH=${UI_X509_OUT_PATH:-./docker/ui/var/certs/ui_cert.pem}

# server truststore path
ZMS_SSL_TRUSTSTORE_PATH=${ZMS_SSL_TRUSTSTORE_PATH:-./docker/zms/var/certs/zms_truststore.jks}
ZTS_SSL_TRUSTSTORE_PATH=${ZTS_SSL_TRUSTSTORE_PATH:-./docker/zts/var/certs/zts_truststore.jks}

# server truststore password
ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS:-athenz}
ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz}



# -------------------------------- ZMS --------------------------------
rm -f ${ZMS_SSL_TRUSTSTORE_PATH}
CERT_ALIAS='zts-https'
keytool -importcert -noprompt -keystore ${ZMS_SSL_TRUSTSTORE_PATH} -storepass "${ZMS_SSL_TRUSTSTORE_PASS}" -storetype JKS -alias "${CERT_ALIAS}" -file ${ZTS_X509_OUT_PATH}
CERT_ALIAS='ui-https'
keytool -importcert -noprompt -keystore ${ZMS_SSL_TRUSTSTORE_PATH} -storepass "${ZMS_SSL_TRUSTSTORE_PASS}" -storetype JKS -alias "${CERT_ALIAS}" -file ${UI_X509_OUT_PATH}

# -------------------------------- ZTS --------------------------------
rm -f ${ZTS_SSL_TRUSTSTORE_PATH}
CERT_ALIAS='zms-https'
keytool -importcert -noprompt -keystore ${ZTS_SSL_TRUSTSTORE_PATH} -storepass "${ZTS_SSL_TRUSTSTORE_PASS}" -storetype JKS -alias "${CERT_ALIAS}" -file ${ZMS_X509_OUT_PATH}
