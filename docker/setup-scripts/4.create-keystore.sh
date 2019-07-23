#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# server HTTPS private key path
ZMS_PK_PATH=${ZMS_PK_PATH:-./docker/zms/var/certs/zms_key.pem}
ZTS_PK_PATH=${ZTS_PK_PATH:-./docker/zts/var/certs/zts_key.pem}
UI_PK_PATH=${UI_PK_PATH:-./docker/ui/var/certs/ui_key.pem}

# server HTTPS private key password
# ZMS_PK_PASS=${ZMS_PK_PASS:-athenz}
# ZTS_PK_PASS=${ZTS_PK_PASS:-athenz}
# UI_PK_PASS=${UI_PK_PASS:-athenz}

# server x509 certificate path
ZMS_X509_OUT_PATH=${ZMS_X509_OUT_PATH:-./docker/zms/var/certs/zms_cert.pem}
ZTS_X509_OUT_PATH=${ZTS_X509_OUT_PATH:-./docker/zts/var/certs/zts_cert.pem}
UI_X509_OUT_PATH=${UI_X509_OUT_PATH:-./docker/ui/var/certs/ui_cert.pem}

# server keystore path
ZMS_SSL_KEYSTORE_PATH=${ZMS_SSL_KEYSTORE_PATH:-./docker/zms/var/certs/zms_keystore.pkcs12}
ZTS_SSL_KEYSTORE_PATH=${ZTS_SSL_KEYSTORE_PATH:-./docker/zts/var/certs/zts_keystore.pkcs12}

# server keystore password
ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS:-athenz}
ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS:-athenz}



# -------------------------------- ZMS --------------------------------
# openssl pkcs12 -export -noiter -nomaciter -out "${ZMS_SSL_KEYSTORE_PATH}" -passout "pass:${ZMS_SSL_KEYSTORE_PASS}" -in "${ZMS_X509_OUT_PATH}" -inkey "${ZMS_PK_PATH}" -passin "pass:${ZMS_PK_PASS}"
openssl pkcs12 -export -noiter -nomaciter -out "${ZMS_SSL_KEYSTORE_PATH}" -passout "pass:${ZMS_SSL_KEYSTORE_PASS}" -in "${ZMS_X509_OUT_PATH}" -inkey "${ZMS_PK_PATH}"

# -------------------------------- ZTS --------------------------------
# openssl pkcs12 -export -noiter -nomaciter -out "${ZTS_SSL_KEYSTORE_PATH}" -passout "pass:${ZTS_SSL_KEYSTORE_PASS}" -in "${ZTS_X509_OUT_PATH}" -inkey "${ZTS_PK_PATH}" -passin "pass:${ZTS_PK_PASS}"
openssl pkcs12 -export -noiter -nomaciter -out "${ZTS_SSL_KEYSTORE_PATH}" -passout "pass:${ZTS_SSL_KEYSTORE_PASS}" -in "${ZTS_X509_OUT_PATH}" -inkey "${ZTS_PK_PATH}"
