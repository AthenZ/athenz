#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# certificate certified days
X509_DAYS=${X509_DAYS:-3650}

# server HTTPS private key path
ZMS_PK_PATH=${ZMS_PK_PATH:-./docker/zms/var/certs/zms_key.pem}
ZTS_PK_PATH=${ZTS_PK_PATH:-./docker/zts/var/certs/zts_key.pem}
UI_PK_PATH=${UI_PK_PATH:-./docker/ui/var/certs/ui_key.pem}

# server HTTPS private key password
# ZMS_PK_PASS=${ZMS_PK_PASS:-athenz}
# ZTS_PK_PASS=${ZTS_PK_PASS:-athenz}
# UI_PK_PASS=${UI_PK_PASS:-athenz}

# server x509 certificate cnf
ZMS_X509_CONFIG_PATH=${ZMS_X509_CONFIG_PATH:-./docker/zms/var/certs/dev_x509_cert.cnf}
ZTS_X509_CONFIG_PATH=${ZTS_X509_CONFIG_PATH:-./docker/zts/var/certs/dev_x509_cert.cnf}
UI_X509_CONFIG_PATH=${UI_X509_CONFIG_PATH:-./docker/ui/var/certs/dev_x509_cert.cnf}

# server x509 certificate path
ZMS_X509_OUT_PATH=${ZMS_X509_OUT_PATH:-./docker/zms/var/certs/zms_cert.pem}
ZTS_X509_OUT_PATH=${ZTS_X509_OUT_PATH:-./docker/zts/var/certs/zts_cert.pem}
UI_X509_OUT_PATH=${UI_X509_OUT_PATH:-./docker/ui/var/certs/ui_cert.pem}



# -------------------------------- ZMS --------------------------------
# openssl req -key "${ZMS_PK_PATH}" -passin "pass:${ZMS_PK_PASS}" -new -x509 -extensions v3_req -days "${X509_DAYS}" -config "${ZMS_X509_CONFIG_PATH}" -out "${ZMS_X509_OUT_PATH}"
openssl req -key "${ZMS_PK_PATH}" -new -x509 -extensions v3_req -days "${X509_DAYS}" -config "${ZMS_X509_CONFIG_PATH}" -out "${ZMS_X509_OUT_PATH}"

# -------------------------------- ZTS --------------------------------
# openssl req -key "${ZTS_PK_PATH}" -passin "pass:${ZTS_PK_PASS}" -new -x509 -extensions v3_req -days "${X509_DAYS}" -config "${ZTS_X509_CONFIG_PATH}" -out "${ZTS_X509_OUT_PATH}"
openssl req -key "${ZTS_PK_PATH}" -new -x509 -extensions v3_req -days "${X509_DAYS}" -config "${ZTS_X509_CONFIG_PATH}" -out "${ZTS_X509_OUT_PATH}"

# -------------------------------- UI --------------------------------
# openssl req -key "${UI_PK_PATH}" -passin "pass:${UI_PK_PASS}" -new -x509 -extensions v3_req -days "${X509_DAYS}" -config "${UI_X509_CONFIG_PATH}" -out "${UI_X509_OUT_PATH}"
openssl req -key "${UI_PK_PATH}" -new -x509 -extensions v3_req -days "${X509_DAYS}" -config "${UI_X509_CONFIG_PATH}" -out "${UI_X509_OUT_PATH}"
