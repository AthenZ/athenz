#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# default key bits
KEY_BITS=${KEY_BITS:-4096}

# server HTTPS private key path
ZMS_PK_PATH=${ZMS_PK_PATH:-./docker/zms/var/certs/zms_key.pem}
ZTS_PK_PATH=${ZTS_PK_PATH:-./docker/zts/var/certs/zts_key.pem}
UI_PK_PATH=${UI_PK_PATH:-./docker/ui/var/certs/ui_key.pem}

# server HTTPS private key password
# ZMS_PK_PASS=${ZMS_PK_PASS:-athenz}
# ZTS_PK_PASS=${ZTS_PK_PASS:-athenz}
# UI_PK_PASS=${UI_PK_PASS:-athenz}



# -------------------------------- ZMS --------------------------------
# openssl genrsa -aes256 -out "${ZMS_PK_PATH}" -passout "pass:${ZMS_PK_PASS}" "${KEY_BITS}"
openssl genrsa -out "${ZMS_PK_PATH}" "${KEY_BITS}"

# -------------------------------- ZTS --------------------------------
# openssl genrsa -aes256 -out "${ZTS_PK_PATH}" -passout "pass:${ZTS_PK_PASS}" "${KEY_BITS}"
openssl genrsa -out "${ZTS_PK_PATH}" "${KEY_BITS}"

# -------------------------------- UI --------------------------------
# openssl genrsa -aes256 -out "${UI_PK_PATH}" -passout "pass:${UI_PK_PASS}" "${KEY_BITS}"
openssl genrsa -out "${UI_PK_PATH}" "${KEY_BITS}"
