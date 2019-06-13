#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# default key bits
KEY_BITS=${KEY_BITS:-3072}

# service private key path
ZMS_SERVICE_PK_PATH=${ZMS_SERVICE_PK_PATH:-./docker/zms/var/keys/zms_private.pem}
ZTS_SERVICE_PK_PATH=${ZTS_SERVICE_PK_PATH:-./docker/zts/var/keys/zts_private.pem}
UI_SERVICE_PK_PATH=${UI_SERVICE_PK_PATH:-./docker/ui/var/keys/athenz.ui-server.pem}

# service public key path
ZMS_SERVICE_PUB_PATH=${ZMS_SERVICE_PUB_PATH:-./docker/zms/var/keys/zms_public.pem}
ZTS_SERVICE_PUB_PATH=${ZTS_SERVICE_PUB_PATH:-./docker/zts/var/keys/zts_public.pem}
UI_SERVICE_PUB_PATH=${UI_SERVICE_PUB_PATH:-./docker/ui/var/keys/athenz.ui-server_pub.pem}



# -------------------------------- ZMS --------------------------------
openssl genrsa -out "${ZMS_SERVICE_PK_PATH}" "${KEY_BITS}"
openssl rsa -in "${ZMS_SERVICE_PK_PATH}" -pubout -out "${ZMS_SERVICE_PUB_PATH}"

# -------------------------------- ZTS --------------------------------
openssl genrsa -out "${ZTS_SERVICE_PK_PATH}" "${KEY_BITS}"
openssl rsa -in "${ZTS_SERVICE_PK_PATH}" -pubout -out "${ZTS_SERVICE_PUB_PATH}"

# -------------------------------- UI --------------------------------
openssl genrsa -out "${UI_SERVICE_PK_PATH}" "${KEY_BITS}"
openssl rsa -in "${UI_SERVICE_PK_PATH}" -pubout -out "${UI_SERVICE_PUB_PATH}"
