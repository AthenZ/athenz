#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# default key bits
KEY_BITS=${KEY_BITS:-4096}
# certificate certified days
X509_DAYS=${X509_DAYS:-3650}

# ZTS certificate signer
ZTS_CERT_SIGNER_PK_PATH=${ZTS_CERT_SIGNER_PK_PATH:-./docker/zts/var/keys/zts_cert_signer_key.pem}
ZTS_CERT_SIGNER_X509_CONFIG_PATH=${ZTS_CERT_SIGNER_X509_CONFIG_PATH:-./docker/zts/var/keys/zts_cert_signer_ca.cnf}
ZTS_CERT_SIGNER_X509_OUT_PATH=${ZTS_CERT_SIGNER_X509_OUT_PATH:-./docker/zts/var/keys/zts_cert_signer_cert.pem}



# -------------------------------- ZTS --------------------------------
openssl req -newkey "rsa:${KEY_BITS}" \
  -keyout "${ZTS_CERT_SIGNER_PK_PATH}" \
  -nodes \
  -new -x509 -extensions v3_ca -days "${X509_DAYS}" \
  -config "${ZTS_CERT_SIGNER_X509_CONFIG_PATH}" \
  -out "${ZTS_CERT_SIGNER_X509_OUT_PATH}"
# unencrypted PKCS8 is not supported, need conversion
openssl rsa -in "${ZTS_CERT_SIGNER_PK_PATH}" -out "${ZTS_CERT_SIGNER_PK_PATH}"
