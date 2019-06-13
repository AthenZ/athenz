#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# default key bits
KEY_BITS=${KEY_BITS:-4096}
# certificate certified days
X509_DAYS=${X509_DAYS:-365}

# ZTS certificate signer
ZTS_CERT_SIGNER_PK_PATH=${ZTS_PK_PATH:-./docker/zts/var/keys/zts_cert_signer_key.pem}
ZTS_CERT_SIGNER_PK_PASS=${ZTS_PK_PASS:-athenz}
ZTS_CERT_SIGNER_X509_CONFIG_PATH=${ZTS_CERT_SIGNER_X509_CONFIG_PATH:-./docker/zts/var/keys/zts_cert_signer_ca.cnf}
ZTS_CERT_SIGNER_X509_OUT_PATH=${ZTS_CERT_SIGNER_X509_OUT_PATH:-./docker/zts/var/keys/zts_cert_signer_cert.pem}

# ZTS truststore
ZTS_SSL_TRUSTSTORE_PATH=${ZTS_SSL_TRUSTSTORE_PATH:-./docker/zts/var/certs/zts_truststore.jks}
ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz}



# -------------------------------- ZTS --------------------------------
openssl req -newkey "rsa:${KEY_BITS}" \
  -keyout "${ZTS_CERT_SIGNER_PK_PATH}" \
  -passout "pass:${ZTS_CERT_SIGNER_PK_PASS}" \
  -new -x509 -extensions v3_ca -days "${X509_DAYS}" \
  -config "${ZTS_CERT_SIGNER_X509_CONFIG_PATH}" \
  -out "${ZTS_CERT_SIGNER_X509_OUT_PATH}"
