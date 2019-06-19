#!/bin/sh

set -e

# build execution env.
docker build -t openssl-alpine -f ./docker/setup-scripts/openssl/Dockerfile ./docker/setup-scripts
docker build -t keytool-alpine -f ./docker/setup-scripts/keytool/Dockerfile ./docker/setup-scripts

# test docker image
docker run --rm --name openssl-alpine openssl-alpine
docker run --rm --name keytool-alpine keytool-alpine

# run setup scripts (1)
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/1.create-private-key.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine

# run setup scripts (2)
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/2.create-service-keypair.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine

# run setup scripts (3)
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/3.generate-self-signed-certificate.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine

# run setup scripts (4)
docker run --rm --entrypoint /usr/bin/run.sh \
  -e ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS:-athenz} \
  -e ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS:-athenz} \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/4.create-keystore.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine

# run setup scripts (5)
docker run --rm --entrypoint /usr/bin/run.sh \
  -e ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS:-athenz} \
  -e ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz} \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/5.create-truststore.sh:/usr/bin/run.sh \
  --name keytool-alpine keytool-alpine

# --- [DEV env. only] prepare key and certificate pairs for ZTS self cert signer ---

# [DEV env. only] run setup scripts (6.1)
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/6.1.create-zts-cert-signer-pair.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine

# [DEV env. only] run setup scripts (6.2)
docker run --rm --entrypoint /usr/bin/run.sh \
  -e ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS:-athenz} \
  -v `pwd`/docker:/usr/bin/docker \
  -v `pwd`/docker/setup-scripts/6.2.trust-zts-cert-signer-CA.sh:/usr/bin/run.sh \
  --name keytool-alpine keytool-alpine

# [for backup only] pass private key passwords to docker env.
# docker run --rm --entrypoint /usr/bin/run.sh \
#   -e ZMS_PK_PASS=${ZMS_PK_PASS:-athenz} \
#   -e ZTS_PK_PASS=${ZTS_PK_PASS:-athenz} \
#   -e UI_PK_PASS=${UI_PK_PASS:-athenz} \
