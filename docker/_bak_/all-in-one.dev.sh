#!/bin/sh

set -e

# build execution env.
printf '\nWill run: docker build for images to execute setup scripts\n'
docker build -q -t openssl-alpine -f ./setup-scripts/openssl/Dockerfile ./setup-scripts
docker build -q -t keytool-alpine -f ./setup-scripts/keytool/Dockerfile ./setup-scripts

# test docker image
# docker run --rm --name openssl-alpine openssl-alpine
# docker run --rm --name keytool-alpine keytool-alpine

# run setup scripts (1)
printf '\nWill run: 1.create-private-key.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/1.create-private-key.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine 2>/dev/null

# run setup scripts (2)
printf '\nWill run: 2.create-service-keypair.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/2.create-service-keypair.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine 2>/dev/null

# run setup scripts (3)
printf '\nWill run: 3.generate-self-signed-certificate.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/3.generate-self-signed-certificate.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine 2>/dev/null

# run setup scripts (4)
printf '\nWill run: 4.create-keystore.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -e ZMS_KEYSTORE_PASS=${ZMS_KEYSTORE_PASS:-athenz} \
  -e ZTS_KEYSTORE_PASS=${ZTS_KEYSTORE_PASS:-athenz} \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/4.create-keystore.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine 2>/dev/null

# run setup scripts (5)
printf '\nWill run: 5.create-truststore.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -e ZMS_TRUSTSTORE_PASS=${ZMS_TRUSTSTORE_PASS:-athenz} \
  -e ZTS_TRUSTSTORE_PASS=${ZTS_TRUSTSTORE_PASS:-athenz} \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/5.create-truststore.sh:/usr/bin/run.sh \
  --name keytool-alpine keytool-alpine 2>/dev/null

# --- [DEV env. only] prepare key and certificate pairs for ZTS self cert signer ---

# [DEV env. only] run setup scripts (6.1)
printf '\nWill run: 6.1.create-zts-cert-signer-pair.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/6.1.create-zts-cert-signer-pair.sh:/usr/bin/run.sh \
  --name openssl-alpine openssl-alpine 2>/dev/null

# [DEV env. only] run setup scripts (6.2)
printf '\nWill run: 6.2.trust-zts-cert-signer-CA.sh\n'
docker run --rm --entrypoint /usr/bin/run.sh \
  -e ZTS_TRUSTSTORE_PASS=${ZTS_TRUSTSTORE_PASS:-athenz} \
  -v `pwd`:/usr/bin/docker \
  -v `pwd`/setup-scripts/6.2.trust-zts-cert-signer-CA.sh:/usr/bin/run.sh \
  --name keytool-alpine keytool-alpine 2>/dev/null

echo 'DEV. setup DONE!'

# [for backup only] pass private key passwords to docker env.
# docker run --rm --entrypoint /usr/bin/run.sh \
#   -e ZMS_PK_PASS=${ZMS_PK_PASS:-athenz} \
#   -e ZTS_PK_PASS=${ZTS_PK_PASS:-athenz} \
#   -e UI_PK_PASS=${UI_PK_PASS:-athenz} \
