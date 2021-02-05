#!/bin/sh

# to setup-scripts directory
cd "$(dirname "$0")"

# import functions
. ../common/color-print.sh
. ../common/local-env-setup.sh

cat <<'EOF' | colored_cat c

#################################################
### obtain x.509 certificate identity
#################################################

EOF

echo 'Get identity certificate for example-service from ZTS using ZTS as a provider' | colored_cat g

until test -e "${BASE_DIR}/docker/sample/example-service/athenz.example-service.cert.pem" ;
do
  zts-svccert -domain athenz -service example-service \
      -private-key "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.key.pem -key-version 0 -zts "${ZTS_URL}"/zts/v1 \
      -dns-domain zts.athenz.cloud -cert-file "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.cert.pem \
      -cacert "${ATHENZ_CA_PATH}" -provider sys.auth.zts -instance instance123
  echo "waiting for 10s for ZTS to get provider authorization" | colored_cat y
  sleep 10
done

echo 'Verify cert CN'
openssl x509 -in "${BASE_DIR}"/docker/sample/example-service/athenz.example-service.cert.pem -noout -subject

echo ''