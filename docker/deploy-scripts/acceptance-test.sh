#!/usr/bin/env bash

set -eu
set -o pipefail

# to script directory
cd "$(dirname "$0")"

# import functions
. ../setup-scripts/common/color-print.sh

#################################################
### Acceptance Test
#################################################

cat <<'EOF' | colored_cat c

#################################################
### Acceptance Test
#################################################

EOF

# set up env.
BASE_DIR="$(git rev-parse --show-toplevel)"
. "${BASE_DIR}/docker/env.sh"
echo "Done loading ENV. from ${BASE_DIR}/docker/env.sh" | colored_cat p
if [ -f "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh" ]; then
    . "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh"
    echo 'NOTE: You are using the DEV settings in dev-env-exports.sh !!!' | colored_cat p
fi



### ----------------------------------------------------------------
echo 'Test preparation' | colored_cat g

echo '1. create workspace' | colored_cat y
TEST_SERVICE_DIR="${DOCKER_DIR}/sample/test_service"
mkdir -p "${TEST_SERVICE_DIR}"
cd "${TEST_SERVICE_DIR}"
tree "${TEST_SERVICE_DIR}" | colored_cat w

echo '2. prepare cnf file for creating CSR' | colored_cat y
cat > "${TEST_SERVICE_DIR}/config.cnf" <<'EOF'
CN = "Not Defined"

[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
string_mask = utf8only

[ dn ]
countryName = US
organizationName = Athenz
commonName = ${ENV::CN}

[ service_ext ]
basicConstraints = critical, CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = @service_alt_names
[ service_alt_names ]
DNS.1 = test_service.testing.dns.athenz.cloud
DNS.2 = test_service.testing.instanceid.athenz.dns.athenz.cloud

[ role_ext ]
basicConstraints = critical, CA:FALSE
extendedKeyUsage = clientAuth
subjectAltName = @role_alt_names
[ role_alt_names ]
email.1 = testing.test_service@dns.athenz.cloud
EOF
echo 'NOTE: using default prop: "athenz.zts.cert_dns_suffix=.athenz.cloud"' | colored_cat p
cat "${TEST_SERVICE_DIR}/config.cnf" | colored_cat w

echo '3. prepare credentails for `test_service`' | colored_cat y
echo '3.1. create CSR' | colored_cat y
{
    CN='testing.test_service' openssl req -nodes \
        -newkey rsa:2048 \
        -keyout "${TEST_SERVICE_DIR}/key.pem" \
        -out "${TEST_SERVICE_DIR}/csr.pem" \
        -config "${TEST_SERVICE_DIR}/config.cnf" -reqexts service_ext

    echo ''
    openssl req -text -in "${TEST_SERVICE_DIR}/csr.pem"
} | colored_cat w
echo '3.2. sign client certificate' | colored_cat y
{
    openssl x509 -req -days 3650 \
        -in "${TEST_SERVICE_DIR}/csr.pem" \
        -CA "${ZTS_SIGNER_CERT_PATH}" \
        -CAkey "${ZTS_SIGNER_CERT_KEY_PATH}" \
        -CAcreateserial \
        -extfile "${TEST_SERVICE_DIR}/config.cnf" -extensions service_ext \
        -out "${TEST_SERVICE_DIR}/cert.pem"
    cat "${ZTS_SIGNER_CERT_PATH}" >> "${TEST_SERVICE_DIR}/cert.pem"

    echo ''
    ls -l "${TEST_SERVICE_DIR}/key.pem" "${TEST_SERVICE_DIR}/cert.pem"

    echo ''
    openssl x509 -text -in "${TEST_SERVICE_DIR}/cert.pem"
} | colored_cat w
echo 'NOTE: intermediate CA is appended to cert.pem' | colored_cat p
echo '3.3. verify client certificate' | colored_cat y
{
    echo "Q" | \
    openssl s_client -connect "${ZTS_HOST}:${ZTS_PORT}" \
    -servername ${ZTS_HOST} \
    -CAfile "${ATHENZ_CA_PATH}" \
    -cert_chain "${TEST_SERVICE_DIR}/cert.pem" \
    -key "${TEST_SERVICE_DIR}/key.pem"
} | colored_cat w
echo '3.4. create public key' | colored_cat y
{
    openssl rsa -pubout -in "${TEST_SERVICE_DIR}/key.pem" -out "${TEST_SERVICE_DIR}/public.pem"
} | colored_cat w



### ----------------------------------------------------------------
echo 'ZMS acceptance test' | colored_cat g

echo '0. test using the domain admin identity (plx prepare in advance)' | colored_cat y
{
    ls -l "${DOMAIN_ADMIN_CERT_KEY_PATH}" "${DOMAIN_ADMIN_CERT_PATH}"
} | colored_cat w
alias admin_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DOMAIN_ADMIN_CERT_PATH} --silent --show-error -D header.http -o response.json"

echo '0.1. confirm `testing` domain not exist' | colored_cat p
echo 'domain:' | colored_cat p
{
    admin_curl --request GET \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
if [ "$(jq -r '.code' response.json)" == '404' ]
then
    echo '`testing` domain not exist, start test...' | colored_cat w
else
    echo '`testing` domain exist, skip test' | colored_cat r
    exit 1
fi

echo '1. create test domain' | colored_cat y
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
{
    "name": "testing",
    "adminUsers": [
        "${DOMAIN_ADMIN}"
    ]
}
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    admin_curl --request POST \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '2. create test service (PutServiceIdentity)' | colored_cat y
TEST_SERVICE_PUB_KEY="$(base64 -w 0 "${TEST_SERVICE_DIR}/public.pem" | tr '\+\=\/' '\.\-\_')"
echo 'NOTE: public key is ybase64-decoded in the request body' | colored_cat p
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
{
    "name": "testing.test_service",
    "publicKeys": [
        {
            "id": "test_public_key",
            "key": "${TEST_SERVICE_PUB_KEY}"
        }
    ]
}
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    admin_curl --request PUT \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/service/test_service" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '3. create test role (PutRole)' | colored_cat y
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
{
    "name": "testing:role.test_role",
    "members": [
        "testing.test_service"
    ]
}
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    admin_curl --request PUT \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/role/test_role" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '4. create test policy (PutPolicy)' | colored_cat y
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
{
    "name": "testing:policy.test_policy",
    "assertions": [
        {
            "role": "testing:role.test_role",
            "action": "obtain",
            "resource": "testing:treasure",
            "effect": 0
        }
    ]
}
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    admin_curl --request PUT \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/policy/test_policy" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '5. verify the created domain, service, role & policy' | colored_cat y
echo 'domain:' | colored_cat p
{
    admin_curl --request GET \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'service:' | colored_cat p
{
    admin_curl --request GET \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/service/test_service" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'role:' | colored_cat p
{
    admin_curl --request GET \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/role/test_role" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'policy:' | colored_cat p
{
    admin_curl --request GET \
        --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/domain/testing/policy/test_policy" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w

echo 'Wait for ZTS to sync...' | colored_cat p
PUB_KEY_IN_ZTS=''
until [ "${TEST_SERVICE_PUB_KEY}" == "${PUB_KEY_IN_ZTS}" ]
do
    admin_curl -X GET "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/domain/testing/service/test_service"
    jq '.' response.json | colored_cat w
    PUB_KEY_IN_ZTS="$(jq -r '.publicKeys[]? | select(.id == "test_public_key") | .key' response.json)"
    echo 'waiting 5s...'
    sleep 5s
done
echo 'ZMS and ZTS sync-ed.' | colored_cat p

### ----------------------------------------------------------------
echo 'ZTS acceptance test' | colored_cat g

echo '0. test using the `test_service` service identity signed by CA (prepared in the `Test preparation` step)' | colored_cat y
{
    ls -l "${TEST_SERVICE_DIR}/key.pem" "${TEST_SERVICE_DIR}/cert.pem"
} | colored_cat w
alias service_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${TEST_SERVICE_DIR}/key.pem --cert ${TEST_SERVICE_DIR}/cert.pem --silent --show-error -D header.http -o response.json"

echo '1. retrieve service access token (PostAccessTokenRequest)' | colored_cat y
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
grant_type=client_credentials&expires_in=86400&scope=testing:role.test_role
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    service_curl --request POST \
        --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/oauth2/token" \
        --header 'content-type: application/x-www-form-urlencoded' \
        --data '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'JWT:' | colored_cat p
{
    jq -r '.access_token' response.json | jq -R 'split(".") | .[1] | @base64d | fromjson'
} | colored_cat w

echo '2. retrieve role token (GetRoleList)' | colored_cat y
echo 'response:' | colored_cat p
{
    service_curl --request GET \
        --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/domain/testing/token?role=test_role"
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '3. retrieve signed policy (GetDomainSignedPolicyData)' | colored_cat y
echo 'response:' | colored_cat p
{
    service_curl --request GET \
        --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/domain/testing/signed_policy_data"
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '4. retrieve role certificate (PostRoleCertificateRequest)' | colored_cat y
echo '4.1. create role certificate CSR' | colored_cat y
{
    CN='testing:role.test_role' openssl req -nodes \
        -newkey rsa:2048 \
        -keyout "${TEST_SERVICE_DIR}/role_key.pem" \
        -out "${TEST_SERVICE_DIR}/role_csr.pem" \
        -config "${TEST_SERVICE_DIR}/config.cnf" -reqexts role_ext

    echo ''
    openssl req -text -in "${TEST_SERVICE_DIR}/role_csr.pem"
} | colored_cat w
echo '4.2. send role certificate request' | colored_cat y
TEST_SERVICE_ROLE_CSR=$(awk -v ORS='\\n' '1' "${TEST_SERVICE_DIR}/role_csr.pem")
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
{
    "expiryTime": 1440,
    "csr": "${TEST_SERVICE_ROLE_CSR}"
}
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    service_curl --request POST \
        --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/domain/testing/role/test_role/token" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'role certificate:' | colored_cat p
{
    jq -r '.token' response.json | openssl x509 -text
} | colored_cat w

echo 'NOTE: Save the role certificate for next test (intermediate CA is added in next step)' | colored_cat p
{
    jq -r '.token' response.json > "${TEST_SERVICE_DIR}/role_cert.pem"
    ls -l "${TEST_SERVICE_DIR}/role_cert.pem"
} | colored_cat w

echo '5. retrieve service certificate (PostInstanceRefreshRequest)' | colored_cat y
TEST_SERVICE_CSR=$(awk -v ORS='\\n' '1' "${TEST_SERVICE_DIR}/csr.pem")
cat > "${TEST_SERVICE_DIR}/body.json" <<EOF
{
    "keyId": "test_public_key",
    "csr": "${TEST_SERVICE_CSR}"
}
EOF
echo 'request body:' | colored_cat p
{
    cat body.json
} | colored_cat w
echo 'response:' | colored_cat p
{
    service_curl --request POST \
        --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/instance/testing/test_service/refresh" \
        --header 'content-type: application/json' \
        --data-binary '@body.json'
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'service certificate:' | colored_cat p
{
    jq -r '.certificate' response.json | openssl x509 -text
} | colored_cat w

echo 'NOTE: Save the service certificate for next test' | colored_cat p
{
    jq -r '.certificate' response.json > "${TEST_SERVICE_DIR}/test_service.crt"
    jq -r '.caCertBundle' response.json >> "${TEST_SERVICE_DIR}/test_service.crt"
    ls -l "${TEST_SERVICE_DIR}/test_service.crt"

    # add intermediate CA to role certificate
    jq -r '.caCertBundle' response.json >> "${TEST_SERVICE_DIR}/role_cert.pem"
} | colored_cat w
echo 'NOTE: intermediate CA is appended to test_service.crt' | colored_cat p
echo 'NOTE: intermediate CA is appended to role_cert.pem' | colored_cat p



### ----------------------------------------------------------------
echo 'Authorization acceptance test' | colored_cat g

echo '1. Using CA signed client certificate' | colored_cat y
alias authz_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${TEST_SERVICE_DIR}/key.pem --cert ${TEST_SERVICE_DIR}/cert.pem --silent --show-error -D header.http -o response.json"
{
    ls -l "${TEST_SERVICE_DIR}/key.pem" "${TEST_SERVICE_DIR}/cert.pem"

    echo ''
    alias authz_curl
} | colored_cat w
echo 'ZMS response:' | colored_cat p
{
    authz_curl --request GET --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/access/obtain/testing:treasure"
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'ZTS response:' | colored_cat p
{
    authz_curl --request GET --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/access/obtain/testing:treasure"
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '2. Using ZTS signed role certificate' | colored_cat y
alias authz_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${TEST_SERVICE_DIR}/role_key.pem --cert ${TEST_SERVICE_DIR}/role_cert.pem --silent --show-error -D header.http -o response.json"
{
    ls -l "${TEST_SERVICE_DIR}/role_key.pem" "${TEST_SERVICE_DIR}/role_cert.pem"

    echo ''
    alias authz_curl
} | colored_cat w
echo 'ZMS response (ONLY role token is allowed):' | colored_cat p
{
    authz_curl --request GET --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/access/obtain/testing:treasure"
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'ZTS response:' | colored_cat p
{
    authz_curl --request GET --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/access/obtain/testing:treasure"
    cat header.http
    jq '.' response.json
} | colored_cat w

echo '3. Using ZTS signed service certificate' | colored_cat y
alias authz_curl="curl --cacert ${ATHENZ_CA_PATH} --key ${TEST_SERVICE_DIR}/key.pem --cert ${TEST_SERVICE_DIR}/test_service.crt --silent --show-error -D header.http -o response.json"
{
    ls -l "${TEST_SERVICE_DIR}/key.pem" "${TEST_SERVICE_DIR}/test_service.crt"

    echo ''
    alias authz_curl
} | colored_cat w
echo 'ZMS response:' | colored_cat p
{
    authz_curl --request GET --url "https://${ZMS_HOST}:${ZMS_PORT}/zms/v1/access/obtain/testing:treasure"
    cat header.http
    jq '.' response.json
} | colored_cat w
echo 'ZTS response:' | colored_cat p
{
    authz_curl --request GET --url "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/access/obtain/testing:treasure"
    cat header.http
    jq '.' response.json
} | colored_cat w



### ----------------------------------------------------------------
echo 'Reset test data' | colored_cat g
. "${DOCKER_DIR}/deploy-scripts/acceptance-test-reset.sh"



### ----------------------------------------------------------------
echo 'Test done🥳' | colored_cat g
