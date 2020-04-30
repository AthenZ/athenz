<a id="markdown-acceptance-test" name="acceptance-test"></a>
# Acceptance test

<!-- TOC -->

- [Acceptance test](#acceptance-test)
    - [Prerequisites](#prerequisites)
    - [Note](#note)
    - [Setup](#setup)
    - [ZMS acceptance test](#zms-acceptance-test)
    - [ZTS acceptance test](#zts-acceptance-test)
    - [Appendix](#appendix)
        - [A. verify CA signed service certificate can access ZTS](#a-verify-ca-signed-service-certificate-can-access-zts)
        - [B. verify ZTS signed service certificate can access ZTS](#b-verify-zts-signed-service-certificate-can-access-zts)

<!-- /TOC -->

<a id="markdown-prerequisites" name="prerequisites"></a>
## Prerequisites

1. `curl 7.54.0`+

<a id="markdown-note" name="note"></a>
## Note

This document is for verifying your development in DEV or testing environment ONLY. Please you need to manaully remove the test data if you plan to run the test in production environment.

<a id="markdown-setup" name="setup"></a>
## Setup

1. create workspace
    ```bash
    # setup
    TEST_SERVICE_DIR="${DOCKER_DIR}/sample/test_service"
    mkdir -p "${TEST_SERVICE_DIR}"
    ```
    ```bash
    # create cnf (using default: athenz.zts.cert_dns_suffix=.athenz.cloud)
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

    # cat "${TEST_SERVICE_DIR}/config.cnf"
    ```

1. create client certificate of `test_service` for authentication
    ```bash
    # create CSR
    CN='testing.test_service' openssl req -nodes \
        -newkey rsa:2048 \
        -keyout "${TEST_SERVICE_DIR}/key.pem" \
        -out "${TEST_SERVICE_DIR}/csr.pem" \
        -config "${TEST_SERVICE_DIR}/config.cnf" -reqexts service_ext

    # openssl req -text -in "${TEST_SERVICE_DIR}/csr.pem"
    ```
    ```bash
    # sign request
    openssl x509 -req -days 3650 \
        -in "${TEST_SERVICE_DIR}/csr.pem" \
        -CA "${ZTS_SIGNER_CERT_PATH}" \
        -CAkey "${ZTS_SIGNER_CERT_KEY_PATH}" \
        -CAcreateserial \
        -extfile "${TEST_SERVICE_DIR}/config.cnf" -extensions service_ext \
        -out "${TEST_SERVICE_DIR}/cert.pem"
    # append intermediate certificate
    cat "${ZTS_SIGNER_CERT_PATH}" >> "${TEST_SERVICE_DIR}/cert.pem"

    # openssl x509 -text -in "${TEST_SERVICE_DIR}/cert.pem"
    # cat "${TEST_SERVICE_DIR}/key.pem"
    # cat "${TEST_SERVICE_DIR}/cert.pem"
    ```
    ```bash
    # verify client certificate
    openssl s_client -connect "${ZTS_HOST}:${ZTS_PORT}" \
        -CAfile "${ATHENZ_CA_PATH}" \
        -cert "${TEST_SERVICE_DIR}/cert.pem" \
        -key "${TEST_SERVICE_DIR}/key.pem" 2> /dev/null | grep 'Verify return code'
    ```

1. create `test_service` public key
    ```bash
    # create public key
    openssl rsa -pubout -in "${TEST_SERVICE_DIR}/key.pem" -out "${TEST_SERVICE_DIR}/public.pem"
    ```

<a id="markdown-zms-acceptance-test" name="zms-acceptance-test"></a>
## ZMS acceptance test

1. ZMS acceptance test
    1. using domain admin identity
        ```bash
        cat "${DOMAIN_ADMIN_CERT_KEY_PATH}"
        cat "${DOMAIN_ADMIN_CERT_PATH}"
        ```
    1. get encoded public key
        ```bash
        # encode public key in ybase64
        base64 -w 0 "${TEST_SERVICE_DIR}/public.pem" | tr '\+\=\/' '\.\-\_'; echo '';
        ```
    1. update the values in ([zms-acceptance-test.http](../sample/http/zms-acceptance-test.http))
        1. encoded public key => `publicKeys`
        1. `user.github-<your github ID>` => `adminUsers`
    1. send the requests to:
        1. create test domain
        1. create test service
        1. create test role
        1. create test policy

<a id="markdown-zts-acceptance-test" name="zts-acceptance-test"></a>
## ZTS acceptance test

1. ZTS acceptance test
    1. using `testing.test_service` identity
        ```bash
        cat "${TEST_SERVICE_DIR}/key.pem"
        cat "${TEST_SERVICE_DIR}/cert.pem"
        ```
    1. get CSR for service certificate
        ```bash
        # print csr
        cat "${TEST_SERVICE_DIR}/csr.pem" | awk -v ORS='\\n' '1'
        ```
    1. get CSR for role certificate
        ```bash
        # create role CSR
        CN='testing:role.test_role' openssl req -nodes \
            -newkey rsa:2048 \
            -keyout "${TEST_SERVICE_DIR}/role_key.pem" \
            -out "${TEST_SERVICE_DIR}/role_csr.pem" \
            -config "${TEST_SERVICE_DIR}/config.cnf" -reqexts role_ext
        # openssl req -text -in "${TEST_SERVICE_DIR}/role_csr.pem"

        # print csr
        cat "${TEST_SERVICE_DIR}/role_csr.pem" | awk -v ORS='\\n' '1'
        ```
    1. update the CSR values in ([zts-acceptance-test.http](../sample/http/zts-acceptance-test.http))
    1. send the requests and get the following ZTS signed objects:
        1. service certificate
        1. role certificate
        1. access token
        1. signed policy
        1. ~~role token~~
    1. verify the ZTS signed certificate ([Appendix](./acceptance-test.md#b-verify-zts-signed-service-certificate-can-access-zts))

<a id="markdown-appendix" name="appendix"></a>
## Appendix

<a id="markdown-a-verify-ca-signed-service-certificate-can-access-zts" name="a-verify-ca-signed-service-certificate-can-access-zts"></a>
### A. verify CA signed service certificate can access ZTS

```bash
curl --cacert "${ATHENZ_CA_PATH}" \
    --cert "${TEST_SERVICE_DIR}/cert.pem" \
    --key "${TEST_SERVICE_DIR}/key.pem" \
    "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/access/obtain/testing:treasure"
### P.S. curl 7.29.0 does not support client certificate chain, please update to latest version

# use docker as an alternative
docker run --rm --entrypoint curl \
    --user "$(id -u):$(id -g)" \
    -v "${ATHENZ_CA_PATH}:/etc/certs/ca.pem" \
    -v "${TEST_SERVICE_DIR}/cert.pem:/etc/certs/cert.pem" \
    -v "${TEST_SERVICE_DIR}/key.pem:/etc/certs/key.pem" \
    --network="${DOCKER_NETWORK}" \
    --name athenz-curl appropriate/curl \
    --silent --fail --show-error \
    --cacert "/etc/certs/ca.pem" \
    --cert "/etc/certs/cert.pem" \
    --key "/etc/certs/key.pem" \
    "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/access/obtain/testing:treasure"
```
```bash
# expected output
{"granted":true}
```

<a id="markdown-b-verify-zts-signed-service-certificate-can-access-zts" name="b-verify-zts-signed-service-certificate-can-access-zts"></a>
### B. verify ZTS signed service certificate can access ZTS

```bash
# sample ZTS output (formatted)
HTTP/1.1 200 OK
Connection: close
Host: athenz-zts-server
Content-Type: application/json
Content-Length: 4124

{
    "name": "testing.test_service",
    "certificate": "-----BEGIN CERTIFICATE-----\nMIIFtDCCA5ygAw...\n-----END CERTIFICATE-----\n",
    "caCertBundle": "-----BEGIN CERTIFICATE-----\nMIIFdjCCA16gAw...\n-----END CERTIFICATE-----\n"
}
```
```bash
# replace the following
CERTIFICATE='-----BEGIN CERTIFICATE-----\nMIIFtDCCA5ygAw...\n-----END CERTIFICATE-----\n'
CA_CERT_BUNDLE='-----BEGIN CERTIFICATE-----\nMIIFdjCCA16gAw...\n-----END CERTIFICATE-----\n'
# concatenate the certificates
echo -e "${CERTIFICATE}" | cat > /tmp/cert.pem
echo -e "${CA_CERT_BUNDLE}" | cat >> /tmp/cert.pem

# openssl x509 -text -in /tmp/cert.pem
# less /tmp/cert.pem
# rm /tmp/cert.pem
```
```bash
# access ZTS
curl --cacert "${ATHENZ_CA_PATH}" \
    --cert "/tmp/cert.pem" \
    --key "${TEST_SERVICE_DIR}/key.pem" \
    "https://${ZTS_HOST}:${ZTS_PORT}/zts/v1/access/obtain/testing:treasure"
```
```bash
# expected output
{"granted":true}
```
