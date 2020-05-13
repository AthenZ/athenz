<a id="markdown-try-out-athenz-with-self-signed-ca-for-dev-only" name="try-out-athenz-with-self-signed-ca-for-dev-only"></a>
# Try out Athenz with self-signed CA (for dev. ONLY)

<!-- TOC -->

- [Try out Athenz with self-signed CA (for dev. ONLY)](#try-out-athenz-with-self-signed-ca-for-dev-only)
    - [Prerequisites](#prerequisites)
    - [Prepare certificates](#prepare-certificates)
    - [Overwrite env., and continue the setup](#overwrite-env-and-continue-the-setup)
    - [Appendix](#appendix)
        - [Note for mac users (not recommended)](#note-for-mac-users-not-recommended)

<!-- /TOC -->

<a id="markdown-prerequisites" name="prerequisites"></a>
## Prerequisites

All the setup commands below are expected to run inside [athenz-setup-env](../setup-scripts/Dockerfile) container.
```bash
BASE_DIR="$(git rev-parse --show-toplevel)"

docker run --rm -it \
    -v "${BASE_DIR}:/athenz" \
    --user "$(id -u):$(id -g)" \
    athenz-setup-env \
    sh
```

<a id="markdown-prepare-certificates" name="prepare-certificates"></a>
## Prepare certificates

1. set up env.
    ```bash
    BASE_DIR="$(git rev-parse --show-toplevel)"

    . "${BASE_DIR}/docker/env.sh"
    . "${DOCKER_DIR}/sample/env.dev.sh"
    ```

1. create the self-signed CAs ([create-self-signed-ca.sh](../sample/CAs/create-self-signed-ca.sh))

    ```bash
    sh "${DEV_CA_DIR}/create-self-signed-ca.sh"
    ```
    ```bash
    # verify result
    ls -l "${DEV_ATHENZ_CA_PATH}"
    ls -l "${DEV_USER_CA_PATH}"
    ls -l "${DEV_SERVICE_CA_PATH}"
    find "${DEV_CA_DIR}" -name '*_ca.pem' | xargs -I _ openssl x509 -text -in _ | grep 'Issuer: '
    ```

1. create self-signed Athenz domain admin user certificate ([create-self-signed-user-cert.sh](../sample/domain-admin/create-self-signed-user-cert.sh))

    ```bash
    # find your github ID
    curl --silent --fail --show-error https://api.github.com/users/<your github username> | grep '"id":'

    export DEV_DOMAIN_ADMIN='user.github-<your github ID>'
    # skip to use default: DEV_DOMAIN_ADMIN='user.github-7654321'
    ```
    ```bash
    sh "${DEV_DOMAIN_ADMIN_DIR}/create-self-signed-user-cert.sh"

    # openssl x509 -text -noout -in "${DEV_DOMAIN_ADMIN_CERT_PATH}" | less
    ```

1. create ZMS server certificate ([create-self-signed-certs.sh](../sample/zms/create-self-signed-certs.sh))

    ```bash
    sh "${DEV_ZMS_DIR}/create-self-signed-certs.sh"

    # openssl x509 -text -noout -in "${DEV_ZMS_CERT_PATH}" | less
    ```

1. create ZTS server certificates ([create-self-signed-certs.sh](../sample/zts/create-self-signed-certs.sh))

    ```bash
    sh "${DEV_ZTS_DIR}/create-self-signed-certs.sh"

    # openssl x509 -text -noout -in "${DEV_ZTS_CERT_PATH}" | less
    # openssl x509 -text -noout -in "${DEV_ZTS_SIGNER_CERT_PATH}" | less
    # openssl x509 -text -noout -in "${DEV_ZMS_CLIENT_CERT_PATH}" | less
    ```

<a id="markdown-overwrite-env-and-continue-the-setup" name="overwrite-env-and-continue-the-setup"></a>
## Overwrite env., and continue the setup

```bash
cat <<EOF > "${DOCKER_DIR}/setup-scripts/dev-env-exports.sh"
# CAs
export CA_DIR="${DEV_CA_DIR}"
export ATHENZ_CA_PATH="${DEV_ATHENZ_CA_PATH}"
export USER_CA_PATH="${DEV_USER_CA_PATH}"
export SERVICE_CA_PATH="${DEV_SERVICE_CA_PATH}"

# Athenz domain admin
export DOMAIN_ADMIN="${DEV_DOMAIN_ADMIN}"
export DOMAIN_ADMIN_DIR="${DEV_CA_DIR}"
export DOMAIN_ADMIN_CERT_KEY_PATH="${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}"
export DOMAIN_ADMIN_CERT_PATH="${DEV_DOMAIN_ADMIN_CERT_PATH}"

# ZMS
export PROD_ZMS_DIR="${DEV_ZMS_DIR}"
export ZMS_CERT_KEY_PATH="${DEV_ZMS_CERT_KEY_PATH}"
export ZMS_CERT_PATH="${DEV_ZMS_CERT_PATH}"

# ZTS
export PROD_ZTS_DIR="${DEV_ZTS_DIR}"
export ZTS_CERT_KEY_PATH="${DEV_ZTS_CERT_KEY_PATH}"
export ZTS_CERT_PATH="${DEV_ZTS_CERT_PATH}"
export ZTS_SIGNER_CERT_KEY_PATH="${DEV_ZTS_SIGNER_CERT_KEY_PATH}"
export ZTS_SIGNER_CERT_PATH="${DEV_ZTS_SIGNER_CERT_PATH}"
export ZMS_CLIENT_CERT_KEY_PATH="${DEV_ZMS_CLIENT_CERT_KEY_PATH}"
# export ZMS_CLIENT_CERT_PATH="${DEV_ZMS_CLIENT_CERT_PATH}"
export ZMS_CLIENT_CERT_PATH="${DEV_ZMS_CLIENT_CERT_BUNDLE_PATH}"
EOF
```

<a id="markdown-appendix" name="appendix"></a>
## Appendix

<a id="markdown-note-for-mac-users-not-recommended" name="note-for-mac-users-not-recommended"></a>
### Note for mac users (not recommended)

If you are using macOS 10.13+, the default `openssl` is `LibreSSL`, which does not support configuration using env. variables.
```bash
openssl version
# output: LibreSSL 2.6.5
```
To fix this, please install the latest `openssl`, and change the reference temporarily.
```bash
brew install openssl
alias openssl=$(brew --prefix openssl)/bin/openssl
```
