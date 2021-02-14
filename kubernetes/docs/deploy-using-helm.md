# Deploy Athenz servers using Helm

<!-- TOC depthFrom:2 updateOnSave:true -->

- [NOTE](#note)
- [Prerequisites](#prerequisites)
- [Steps](#steps)
  - [0. Set up ENV for the following steps](#0-set-up-env-for-the-following-steps)
  - [1. Prepare the docker images](#1-prepare-the-docker-images)
    - [1.1. build the Athenz docker images](#11-build-the-athenz-docker-images)
    - [1.2. push the Athenz docker images to your own repo](#12-push-the-athenz-docker-images-to-your-own-repo)
  - [2. Define trust of your deployment](#2-define-trust-of-your-deployment)
  - [3. Prepare ZMS credentials](#3-prepare-zms-credentials)
  - [4. Prepare ZTS credentials](#4-prepare-zts-credentials)
  - [5. Setup ZMS DB](#5-setup-zms-db)
  - [6. Deploy ZMS](#6-deploy-zms)
  - [7. Register ZTS service's key to ZMS](#7-register-zts-services-key-to-zms)
  - [8. Generate athenz_conf.json](#8-generate-athenz_confjson)
  - [9. Setup ZTS DB](#9-setup-zts-db)
  - [10. Deploy ZTS](#10-deploy-zts)

<!-- /TOC -->

<a id="markdown-note" name="note"></a>
## NOTE

1. This procedure is for DEV env. ONLY. Please review every steps with your security policies before deploying to the production environment.
1. This procedure works on `default` namespace ONLY.

<a id="markdown-prerequisites" name="prerequisites"></a>
## Prerequisites

1. `helm`
1. `kubectl`

<a id="markdown-steps" name="steps"></a>
## Steps

<a id="markdown-0-set-up-env-for-the-following-steps" name="0-set-up-env-for-the-following-steps"></a>
### 0. Set up ENV for the following steps

**Extra prerequisites**: `bash`, `python`, `openssl`, `curl`

```bash
# default values
export BASE_DIR="$(git rev-parse --show-toplevel)"
. "${BASE_DIR}/docker/env.sh"
. "${DOCKER_DIR}/sample/env.dev.sh"

export WORKSPACE="${BASE_DIR}/kubernetes/docs/sample"
export ZMS_HELM_FILE="${BASE_DIR}/kubernetes/docs/sample/zms-files"
export ZTS_HELM_FILE="${BASE_DIR}/kubernetes/docs/sample/zts-files"

relpath() {
  python -c "import os.path,sys;print(os.path.relpath(sys.argv[1],sys.argv[2]))" "$1" "$2"
}
create_rel_link() {
  ln -sf "$(relpath "$1" "$2")" "$2"
}

alias admin_curl="curl --silent --fail --show-error --cacert ${DEV_ATHENZ_CA_PATH} --key ${DEV_DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DEV_DOMAIN_ADMIN_CERT_PATH}"
```

```bash
# variables
export DEV_DOMAIN_ADMIN='user.github-1234567'
export HOST_EXTERNAL_IP='127.0.0.1'
export ZMS_RELEASE_NAME='dev-zms'
export ZTS_RELEASE_NAME='dev-zts'

export ZMS_URL="https://${HOST_EXTERNAL_IP}:8000"
export ZTS_URL="https://${HOST_EXTERNAL_IP}:8001"
export ZMS_HOST="${ZMS_RELEASE_NAME}-athenz-zms.default.svc.cluster.local"
export ZTS_HOST="${ZTS_RELEASE_NAME}-athenz-zts.default.svc.cluster.local"

export ZMS_DB_ADMIN_PASS=<your-password>
export ZMS_RODB_ADMIN_PASS=<your-password>
export ZTS_DB_ADMIN_PASS=<your-password>
```

<a id="markdown-1-prepare-the-docker-images" name="1-prepare-the-docker-images"></a>
### 1. Prepare the docker images

<a id="markdown-11-build-the-athenz-docker-images" name="11-build-the-athenz-docker-images"></a>
#### 1.1. build the Athenz docker images

To build the Athenz docker image, plx refer to [build-athenz](../../docker/README.md#build-athenz).

<a id="markdown-12-push-the-athenz-docker-images-to-your-own-repo" name="12-push-the-athenz-docker-images-to-your-own-repo"></a>
#### 1.2. push the Athenz docker images to your own repo

```bash
# variables
ATHENZ_TAG=1.9.27
DOCKER_REPO_NAME=athenz

# tag
docker tag athenz-zms-server "${DOCKER_REPO_NAME}/athenz-zms-server:${ATHENZ_TAG}"
docker tag athenz-zts-server "${DOCKER_REPO_NAME}/athenz-zts-server:${ATHENZ_TAG}"
docker tag athenz-setup-env "${DOCKER_REPO_NAME}/athenz-setup-env:${ATHENZ_TAG}"

# push
docker push "${DOCKER_REPO_NAME}/athenz-zms-server:${ATHENZ_TAG}"
docker push "${DOCKER_REPO_NAME}/athenz-zts-server:${ATHENZ_TAG}"
docker push "${DOCKER_REPO_NAME}/athenz-setup-env:${ATHENZ_TAG}"
```

<a id="markdown-2-define-trust-of-your-deployment" name="2-define-trust-of-your-deployment"></a>
### 2. Define trust of your deployment

For details, please refer to [Trust in Athenz](../../docker/docs/Athenz-bootstrap.md#trust-in-athenz).

```bash
# create CA certificates
sh "${DEV_CA_DIR}/create-self-signed-ca.sh"
find "${DEV_CA_DIR}" -name '*_ca.pem' | xargs -I _ openssl x509 -text -in _ | grep 'Issuer: '

# create domain admin certificate
sh "${DEV_DOMAIN_ADMIN_DIR}/create-self-signed-user-cert.sh"
openssl x509 -text -noout -in "${DEV_DOMAIN_ADMIN_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
```

<a id="markdown-3-prepare-zms-credentials" name="3-prepare-zms-credentials"></a>
### 3. Prepare ZMS credentials

For details, please refer to [zms-setup](../../docker/docs/zms-setup.md#target).

```bash
# create ZMS certificates
sh "${DEV_ZMS_DIR}/create-self-signed-certs.sh"
openssl x509 -text -noout -in "${DEV_ZMS_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'

# create ZMS private key
openssl ecparam -noout -genkey -name prime256v1 -out "${ZMS_PRIVATE_KEY_PATH}"
openssl ec -pubout -in "${ZMS_PRIVATE_KEY_PATH}" -out "${ZMS_PUBLIC_KEY_PATH}"

# create symbolic links for helm deployment
mkdir -p "${ZMS_HELM_FILE}/secrets/tls/CAs"
# === CAs ===
create_rel_link "${DEV_CA_DIR}/athenz_ca.pem" "${ZMS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/service_ca.pem" "${ZMS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/user_ca.pem" "${ZMS_HELM_FILE}/secrets/tls/CAs"
# === certificates ===
create_rel_link "${DEV_ZMS_CERT_PATH}" "${ZMS_HELM_FILE}/secrets/tls"
create_rel_link "${DEV_ZMS_CERT_KEY_PATH}" "${ZMS_HELM_FILE}/secrets/tls"
# === private key ===
create_rel_link "${ZMS_PRIVATE_KEY_PATH}" "${ZMS_HELM_FILE}/secrets"
```

<a id="markdown-4-prepare-zts-credentials" name="4-prepare-zts-credentials"></a>
### 4. Prepare ZTS credentials

For details, please refer to [zts-setup](../../docker/docs/zts-setup.md#target).

```bash
# create ZTS certificates
sh "${DEV_ZTS_DIR}/create-self-signed-certs.sh"
openssl x509 -text -noout -in "${DEV_ZTS_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
openssl x509 -text -noout -in "${DEV_ZTS_SIGNER_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
openssl x509 -text -noout -in "${DEV_ZMS_CLIENT_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'

# create ZTS private key
openssl ecparam -noout -genkey -name prime256v1 -out "${ZTS_PRIVATE_KEY_PATH}"
openssl ec -pubout -in "${ZTS_PRIVATE_KEY_PATH}" -out "${ZTS_PUBLIC_KEY_PATH}"

# create symbolic links for helm deployment
mkdir -p "${ZTS_HELM_FILE}/secrets/tls/CAs"
mkdir -p "${ZTS_HELM_FILE}/secrets/signer"
mkdir -p "${ZTS_HELM_FILE}/secrets/zms-client"
# === CAs ===
create_rel_link "${DEV_CA_DIR}/athenz_ca.pem" "${ZTS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/service_ca.pem" "${ZTS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/user_ca.pem" "${ZTS_HELM_FILE}/secrets/tls/CAs"
# === certificates ===
create_rel_link "${DEV_ZTS_CERT_PATH}" "${ZTS_HELM_FILE}/secrets/tls"
create_rel_link "${DEV_ZTS_CERT_KEY_PATH}" "${ZTS_HELM_FILE}/secrets/tls"
# === signer ===
create_rel_link "${DEV_ZTS_SIGNER_CERT_PATH}" "${ZTS_HELM_FILE}/secrets/signer"
create_rel_link "${DEV_ZTS_SIGNER_CERT_KEY_PATH}" "${ZTS_HELM_FILE}/secrets/signer"
# === zms-client ===
create_rel_link "${DEV_ZMS_CLIENT_CERT_BUNDLE_PATH}" "${ZTS_HELM_FILE}/secrets/zms-client"
create_rel_link "${DEV_ZMS_CLIENT_CERT_KEY_PATH}" "${ZTS_HELM_FILE}/secrets/zms-client"
# === private key ===
create_rel_link "${ZTS_PRIVATE_KEY_PATH}" "${ZTS_HELM_FILE}/secrets"
```

<a id="markdown-5-setup-zms-db" name="5-setup-zms-db"></a>
### 5. Setup ZMS DB

To setup a database, please refer to [this page](https://AthenZ.github.io/athenz/setup_zms_prod/#mysql-server).
- Schema SQL file: `curl "https://raw.githubusercontent.com/AthenZ/athenz/v${ATHENZ_TAG}/servers/zms/schema/zms_server.sql"`
- Database name: `zms_server`
- Database user: `zms_admin`

```bash
# verify DB setup

mysql -u root
# mysql> show grants;
# mysql> select user, host from mysql.user;

mysql -u zms_admin
# mysql> show grants;
# mysql> show tables in zms_server;
```

Update corresponding ZMS properties: update after `helm pull` (see below)

<a id="markdown-6-deploy-zms" name="6-deploy-zms"></a>
### 6. Deploy ZMS

```bash
# download chart
helm pull athenz-zms -d "${WORKSPACE}" --untar \
  --repo "https://raw.githubusercontent.com/AthenZ/athenz/v${ATHENZ_TAG}/kubernetes/charts"

# update corresponding ZMS properties
vi "${WORKSPACE}/athenz-zms/files/conf/zms.properties"

# update the following property
# athenz.zms.jdbc_store=jdbc:mysql://<your_db_host>:3306/zms_server
# athenz.zms.jdbc_ro_store=jdbc:mysql://<your_rodb_host>:3306/zms_server

# create symbolic links
ln -sf "${ZMS_HELM_FILE}/secrets" "${WORKSPACE}/athenz-zms/files/"

# confirm your docker image repository, you may need to update this value to your own repository
grep -B 1 -A 6 'registry: ' "${BASE_DIR}/kubernetes/docs/sample/dev-zms-values.yaml"

# deploy ZMS
# helm upgrade --install "${ZMS_RELEASE_NAME}" "${BASE_DIR}/kubernetes/charts/athenz-zms" \
helm upgrade --install "${ZMS_RELEASE_NAME}" "${WORKSPACE}/athenz-zms" \
  --set "password.jdbc=${ZMS_DB_ADMIN_PASS}" \
  --set "password.jdbcRo=${ZMS_RODB_ADMIN_PASS}" \
  --set "password.keystore=${ZMS_KEYSTORE_PASS}" \
  --set "password.truststore=${ZMS_TRUSTSTORE_PASS}" \
  -f "${BASE_DIR}/kubernetes/docs/sample/dev-zms-values.yaml"
```

```bash
# use kubectl to forward request to ZMS
while true; do kubectl port-forward --address 0.0.0.0 "$(kubectl get pod -l app=athenz-zms -o jsonpath='{.items[0].metadata.name}')" 8000:4443; done
```

```bash
# verify
# === ZMS status ===
admin_curl --request GET --url "${ZMS_URL}/zms/v1/status" | jq
# === ZMS service ===
admin_curl --request GET --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms" | jq
# === ZMS principal ===
admin_curl --request GET --url "${ZMS_URL}/zms/v1/principal" | jq '.service'
```

```bash
# debug
kubectl describe $(kubectl get pod -l "app=athenz-zms" -o name)
kubectl logs --tail=50 --all-containers $(kubectl get pod -l "app=athenz-zms" -o name) --timestamps=true | sort
kubectl get events --sort-by=.metadata.creationTimestamp

kubectl exec -it $(kubectl get pod -l "app=athenz-zms" -o name) -- /bin/sh
less /opt/athenz/zms/logs/zms_server/server.log
# grep "ERROR" /opt/athenz/zms/logs/zms_server/server.log
# ls -l -R /opt/athenz/zms/var
# wget -qO- --no-check-certificate https://localhost:4443/zms/v1/status
# wget -qO- http://localhost:8181/metrics
```

```bash
# reset
rm -rf "${WORKSPACE}/athenz-zms"*
helm uninstall "${ZMS_RELEASE_NAME}"
```

<a id="markdown-7-register-zts-services-key-to-zms" name="7-register-zts-services-key-to-zms"></a>
### 7. Register ZTS service's key to ZMS

```bash
# register ZTS service's key

# === for linux ===
# ENCODED_ZTS_PUBLIC_KEY="$(cat "${ZTS_PUBLIC_KEY_PATH}" | base64 -w 0 | tr '\+\=\/' '\.\-\_')"

# === for mac ===
ENCODED_ZTS_PUBLIC_KEY="$(cat "${ZTS_PUBLIC_KEY_PATH}" | base64 -b 0 | tr '\+\=\/' '\.\-\_')"
DATA='{"name": "sys.auth.zts","publicKeys": [{"id": "0","key": "'"${ENCODED_ZTS_PUBLIC_KEY}"'"}]}'

# delete ZTS service
admin_curl --request DELETE -D - --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zts"
# create ZTS service
admin_curl --request PUT -D - --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zts" \
  --header 'content-type: application/json' \
  --data "${DATA}"
# verify
admin_curl --request GET --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zts" | jq
```

```bash
# [optional] reset ZMS service's key

# === for linux ===
# ENCODED_ZMS_PUBLIC_KEY="$(cat "${ZMS_PUBLIC_KEY_PATH}" | base64 -w 0 | tr '\+\=\/' '\.\-\_')"

# === for mac ===
ENCODED_ZMS_PUBLIC_KEY="$(cat "${ZMS_PUBLIC_KEY_PATH}" | base64 -b 0 | tr '\+\=\/' '\.\-\_')"
DATA='{"name": "sys.auth.zms","publicKeys": [{"id": "0","key": "'"${ENCODED_ZMS_PUBLIC_KEY}"'"}]}'

admin_curl --request DELETE -D - --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms"
admin_curl --request PUT -D - --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms" \
  --header 'content-type: application/json' \
  --data "${DATA}"
# verify
admin_curl --request GET --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms" | jq
```

<a id="markdown-8-generate-athenz_confjson" name="8-generate-athenz_confjson"></a>
### 8. Generate athenz_conf.json
Download athenz-utils-${ATHENZ_TAG}-bin.tar.gz from [Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils)
(click on the `Browse` button, choose the latest version directory).

```bash
tar xvfz athenz-utils-${ATHENZ_TAG}-bin.tar.gz
cp athenz-utils-${ATHENZ_TAG}/bin/<PLATFORM>/athenz-conf ./

mkdir -p "${ZTS_HELM_FILE}/conf"
./athenz-conf -c "${DEV_ATHENZ_CA_PATH}" \
  -svc-key-file "${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}" \
  -svc-cert-file "${DEV_DOMAIN_ADMIN_CERT_PATH}" \
  -o "${ZTS_HELM_FILE}/conf/athenz_conf.json" \
  -t "https://${ZTS_HOST}:8443" \
  -z "${ZMS_URL}"
sed -i '' "s,${ZMS_URL},https://${ZMS_HOST}:4443," "${ZTS_HELM_FILE}/conf/athenz_conf.json"

less "${ZTS_HELM_FILE}/conf/athenz_conf.json"
```

<a id="markdown-9-setup-zts-db" name="9-setup-zts-db"></a>
### 9. Setup ZTS DB
To setup a database, please refer to [this page](https://yahoo.github.io/athenz/setup_zms_prod/#mysql-server). The differences between ZMS and ZTS are:
- Schema SQL file: `curl "https://raw.githubusercontent.com/AthenZ/athenz/v${ATHENZ_TAG}/servers/zts/schema/zts_server.sql"`
- Database name: `zts_store`
- Database user: `zts_admin`

```bash
# verify DB setup

mysql -u root
# mysql> show grants;
# mysql> select user, host from mysql.user;

mysql -u zts_admin
# mysql> show grants;
# mysql> show tables in zts_store;
```

Update corresponding ZTS properties: update after `helm pull` (see below)

<a id="markdown-10-deploy-zts" name="10-deploy-zts"></a>
### 10. Deploy ZTS

```bash
# download chart
helm pull athenz-zts -d "${WORKSPACE}" --untar \
  --repo "https://raw.githubusercontent.com/AthenZ/athenz/v${ATHENZ_TAG}/kubernetes/charts"

# update corresponding ZTS properties
vi "${WORKSPACE}/athenz-zts/files/conf/zts.properties"

# update the following property
# athenz.zts.cert_jdbc_store=jdbc:mysql://<your_db_host>:3306/zts_store

# create symbolic links
ln -sf "${ZTS_HELM_FILE}/conf/athenz_conf.json" "${WORKSPACE}/athenz-zts/files/conf/"
ln -sf "${ZTS_HELM_FILE}/secrets" "${WORKSPACE}/athenz-zts/files/"

# confirm your docker image repository, you may need to update this value to your own repository
grep -B 1 -A 6 'registry: ' "${BASE_DIR}/kubernetes/docs/sample/dev-zts-values.yaml"

# deploy ZTS
# helm upgrade --install "${ZTS_RELEASE_NAME}" "${BASE_DIR}/kubernetes/charts/athenz-zts" \
helm upgrade --install "${ZTS_RELEASE_NAME}" "${WORKSPACE}/athenz-zts" \
  --set "password.jdbc=${ZTS_DB_ADMIN_PASS}" \
  --set "password.keystore=${ZTS_KEYSTORE_PASS}" \
  --set "password.truststore=${ZTS_TRUSTSTORE_PASS}" \
  --set "password.signerKeystore=${ZTS_SIGNER_KEYSTORE_PASS}" \
  --set "password.signerTruststore=${ZTS_SIGNER_TRUSTSTORE_PASS}" \
  --set "password.zmsClientKeystore=${ZMS_CLIENT_KEYSTORE_PASS}" \
  --set "password.zmsClientTruststore=${ZMS_CLIENT_TRUSTSTORE_PASS}" \
  -f "${BASE_DIR}/kubernetes/docs/sample/dev-zts-values.yaml"
```

```bash
# use kubectl to forward request to ZTS
while true; do kubectl port-forward --address 0.0.0.0 "$(kubectl get pod -l app=athenz-zts -o jsonpath='{.items[0].metadata.name}')" 8001:8443; done
```

```bash
# verify
# === ZTS status ===
admin_curl --request GET --url "${ZTS_URL}/zts/v1/status" | jq
# === ZTS service ===
admin_curl --request GET --url "${ZTS_URL}/zts/v1/domain/sys.auth/service/zts" | jq
# === ZTS role token ===
admin_curl --request GET --url "${ZTS_URL}/zts/v1/domain/sys.auth/token?role=admin" | jq '.token'
```

```bash
# debug
kubectl describe $(kubectl get pod -l "app=athenz-zts" -o name)
kubectl logs --tail=100 --all-containers $(kubectl get pod -l "app=athenz-zts" -o name) --timestamps=true | sort
kubectl get events --sort-by=.metadata.creationTimestamp

kubectl exec -it $(kubectl get pod -l "app=athenz-zts" -o name) -- /bin/sh
less /opt/athenz/zts/logs/zts_server/server.log
# grep "ERROR" /opt/athenz/zts/logs/zts_server/server.log
# ls -l -R /opt/athenz/zts/var
# wget -qO- --no-check-certificate https://localhost:8443/zts/v1/status
# wget -qO- http://localhost:8181/metrics
```

```bash
# reset
rm -rf "${WORKSPACE}/athenz-zts"*
helm uninstall "${ZTS_RELEASE_NAME}"
```
