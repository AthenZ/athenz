<a id="markdown-deploy-athenz-servers-using-helm" name="deploy-athenz-servers-using-helm"></a>
# Deploy Athenz servers using Helm

<!-- TOC -->

- [Deploy Athenz servers using Helm](#deploy-athenz-servers-using-helm)
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
    - [5. Deploy ZMS DB](#5-deploy-zms-db)
    - [6. Deploy ZMS](#6-deploy-zms)
    - [7. Register ZTS service's key to ZMS](#7-register-zts-services-key-to-zms)
    - [8. Download athenz_conf.json](#8-download-athenz_confjson)
    - [9. Deploy ZTS DB](#9-deploy-zts-db)
    - [10. Deploy ZTS](#10-deploy-zts)
  - [Metrics](#metrics)

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
export HOST_EXTERNAL_IP='172.21.97.103'
export ZMS_RELEASE_NAME='dev-zms'
export ZTS_RELEASE_NAME='dev-zts'

export ZMS_URL="https://${HOST_EXTERNAL_IP}:30007"
export ZTS_URL="https://${HOST_EXTERNAL_IP}:30008"
export ZMS_HOST="${ZMS_RELEASE_NAME}-athenz-zms.default.svc.cluster.local"
export ZTS_HOST="${ZTS_RELEASE_NAME}-athenz-zts.default.svc.cluster.local"
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
ATHENZ_TAG=1.9.6
DOCKER_REPO_NAME=wzyahoo

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

<a id="markdown-5-deploy-zms-db" name="5-deploy-zms-db"></a>
### 5. Deploy ZMS DB

```bash
# helm repo add bitnami https://charts.bitnami.com/bitnami
helm install dev-zms-db bitnami/mariadb \
  --set "rootUser.password=${ZMS_DB_ROOT_PASS}" \
  --set "db.password=${ZMS_DB_ADMIN_PASS}" \
  --set-file "initdbScripts.zms_server\.sql=${BASE_DIR}/servers/zms/schema/zms_server.sql" \
  -f "${BASE_DIR}/kubernetes/docs/sample/dev-zms-db-values.yaml"
```

```bash
# run mysql client
kubectl run dev-zms-db-mariadb-client --rm --tty -i --restart='Never' \
  --image docker.io/bitnami/mariadb:10.3.22-debian-10-r60 \
  --env "ZMS_DB_ROOT_PASS=${ZMS_DB_ROOT_PASS}" \
  --env "ZMS_DB_ADMIN_PASS=${ZMS_DB_ADMIN_PASS}" \
  --command -- bash
# prepare test SQLs
cat > /tmp/root_test.sql << 'EOF'
-- show users
SELECT user, host FROM mysql.user;

-- show grants
show grants;
EOF
cat > /tmp/zms_admin_test.sql << 'EOF'
-- show all tables
select table_schema as database_name, table_name
from information_schema.tables
where table_type = 'BASE TABLE'
and table_schema not in ('information_schema','mysql', 'performance_schema','sys')
order by database_name, table_name;

-- show grants
show grants;
EOF
# test as root user
mysql -h dev-zms-db-mariadb.default.svc.cluster.local -uroot -p"${ZMS_DB_ROOT_PASS}" < /tmp/root_test.sql
# test as zms_admin in master
mysql -h dev-zms-db-mariadb.default.svc.cluster.local -uzms_admin -p"${ZMS_DB_ADMIN_PASS}" < /tmp/zms_admin_test.sql
# test as zms_admin in slave
mysql -h dev-zms-db-mariadb-slave.default.svc.cluster.local -uzms_admin -p"${ZMS_DB_ADMIN_PASS}" < /tmp/zms_admin_test.sql
```

```bash
# debug
kubectl logs dev-zms-db-mariadb-master-0
kubectl describe pod dev-zms-db-mariadb-master-0
```

```bash
# reset
helm uninstall dev-zms-db
```

<a id="markdown-6-deploy-zms" name="6-deploy-zms"></a>
### 6. Deploy ZMS

```bash
# download chart
helm pull athenz-zms -d "${WORKSPACE}" --untar \
  --repo https://windzcuhk.github.io/athenz/kubernetes/charts

# create symbolic links
ln -sf "${ZMS_HELM_FILE}/secrets" "${WORKSPACE}/athenz-zms/files/"

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

<a id="markdown-8-download-athenz_confjson" name="8-download-athenz_confjson"></a>
### 8. Download athenz_conf.json

```bash
mkdir -p "${ZTS_HELM_FILE}/conf"
athenz-conf -c "${DEV_ATHENZ_CA_PATH}" \
  -svc-key-file "${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}" \
  -svc-cert-file "${DEV_DOMAIN_ADMIN_CERT_PATH}" \
  -o "${ZTS_HELM_FILE}/conf/athenz_conf.json" \
  -t "https://${ZTS_HOST}:8443" \
  -z "${ZMS_URL}"
sed -i '' "s,${ZMS_URL},https://${ZMS_HOST}:4443," "${ZTS_HELM_FILE}/conf/athenz_conf.json"

less "${ZTS_HELM_FILE}/conf/athenz_conf.json"
```

<a id="markdown-9-deploy-zts-db" name="9-deploy-zts-db"></a>
### 9. Deploy ZTS DB

```bash
# helm repo add bitnami https://charts.bitnami.com/bitnami
helm install dev-zts-db bitnami/mariadb \
  --set "rootUser.password=${ZTS_DB_ROOT_PASS}" \
  --set "db.password=${ZTS_DB_ADMIN_PASS}" \
  --set-file "initdbScripts.zts_server\.sql=${BASE_DIR}/servers/zts/schema/zts_server.sql" \
  -f "${BASE_DIR}/kubernetes/docs/sample/dev-zts-db-values.yaml"
```

```bash
# run mysql client
kubectl run dev-zts-db-mariadb-client --rm --tty -i --restart='Never' \
  --image docker.io/bitnami/mariadb:10.3.22-debian-10-r60 \
  --env "ZTS_DB_ROOT_PASS=${ZTS_DB_ROOT_PASS}" \
  --env "ZTS_DB_ADMIN_PASS=${ZTS_DB_ADMIN_PASS}" \
  --command -- bash
# prepare test SQLs
cat > /tmp/root_test.sql << 'EOF'
-- show users
SELECT user, host FROM mysql.user;

-- show grants
show grants;
EOF
cat > /tmp/zts_admin_test.sql << 'EOF'
-- show all tables
select table_schema as database_name, table_name
from information_schema.tables
where table_type = 'BASE TABLE'
and table_schema not in ('information_schema','mysql', 'performance_schema','sys')
order by database_name, table_name;

-- show grants
show grants;
EOF
# test as root user
mysql -h dev-zts-db-mariadb.default.svc.cluster.local -uroot -p"${ZTS_DB_ROOT_PASS}" < /tmp/root_test.sql
# test as zts_admin in master
mysql -h dev-zts-db-mariadb.default.svc.cluster.local -uzts_admin -p"${ZTS_DB_ADMIN_PASS}" < /tmp/zts_admin_test.sql
# test as zts_admin in slave
mysql -h dev-zts-db-mariadb-slave.default.svc.cluster.local -uzts_admin -p"${ZTS_DB_ADMIN_PASS}" < /tmp/zts_admin_test.sql
```

```bash
# debug
kubectl logs dev-zts-db-mariadb-master-0
kubectl describe pod dev-zts-db-mariadb-master-0
```

```bash
# reset
helm uninstall dev-zts-db
```

<a id="markdown-10-deploy-zts" name="10-deploy-zts"></a>
### 10. Deploy ZTS

```bash
# download chart
helm pull athenz-zts -d "${WORKSPACE}" --untar \
  --repo https://windzcuhk.github.io/athenz/kubernetes/charts

# create symbolic links
ln -sf "${ZTS_HELM_FILE}/conf/athenz_conf.json" "${WORKSPACE}/athenz-zts/files/conf/"
ln -sf "${ZTS_HELM_FILE}/secrets" "${WORKSPACE}/athenz-zts/files/"

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

<a id="markdown-metrics" name="metrics"></a>
## Metrics

ZMS and ZTS report Prometheus by default. You can deploy Prometheus and query their metrics as below.

```bash
helm repo add stable https://kubernetes-charts.storage.googleapis.com/
helm repo update

helm install prometheus stable/prometheus \
  --set 'alertmanager.persistentVolume.enabled=false' \
  --set 'pushgateway.persistentVolume.enabled=false' \
  --set 'server.persistentVolume.enabled=false'

kubectl get service

export POD_NAME=$(kubectl get pods --namespace default -l "app=prometheus,component=server" -o jsonpath="{.items[0].metadata.name}")
kubectl --namespace default port-forward $POD_NAME 9090

open 127.0.0.1:9090

helm delete prometheus
```
