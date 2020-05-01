
<a id="markdown-helm" name="helm"></a>
# helm

<!-- TOC -->

- [helm](#helm)
  - [concerns](#concerns)
  - [preparation](#preparation)
  - [run helm](#run-helm)
- [athenz_conf.json](#athenz_confjson)
- [register ZTS public key](#register-zts-public-key)
- [setup](#setup)
  - [1. prepare config files](#1-prepare-config-files)
    - [0. setup ENV](#0-setup-env)
    - [1. create certificates](#1-create-certificates)
    - [2. create private keys](#2-create-private-keys)
    - [3. link files to helm](#3-link-files-to-helm)
    - [4. register ZTS public key](#4-register-zts-public-key)

<!-- /TOC -->

<a id="markdown-concerns" name="concerns"></a>
## concerns

- [concerns](./concerns.md)

<a id="markdown-preparation" name="preparation"></a>
## preparation

Generate the certificates (you can copy from `./docker/sample`)
```bash
$ tree ./k8s/athenz-zms/files
```


<a id="markdown-run-helm" name="run-helm"></a>
## run helm

```bash
BASE_DIR="`git rev-parse --show-toplevel`"
cd ${BASE_DIR}/docker

# download dependency (exec. once)
helm dependency update ./k8s/athenz-zms
helm lint ./k8s/athenz-zms

# dry run
helm upgrade --install wzzms --namespace default ./k8s/athenz-zms -f ./k8s/athenz-zms/my-values.yaml --dry-run --debug > ./k8s/zms_gen.yaml
helm upgrade --install wzzts --namespace default ./k8s/athenz-zts -f ./k8s/athenz-zts/my-values.yaml --dry-run --debug > ./k8s/zts_gen.yaml


# install
helm upgrade --install wzzms --namespace default ./k8s/athenz-zms -f ./k8s/athenz-zms/my-values.yaml
helm upgrade --install wzzts --namespace default ./k8s/athenz-zts -f ./k8s/athenz-zts/my-values.yaml
# helm upgrade --install wzzms --namespace default --values <values file> ./k8s/athenz-zms

# uninstall
helm delete --namespace default wzzms
helm delete --namespace default wzzts
```

```bash
# debug ZMS
kubectl describe $(kubectl get pod -l "app=athenz-zms" -o name)
kubectl logs --tail=30 --all-containers $(kubectl get pod -l "app=athenz-zms" -o name)
kubectl exec -it $(kubectl get pod -l "app=athenz-zms" -o name) -- /bin/sh
less /opt/athenz/zms/logs/zms_server/server.log
# grep "ERROR" /opt/athenz/zms/logs/zms_server/server.log
# ls -l -R /opt/athenz/zms/var
# wget localhost:8181/metrics

# debug ZTS
kubectl describe $(kubectl get pod -l "app=athenz-zts" -o name)
kubectl logs --tail=30 --all-containers $(kubectl get pod -l "app=athenz-zts" -o name)
kubectl exec -it $(kubectl get pod -l "app=athenz-zts" -o name) -- /bin/sh
less /opt/athenz/zts/logs/zts_server/server.log
# grep "ERROR" /opt/athenz/zms/logs/zms_server/server.log
# ls -l -R /opt/athenz/zms/var
# wget localhost:8181/metrics

# restart ZMS
kubectl delete $(kubectl get pod -l "app=athenz-zms" -o name)

# kubectl run zts-setup --rm --tty -i --restart='Never' --image docker.io/wzyahoo/athenz-setup-env:latest --namespace default --command -- sh
```
```bash
# debug DB
kubectl exec -it wzzms-zms-db-master-0 -- /bin/sh
kubectl logs wzzms-zms-db-master-0
```





<a id="markdown-setup" name="setup"></a>
# setup

<a id="markdown-1-prepare-config-files" name="1-prepare-config-files"></a>
## 1. prepare config files

<a id="markdown-0-setup-env" name="0-setup-env"></a>
### 0. setup ENV

```bash
### ENV ###
export ZMS_HOST='wzzms-athenz-zms.default.svc.cluster.local'
export ZTS_HOST='wzzts-athenz-zts.default.svc.cluster.local'
export HOST_EXTERNAL_IP='172.21.97.103'
export DEV_DOMAIN_ADMIN='user.github-1234567'

export BASE_DIR="$(git rev-parse --show-toplevel)"
. "${BASE_DIR}/docker/env.sh"
. "${DOCKER_DIR}/sample/env.dev.sh"
```
```bash
### admin_curl ###
alias admin_curl="curl --silent --fail --show-error --cacert ${DEV_ATHENZ_CA_PATH} --key ${DEV_DOMAIN_ADMIN_CERT_KEY_PATH} --cert ${DEV_DOMAIN_ADMIN_CERT_PATH}"

export ZMS_URL='https://172.21.97.103:30007'
export ZTS_URL='https://172.21.97.103:30008'
export ZMS_HELM_FILE="${BASE_DIR}/kubernetes/charts/athenz-zms/files"
export ZTS_HELM_FILE="${BASE_DIR}/kubernetes/charts/athenz-zts/files"
```

<a id="markdown-1-create-certificates" name="1-create-certificates"></a>
### 1. create certificates

```bash
sh "${DEV_CA_DIR}/create-self-signed-ca.sh"
find "${DEV_CA_DIR}" -name '*_ca.pem' | xargs -I _ openssl x509 -text -in _ | grep 'Issuer: '
#CA
sh "${DEV_DOMAIN_ADMIN_DIR}/create-self-signed-user-cert.sh"
openssl x509 -text -noout -in "${DEV_DOMAIN_ADMIN_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
# ZMS
sh "${DEV_ZMS_DIR}/create-self-signed-certs.sh"
openssl x509 -text -noout -in "${DEV_ZMS_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
# ZTS
sh "${DEV_ZTS_DIR}/create-self-signed-certs.sh"
openssl x509 -text -noout -in "${DEV_ZTS_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
openssl x509 -text -noout -in "${DEV_ZTS_SIGNER_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
openssl x509 -text -noout -in "${DEV_ZMS_CLIENT_CERT_PATH}" | grep -E 'Issuer:|Subject:|DNS:'
```


<a id="markdown-2-create-private-keys" name="2-create-private-keys"></a>
### 2. create private keys

```bash
# ZMS
openssl ecparam -noout -genkey -name prime256v1 -out "${ZMS_PRIVATE_KEY_PATH}"
openssl ec -pubout -in "${ZMS_PRIVATE_KEY_PATH}" -out "${ZMS_PUBLIC_KEY_PATH}"
# ZTS
openssl ecparam -noout -genkey -name prime256v1 -out "${ZTS_PRIVATE_KEY_PATH}"
openssl ec -pubout -in "${ZTS_PRIVATE_KEY_PATH}" -out "${ZTS_PUBLIC_KEY_PATH}"
```


<a id="markdown-3-link-files-to-helm" name="3-link-files-to-helm"></a>
### 3. link files to helm

```bash
relpath() {
  python -c "import os.path,sys;print(os.path.relpath(sys.argv[1],sys.argv[2]))" "$1" "$2"
}
create_rel_link() {
  ln -sf "$(relpath "$1" "$2")" "$2"
}
```

```bash
### ZMS ###
# CAs
create_rel_link "${DEV_CA_DIR}/athenz_ca.pem" "${ZMS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/service_ca.pem" "${ZMS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/user_ca.pem" "${ZMS_HELM_FILE}/secrets/tls/CAs"
# certificates
create_rel_link "${DEV_ZMS_CERT_PATH}" "${ZMS_HELM_FILE}/secrets/tls"
create_rel_link "${DEV_ZMS_CERT_KEY_PATH}" "${ZMS_HELM_FILE}/secrets/tls"
# private key
create_rel_link "${ZMS_PRIVATE_KEY_PATH}" "${ZMS_HELM_FILE}/secrets"
```

```bash
### ZTS ###
# CAs
create_rel_link "${DEV_CA_DIR}/athenz_ca.pem" "${ZTS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/service_ca.pem" "${ZTS_HELM_FILE}/secrets/tls/CAs"
create_rel_link "${DEV_CA_DIR}/user_ca.pem" "${ZTS_HELM_FILE}/secrets/tls/CAs"
# certificates
create_rel_link "${DEV_ZTS_CERT_PATH}" "${ZTS_HELM_FILE}/secrets/tls"
create_rel_link "${DEV_ZTS_CERT_KEY_PATH}" "${ZTS_HELM_FILE}/secrets/tls"
# signer
create_rel_link "${DEV_ZTS_SIGNER_CERT_PATH}" "${ZTS_HELM_FILE}/secrets/signer"
create_rel_link "${DEV_ZTS_SIGNER_CERT_KEY_PATH}" "${ZTS_HELM_FILE}/secrets/signer"
# zms-client
create_rel_link "${DEV_ZMS_CLIENT_CERT_BUNDLE_PATH}" "${ZTS_HELM_FILE}/secrets/zms-client"
create_rel_link "${DEV_ZMS_CLIENT_CERT_KEY_PATH}" "${ZTS_HELM_FILE}/secrets/zms-client"
# private key
create_rel_link "${ZTS_PRIVATE_KEY_PATH}" "${ZTS_HELM_FILE}/secrets"
```

<a id="markdown-4-register-zts-public-key" name="4-register-zts-public-key"></a>
### 4. deploy ZMS

```bash
helm delete --namespace default wzzms
helm upgrade --install wzzms "${BASE_DIR}/docker/k8s/athenz-zms" -f "${BASE_DIR}/docker/k8s/zms-values.yaml"

# ZMS status
admin_curl --request GET --url "${ZMS_URL}/zms/v1/status" | jq
# ZMS mTLS
admin_curl --request GET --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms" | jq
# ZMS principal
admin_curl --request GET --url "${ZMS_URL}/zms/v1/principal" | jq '.service'
```

### 5. register ZTS public key
```bash
### (🔺) reset ZMS service ###
# === In linux  ===
# ENCODED_ZMS_PUBLIC_KEY="$(cat "${ZMS_PUBLIC_KEY_PATH}" | base64 -w 0 | tr '\+\=\/' '\.\-\_')"
ENCODED_ZMS_PUBLIC_KEY="$(cat "${ZMS_PUBLIC_KEY_PATH}" | base64 -b 0 | tr '\+\=\/' '\.\-\_')"
DATA='{"name": "sys.auth.zms","publicKeys": [{"id": "0","key": "'"${ENCODED_ZMS_PUBLIC_KEY}"'"}]}'

admin_curl --request DELETE -D - --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms"
admin_curl --request PUT -D - --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms" \
  --header 'content-type: application/json' \
  --data "${DATA}"
# verify
admin_curl --request GET --url "${ZMS_URL}/zms/v1/domain/sys.auth/service/zms" | jq
```
```bash
### (✅) register ZTS service ###
# === In linux  ===
# ENCODED_ZTS_PUBLIC_KEY="$(cat "${ZTS_PUBLIC_KEY_PATH}" | base64 -w 0 | tr '\+\=\/' '\.\-\_')"
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

### 5. athenz_conf.json

```bash
athenz-conf -c "${DEV_ATHENZ_CA_PATH}" \
  -svc-key-file "${DEV_DOMAIN_ADMIN_CERT_KEY_PATH}" \
  -svc-cert-file "${DEV_DOMAIN_ADMIN_CERT_PATH}" \
  -o "${ZTS_HELM_FILE}/conf/athenz_conf.json" \
  -t "https://${ZTS_HOST}:8443" \
  -z "${ZMS_URL}"
sed -i '' "s,${ZMS_URL},https://${ZMS_HOST}:4443," "${ZTS_HELM_FILE}/conf/athenz_conf.json"

less "${ZTS_HELM_FILE}/conf/athenz_conf.json"
```

### 6. deploy ZTS

```bash
helm delete --namespace default wzzts
helm upgrade --install wzzts "${BASE_DIR}/docker/k8s/athenz-zts" -f "${BASE_DIR}/docker/k8s/zts-values.yaml"

# ZTS status
admin_curl --request GET --url "${ZTS_URL}/zts/v1/status" | jq
# ZTS mTLS
admin_curl --request GET --url "${ZTS_URL}/zts/v1/domain/sys.auth/service/zts" | jq
# ZTS role token
admin_curl --request GET --url "${ZTS_URL}/zts/v1/domain/sys.auth/token?role=admin" | jq
```



## monitoring

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

