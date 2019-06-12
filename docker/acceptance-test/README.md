## prepare athenz-cli for testing

```bash
# cat > ./docker/util/Dockerfile

# docker build -t athenz-cli-util -f docker/util/Dockerfile .

# test inspect docker image
docker run -it --network=host --name athenz-cli-util athenz-cli-util sh ; docker rm athenz-cli-util > /dev/null;

# alias
acli() { docker run --network=host --name athenz-cli-util athenz-cli-util $@ ; docker rm athenz-cli-util > /dev/null; }

# test cli
acli ./utils/zms-cli/target/linux/zms-cli version
```

## acceptance-test for ZTS

- [x] 0. prepare test data
    - [x] 0.1. set up ZMS for testing
    - [x] 0.2. generate n-token
```bash
cd ${PROJECT_ROOT}

# add garm.tester service to ZMS
docker run -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  add-domain garm admin \
  ; docker rm athenz-zms-cli > /dev/null;
docker run -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/acceptance-test/public.pem:/etc/certs/public.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d garm add-service tester tmp /etc/certs/public.pem \
  ; docker rm athenz-zms-cli > /dev/null;

# add demo-role to garm domain with member garm.tester to ZMS
docker run -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/acceptance-test/public.pem:/etc/certs/public.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d garm add-group-role demo-role garm.tester \
  ; docker rm athenz-zms-cli > /dev/null;

# add policy to ZMS and test the client certificate
docker run -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/ui/keys/athenz.ui-server_pub.pem:/etc/certs/athenz.ui-server_pub.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d garm add-policy demo-policy grant get to demo-role on treasure \
  ; docker rm athenz-zms-cli > /dev/null;
```
```bash
# generate n-token locally
docker run -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zms-svctoken/target/linux/zms-svctoken \
  -domain garm -service tester \
  -key-version tmp \
  -private-key /etc/acceptance-test/private.pem > `pwd`/docker/acceptance-test/n-token \
  ; docker rm athenz-cli-util > /dev/null;

### checking:
less ./docker/acceptance-test/n-token
```

- [x] 1. get role token
```bash
# get role token by n-token (may take a moment for ZTS to sync the changes)
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/ssl/certs/ca-certificates.crt \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zts-roletoken/target/linux/zts-roletoken \
  -domain garm -role demo-role \
  -ntoken-file /etc/acceptance-test/n-token \
  -zts https://localhost:8443/zts/v1 \
  ; docker rm athenz-cli-util > /dev/null;

### expect:
### <role token print in stdout>
```

- [x] 2. get valid client certificate
```bash
# get client certificate for the service
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/certs/zts_cert.pem \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zts-svccert/target/linux/zts-svccert \
  -domain garm -service tester \
  -key-version tmp \
  -private-key /etc/acceptance-test/private.pem \
  -cacert /etc/certs/zts_cert.pem \
  -zts https://localhost:8443/zts/v1 \
  -dns-domain dns.athenz.cloud \
  -instance dummy-instance \
  -hdr Athenz-Principal-Auth \
  -cert-file /etc/acceptance-test/service.crt \
  -signer-cert-file /etc/acceptance-test/intermediate.crt \
  ; docker rm athenz-cli-util > /dev/null;

### checking:
openssl x509 -text -noout -in ./docker/acceptance-test/service.crt | less
openssl x509 -text -noout -in ./docker/acceptance-test/intermediate.crt | less
openssl verify -CAfile ./docker/zts/var/keys/zts_root_ca_cert.pem ./docker/acceptance-test/service.crt
### expect:
### ./docker/acceptance-test/service.crt: OK

### checking:
curl -k --cert ./docker/acceptance-test/service.crt --key ./docker/acceptance-test/private.pem "https://localhost:8443/zts/v1/access/get/garm:treasure"
### expect:
### {"granted":true}
```

- [x] 2. get valid role certificate
```bash
# get role token by client certificate
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/certs/zts_cert.pem \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zts-rolecert/target/linux/zts-rolecert \
  -domain garm -service tester \
  -svc-key-file /etc/acceptance-test/private.pem \
  -svc-cert-file /etc/acceptance-test/service.crt \
  -cacert /etc/certs/zts_cert.pem \
  -zts https://localhost:8443/zts/v1 \
  -role-domain garm -role-name demo-role \
  -dns-domain dns.athenz.cloud \
  -role-cert-file /etc/acceptance-test/role.crt \
  ; docker rm athenz-cli-util > /dev/null;

### checking:
openssl x509 -text -noout -in ./docker/acceptance-test/role.crt | less
openssl verify -CAfile ./docker/zts/var/keys/zts_root_ca_cert.pem ./docker/acceptance-test/role.crt
### expect:
### ./docker/acceptance-test/role.crt: OK

### checking:
curl -k --cert ./docker/acceptance-test/role.crt --key ./docker/acceptance-test/private.pem "https://localhost:8443/zts/v1/access/get/garm:treasure"
### expect:
### {"granted":true}
```

- [x] 3. get policy
```bash
# get policy - ZPU
mkdir -p ./docker/acceptance-test/zpu/metrics
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/certs/zts_cert.pem \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  -v `pwd`/docker/acceptance-test/zpu:/home/athenz/tmp/zpe \
  -v `pwd`/docker/zts/conf/athenz.conf:/tmp/athenz.conf \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zpe-updater/target/linux/zpu \
  -athenzConf /tmp/athenz.conf -zpuConf /etc/acceptance-test/zpu.conf \
  -logFile /etc/acceptance-test/zpu.log \
  ; docker rm athenz-cli-util > /dev/null;

### checking:
less ./docker/acceptance-test/zpu/garm.pol
```
