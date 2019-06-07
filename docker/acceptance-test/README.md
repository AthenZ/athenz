## prepare athenz-cli for testing

```bash
# cat > ./docker/util/Dockerfile

# docker build -t athenz-cli-util -f docker/util/Dockerfile .

# test inspect docker image
docker run -it --network=host --name athenz-cli-util athenz-cli-util sh ; docker rm athenz-cli-util
```

## acceptance-test for ZTS

- [x] get role token
- [ ] get policy
- [x] get client certificate

```bash
cd ${PROJECT_ROOT}

# alias
acli() { docker run --network=host --name athenz-cli-util athenz-cli-util $@ ; docker rm athenz-cli-util > /dev/null; }

# test cli
acli ./utils/zms-cli/target/linux/zms-cli version

# add garm.tester service to ZMS
docker run -it --net=host \
    -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
    --name athenz-zms-cli athenz-zms-cli \
    -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
    add-domain garm admin \
    ; docker rm athenz-zms-cli
docker run -it --net=host \
    -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
    -v `pwd`/docker/acceptance-test/public.pem:/etc/certs/public.pem \
    --name athenz-zms-cli athenz-zms-cli \
    -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
    -d garm add-service tester tmp /etc/certs/public.pem \
    ; docker rm athenz-zms-cli

# add demo-role to garm domain with member garm.tester to ZMS
docker run -it --net=host \
    -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
    -v `pwd`/docker/acceptance-test/public.pem:/etc/certs/public.pem \
    --name athenz-zms-cli athenz-zms-cli \
    -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
    -d garm add-group-role demo-role garm.tester \
    ; docker rm athenz-zms-cli

# generate n-token locally
docker run -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zms-svctoken/target/linux/zms-svctoken \
  -domain garm -service tester \
  -key-version tmp \
  -private-key /etc/acceptance-test/private.pem > `pwd`/docker/acceptance-test/n-token \
  ; docker rm athenz-cli-util > /dev/null;
### less ./docker/acceptance-test/n-token

# get role token by n-token
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/ssl/certs/ca-certificates.crt \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zts-roletoken/target/linux/zts-roletoken \
  -domain garm -role demo-role \
  -ntoken-file /etc/acceptance-test/n-token \
  -zts https://localhost:8443/zts/v1 \
  ; docker rm athenz-cli-util > /dev/null;
### role token print in stdout

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
### less ./docker/acceptance-test/service.crt ./docker/acceptance-test/intermediate.crt

# get role token by client certificate (not working, err: 401 Invalid credentials)
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/ssl/certs/ca-certificates.crt \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zts-rolecert/target/linux/zts-rolecert \
  -domain garm -service tester \
  -svc-key-file /etc/acceptance-test/private.pem \
  -svc-cert-file /etc/acceptance-test/service.crt \
  -zts https://localhost:8443/zts/v1 \
  -role-domain garm -role-name demo-role \
  -dns-domain dns.athenz.cloud \
  -role-cert-file /etc/acceptance-test/role.crt \
  ; docker rm athenz-cli-util > /dev/null;
### less ./docker/acceptance-test/role.crt

# get policy - ZPU
docker run --net=host \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/certs/zts_cert.pem \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  -v `pwd`/docker/zts/conf/athenz.conf:/tmp/athenz.conf \
  --name athenz-cli-util athenz-cli-util \
  ./utils/zpe-updater/target/linux/zpu \
  -athenzConf /tmp/athenz.conf -zpuConf /etc/acceptance-test/zpu.conf \
  -logFile /etc/acceptance-test/zpu.log \
  ; docker rm athenz-cli-util > /dev/null;

```
