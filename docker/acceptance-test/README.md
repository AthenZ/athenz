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
### openssl x509 -text -noout -in ./docker/acceptance-test/service.crt | less
### openssl x509 -text -noout -in ./docker/acceptance-test/intermediate.crt | less

# add policy to ZMS and test the client certificate
docker run -it --net=host \
  -v `pwd`/docker/zms/var/certs/zms_cert.pem:/etc/certs/zms_cert.pem \
  -v `pwd`/docker/ui/keys/athenz.ui-server_pub.pem:/etc/certs/athenz.ui-server_pub.pem \
  --name athenz-zms-cli athenz-zms-cli \
  -i user.admin -z https://localhost:4443/zms/v1 -c /etc/certs/zms_cert.pem \
  -d garm add-policy demo-policy grant get to demo-role on treasure \
  ; docker rm athenz-zms-cli > /dev/null;
curl -k --cert ./docker/acceptance-test/service.crt --key ./docker/acceptance-test/private.pem "https://localhost:8443/zts/v1/access/get/garm:treasure"
# expected output: {"granted":true}

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
### less ./docker/acceptance-test/role.crt

# get policy - ZPU
mkdir -p ./docker/acceptance-test/zpu
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



```bash
# poke SSL
ZTS_SSL_TRUST_STORE_PASSWORD=athegfhmtyjrtyjrtmfghmfgnz
java -Djavax.net.ssl.trustStore=/home/wfan/athenz/docker/zts/var/certs/zts_truststore.jks -Djavax.net.ssl.trustStorePassword=${ZTS_SSL_TRUST_STORE_PASSWORD} -jar build/libs/SSLPoke-1.0.jar localhost 6443

# service certificate
openssl s_server -accept 6443 -cert ./service.crt -key ./private.pem -WWW

curl -k --cert ./service.crt --key ./private.pem https://localhost:8443/

# gen cert by CA
openssl genrsa -out mydomain.com.key 2048
openssl req -new -sha256 -key mydomain.com.key -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=mydomain.com" -out mydomain.com.csr
openssl x509 -req -in mydomain.com.csr -CA /home/wfan/athenz/docker/zts/var/keys/zts_root_ca_cert.pem -CAkey /home/wfan/athenz/docker/zts/var/keys/zts_root_ca_cert.pem -CAcreateserial -out mydomain.com.crt -days 500 -sha256

curl -k --cert ./mydomain.com.crt --key ./mydomain.com.key https://localhost:8443/

openssl verify -CAfile /home/wfan/athenz/docker/zts/var/keys/zts_root_ca_cert.pem service.crt

openssl s_server -accept 6443 -WWW -CAfile ./zts_root_ca_cert.pem -cert ../certs/zts_cert.pem -key ../certs/zts_key.pem
```
https://cptl.corp.yahoo.co.jp/pages/viewpage.action?pageId=1489197587
https://cptl.corp.yahoo.co.jp/pages/viewpage.action?pageId=1419494101
https://cptl.corp.yahoo.co.jp/pages/viewpage.action?pageId=1497450760


```bash
docker build -t athenz-mysql-db -f ./Dockerfile .

docker run -d \
    --network=host -p 33077:33077 \
    -v `pwd`/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf \
    -e MYSQL_ROOT_PASSWORD=123456 \
    --name athenz-mysql-db athenz-mysql-db

mysql -v -u root --password=123456 --host=127.0.0.1 --port=33077

docker stop athenz-mysql-db; docker rm athenz-mysql-db
```

```bash

docker run --net=host -it \
  -v `pwd`/docker/zts/var/certs/zts_cert.pem:/etc/certs/zts_cert.pem \
  -v `pwd`/docker/acceptance-test:/etc/acceptance-test \
  --name athenz-cli-util athenz-cli-util sh

docker rm athenz-cli-util > /dev/null;

dl -f --tail 10 athenz-zts-server

go run main.go -cert /etc/acceptance-test/service.crt -key /etc/acceptance-test/private.pem -CA /etc/certs/zts_cert.pem
```
