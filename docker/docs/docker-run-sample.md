# Run Athenz docker images

## start up
### ZMS & ZTS Databases
```bash
docker run -d -h localhost \
  --network=host \
  # -p 3306 \
  -v `pwd`/docker/db/zms/zms-db.cnf:/etc/mysql/conf.d/zms-db.cnf \
  -e MYSQL_ROOT_PASSWORD=${ZMS_JDBC_PASSWORD} \
  --name athenz-zms-db athenz-zms-db
docker run -d -h localhost \
  --network=host \
  # -p 3307 \
  -v `pwd`/docker/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf \
  -e MYSQL_ROOT_PASSWORD=${ZTS_CERT_JDBC_PASSWORD} \
  --name athenz-zts-db athenz-zts-db
```

### ZMS
```bash
docker run -d -h localhost \
  --network=host \
  # -p 4443 \
  -v `pwd`/docker/zms/var:/opt/athenz/zms/var \
  -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server \
  -v `pwd`/docker/logs/zms:/opt/athenz/zms/logs/zms_server \
  -e ZMS_JDBC_PASSWORD=${ZMS_JDBC_PASSWORD} \
  -e ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS} \
  -e ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS} \
  --name athenz-zms-server athenz-zms-server
```

### ZTS
```bash
docker run -d -h localhost \
  --network=host \
  # -p 8443 \
  -v `pwd`/docker/zts/var:/opt/athenz/zts/var \
  -v `pwd`/docker/zts/conf:/opt/athenz/zts/conf/zts_server \
  -v `pwd`/docker/logs/zts:/opt/athenz/zts/logs/zts_server \
  # -e JAVA_OPTS='-Djavax.net.debug=all' \
  -e ZTS_CERT_JDBC_PASSWORD=${ZTS_CERT_JDBC_PASSWORD} \
  -e ZTS_SSL_KEYSTORE_PASS=${ZTS_SSL_KEYSTORE_PASS} \
  -e ZTS_SSL_TRUSTSTORE_PASS=${ZTS_SSL_TRUSTSTORE_PASS} \
  -e ZTS_ZTS_SSL_KEYSTORE_PASS=${ZTS_ZTS_SSL_KEYSTORE_PASS} \
  -e ZTS_ZTS_SSL_TRUSTSTORE_PASS=${ZTS_ZTS_SSL_TRUSTSTORE_PASS} \
  --name athenz-zts-server athenz-zts-server
```

### UI
```bash
docker run -d -h localhost \
  --network=host \
  # -p 443 \
  -v `pwd`/docker/zts/conf/athenz.conf:/opt/athenz/ui/config/athenz.conf \
  -v `pwd`/docker/ui/keys:/opt/athenz/ui/keys \
  --name athenz-ui athenz-ui
```

## clean up
```bash
docker ps -a | grep athenz- | awk '{print $1}' | xargs docker stop
docker ps -a | grep athenz- | awk '{print $1}' | xargs docker rm
```

## extra
### run ZMS with extra jars
```bash
docker run -d -h localhost \
  --network=host \
  # -p 4443 \
  # --- set JAVA classpath and mount custom jars ---
  -e USER_CLASSPATH='lib/usr/jars/*' \
  -v `pwd`/docker/zms/jars:/opt/athenz/zms/lib/usr/jars
  # --- set JAVA classpath and mount custom jars ---
  -v `pwd`/docker/zms/var:/opt/athenz/zms/var \
  -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server \
  -v `pwd`/docker/logs/zms:/opt/athenz/zms/logs/zms_server \
  -e ZMS_JDBC_PASSWORD=${ZMS_JDBC_PASSWORD} \
  -e ZMS_SSL_KEYSTORE_PASS=${ZMS_SSL_KEYSTORE_PASS} \
  -e ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS} \
  --name athenz-zms-server athenz-zms-server
```

### run ZMS with custom CMD
```bash
docker run -d -h localhost \
  --network=host \
  # -p 4443 \
  -v `pwd`/docker/zms/var:/opt/athenz/zms/var \
  -v `pwd`/docker/zms/conf:/opt/athenz/zms/conf/zms_server \
  -v `pwd`/docker/logs/zms:/opt/athenz/zms/logs/zms_server \
  -e ZMS_SSL_TRUSTSTORE_PASS=${ZMS_SSL_TRUSTSTORE_PASS} \
  --name athenz-zms-server athenz-zms-server \
  # --- custom JAVA args ---
  -classpath "/path/to/all/jars"
  # --- custom JAVA args ---
```
