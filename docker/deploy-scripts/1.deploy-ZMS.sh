#!/bin/sh

# to script directory
cd "$(dirname "$0")"

# start ZMS DB
docker run -d -h localhost \
  --network=host \
  # -p 3306 \
  -v `pwd`/docker/db/zms/zms-db.cnf:/etc/mysql/conf.d/zms-db.cnf \
  -e MYSQL_ROOT_PASSWORD=${ZMS_JDBC_PASSWORD} \
  --name athenz-zms-db athenz-zms-db

# wait for ZMS DB ready
docker run --rm -h localhost \
  --network=host \
  -v `pwd`/docker/db/zms/zms-db.cnf:/etc/my.cnf \
  -e MYSQL_PWD=${ZMS_JDBC_PASSWORD} \
  --name wait-for-mysql wait-for-mysql

# start ZMS
docker run -d -h localhost \
  --network=host \
  # -p 3307 \
  -v `pwd`/docker/db/zts/zts-db.cnf:/etc/mysql/conf.d/zts-db.cnf \
  -e MYSQL_ROOT_PASSWORD=${ZTS_CERT_JDBC_PASSWORD} \
  --name athenz-zts-db athenz-zts-db
