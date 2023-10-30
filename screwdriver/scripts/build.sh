#!/usr/bin/env bash

set -e

export PATH=$PATH:/usr/local/go/bin
cp ${SD_SOURCE_DIR}/servers/zms/schema/zms_server.sql ${SD_SOURCE_DIR}/servers/zms/src/test/resources/mysql
ls -ltr ${SD_SOURCE_DIR}/servers/zms/src/test/resources/mysql
mvn -B install
