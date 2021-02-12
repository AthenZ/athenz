#!/usr/bin/env bash

set -ev

mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-auth-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-java-client --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpe-java-client --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-client-common --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-cert-refresher --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-server-common --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-instance-provider --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-jetty-container --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpu --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-utils --settings screwdriver/settings/settings-publish.xml
