#!/usr/bin/env bash

set -ev

mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz --settings screwdriver/settings/settings-athenz-parent.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-core --settings screwdriver/settings/settings-zms-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-core --settings screwdriver/settings/settings-zts-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-auth-core --settings screwdriver/settings/settings-auth-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-java-client --settings screwdriver/settings/settings-zms-java-client.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client-core --settings screwdriver/settings/settings-zts-java-client-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client --settings screwdriver/settings/settings-zts-java-client.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpe-java-client --settings screwdriver/settings/settings-zpe-java-client.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-client-common --settings screwdriver/settings/settings-client-common.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-cert-refresher --settings screwdriver/settings/settings-cert-refresher.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-server-common --settings screwdriver/settings/settings-server-common.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-instance-provider --settings screwdriver/settings/settings-athenz-instance-provider.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-jetty-container --settings screwdriver/settings/settings-athenz-jetty-container.xml
