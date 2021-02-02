#!/usr/bin/env bash

set -ev

mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz --settings travis/settings-athenz-parent.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-core --settings travis/settings-zms-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-core --settings travis/settings-zts-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-auth-core --settings travis/settings-auth-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-java-client --settings travis/settings-zms-java-client.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client-core --settings travis/settings-zts-java-client-core.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client --settings travis/settings-zts-java-client.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpe-java-client --settings travis/settings-zpe-java-client.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-client-common --settings travis/settings-client-common.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-cert-refresher --settings travis/settings-cert-refresher.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-server-common --settings travis/settings-server-common.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-instance-provider --settings travis/settings-athenz-instance-provider.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-jetty-container --settings travis/settings-athenz-jetty-container.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpe-policy-updater --settings travis/settings-zpe-policy-updater.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms --settings travis/settings-athenz-zms.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts --settings travis/settings-athenz-zts.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpu --settings travis/settings-athenz-zpu.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-ui --settings travis/settings-athenz-ui.xml
mvn -B deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-utils --settings travis/settings-athenz-utils.xml
