#!/usr/bin/env bash

set -ev

mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz --settings travis/settings-athenz-parent.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:zms_core --settings travis/settings-zms-core.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:zts_core --settings travis/settings-zts-core.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:auth_core --settings travis/settings-auth-core.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:zms_java_client --settings travis/settings-zms-java-client.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:zts_java_client --settings travis/settings-zts-java-client.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:zpe_java_client --settings travis/settings-zpe-java-client.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:client_common --settings travis/settings-client-common.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:server_common --settings travis/settings-server-common.xml
mvn deploy -Dmaven.test.skip=true --projects com.yahoo.athenz:zpe_policy_updater --settings travis/settings-zpe-policy-updater.xml
