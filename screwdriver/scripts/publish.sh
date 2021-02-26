#!/usr/bin/env bash

set -e

# for openssl 1.1+ we need to add -pbkdf2 to remove the
# warning but that option does not exist in openssl 1.0.x

openssl aes-256-cbc -pass pass:$GPG_ENCPHRASE -in screwdriver/pubring.gpg.enc -out screwdriver/pubring.gpg -nopad -pbkdf2 -d
openssl aes-256-cbc -pass pass:$GPG_ENCPHRASE -in screwdriver/secring.gpg.enc -out screwdriver/secring.gpg -nopad -pbkdf2 -d

mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-auth-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-client-common --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-cert-refresher --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zms-java-client --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client-core --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zts-java-client --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-zpe-java-client --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-server-common --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-instance-provider --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-jetty-container --settings screwdriver/settings/settings-publish.xml
mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects com.yahoo.athenz:athenz-utils --settings screwdriver/settings/settings-publish.xml
