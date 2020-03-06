#!/bin/bash

# If any of the RDL files have been updated, then this script should be run
# rdl to generate the appropriate model classes.
# however, we're not going to run this utility during our automated builds since
# builds must be done based on files already checked-in into git

if [ ! -z "${TRAVIS_PULL_REQUEST}" ] || [ ! -z "${TRAVIS_TAG}" ]; then
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE NOTICE";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Automated Build. Skipping source generation...";
    exit 0;
fi

# Note this script is dependent on the rdl utility.
# go get github.com/ardielle/ardielle-tools/...
#

if [ -x "$(command -v go)" ]; then
    go get -u github.com/ardielle/ardielle-tools/...
fi

command -v rdl >/dev/null 2>&1 || {
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE WARNING";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Please install rdl utility: go get -u github.com/ardielle/ardielle-tools/...";
    echo >&2 "Skipping source generation...";
    exit 0;
}

RDL_ZMS_FILE=src/main/rdl/ZMS.rdl

echo "Generating model classes..."
rdl -s generate -x getsetters=true -o src/main/java java-model $RDL_ZMS_FILE

# need to override the protected header in the JWSDomain
# since that value is a reserved java keyword. we'll use
# copy/mv instead of -i to avoid mac/linux differences

JWS_DOMAIN_FILE=src/main/java/com/yahoo/athenz/zms/JWSDomain.java
JWS_DOMAIN_TEMP=src/main/java/com/yahoo/athenz/zms/JWSDomain.tmp
sed 's/    public String protectedHeader;/    \@com.fasterxml.jackson.annotation.JsonProperty\(\"protected\"\) public String protectedHeader;/g' $JWS_DOMAIN_FILE > $JWS_DOMAIN_TEMP
mv $JWS_DOMAIN_TEMP $JWS_DOMAIN_FILE

# Copyright 2016 Yahoo Inc.
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
