#!/bin/bash

# If the zms_core dependency has been updated, then this script should be run
# manually to pick up the latest rdl to generate the appropriate client library

# Note this script is dependent on the rdl utility.
# go get github.com/ardielle/ardielle-tools/...

if [ -x "$(command -v go)" ]; then
    go get github.com/ardielle/ardielle-tools/...
fi

command -v rdl >/dev/null 2>&1 || {
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE WARNING";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Please install rdl utility: go get github.com/ardielle/ardielle-tools/...";
    echo >&2 "Skipping source generation...";
    exit 0;
}

RDL_FILE=../../../core/zms/src/main/rdl/ZMS.rdl

echo "Generate the client library..."
rdl -s generate -o src/main/java -x clientclass=ZMSRDLGenerated java-client $RDL_FILE

# Copyright 2016 Yahoo Inc.
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
