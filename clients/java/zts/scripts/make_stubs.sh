#!/bin/bash

# If the zts_core dependency has been updated, then this script should be run
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

RDL_FILE=../../../core/zts/src/main/rdl/ZTS.rdl

echo "Generate the client library..."
rdl -s generate -o src/main/java -x clientclass=ZTSRDLGenerated java-client $RDL_FILE
