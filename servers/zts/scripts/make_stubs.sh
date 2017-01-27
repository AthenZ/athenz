#!/bin/bash

# If the zts_core dependency has been updated, then this script should be run
# manually to pick up the latest rdl to generate the appropriate server stubs.

# Note this script is dependent on the rdl utility.
#
# Use open source version of rdl https://github.com/ardielle/ardielle-tools
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

echo "Update the ZTS.rdl to define string type"
RDL_FILE=src/main/rdl/ZTS.rdl

echo "Generate the ZTS server stubs"
rdl -s generate -o src/main/java java-server $RDL_FILE

echo "Removing not needed ZTS Server file..."
rm src/main/java/com/yahoo/athenz/zts/ZTSServer.java
