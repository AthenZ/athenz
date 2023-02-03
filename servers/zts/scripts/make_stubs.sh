#!/bin/bash

# If the zts_core dependency has been updated, then this script should be run
# manually to pick up the latest rdl to generate the appropriate server stubs.
# however, we're not going to run this utility during our automated builds since
# builds must be done based on files already checked-in into git

if [ ! -z "${SCREWDRIVER}" ] || [ ! -z "${TRAVIS_PULL_REQUEST}" ] || [ ! -z "${TRAVIS_TAG}" ]; then
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE NOTICE";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Automated Build. Skipping source generation...";
    exit 0;
fi

# Note this script is dependent on the rdl utility.
#
# Use open source version of rdl https://github.com/ardielle/ardielle-tools
# go install github.com/ardielle/ardielle-tools/rdl@latest

if [ -x "$(command -v go)" ]; then
    go install github.com/ardielle/ardielle-tools/rdl@latest
fi

command -v rdl >/dev/null 2>&1 || {
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE WARNING";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Please install rdl utility: go install github.com/ardielle/ardielle-tools/rdl@latest";
    echo >&2 "Skipping source generation...";
    exit 0;
}

echo "Update the ZTS.rdl to define string type"
RDL_FILE=src/main/rdl/ZTS.rdl

echo "Generate the ZTS server stubs"
rdl -s generate -b="/v1" -o="src/main/java" athenz-server $RDL_FILE
