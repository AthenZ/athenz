#!/bin/bash
# Copyright The Athenz Authors
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

# If any of the RDL files have been updated, then this script should be run
# rdl to generate the appropriate model classes.
# however, we're not going to run this utility during our automated builds since
# builds must be done based on files already checked-in into git

if [ ! -z "${SCREWDRIVER}" ]; then
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE NOTICE";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Automated Build. Skipping source generation...";
    exit 0;
fi

# Note this script is dependent on the rdl utility.
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

RDL_MSD_FILE=src/main/rdl/MSD.rdl

echo "Generating model classes..."
rdl -s generate -o src/main/java athenz-java-model $RDL_MSD_FILE

