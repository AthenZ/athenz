#!/bin/bash

# For Athenz services we're using our own generator. This is a go utility
# so the system must have go installed. This is required when changes
# are made to the RDL and the corresponding resource files must be
# generated. Otherwise, the server has all the auto-generated code already
# checked-in into git.

if [ ! -z "${SCREWDRIVER}" ] || [ ! -z "${TRAVIS_PULL_REQUEST}" ] || [ ! -z "${TRAVIS_TAG}" ]; then
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE NOTICE";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Automated Build. Skipping source generation...";
    exit 0;
fi

command -v go >/dev/null 2>&1 || {
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "SOURCE WARNING";
    echo >&2 "------------------------------------------------------------------------";
    echo >&2 "Please install go compiler from https://golang.org";
    echo >&2 "Skipping rdl server generator build...";
    exit 0;
}

if [ -z "${GOPATH}" ]; then
    echo >&2 "GOPATH is not set. please configure this environment variable"
    exit 1;
fi

if [ ! -d "${GOPATH}/bin" ]; then
    echo >&2 "$GOPATH/bin directory does not exist. Please create this directory."
    exit 1;
fi

go get -u github.com/ardielle/ardielle-go/...
go build
cp rdl-gen-athenz-server ${GOPATH}/bin/rdl-gen-athenz-server

# Copyright 2018 Oath Inc.
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
