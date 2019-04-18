#!/bin/bash

# For Athenz Go clients we're using our own generator. This is a go utility
# so the system must have go installed. This is required when changes
# are made to the RDL and the corresponding resource files must be
# generated. Otherwise, the client has all the auto-generated code already
# checked-in into git.

if [ ! -z "${TRAVIS_PULL_REQUEST}" ] || [ ! -z "${TRAVIS_TAG}" ]; then
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
    echo >&2 "Skipping rdl go client generator build...";
    exit 0;
}

if [ -z "${GOPATH}" ]; then
    echo >&2 "GOPATH is not set. please configure this environment variable"
    exit 1;
fi

go get -u github.com/ardielle/ardielle-go/...
go build
cp rdl-gen-athenz-go-client ${GOPATH}/bin/rdl-gen-athenz-go-client

# Copyright 2019 Oath Holdings Inc.
# Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
