#!/usr/bin/env bash

set -ev

mvn install -DskipTests=true -Dmaven.javadoc.skip=true -B -V
