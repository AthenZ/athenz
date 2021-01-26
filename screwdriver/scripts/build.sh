#!/usr/bin/env bash

set -ev

readonly NUM_THREADS=$(( $(nproc) + 2 ))

export MAVEN_OPTS="-Xss1m -Xms128m -Xmx2g"

mvn install --batch-mode --threads ${NUM_THREADS}