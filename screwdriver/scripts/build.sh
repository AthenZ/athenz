#!/usr/bin/env bash

set -ev

readonly NUM_THREADS=$(( $(nproc) + 2 ))

export MAVEN_OPTS="-Xss1m -Xms128m -Xmx2g"
export ATHENZ_MAVEN_EXTRA_OPTS="${ATHENZ_MAVEN_EXTRA_OPTS:+${ATHENZ_MAVEN_EXTRA_OPTS} }--no-snapshot-updates --batch-mode --threads ${NUM_THREADS}"

mvn install