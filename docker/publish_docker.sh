#!/usr/bin/env bash
set -ev

docker build -t athenz/athenz .
docker login -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
docker push athenz/athenz
