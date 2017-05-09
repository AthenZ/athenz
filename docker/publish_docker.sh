#!/usr/bin/env bash
set -ev

echo "-----------------------------------------------"
echo "Creating Athenz Docker image..."
echo "-----------------------------------------------"

docker build -t athenz/athenz .
docker login -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"
TRAVIS_TAG=1.7.10-SNAPSHOT
echo "tagging Athenz Docker image with tag: $TRAVIS_TAG"
docker tag athenz/athenz athenz/athenz:$TRAVIS_TAG
docker push athenz/athenz

echo "-----------------------------------------------"
echo "Athenz Docker Image Completed"
echo "-----------------------------------------------"