#!/bin/bash

# Copyright 2021 Adevinta

# set -e   # Uncomment this to make the pipeline fail in case of a security vuln.

echo "Start target app"
docker pull appsecco/dsvw
docker run -p 1234:8000 --restart unless-stopped --name dsvw -d appsecco/dsvw

sleep 5

echo "Test based on yaml config using lightweight policy"
./vulcan-local -c ./vulcan.yaml -c ./script/vulcan-policies.yaml -p lightweight
echo "exit=$?"

echo "Test local path as a git repository excluding the github check"
./vulcan-local -t . -e github -u file://./script/checktypes-stable.json
echo "exit=$?"

# Add a path and a tag to bypass check target validations.
docker tag vulcan-local path/vulcan-local:xxx
echo "Test local docker image"
./vulcan-local -t path/vulcan-local:xxx -a DockerImage -i trivy -u file://./script/checktypes-stable.json
echo "exit=$?"

echo "Docker test based on yaml config"
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock  \
    -v "$PWD":/target -e TRAVIS_BUILD_DIR=/target \
    -e REGISTRY_SERVER -e REGISTRY_USERNAME -e REGISTRY_PASSWORD \
    vulcan-local -c /target/vulcan.yaml -i retirejs
echo "exit=$?"

echo "Docker test local app as a webaddress excluding nessus and zap"
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock  \
    -v "$PWD":/target \
    -e TRAVIS_BUILD_DIR=/target -e REGISTRY_SERVER -e REGISTRY_USERNAME -e REGISTRY_PASSWORD \
    vulcan-local -t http://localhost:1234 -e '(nessus|zap)' -u file:///target/script/checktypes-stable.json
echo "exit=$?"

echo "Stopping target app"
docker rm -f dsvw
