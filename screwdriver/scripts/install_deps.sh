#!/usr/bin/env bash

set -e

apt-get update
apt-get clean
apt-get autoremove

echo "-----------------Install libs: -----------------"
apt-get install -y libaio1 libnuma-dev build-essential libncurses5 aptitude net-tools

echo "-----------------Install maven: -----------------"
apt-get install -y maven

echo "-----------------Install nodejs: -----------------"
apt-get update
apt-get install -y ca-certificates curl gnupg apt-transport-https
mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
NODE_MAJOR=18
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
apt-get update
apt-get install nodejs -y
aptitude install -y npm
npm install -g npm@latest

echo "-----------------Install gcc: -----------------"
apt-get install -y software-properties-common
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get install -y gcc
apt-get install -y g++

echo "-----------------Install golang: -----------------"
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

echo "-----------------Install Docker: -----------------"
# Add Docker's official GPG key:
apt-get update
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
apt-key fingerprint 0EBFCD88

add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
docker system info
ls -la $SD_DIND_SHARE_PATH

# check all installed dependencies
echo "-----------------Java Version: -----------------"
java -version
echo "-----------------Maven Version: -----------------"
mvn -version
echo "-----------------Nodejs Version: -----------------"
node -v
echo "-----------------NPM Version: -----------------"
npm -v
echo "-----------------Golang Version: -----------------"
go version
echo "-----------------Docker Version: -----------------"
docker version
