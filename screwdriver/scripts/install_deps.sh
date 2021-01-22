#!/usr/bin/env bash

set e

apt-get update

#install nodejs 12.x repo
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-get install -y nodejs
apt-get install -y npm
apt-get install -y software-properties-common
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get install -y gcc
apt-get install -y g++
apt-get install build-essential
npm install -g npm@latest

# install go
wget https://golang.org/dl/go1.13.4.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.13.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

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
