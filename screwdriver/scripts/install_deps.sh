#!/usr/bin/env bash

set e

apt-get update

#install nodejs 12.x repo
curl -sL https://rpm.nodesource.com/setup_12.x | sudo bash -
apt-get install -y nodejs
apt-get install -y npm
apt-get install -y software-properties-common
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get install -y gcc
apt-get install -y g++
npm install -g npm@latest

# install go

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
