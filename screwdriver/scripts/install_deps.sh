#!/usr/bin/env bash

set -ev

apt-get update
apt-get clean
apt-get autoremove

echo "-----------------Install libs: -----------------"
apt-get install -y libaio1 libnuma-dev build-essential libncurses5 aptitude

echo "-----------------Install nodejs: -----------------"
#install nodejs 12.x repo
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-get install -y nodejs
aptitude install -y npm
npm install -g npm@latest

echo "-----------------Install gcc: -----------------"
apt-get install -y software-properties-common
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get install -y gcc
apt-get install -y g++

echo "-----------------Install golang: -----------------"
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
