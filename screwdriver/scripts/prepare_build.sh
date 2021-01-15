set e

apt-get update

apt-get install -y nodejs
apt-get install -y npm
curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.37.2/install.sh | bash
source ~/.bashrc
nvm install 12
npm install -g npm@latest

apt-get install -y software-properties-common
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get install -y gcc
apt-get install -y g++
