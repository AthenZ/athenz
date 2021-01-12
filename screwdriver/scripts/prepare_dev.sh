set e

nvm install 12
npm install -g npm@latest
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install gcc-4.8
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 50
sudo apt-get install g++-4.8
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 50