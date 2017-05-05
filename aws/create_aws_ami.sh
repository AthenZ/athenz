#!/usr/bin/env bash
set -ev

CUR_DIR="$( pwd )"

#setup provision directory
export PROVISION=$CUR_DIR/provision
mkdir -p ${PROVISION} 

#setup services
cp ./aws/start.sh ${PROVISION}/
cp ./aws/stop.sh ${PROVISION}/

#setup zms
cp ./assembly/zms/target/athenz-zms-*-bin.tar.gz ${PROVISION}/

#setup zts
cp ./assembly/zts/target/athenz-zts-*-bin.tar.gz ${PROVISION}/

#setup ui
cp ./assembly/ui/target/athenz-ui-*-bin.tar.gz ${PROVISION}/

#setup utility
cp ./assembly/utils/target/athenz-utils-*-bin.tar.gz ${PROVISION}/

#setup packer
PACKER_DIR=/usr/local/bin
mkdir -p ${PACKER_DIR} && cd ${PACKER_DIR}
sudo wget https://releases.hashicorp.com/packer/0.12.1/packer_0.12.1_linux_amd64.zip
sudo unzip -o packer_0.12.1_linux_amd64.zip
cd $CUR_DIR

#run packer
export BASE_AMI_ID=ami-a58d0dc5
sudo ${PACKER_DIR}/packer build -machine-readable ./aws/athenz_ami.json && touch .ami
