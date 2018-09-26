#!/bin/bash

displayUsage() {
  echo "add_user.sh [username] [bucket_name] ";
}

if [ $# -ne 2 ]
then
  displayUsage
  exit 1
fi

adminUser=$1
bucketName=$2
passFile=/tmp/admin_pass

aws s3 cp s3://$bucketName/admin_pass $passFile
adminPass=$(cat $passFile)

sudo useradd $adminUser
echo $adminPass | sudo passwd $adminUser --stdin

sudo rm $passFile