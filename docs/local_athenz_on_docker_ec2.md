## Overview
In this introduction to Athenz, you will be able to run Athenz on your EC2 instance in AWS.

## Prerequisites
* AWS account with access to make changes to policies, IAM roles etc.

## Steps

Create a new policy with following JSON

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": [
                "arn:aws:iam::*:role/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups"
            ],
            "Resource": [
                "arn:aws:logs:*:*:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeTags"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

Create a new IAM role and associate the above created policy with it.

!!! Note
    Make sure your VPC is set up  with an Internet Gateway and necessary NACL, Route Table rules to allow EC2 instances in that VPC to be
    able to reach internet.


Create a new EC2 instance in your VPC with the above created role as instance profile role. We will be using Amazon Linux 2 AMI and t2.2xlarge
instance type since we will be running 5 docker containers for the purpose of this demo.

SSH to the EC2 instance and run following commands to install git and docker -

```shell
sudo yum update -y
sudo yum install git
sudo yum install docker -y
sudo usermod -a -G docker ec2-user
sudo service docker start
```

!!! Note
    You might have to log out and log back in for ec2-user's docker group membership to come into effect.


Checkout Athenz from Github
```shell
git clone https://github.com/AthenZ/athenz.git
```
`cd` to checked out directory and run following command:
```shell
cd athenz && ./start-local-athenz.sh
```
   
This script will -
   
- download Athenz components docker images from DockerHub
- generate self-signed certificates to be used by Athenz components
- configure Athenz with meaningful defaults suitable for local environment ( for production set up, please refer to "Production set up" section of docs.)
- start local containers corresponding to Athenz components (ZMS, ZMS DB, ZTS, ZTS DB, UI)

