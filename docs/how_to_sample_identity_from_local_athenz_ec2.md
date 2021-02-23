## Overview
In this guide, you will be able to create a service in Athenz and obtain a service identity in the form of X.509 certificate from 
Athenz for an instance running on AWS EC2.

## Prerequisites
* [Athenz running locally on EC2 in docker](local_athenz_on_docker_ec2.md)

## Steps

As part of local set up, an example domain by the name "athenz" is created and "athenz-admin" user is added as a domain administrator of 
that domain. Please refer to [concepts](data_model.md#domains) to understand more about domains.

To see the workflow of obtaining a service identity certificate from Athenz, please use following steps -

* Login to the ec2-docker instance created [Athenz running locally on EC2 in docker](local_athenz_on_docker_ec2.md)

* `cd` to the directory where Athenz is checked out from GitHub

* Download latest Athenz Utils from [Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils)
  (click on the `Browse` button, choose the latest version directory and then
  download the `athenz-utils-$latestVer-bin.tar.gz` file)
  & add it in the current shell PATH variable.
  Below `$athenzUtilsLocation` denotes the path where file is downloaded from Maven Central. 

```shell
tar -xf $athenzUtilsLocation/athenz-utils-$latestVer-bin.tar.gz -C $athenzUtilsLocation
export PATH=$athenzUtilsLocation/athenz-utils-$latestVer/bin/`uname | tr '[:upper:]' '[:lower:]'`:$PATH
```

* Create a new service using Athenz management Service client utility. Athenz Management Service (ZMS) is running inside a docker container exposed over local port 4443. 
  We will be using a different EC2 instance to get the identity for the ec2-demo service.
```shell
zms-cli -z https://127.0.0.1:4443/zms/v1 -cert docker/sample/domain-admin/team_admin_cert.pem \
  -key docker/sample/domain-admin/team_admin_key.pem -c docker/sample/CAs/athenz_ca.pem -d athenz add-service ec2-demo
```

Now to obtain a service identity certificate, first domain admin needs to authorize a provider. 
Athenz uses a generalized model for service providers to launch other service identities in an authorized way through a callback-based verification model.
For more details please refer to [copper argos](copper_argos.md)
Athenz code comes bundled with AWS EC2 instance provider which verifies instance metadata in the request before issuing identity certificate.

* Domain administrators have a full control over which provider they can authorize to launch their domains' services. 
  Run following command to authorize the EC2 provider to issue identity certificates for the service created previously

```shell
zms-cli -z https://127.0.0.1:4443/zms/v1 -cert docker/sample/domain-admin/team_admin_cert.pem -key docker/sample/domain-admin/team_admin_key.pem \
      -c docker/sample/CAs/athenz_ca.pem -d athenz set-domain-template aws_instance_launch_provider service=ec2-demo
```

* For verification purposes, we also need to tell Athenz which AWS account is associated with the incoming instance's Athenz domain.
  Replace the AWS account id you are running this demo, in the command below. This should be done with Athenz system administrator credentials.
  
```shell
zms-cli -z https://127.0.0.1:4443/zms/v1 -cert docker/sample/domain-admin/domain_admin_cert.pem -key docker/sample/domain-admin/domain_admin_key.pem \
      -c docker/sample/CAs/athenz_ca.pem -d athenz set-aws-account 111111111111
```

* Create a new role ( e.g ec2-identity-demo ) which will be used as instance profile role for a new EC2 instance for which we will get identity from Athenz. You can re-purpose the policy
  created for EC2 docker instance for this.
  
* Create another role by name "athenz.ec2-demo" which is in the form of <domain>.<service> where athenz is the name of the domain and ec2-demo is the service.
  This role wouldnt have any permissions set attached to it, but it will define a trust relationship with the EC2 instance profile role created above, so that
  EC2 instance profile can assume this role.
  The trust relationship policy json should look like below. Replace the AWS account id you are running this demo, in the policy json.
  
```shell
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    },
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::1111111111111:role/ec2-identity-demo"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

  For additional details, refer to [AWS EC2 identity set up](service_x509_credentials_aws.md) 
   
* We will be using Athenz's Service Identity Agent Daemon ( siad ) for EC2 to get the identity. Drop a config file `/etc/sia/sia_config` which will be used by siad
  with following content -
  
```json
{
  "version": "1.0.0",
  "service": "aws-demo",
  "ssh": false,
  "accounts": [
    {
      "domain": "athenz",
      "account": "111111111111"
    }
  ]
}
```

  Athenz ZTS can issue SSH certificates as well, but for now we will not be using that option. Replace the account id in the config above.

* Make /etc/hosts file entry pointing to the ec2-docker instance Athenz is running on. e.g.
  
```shell
10.0.0.150 athenz-zts-server
```

!!! Note
    Make sure this ec2 instance can communicate with ec2-docker instance over port 8443 ( Athenz Token Management Service is listening on port 8443 )

* Get the Athenz CA certificate from ec2-docker instance and store it at /opt/athenz/athenz_ca.pem You will be able to find this file on ec2-docker instance
  at `docker/sample/CAs/athenz_ca.pem` inside the git check out directory of Athenz.
  
* Download siad binary for Linux and copy it to `/usr/local/bin`

* Run following command to get the identity certificate 

```shell
sudo /usr/local/bin/siad -cmd post -zts athenz-zts-server -ztscacert /opt/athenz/athenz_ca.pem -ztsawsdomain aws.athenz.cloud
```
  
* SIAD stores the certificate at `/var/lib/sia/certs` and corresponding private key at `/var/lib/sia/keys`. Verify the Common Name ( CN ) in the certificate

```shell
openssl x509 -in /var/lib/sia/certs/athenz.ec2-demo.cert.pem -noout -subject
```
