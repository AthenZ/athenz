# Setup ZMS on AWS

- [IAM Role Setup](#iam-role-setup)
- [S3 Bucket for ELB Access Logs](#s3-bucket-for-elb-access-logs)
- [VPC setup](#vpc-setup)
- [RDS Setup](#rds-setup)
    - [Create Aurora MySQL Cluster](#create-aurora-mysql-cluster)
    - [Schema Setup](#schema-setup)
- [S3 Bucket to Store ZMS Data](#create-s3-bucket-to-store-zms-data)
    - [Generate and Upload Service Private Key](#generate-and-upload-service-private-key-and-id)
    - [Upload Server X.509 Cert and Key](#upload-server-x-509-cert-and-key)
    - [Upload RDS CA Certs](#upload-rds-ca-certs)
    - [Upload Truststore Password](#upload-truststore-password) 
    - [Upload ZMS DB User Password](#upload-zms-db-user-password)
- [Create S3 Bucket for Audit logs](#create-s3-bucket-for-audit-logs)
- [Configure Variables and Properties](#configure-variables-and-properties)
    - [aws_init.sh](#edit-aws_init-sh)
    - [zms.properties](#edit-zms-properties-file)
        - [Database Access](#database-access)
        - [User Authentication](#user-authentication)
        - [Domain Admins](#domain-admins)
    - [athenz.properties](#edit-athenz-properties-file)
        - [Truststore and Keystore Settings](#truststore-and-keystore-settings)
- [Packer](#packer)
    - [Packer VPC setup](#packer-vpc-setup)
    - [Build ZMS Image](#build-zms-image)
- [Deploy ZMS](#deploy-zms) 


## IAM Role Setup

Create an EC2 profile role for ZMS using the following [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/zms-setup/cloud-formation/athens-zms-aws-roles-setup.yaml).
This template creates a role named `athenz.zms-service`.

## S3 Bucket for ELB Access Logs

Create a S3 bucket needed to store ELB access logs with the following bucket policy:

```
{
 "Version": "2012-10-17",
 "Statement": [
     {
         "Sid": "",
         "Effect": "Allow",
         "Principal": {
             "AWS": "arn:aws:iam::<aws-account-id>:root"
         },
         "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::<your bucket name>/*/AWSLogs/<aws-account-id>/*"
     }
 ]
}
```

Refer to [AWS ELB Documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#access-logging-bucket-permissions) for more details on bucket policy.

## VPC Setup

Setup a VPC using the following [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/zms-setup/cloud-formation/athens-zms-aws-resource-setup.yaml) by giving the these mandatory parameters:

- `Route53HostedZoneName`
- `Route53RecordName`
- `S3AccessLogBucketName` (Created in the previous step)
- `Environment`

The other parameters are set by default. Change them as per your requirements.

*NOTE - Modifying the other defaults might require subsequent changes.*

Following resources will be created after executing the template:
1. 2 availability zones
1. Public & Private subnets for each availability zone
1. 2 NAT gateways and elastic IPs
1. NACL's for the subnets
1. Internet gateways for all public subnets
1. Route tables for all subnets
1. Elastic load balancer
1. Route 53 DNS entry
1. ZMS Server and ELB security groups

## RDS Setup

### Create Aurora MySQL cluster

Setup an Aurora MySQL compatible cluster using the following [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/zms-setup/cloud-formation/athens-zms-aws-rds-setup.yaml) by giving the following mandatory parameters:

- `Route53HostedZoneName`
- `Route53RecordName`
- `DatabaseUsername`
- `DatabasePassword`
- `Environment`

The other parameters are set by default. Change them as per your requirements.

### Schema Setup

- Create an EC2 instance in private subnet and ssh login into it. After logging in, install the mysql package and use the following command to connect to the cluster

```
mysql -h <RDS_CLUSTER_ENDPOINT> -P 3306 -u <DB_USER> -p
```

- Copy the [zms_server.sql](https://github.com/yahoo/athenz/blob/master/servers/zms/schema/zms_server.sql) file from the Athenz Git repository onto this host and create the database using the following command:

```
mysql -h <RDS_CLUSTER_ENDPOINT> -P 3306 -u <DB_USER> -p  < zms_server.sql
```

- Create a user with full privileges on zms database created above. For e.g. if your ZMS Server will be running on zms1.athenz.com and the user to be created is `athenz-zms` having password `athenz-pass`:

```
CREATE USER 'athenz-zms'@'zms1.athenz.com' IDENTIFIED BY 'athenz-pass';
GRANT ALL PRIVILEGES ON zms_server TO 'athenz-zms'@'zms1.athenz.com';
FLUSH PRIVILEGES;
```

## Create S3 Bucket to Store ZMS Data

Create a S3 bucket for storing zms certificates & keys among other configuration data with an appropriate policy as follows:

```
{
"Version": "2012-10-17",
"Statement": [
    {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::<aws_account_id>:role/athenz.zms-service"
        },
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::<bucket-name>/*"
    }
    ]
}
```

Also enable `Default Encryption` for your bucket.

*NOTE - athenz.zms-service is the EC2 role created using IAM template above*

### Generate and Upload Service Private Key and Id

Generate a unique private key that ZMS Server will use to sign any NTokens it issues:

```
openssl genrsa -out service_private_key 2048
openssl rsa -in service_private_key -pubout > zms_service_x509_key_public
```

Upload the service private key with name `service_private_key` onto the s3 bucket.

Upload the service private key id with name `service_private_key_id` onto the s3 bucket. This file just contains
the id of private key. It is not mandatory as the id defaults to `0` if not specified.

### Upload Server X.509 Cert and Key

*NOTE - While it is still possible to generate and use a self-signed X509 certificate for ZMS Server, it is recommended to purchase one for your production server from a well known certificate authority. Having such a certificate installed on your ZMS Servers will no longer require to distribute the server's CA certificate to other hosts (e.g. ZTS Servers, Hosts running ZPU).*

- Follow the instructions provided by the Certificate Authority that you're going to purchase your certificate from to generate your private key and Certificate Request (CSR). Submit your CSR to your CA to generate a x.509 certificate for your ZMS server.

- If you are using self signed certs then run the following commands:

```
openssl genrsa -des3 -out zms_ca_key 4096 (Create ZMS CA Key)
openssl req -x509 -new -nodes -key zms_ca_key -sha256 -days 1024 -out service_x509_ca_certs  (Generate CA Cert)
openssl genrsa -out service_x509_key 2048  (Generate your private key)
openssl req -new -key service_x509_key -out service_x509_csr  (Generate your CSR)
openssl x509 -req -in service_x509_csr -CA service_x509_ca_certs -CAkey zms_ca_key -CAcreateserial -out service_x509_cert -days 730 -sha256  (Generate your Certificate)
```

- Verify your certs

```
openssl x509 -in service_x509_ca_certs -text -noout
openssl x509 -in service_x509_cert -text -noout
```

Once you have received your X509 certificate and key:
    - Upload the certificate to s3 bucket with name `service_x509_cert`
    - Upload the private key with name `service_x509_key`
    - Upload the Root CA cert with name `service_x509_ca_certs`

### Upload RDS CA Certs

RDS Certs are needed if you have set `athenz.zms.jdbc_use_ssl=` property in `zms.properties` to `true`. By default it is set to `false`

- Upload the RDS CA Certs with a filename `service_rds_ca_certs`.

For details on AWS RDS Certs, Please refer to [RDS SSL Certificates in AWS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)

### Upload truststore password

- Upload password you want to use for truststore with a filename `service_x509_store_pwd`

### Upload ZMS DB User Password

- Create a file containing only the password for ZMS Database user(`athenz-zms`) created above during RDS schema setup
- Upload the file to bucket with name `db_user_data`

## Create S3 Bucket for Audit Logs 

Create another bucket for audit logs having the following bucket policy:

```
{
"Version": "2012-10-17",
"Statement": [
    {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {
            "AWS": [
                "arn:aws:iam::488664618023:role/athenz.zms-service"
            ]
        },
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject"
        ],
        "Resource": [
            "arn:aws:s3:::<audit_log_bucket_name>",
            "arn:aws:s3:::<audit_log_bucket_name>/*"
        ]
    }
]
}
```

## Configure Variables and Properties

### Edit aws_init.sh

Update the bucket names, domain admin and RDS Endpoint in `athenz/aws-setup/zms-setup/build/bin/aws_init.sh` by editing the below lines:

```
export ZMS_DATA_BUCKET_NAME="<The name of your zms data bucket>"
export ZMS_AUDIT_LOG_BUCKET_NAME="<The name of your zms audit data bucket>"
export DOMAIN_ADMINS="<zms-admin-name>"
export RDS_MASTER="<zms-rds-database-cluster-endpoint>"
```

When running the server very first time, ZMS Server automatically creates the required domains and sets the running user as the system administrator. The system administrators are the only ones authorized to create top level domains in Athenz. Before running the server very first time, you can configure the set of system administrators who are authorized to create top level domains in Athenz. Set DOMAIN\_ADMINS to unix user id that you want to add as Athenz system administrator. The password for this user is uploaded to ZMS Data S3 Bucket created above with name `admin_pass`.

- Create a file containing password for ZMS Domain Admin
- Upload the file to bucket with name `admin_pass`

The other variables are for truststore & keystore setup. We recommend to use the defaults but if you change then update the corresponding values in `athenz.properties` file discussed later.

### Edit zms.properties file

The following properties need to be edited in `zms.properties` file located at `athenz/aws-setup/zms-setup/build/conf/zms.properties`

#### Database Access

Modify the following settings if RDS username & RDS password filename (stored on S3) are different from defaults suggested above.

```
athenz.zms.object_store_factory_class=com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory
athenz.zms.jdbc_user=athenz-zms
athenz.zms.jdbc_password=db_user_data
```

#### User Authentication

For a user to authenticate himself/herself in ZMS, the server must have the appropriate authentication authority implementation configured. By default, ZMS enables the following two authorities:

- Unix User Authority - using pam login profile to authenticate users
- Principal Authority - validating Principal Tokens that are issued when users authenticate using their unix login password.

This is set using the following properties `athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority`

The server also provides other authorities - e.g. Kerberos, TLS Certificate, that are not enabled by default.

To add your own authentication authority modify the: `athenz.zms.authority_classes=com.yahoo.athenz.auth.impl.PrincipalAuthority,com.yahoo.athenz.auth.impl.UserAuthority` line in `zms.properties` file and include comma separated list of authority implementation classes to support.

#### Domain Admins

Modify the below setting and set it to unix user you passed as domain admin in `aws_init_file` in above steps.

`athenz.zms.domain_admin=user.zms-admin`

### Edit athenz.properties file

The following properties need to be edited in `athenz.properties` file located at `athenz/aws-setup/zms-setup/build/conf/athenz.properties`

#### Truststore and Keystore Settings

If you modified the truststore and keystore paths and password in the `aws_init.sh` file then change the below settings in `athenz.properties` file accordingly:

  - `athenz.ssl_key_store=/opt/zms/conf/zms_keystore.pkcs12 //path to the keystore file that contains the server's certificate`
  - `athenz.ssl_key_store_type=PKCS12 //specifies the type for the keystore specified in the`
  - `athenz.ssl_key_store_password=service_x509_store_pwd //S3 bucket  key name for Password for the keystore specified in the athenz.ssl_key_store property`
  - `athenz.ssl_trust_store=/opt/zms/conf/zms_truststore.jks //path to the trust store file that contains CA certificates trusted by this Jetty instance`
  - `athenz.ssl_trust_store_type=JKS //specifies the type for the truststore specified`
  - `athenz.ssl_trust_store_password=service_x509_store_pwd //password for the truststore`

## Packer

### Packer VPC Setup

Setup packer vpc by using the [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/cloud-formation/packer_vpc.yaml) and update `packer.json` file accordingly.

```
{
   "subnet_id":"<packer_public_subnet_id>",
   "vpc_id": "<vpc_id>",
   "aws_region": "<aws-region where you created the resources>",
   "aws_ami_name": "zms-aws-cd-image",
   "aws_access_key": "{{env `AWS_ACCESS_KEY_ID`}}",
   "aws_secret_key": "{{env `AWS_SECRET_ACCESS_KEY`}}",
   "aws_session_token": "{{env `AWS_SESSION_TOKEN`}}",
   "ssh_keypair_name":"<EC2_SSH_Key_Name>",
   "ssh_private_key_file":"<PATH_TO_SSH_KEYPAIR>",
   "source_ami": "ami-02c71d7a"
}
```

### Build ZMS image

Build the image with packer using the following command:

```
cd /aws-setup/zms-setup
packer build packer/aws/packer.json
```

## Deploy ZMS

Run [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/zms-setup/cloud-formation/athenz-zms-aws-instance-deployment.yaml) to bring up the zms-instances in 2 availability zones.

- The imageID parameter should be set to the image created in previous step.

The ZMS Server is now up and running.
