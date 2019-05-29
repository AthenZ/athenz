# Setup UI on AWS

- [IAM role setup](#iam-role-setup)
- [VPC setup](#vpc-setup)
- [S3 bucket for UI data](#create-s3-bucket-to-store-ui-data)    
    - [Generate and upload service private key](#generate-and-upload-service-private-key)
    - [Upload server X.509 cert and key](#upload-server-x-509-cert-and-key)
    - [Upload ZMS CA Certs](#upload-zms-ca-certs)
    - [Upload ZMS Public key](#upload-zms-public-key)
- [Update ZMS DATA BUCKET](#update-zms-data-bucket)
- [Register UI Service](#register-ui-service)
- [Packer](#packer)
    - [Packer VPC setup](#packer-vpc-setup)
    - [Build UI Image](#build-ui-image)
- [Deploy UI](#deploy-ui) 

## IAM role setup

Create EC2 profile role for UI using [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/ui-setup/cloud-formation/athens-ui-aws-roles-setup.yaml). This template creates a role named `athenz.ui-service`

## VPC Setup

Setup VPC using the [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/ui-setup/cloud-formation/athens-ui-aws-resource-setup.yaml) and giving the following mandatory parameters:

- `Route53HostedZoneName`
- `Route53RecordName`
- `S3AccessLogBucketName`(Created during ZMS Setup)
- `Environment`

The other parameters are set by default. Change them as per your requirement

*NOTE - Modifying the other defaults might require subsequent changes.*

Following resources will be created after executing the template
1. 2 availability zones
1. Public & Private subnets for ui in each availability zone
1. 2 NAT gateways and elastic IPs
1. NACL's for the subnets
1. Internet gateways for all public subnets
1. Route tables for all subnets
1. Elastic load balancer
1. Route 53 DNS entry
1. UI server & ELB security groups

## Create S3 bucket to store UI data

Create S3 bucket for storing ui certificates & keys with appropriate policy as follows:

```
{
"Version": "2012-10-17",
"Statement": [ 
    {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::<aws_account_id>:role/athenz.ui-service"
        },
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3::: <bucket-name> /*"
    }
    ]
}
```

Also enable Default Encryption for your bucket.

*NOTE - athenz.ui-service is the EC2 role created using IAM template above*

### Generate and upload service private key

Generate a unique private key that UI Server will use to sign user's authorized service tokens. The UI has already been authorized to be allowed to carry out the users' requested operations.

```
openssl genrsa -out service_private_key 2048
openssl rsa -in service_private_key -pubout > ui_service_x509_key_public
```

Upload the service private key with name `service_private_key` onto the s3 bucket

### Upload server X.509 cert and key

*NOTE - For Athenz UI production server it is strongly recommended to purchase a certificate for HTTPS access from a well known certificate authority.Follow the instructions provided by the Certificate Authority to generate your private key and then the Certificate Request (CSR).*

However if you want to use the self signed certificate, you can generate a self signed certificate
as below:

```
openssl req -newkey rsa:2048 -nodes -keyout service_x509_key -x509 -days 365 -out service_x509_cer
```

- Verify your certs

```
openssl x509 -in service_x509_cert -text -noout
```

- Once you have received your X509 certificate and key,
    - Upload the certificate on s3 bucket with name `service_x509_cert`
    - Upload the private key with name `service_x509_key`

### Upload ZMS CA Certs

- Upload ZMS CA Cert with key `zms_service_x509_ca_certs`. They will be needed so that UI can communicate securely with ZMS

### Upload ZMS Public key

- Upload ZMS public key with name `zms_service_x509_key_public.pem`

It is required to generate athenz.conf file at `/opt/athenz-ui/conf/athenz.conf` to include the ZMS Server URL and the registered public keys that the athenz client libraries and utilities will use to establish connection and validate any data signed by the ZMS Server.

## Update ZMS Data Bucket

- Upload UI service public key to ZMS Data Bucket with key `ui_service_x509_key_public.pem`

## Register UI Service

In order for UI to access ZMS domain data, it must identify itself as a registered service in ZMS. Use `zms-cli` utility to register a new service in `athenz` domain. If ZMS Servers are running with a X509 certificate from a well known certificate authority (not a self-signed one) we don't need to reference the CA cert like we are doing below for self signed certs.

Login into your zms-server instance as domain admin you created during zms setup and run the below commands:

```
- Download ZMS CA Certs(If using self signed certs)
    aws s3 cp s3://<zms_bucket_name>/zms_service_x509_ca_certs /tmp/zms_service_x509_ca_certs
- Download UI public key
    aws s3 cp s3://<zms_bucket_name>/ui_service_x509_key_public.pem/tmp/ui_service_x509_key_public.pem
- Add a new domain named `athenz`
    /opt/zms/bin/zms-cli -c /tmp/service_x509_ca_certs -z  <zms_url> -add-domain athenz
- Register Service using zms-cli
    /opt/zms/bin/zms-cli -c /tmp/service_x509_ca_certs -z <zms_url> -d athenz add-service ui 0 /tmp/ui_service_x509_key_public.pem
```

For e.g. If your zms server is running at https://athenz.zms.com:4443 then pass `https://athenz.zms.com:4443/zms/v1`.

## Packer

### Packer VPC Setup

Packer VPC was set during zms setup, update `packer.json` accordingly:

```
{
   "subnet_id":"<packer_public_subnet_id>",
   "vpc_id": "<vpc_id>",
   "aws_region": "<aws-region where you created the resources>",
   "aws_ami_name": "ui-aws-cd-image",
   "aws_access_key": "{{env `AWS_ACCESS_KEY_ID`}}",
   "aws_secret_key": "{{env `AWS_SECRET_ACCESS_KEY`}}",
   "aws_session_token": "{{env `AWS_SESSION_TOKEN`}}",
   "ssh_keypair_name":"<EC2_SSH_Key_Name>",
   "ssh_private_key_file":"<PATH_TO_SSH_KEYPAIR>",
   "source_ami": "ami-02c71d7a"
}
```

### Build UI image

Build the image with packer using the following command 

```
cd /aws-setup/ui-setup
packer build packer/aws/packer.json
```

## Deploy UI

Run [cloudformation template](https://github.com/yahoo/athenz/blob/master/aws-setup/ui-setup/cloud-formation/athenz-ui-aws-instance-deployment.yaml) to bring up the ui-instances in 2 availability zones.

- The imageID parameter should be set to the image created in above step.

The UI Server is now up and running.

*NOTE - If using self-signed X509 certificates for Athenz ZMS and UI servers, the administrator must add exceptions when accessing Athenz UI or install the self-signed certificates for those two servers into his/her own web browser. The administrator must first access the ZMS Server endpoint in the browser to accept the exception since the Athenz UI contacts ZMS Server to get an authorized token for the user when logging in. Alternatively, the administrator may decide to install the self-signed certificates for the ZMS and UI servers in their browser.* 
