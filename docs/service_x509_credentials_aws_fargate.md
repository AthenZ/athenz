## Domain Registration

Identify your Athenz domain before you can proceed by visiting Athenz UI.

Follow the [instructions documented for EC2 instances](service_x509_credentials_aws.md#domain-registration) to register your domain if one doesn't exist already.

## AWS Account ID Registration

To register an AWS Account with a domain, run the following command:
```
zms-cli -d <domain-name> set-aws-account <aws-account-id>
```

## Athenz Service Identity Registration

Create a service identity for your AWS Fargate task in your Athenz domain. This full service identity name `<domain>.<service>` will be the IAM role name that you will need to create in AWS IAM and set up a trust relationship with your Fargate Task Service Role.

In the Athenz UI, select your domain, select the `Services` tab and then choose `Add a Service`  link in the top left corner. You must provide a service name and an optional description for your service. Since this is for AWS Fargate, you do not need to provide a public key as we'll obtain a client certificate based on AWS credentials.

![Service Identity Registration](images/aws-service-register.png)

## Athenz Service Identity Authorization Role and Policy

Before ZTS can validate and issue X.509 TLS Certificates to the AWS Fargate tasks, it must validate that the service owner has authorized its service to be launched by AWS Fargate Provider. In the Athenz UI select your service that was created in the previous step and click on the icon in the `Providers` column:

![Service Identity Authorization_1](images/aws-service-authorize.png)

Then, click on the `Allow` button to authorize your service to be launched by AWS EC2/EKS/Fargate provider.

![Service Identity Authorization_2](images/aws-service-authorize-2.png)

## IAM Role Setup

There are two IAM roles required for instances to obtain Athenz X.509 certificates:

- Fargate Task Role
- Athenz Service Identity Assume Role

It is assumed that at this point you have already configured the first Fargate Task Role that your code will be launched with. This recommended name for this role is `<domain>.<service>-service` since this allows to automatically determine the service name (by stripping the -service suffix) without requiring the administrator to provide a `sia_config` file as part of the bootstrap.

The second Athenz Service Identity IAM Assume Role must be created and must have the `<domain>.<service>` name. This role will not have any permissions but instead will have a trust relationship with your Fargate task role such that your Fargate task role can assume this role.

In the AWS Console, select `IAM` from the Services drop down and then click on the `Roles` link in the left sidebar. Choose the `Create Role` button. Under the `AWS Service` type, select `Elastic Container Service` and choose `Next: Permissions` button in the bottom right corner.

In the `Attach permissions policy` screen do not choose any permissions and just click on the `Next: Review` button in the bottom right corner to continue. Specify the `Role name` in the `<domain>.<service>` format and choose `Create Role` to complete the process.

In the Roles list view, choose the role just created and choose the `Trust Relationships` tab.

Click on `Edit trust relationship` button and append a block containing the following policy to the `Statement` block Replace the `<account-id>` and `<fargate-task-role>` values with their corresponding values for your environment:

```
 {
   "Effect": "Allow",
   "Principal": {
     "AWS": "arn:aws:iam::<account-id>:role/<fargate-task-role>"
   },
   "Action": "sts:AssumeRole"
 }
```

Once correctly updated, your Fargate task role must appear in the `Trusted entities` table.

## Installing SIA in Container

The AWS SIA source is part of the Athenz project and can be found in:
```
provider/aws/sia-ec2
``` 
Follow the readme for instructions on how to install it.

Typically you run the `siad` binary in your container and let it run continuously to register and refresh your service certificate daily
since `systemd` does not run in a typical docker image. If you only want to run `siad` as a command line
utility that just registers and refreshes the service and role certificates when executed, you can use the following
command line options (Register must be called once within the first 30 mins when the instance is bootstrapped):

- Instance Register: `/usr/sbin/siad -cmd post`
- Service Certificate Refresh: `/usr/sbin/siad -cmd rotate`
- Role Certificate Refresh: `/usr/sbin/siad -cmd rolecert`

## Expiry Time

Unlike EC2, Athenz x.509 Certificate for Fargate are only issued for 7 days only due to different security requirements.
