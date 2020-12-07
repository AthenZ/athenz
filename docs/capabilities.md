# Athenz Capabilities


## OAuth2 Access Token Support

Athenz supports the OAuth2 standard by enabling the generation of Access Tokens.
Access tokens represent an authoritative statement that a given principal may assume some number of roles in a domain for a limited period. They are signed to prevent tampering.
For more information, please refer to [Obtaining OAuth2 Access Tokens](zts_access_token_guide.md)

## Notifications

Athenz can be configured to send Email Notifications. These notifications can remind users that there are tasks that require their attention such as approving a member's request to join a role, warn them on a certificate that is close to expiration, and even alert them on Athenz health when needed.
To enable notifications, refer to [Email Notifications](email_notifications.md)
 
## Templates

Templates are a collection of predefined roles, policies, and services that can be applied to a domain.
For more information, please refer to [Athenz Templates](athenz_templates.md)

## Audit features

Athenz maintains a history of all the changes that were executed in a domain by their respective administrators. The audit log can be used whenever the administrator wants to find out who made a specific change. The query can be filtered for a specific role in a given period.

## AWS service identity certificate support

The term service within Athenz is more generic than a traditional service. A service identity could represent a command, job, daemon, workflow, as well as both a client and a server.
EC2 instances in AWS are no exception. They too can be bootstrapped to Athenz which allows them to access other Athenz enabled services while providing services for identities with valid authorization.
For more information, please refer to [Athenz Service Identity X.509 Certificate for AWS EC2 instances](service_x509_credentials_aws.md)

## AWS temp credentials support

This feature allows any service to obtain temporary session credentials for a role defined in AWS IAM to carry out operations against AWS Services.
For more information, please refer to [AWS Temp Credentials](aws_temp_creds.md)