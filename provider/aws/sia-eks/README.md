# SIA for AWS EKS

## Configuration

SIA EKS requires a configuration file to be present in the /etc/sia/sia_config with the
following required attributes:

```json
{
    "version": "1.0.0",
    "service": "application-service-name",
    "accounts": [
        {
            "domain":  "application-domain-name",
            "account": "application-account-aws-id"
        }
    ]
}
```

The AWS Account administrator must create an IAM Role called
`<application-domain-name>.<application-service-name>` and this role must be setup
with a trust relationship configured with trusted entity as the role name for EKS IAM Role for Kubernetes Service Account,
which will be used by the application.


SIA Configuration file provides a way to change the default user/group settings that the private key is owned by. 
By default, the private key is owned by user `root` and readable by group `athenz`. If the user wants to
provide access to their service identity private key to another user, it can be accomplished by adding the user to the group `athenz`. 
If the user wants to change the user and group values, a config file must contain following optional fields:

```json
{
    "version": "1.0.0",
    "service": "application-service-name",
    "accounts": [
        {
            "domain":  "application-domain-name",
            "account": "application-account-aws-id",
            "user": "unix-username",
            "group": "unix-groupname"
        }
    ]
}
```

SIA-EKS can be built with following parameters -
e.g.

```shell
GOOS=linux go install -ldflags "-X main.Version=1.0.0 -X main.ZtsEndPoint=zts.athenz.io -X main.DnsDomain=aws.athenz.cloud -X main.ProviderPrefix=athenz.aws" ./...
```

alternatively, those parameters can be passed during runtime and runtime parameters will take precedence over build time parameters.