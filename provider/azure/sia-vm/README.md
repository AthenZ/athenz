# SIA for Azure VMs

## Configuration

SIA Azure requires a configuration file to be present in the /etc/sia/sia_config with the
following required attributes if the property does not want to use the default settings
which require the use of the Azure VM tags in the name format of
`athenz:<property-domain-name>.<property-service-name>`:

```json
{
    "version": "1.0.0",
    "service": "property-service-name",
    "accounts": [
        {
            "domain":  "property-domain-name",
            "account": "account-azure-subscription-id"
        }
    ]
}
```

SIA Configuration file is also required if the user wants to change the default
user/group settings that the private key is owned by. By default, the private key
is owned by user `root` and readable by group `athenz`. If the user wants to
provide access to their service identity private key to another user, it can
be accomplished by adding the user to the group `athenz`. If the user wants to
change the user and group values, a config file must be dropped with the following
optional fields:

```json
{
    "version": "1.0.0",
    "service": "property-service-name",
    "accounts": [
        {
            "domain":  "property-domain-name",
            "account": "account-azure-subscription-id",
            "user": "unix-username",
            "group": "unix-groupname"
        }
    ]
}
```
