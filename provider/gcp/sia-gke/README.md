# SIA for GCP GKE

## Configuration

SIA GKE requires a configuration file to be present in the /etc/sia/sia_config with the
following required attributes:

```json
{
    "version": "1.0.0",
    "domain": "application-domain-name",
    "service": "application-service-name"
}
```

The Google Project administrator must create a Google Service Account with the name
`<application-service-name>` and this Service Account must allow the Kubernetes Service Account to impersonate
using workloadIdentityUser role, which will be used by the application.


SIA Configuration file provides a way to change the default user/group settings that the private key is owned by. 
By default, the private key is owned by user `root` and readable by group `athenz`. If the admin wants to
provide access to their service identity private key to another user, it can be accomplished by adding the user to the group `athenz`. 
If the user wants to change the user and group values, a config file must contain following optional fields:

```json
{
    "version": "1.0.0",
    "domain": "application-domain-name",
    "service": "application-service-name",
    "user": "unix-username",
    "group": "unix-groupname"
}
```

SIA-GKE can be built with following parameters -
e.g.

```shell
GOOS=linux go install -ldflags "-X main.Version=1.0.0 -X main.ZtsEndPoint=zts.athenz.io -X main.DnsDomain=gcp.athenz.cloud -X main.ProviderPrefix=athenz.gcp" ./...
```

alternatively, those parameters can be passed during runtime and runtime parameters will take precedence over build time parameters.