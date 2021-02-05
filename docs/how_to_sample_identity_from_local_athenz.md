## Overview
In this guide, you will be able to create a service in Athenz and obtain a service identity in the form of X.509 certificate from Athenz.

## Prerequisites
* [Athenz running locally on docker](local_athenz_on_docker.md)

## Steps

As part of local set up, an example domain by the name "athenz" is created and "athenz-admin" user is added as a domain administrator of that domain. Please refer to [concepts](data_model.md#domains) to understand more about domains.

To see the workflow of obtaining a service identity certificate from Athenz, please use following steps -

* Create a public private key pair, register the new service and its public key in Athenz Management Service

```shell
docker run --rm -t --network="athenz" -v "$(git rev-parse --show-toplevel):/athenz" --user "$(id -u):$(id -g)" athenz/athenz-setup-env sh /athenz/docker/setup-scripts/sample-identity/sample-service-setup.sh
```

Now to obtain a service identity certificate, first domain admin needs to allow a provider. Athenz uses a generalized model for service providers to launch other service identities in an authorized way through a callback-based verification model.
For more details please refer to [copper argos](copper_argos.md)

In this case we will be using Athenz Token Service itself as a provider. In production it can be any provider like Kubernetes, Openstack, AWS EC2 etc.

Add Athenz Token Service as a provider

```shell
docker run --rm -t --network="athenz" -v "$(git rev-parse --show-toplevel):/athenz" --user "$(id -u):$(id -g)" athenz/athenz-setup-env sh /athenz/docker/setup-scripts/sample-identity/zts-provider-setup.sh
```

Domain administrators has a full control over which provider they can authorize to launch their domains' services. Run following command to authorize Athenz Token Service to provide identity certificate for the service created previously

```shell
docker run --rm -t --network="athenz" -v "$(git rev-parse --show-toplevel):/athenz" --user "$(id -u):$(id -g)" athenz/athenz-setup-env sh /athenz/docker/setup-scripts/sample-identity/launch-authorization.sh
```

Use `zts-svccert` utility to obtain the service identity certificate from Athenz. Athenz also provides agents which can do this for you automatically. 

```shell
docker run --rm -t --network="athenz" -v "$(git rev-parse --show-toplevel):/athenz" --user "$(id -u):$(id -g)" athenz/athenz-setup-env sh /athenz/docker/setup-scripts/sample-identity/obtain-identity.sh
```
