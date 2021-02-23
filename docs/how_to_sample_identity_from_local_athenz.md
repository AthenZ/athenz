## Overview
In this guide, you will be able to create a service in Athenz and obtain a service identity in the form of X.509 certificate from Athenz.

## Prerequisites
* [Athenz running locally on docker](local_athenz_on_docker.md)

## Steps

As part of local set up, an example domain by the name "athenz" is created and "athenz-admin" user is added as a domain administrator of that domain. Please refer to [concepts](data_model.md#domains) to understand more about domains.

To see the workflow of obtaining a service identity certificate from Athenz, please use following steps -

* Download latest Athenz Utils from [Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils)
  (click on the `Browse` button, choose the latest version directory and then
  download the `athenz-utils-$latestVer-bin.tar.gz` file)
  & add it in the current shell PATH variable.
  Below `$athenzUtilsLocation` denotes the path where file is downloaded from Maven Central.

```shell
tar -xf $athenzUtilsLocation/athenz-utils-$latestVer-bin.tar.gz -C $athenzUtilsLocation
export PATH=$athenzUtilsLocation/athenz-utils-$latestVer/bin/`uname | tr '[:upper:]' '[:lower:]'`:$PATH
```

* Create a public private key pair, register the new service and its public key in Athenz Management Service. Athenz Management Service (ZMS) is running inside a docker container exposed over local port 4443. 

```shell
mkdir -p docker/sample/example-service
openssl genrsa -out docker/sample/example-service/athenz.example-service.key.pem 4096 2> /dev/null
openssl rsa -pubout -in docker/sample/example-service/athenz.example-service.key.pem -out docker/sample/example-service/athenz.example-service.pub.pem
zms-cli -z https://127.0.0.1:4443/zms/v1 -cert docker/sample/domain-admin/team_admin_cert.pem -key docker/sample/domain-admin/team_admin_key.pem \
      -d athenz add-service example-service v0 docker/sample/example-service/athenz.example-service.pub.pem
```

Now to obtain a service identity certificate, first domain admin needs to authorize a provider. Athenz uses a generalized model for service providers to launch other service identities in an authorized way through a callback-based verification model.
For more details please refer to [copper argos](copper_argos.md)
In this case we will be using Athenz Token Service itself as a provider. In production, it can be any provider like Kubernetes, Openstack, AWS EC2 etc.

* Domain administrators have a full control over which provider they can authorize to launch their domains' services. Run following command to authorize Athenz Token Service to issue identity certificates for the service created previously

```shell
zms-cli -z https://127.0.0.1:4443/zms/v1 -cert docker/sample/domain-admin/team_admin_cert.pem -key docker/sample/domain-admin/team_admin_key.pem \
      -d athenz set-domain-template zts_instance_launch_provider service=example-service
```

Wait for few seconds for Athenz Token Service to receive the launch authorization changes from Management Service. Athenz Token Service (ZTS) is running inside a docker container exposed over local port 8443.

* Use `zts-svccert` utility to obtain the service identity certificate from Athenz. Athenz also provides agents which can do this for you automatically. 

```shell
zts-svccert -domain athenz -service example-service \
      -private-key docker/sample/example-service/athenz.example-service.key.pem -key-version v0 -zts https://127.0.0.1:8443/zts/v1 \
      -dns-domain zts.athenz.cloud -cert-file docker/sample/example-service/athenz.example-service.cert.pem \
      -cacert docker/sample/CAs/athenz_ca.pem -provider sys.auth.zts -instance instance123
```

* Verify the Common Name ( CN ) in the certificate

```shell
openssl x509 -in docker/sample/example-service/athenz.example-service.cert.pem -noout -subject
```
