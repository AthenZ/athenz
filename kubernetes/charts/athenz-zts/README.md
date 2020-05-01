<a id="markdown-athenz-zts-authz-management-system" name="athenz-zts-authz-management-system"></a>
# Athenz ZTS (authZ Management System)

Server for managing Athenz RBAC policy and performing centralized authorization.

<!-- TOC -->

- [Athenz ZTS (authZ Management System)](#athenz-zts-authz-management-system)
    - [Getting Started](#getting-started)
    - [Introduction](#introduction)
        - [Prerequisites](#prerequisites)
        - [Usage](#usage)
            - [install/deploy](#installdeploy)
            - [uninstall/delete](#uninstalldelete)
    - [Parameters](#parameters)
        - [Global parameters](#global-parameters)
        - [ZTS parameters](#zts-parameters)
        - [Values read from properties files](#values-read-from-properties-files)
    - [Points to Note](#points-to-note)
        - [Using `helm upgrade`](#using-helm-upgrade)
        - [About ZTS passwords](#about-zts-passwords)
        - [TODO](#todo)
    - [Authors](#authors)
    - [License](#license)
    - [Acknowledgments](#acknowledgments)

<!-- /TOC -->

<a id="markdown-getting-started" name="getting-started"></a>
## Getting Started

```bash
helm upgrade --install my-release ./athenz-zts
# helm upgrade --install my-release ./athenz-zts --dry-run --debug
```

<a id="markdown-introduction" name="introduction"></a>
## Introduction

This chart bootstraps an Athenz ZTS deployment on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

Database deployment is not inclued in this chart. Please prepare your database (or other ZTS compatible storage) in advance.


<a id="markdown-prerequisites" name="prerequisites"></a>
### Prerequisites

- environment
    - Kubernetes v1.17+
    - Helm v3.1.1+
- configuration
    - MySQL database with required [schema](https://github.com/yahoo/athenz/blob/master/servers/zts/schema/zts_server.sql)
    - TLS
        - server certificate
        - trusted CAs
    - ZTS private key
    - ZTS configuration files ([templates](./files/conf))

<a id="markdown-usage" name="usage"></a>
### Usage

<a id="markdown-installdeploy" name="installdeploy"></a>
#### install/deploy

```bash
# deploys with default configuration
helm install my-release ./athenz-zts

# deploys with custom configuration
# helm install my-release ./athenz-zts -f ./my-values.yaml
```
The command deploys ZTS to the Kubernetes cluster. Please refer to the [Parameters](#parameters) section for customizable values.

<a id="markdown-uninstalldelete" name="uninstalldelete"></a>
#### uninstall/delete

```bash
helm delete my-release
```
The command removes all the Kubernetes components associated with the chart and deletes the release.

<a id="markdown-parameters" name="parameters"></a>
## Parameters

<a id="markdown-global-parameters" name="global-parameters"></a>
### Global parameters

| **Parameter**             | **Description**                                 | **Default** |
| ------------------------- | ----------------------------------------------- | ----------- |
| `global.imageRegistry`    | Global Docker image registry                    | `""`        |
| `global.imagePullSecrets` | Global Docker registry secret names as an array | `[]`        |


<a id="markdown-zts-parameters" name="zts-parameters"></a>
### ZTS parameters

| **Parameter**                        | **Description**                                                                                                                                                                                                                                                                                                                                      | **Default**                                                                                                              |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `image.registry`                     | ZTS image registry                                                                                                                                                                                                                                                                                                                                   | `docker.io`                                                                                                              |
| `image.repository`                   | ZTS image name                                                                                                                                                                                                                                                                                                                                       | `wzyahoo/athenz-zts-server`                                                                                              |
| `image.tag`                          | ZTS image tag                                                                                                                                                                                                                                                                                                                                        | `latest`                                                                                                                 |
| `image.setup.repository`             | ZTS setup image name                                                                                                                                                                                                                                                                                                                                 | `wzyahoo/athenz-setup-env`                                                                                               |
| `image.setup.tag`                    | ZTS setup image tag                                                                                                                                                                                                                                                                                                                                  | `latest`                                                                                                                 |
| `image.mysql.repository`             | MySQL client image name                                                                                                                                                                                                                                                                                                                              | `mariadb`                                                                                                                |
| `image.mysql.tag`                    | MySQL client image tag                                                                                                                                                                                                                                                                                                                               | `10.5.2`                                                                                                                 |
| `image.pullPolicy`                   | ZTS image pull policy                                                                                                                                                                                                                                                                                                                                | `IfNotPresent`                                                                                                           |
| `image.pullSecrets`                  | Specify docker-registry secret names as an array                                                                                                                                                                                                                                                                                                     | `[]`                                                                                                                     |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `password.jdbc`                      | MySQL password                                                                                                                                                                                                                                                                                                                                       | `""`                                                                                                                     |
| `password.keystore`                  | Key store password (auto-generated if not set)                                                                                                                                                                                                                                                                                                       | `""`                                                                                                                     |
| `password.truststore`                | Trust store password (auto-generated if not set)                                                                                                                                                                                                                                                                                                     | `""`                                                                                                                     |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `files.ztsKey`                       | ZTS private key path                                                                                                                                                                                                                                                                                                                                 | `files/secrets/zts_private.pem`                                                                                          |
| `files.tls.crt`                      | ZTS server certificate path                                                                                                                                                                                                                                                                                                                          | `files/secrets/tls/zts_cert.pem`                                                                                         |
| `files.tls.key`                      | ZTS server certificate private key path                                                                                                                                                                                                                                                                                                              | `files/secrets/tls/zts_key.pem`                                                                                          |
| `files.tls.ca`                       | ZTS trusted CA certificate paths                                                                                                                                                                                                                                                                                                                     | `[ "files/secrets/tls/CAs/athenz_ca.pem", "files/secrets/tls/CAs/service_ca.pem", "files/secrets/tls/CAs/user_ca.pem" ]` |
| `files.conf`                         | ZTS config file path (wildcard)                                                                                                                                                                                                                                                                                                                      | `files/conf/*`                                                                                                           |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `existingSecret`                     | Use existing secret for password, keys: `zts_private.pem`, `jdbc`, `keystore`, `truststore`                                                                                                                                                                                                                                                          | `""`                                                                                                                     |
| `existingTLSSecret`                  | Use existing secret for TLS certificate, keys: `tls.crt`, `tls.key`                                                                                                                                                                                                                                                                                  | `""`                                                                                                                     |
| `existingTLSCASecret`                | Use existing secret as trusted certificates                                                                                                                                                                                                                                                                                                          | `""`                                                                                                                     |
| `existingTLSStoreSecret`             | Use existing secret for key store & trust store, keys: `zts_keystore.pkcs12`, `zts_truststore.jks`                                                                                                                                                                                                                                                   | `""`                                                                                                                     |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `serviceAccountName`                 | Service account of the deployment                                                                                                                                                                                                                                                                                                                    | `""`                                                                                                                     |
| `replicaCount`                       | Number of ZTS Pods to run                                                                                                                                                                                                                                                                                                                            | `1`                                                                                                                      |
| `updateStrategy`                     | Set up update strategy                                                                                                                                                                                                                                                                                                                               | `{"type": "RollingUpdate"}`                                                                                              |
| `schedulerName`                      | Name of the alternate scheduler                                                                                                                                                                                                                                                                                                                      | `""`                                                                                                                     |
| `podAnnotations`                     | Pod annotations                                                                                                                                                                                                                                                                                                                                      | `{}` (evaluated as a YAML)                                                                                               |
| `affinity`                           | Affinity for pod assignment                                                                                                                                                                                                                                                                                                                          | `{}` (evaluated as a YAML)                                                                                               |
| `nodeSelector`                       | Node labels for pod assignment                                                                                                                                                                                                                                                                                                                       | `{}` (evaluated as a YAML)                                                                                               |
| `tolerations`                        | Tolerations for pod assignment                                                                                                                                                                                                                                                                                                                       | `[]` (evaluated as a YAML)                                                                                               |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `securityContext.enabled`            | Enable security context for ZTS pods                                                                                                                                                                                                                                                                                                                 | `true`                                                                                                                   |
| `securityContext.fsGroup`            | Group ID for the ZTS filesystem                                                                                                                                                                                                                                                                                                                      | `1001`                                                                                                                   |
| `securityContext.runAsGroup`         | Group ID for the ZTS container                                                                                                                                                                                                                                                                                                                       | `1001`                                                                                                                   |
| `securityContext.runAsUser`          | User ID for the ZTS container                                                                                                                                                                                                                                                                                                                        | `10001`                                                                                                                  |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `livenessProbe.initialDelaySeconds`  | Delay before liveness probe is initiated                                                                                                                                                                                                                                                                                                             | `60`                                                                                                                     |
| `livenessProbe.periodSeconds`        | How often to perform the probe                                                                                                                                                                                                                                                                                                                       | `10`                                                                                                                     |
| `livenessProbe.timeoutSeconds`       | When the probe times out                                                                                                                                                                                                                                                                                                                             | `1`                                                                                                                      |
| `livenessProbe.failureThreshold`     | Minimum consecutive failures for the probe                                                                                                                                                                                                                                                                                                           | `5`                                                                                                                      |
| `livenessProbe.successThreshold`     | Minimum consecutive successes for the probe                                                                                                                                                                                                                                                                                                          | `1`                                                                                                                      |
| `readinessProbe.enabled`             | Enable/disable readinessProbe                                                                                                                                                                                                                                                                                                                        | `60`                                                                                                                     |
| `readinessProbe.initialDelaySeconds` | Delay before readiness probe is initiated                                                                                                                                                                                                                                                                                                            | `30`                                                                                                                     |
| `readinessProbe.periodSeconds`       | How often to perform the probe                                                                                                                                                                                                                                                                                                                       | `10`                                                                                                                     |
| `readinessProbe.timeoutSeconds`      | When the probe times out                                                                                                                                                                                                                                                                                                                             | `1`                                                                                                                      |
| `readinessProbe.failureThreshold`    | Minimum consecutive failures for the probe                                                                                                                                                                                                                                                                                                           | `2`                                                                                                                      |
| `readinessProbe.successThreshold`    | Minimum consecutive successes for the probe                                                                                                                                                                                                                                                                                                          | `1`                                                                                                                      |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `resources.limits`                   | The resources limits for the ZTS container                                                                                                                                                                                                                                                                                                           | `{}`                                                                                                                     |
| `resources.requests`                 | The requested resources for the ZTS container                                                                                                                                                                                                                                                                                                        | `{"memory": "4096Mi", "cpu": "500m"}`                                                                                    |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `service.annotations`                | Service annotations                                                                                                                                                                                                                                                                                                                                  | `{}` (evaluated as a YAML)                                                                                               |
| `service.port`                       | Service TCP port                                                                                                                                                                                                                                                                                                                                     | `4443`                                                                                                                   |
| `service.type`                       | Kubernetes Service type                                                                                                                                                                                                                                                                                                                              | `LoadBalancer`                                                                                                           |
| `service.clusterIP`                  | Service cluster IP address                                                                                                                                                                                                                                                                                                                           | `""`                                                                                                                     |
| `service.externalIPs`                | Service external IP addresses                                                                                                                                                                                                                                                                                                                        | `[]`                                                                                                                     |
| `service.loadBalancerIP`             | User-specified load balancer IP                                                                                                                                                                                                                                                                                                                      | `""`                                                                                                                     |
| `service.loadBalancerSourceRanges`   | Restricts access for load balancer                                                                                                                                                                                                                                                                                                                   | `[]`                                                                                                                     |
| `service.externalTrafficPolicy`      | Enable client source IP preservation                                                                                                                                                                                                                                                                                                                 | `""`                                                                                                                     |
| `service.sessionAffinity`            | Enables client IP based session affinity. Must be `ClientIP` or `None` if set.                                                                                                                                                                                                                                                                       | `""`                                                                                                                     |
| `service.healthCheckNodePort`        | If `service.type` is `NodePort` or `LoadBalancer` and `service.externalTrafficPolicy` is set to `Local`, set this to [the managed health-check port the kube-proxy will expose](https://kubernetes.io/docs/tutorials/services/source-ip/#source-ip-for-services-with-typenodeport). If blank, a random port in the `NodePort` range will be assigned | `0`                                                                                                                      |
| `service.nodePort`                   | Service TCP node port                                                                                                                                                                                                                                                                                                                                | `0`                                                                                                                      |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `extraInitContainers`                | Additional init. containers as a string to be passed to the `tpl` function                                                                                                                                                                                                                                                                           |                                                                                                                          |
| `sidecarContainers`                  | Additional sidecars as a string to be passed to the `tpl` function                                                                                                                                                                                                                                                                                   |                                                                                                                          |

<a id="markdown-values-read-from-properties-files" name="values-read-from-properties-files"></a>
### Values read from properties files

| **Parameter**                                  | **Description**                    | **Default**                                                                   |
| ---------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------- |
| `athenz.zts.jdbc_user`                         | ZTS MySQL user                     | `zts_admin`                                                                   |
| `athenz.zts.jdbc_store`                        | ZTS MySQL URL                      | `jdbc:mysql://zts-db-mariadb.default.svc.cluster.local:3306/zts_server`       |
| `athenz.zts.jdbc_ro_user`                      | ZTS MySQL (read-only) user         | `zts_admin`                                                                   |
| `athenz.zts.jdbc_ro_store`                     | ZTS MySQL (read-only) URL          | `jdbc:mysql://zts-db-mariadb-slave.default.svc.cluster.local:3306/zts_server` |
| `athenz.metrics.prometheus.enable`             | Prometheus metric enabled          | `true`                                                                        |
| `athenz.metrics.prometheus.http_server.enable` | Prometheus scrape endpoint enabled | `true`                                                                        |
| `athenz.metrics.prometheus.http_server.port`   | Prometheus port                    | `8181`                                                                        |


<a id="markdown-points-to-note" name="points-to-note"></a>
## Points to Note

<a id="markdown-using-helm-upgrade" name="using-helm-upgrade"></a>
### Using `helm upgrade`

ZTS requires a restart to reload its configuration. To ensure that ZTS will always restart when the underlying configuration changed, please refers to [automatically-roll-deployments](https://helm.sh/docs/howto/charts_tips_and_tricks/#automatically-roll-deployments).

<a id="markdown-about-zts-passwords" name="about-zts-passwords"></a>
### About ZTS passwords

Please pass the ZTS passwords as values to helm during deployment. Prevent including passwords in your properties file since config files  will be deployed as ConfigMap.

<a id="markdown-todo" name="todo"></a>
### TODO

1. add `values.schema.json`
1. support `athenz.zms.client.keymanager_password=dummy` and `athenz.zts.ssl_key_manager_password=`?
    1. moving to HSM?
1. jdbc remove slave
1. add zms URL
1. check egress for provider API
1. About init. container `chmod`, `ZMSFileChangeLogStore.java` need to have permission to chagne to folder permission


<a id="markdown-authors" name="authors"></a>
## Authors

- [WindzCUHK](https://github.com/WindzCUHK)


<a id="markdown-license" name="license"></a>
## License

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0


<a id="markdown-acknowledgments" name="acknowledgments"></a>
## Acknowledgments

- [Yahoo Developer Network](https://developer.yahoo.com/blogs/160486747984/)
- [ZTS Server - Athenz](https://yahoo.github.io/athenz/site/setup_zts_prod/)
