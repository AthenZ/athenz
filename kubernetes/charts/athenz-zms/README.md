# Athenz ZMS (authZ Management System)

Server for managing Athenz RBAC policy and performing centralized authorization.

<!-- TOC depthFrom:2 updateOnSave:true -->

- [Getting Started](#getting-started)
- [Introduction](#introduction)
    - [Prerequisites](#prerequisites)
    - [Usage](#usage)
        - [install/deploy](#installdeploy)
        - [uninstall/delete](#uninstalldelete)
- [Parameters](#parameters)
    - [Global parameters](#global-parameters)
    - [ZMS parameters](#zms-parameters)
    - [Values read from properties files](#values-read-from-properties-files)
- [Points to Note](#points-to-note)
    - [Using `helm upgrade`](#using-helm-upgrade)
    - [About ZMS passwords](#about-zms-passwords)
- [Authors](#authors)
- [License](#license)
- [Acknowledgments](#acknowledgments)

<!-- /TOC -->

<a id="markdown-getting-started" name="getting-started"></a>
## Getting Started

```bash
helm upgrade --install my-release ./athenz-zms
# helm upgrade --install my-release ./athenz-zms --dry-run --debug
```

<a id="markdown-introduction" name="introduction"></a>
## Introduction

This chart bootstraps an Athenz ZMS deployment on a [Kubernetes](http://kubernetes.io) cluster using the [Helm](https://helm.sh) package manager.

Database deployment is not inclued in this chart. Please prepare your database (or other ZMS compatible storage) in advance.


<a id="markdown-prerequisites" name="prerequisites"></a>
### Prerequisites

- environment
    - Kubernetes v1.17+
    - Helm v3.1.1+
- configuration
    - MySQL database with required [schema](https://github.com/AthenZ/athenz/blob/master/servers/zms/schema/zms_server.sql)
    - TLS
        - server certificate
        - trusted CAs
    - ZMS private key
    - ZMS configuration files ([templates](./files/conf))

<a id="markdown-usage" name="usage"></a>
### Usage

<a id="markdown-installdeploy" name="installdeploy"></a>
#### install/deploy

```bash
# deploys with default configuration
helm install my-release ./athenz-zms

# deploys with custom configuration
# helm install my-release ./athenz-zms -f ./my-values.yaml
```
The command deploys ZMS to the Kubernetes cluster. Please refer to the [Parameters](#parameters) section for customizable values.

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


<a id="markdown-zms-parameters" name="zms-parameters"></a>
### ZMS parameters

| **Parameter**                        | **Description**                                                                                                                                                                                                                                                                                                                                      | **Default**                                                                                                              |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `image.registry`                     | ZMS image registry                                                                                                                                                                                                                                                                                                                                   | `docker.io`                                                                                                              |
| `image.tag`                          | ZMS image tag                                                                                                                                                                                                                                                                                                                                        | `latest`                                                                                                                 |
| `image.repository`                   | ZMS image name                                                                                                                                                                                                                                                                                                                                       | `athenz/athenz-zms-server`                                                                                          |
| `image.setup.repository`             | ZMS setup image name                                                                                                                                                                                                                                                                                                                                 | `athenz/athenz-setup-env`                                                                                               |
| `image.setup.tag`                    | ZMS setup image tag                                                                                                                                                                                                                                                                                                                                  | `latest`                                                                                                                 |
| `image.pullPolicy`                   | ZMS image pull policy                                                                                                                                                                                                                                                                                                                                | `IfNotPresent`                                                                                                           |
| `image.pullSecrets`                  | Specify docker-registry secret names as an array                                                                                                                                                                                                                                                                                                     | `[]`                                                                                                                     |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `password.jdbc`                      | MySQL password                                                                                                                                                                                                                                                                                                                                       | `""`                                                                                                                     |
| `password.jdbcRo`                    | MySQL (read-only) password                                                                                                                                                                                                                                                                                                                           | `""`                                                                                                                     |
| `password.keystore`                  | Key store password (auto-generated if not set)                                                                                                                                                                                                                                                                                                       | `""`                                                                                                                     |
| `password.truststore`                | Trust store password (auto-generated if not set)                                                                                                                                                                                                                                                                                                     | `""`                                                                                                                     |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `files.zmsKey`                       | ZMS private key path                                                                                                                                                                                                                                                                                                                                 | `files/secrets/zms_private.pem`                                                                                          |
| `files.tls.crt`                      | ZMS server certificate path                                                                                                                                                                                                                                                                                                                          | `files/secrets/tls/zms_cert.pem`                                                                                         |
| `files.tls.key`                      | ZMS server certificate private key path                                                                                                                                                                                                                                                                                                              | `files/secrets/tls/zms_key.pem`                                                                                          |
| `files.tls.ca`                       | ZMS trusted CA certificate paths                                                                                                                                                                                                                                                                                                                     | `[ "files/secrets/tls/CAs/athenz_ca.pem", "files/secrets/tls/CAs/service_ca.pem", "files/secrets/tls/CAs/user_ca.pem" ]` |
| `files.conf`                         | ZMS config file path (wildcard)                                                                                                                                                                                                                                                                                                                      | `files/conf/*`                                                                                                           |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `existingSecret`                     | Use existing secret for password, keys: `zms_private.pem`, `jdbc`, `jdbcRo`, `keystore`, `truststore`                                                                                                                                                                                                                                                | `""`                                                                                                                     |
| `existingTLSSecret`                  | Use existing secret for TLS certificate, keys: `tls.crt`, `tls.key`                                                                                                                                                                                                                                                                                  | `""`                                                                                                                     |
| `existingTLSCASecret`                | Use existing secret as trusted certificates (all items will be added to the trust store)                                                                                                                                                                                                                                                             | `""`                                                                                                                     |
| `existingTLSStoreSecret`             | Use existing secret for key store & trust store, keys: `zms_keystore.pkcs12`, `zms_truststore.jks`                                                                                                                                                                                                                                                   | `""`                                                                                                                     |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `serviceAccountName`                 | Service account of the deployment                                                                                                                                                                                                                                                                                                                    | `""`                                                                                                                     |
| `replicaCount`                       | Number of ZMS Pods to run                                                                                                                                                                                                                                                                                                                            | `1`                                                                                                                      |
| `updateStrategy`                     | Set up update strategy                                                                                                                                                                                                                                                                                                                               | `{"type": "RollingUpdate"}`                                                                                              |
| `schedulerName`                      | Name of the alternate scheduler                                                                                                                                                                                                                                                                                                                      | `""`                                                                                                                     |
| `podAnnotations`                     | Pod annotations                                                                                                                                                                                                                                                                                                                                      | `{}` (evaluated as a YAML)                                                                                               |
| `affinity`                           | Affinity for pod assignment                                                                                                                                                                                                                                                                                                                          | `{}` (evaluated as a YAML)                                                                                               |
| `nodeSelector`                       | Node labels for pod assignment                                                                                                                                                                                                                                                                                                                       | `{}` (evaluated as a YAML)                                                                                               |
| `tolerations`                        | Tolerations for pod assignment                                                                                                                                                                                                                                                                                                                       | `[]` (evaluated as a YAML)                                                                                               |
|                                      |                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                          |
| `securityContext.enabled`            | Enable security context for ZMS pods                                                                                                                                                                                                                                                                                                                 | `true`                                                                                                                   |
| `securityContext.fsGroup`            | Group ID for the ZMS filesystem                                                                                                                                                                                                                                                                                                                      | `1001`                                                                                                                   |
| `securityContext.runAsGroup`         | Group ID for the ZTS container                                                                                                                                                                                                                                                                                                                       | `1001`                                                                                                                   |
| `securityContext.runAsUser`          | User ID for the ZMS container                                                                                                                                                                                                                                                                                                                        | `10001`                                                                                                                  |
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
| `resources.limits`                   | The resources limits for the ZMS container                                                                                                                                                                                                                                                                                                           | `{}`                                                                                                                     |
| `resources.requests`                 | The requested resources for the ZMS container                                                                                                                                                                                                                                                                                                        | `{"memory": "4096Mi", "cpu": "500m"}`                                                                                    |
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

| **Parameter**                                  | **Description**                    | **Default**                                                                       |
| ---------------------------------------------- | ---------------------------------- | --------------------------------------------------------------------------------- |
| `athenz.metrics.prometheus.enable`             | Prometheus metrics enabled         | `true`                                                                            |
| `athenz.metrics.prometheus.http_server.enable` | Prometheus scrape endpoint enabled | `true`                                                                            |
| `athenz.metrics.prometheus.http_server.port`   | Prometheus port                    | `8181`                                                                            |


<a id="markdown-points-to-note" name="points-to-note"></a>
## Points to Note

<a id="markdown-using-helm-upgrade" name="using-helm-upgrade"></a>
### Using `helm upgrade`

ZMS requires a restart to reload its configuration. To ensure that ZMS will always restart when the underlying configuration changed, please refers to [automatically-roll-deployments](https://helm.sh/docs/howto/charts_tips_and_tricks/#automatically-roll-deployments).

<a id="markdown-about-zms-passwords" name="about-zms-passwords"></a>
### About ZMS passwords

Please pass the ZMS passwords as values to helm during deployment. Prevent including passwords in your properties file since config files will be deployed as ConfigMap.

<a id="markdown-authors" name="authors"></a>
## Authors

- [WindzCUHK](https://github.com/WindzCUHK)


<a id="markdown-license" name="license"></a>
## License

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0


<a id="markdown-acknowledgments" name="acknowledgments"></a>
## Acknowledgments

- [Yahoo Developer Network](https://developer.yahoo.com/blogs/160486747984/)
- [ZMS Server - Athenz](https://yahoo.github.io/athenz/site/setup_zms_prod/)
