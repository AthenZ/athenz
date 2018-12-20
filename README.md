![Athenz](docs/images/athenz-logo.png)

# Athenz

[![Build Status](https://travis-ci.org/yahoo/athenz.svg?branch=master)](https://travis-ci.org/yahoo/athenz)

> Athenz is a set of services and libraries supporting service authentication and role-based authorization (RBAC) for provisioning and configuration (centralized authorization) use cases as well as serving/runtime (decentralized authorization) use cases. Athenz authorization system utilizes x.509 certificates and two types of tokens: Principal Tokens (N-Tokens) and RoleTokens (Z-Tokens). The use of x.509 certificates is strongly recommended over tokens. The name "Athenz" is derived from "AuthNZ" (N for authentication and Z for authorization).

## Table of Contents

* [Background](#background)
* [Install](#install)
* [Usage](#usage)
* [Contribute](#contribute)
* [License](#license)

## Background

Athenz is an open source platform for X.509 certificate based service authentication
and fine grained role based access control in dynamic infrastructures. It provides
support for the following three major functional areas.

### Service Authentication

Athenz provides secure identity in the form of short lived X.509 certificate
for every workload or service deployed in private (e.g. Openstack, K8S, Screwdriver)
or public cloud (e.g. AWS EC2, ECS, Fargate, Lambda). Using these X.509 certificates
clients and services establish secure connections and through mutual TLS authentication verify
each other's identity. The service identity certificates are valid for 30 days only
and the service identity agents (SIA) part of those frameworks automatically refresh
them daily. The term service within Athenz is more generic than a traditional service.
A service identity could represent a command, job, daemon, workflow, as well as both an
application client and an application service.

Since Athenz service authentication is based on
[X.509 certificates](https://en.wikipedia.org/wiki/X.509), it is
important that you have a good understanding what X.509 certificates are
and how they're used to establish secure connections in Internet protocols
such as [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security).

### Role-Based Authorization (RBAC)

Once the client is authenticated with its x.509 certificate, the service
can then check if the given client is authorized to carry out the requested
action. Athenz provides fine-grained role-based access control (RBAC) support
for a centralized management system with support for control-plane access control
decisions and a decentralized enforcement mechanism suitable for data-plane
access control decisions. It also provides a delegated management model that
supports multi-tenant and self-service concepts.

### AWS Temporary Credentials Support

When working with AWS, Athenz provides support to access AWS services
from on-prem services with using AWS temporary credentials rather than
static credentials. Athenz ZTS server can be used to request AWS temporary
credentials for configured AWS IAM roles.

## Install

* [Development Environment](docs/dev_environment.md)
* Local/Development Environment Setup
    * [ZMS Server](docs/setup_zms.md)
    * [ZTS Server](docs/setup_zts.md)
    * [UI Server](docs/setup_ui.md)
* Production Environment Setup
    * [ZMS Server](docs/setup_zms_prod.md)
    * [ZTS Server](docs/setup_zts_prod.md)
    * [UI Server](docs/setup_ui_prod.md)
* AWS Production Environment Setup
    * [Introduction](docs/aws_athenz_setup.md)
    * [ZMS Server](docs/aws_zms_setup.md)
    * [ZTS Server](docs/aws_zts_setup.md)
    * [UI Server](docs/aws_ui_setup.md)

## Usage

* Architecture
    * [Data Model](docs/data_model.md)
    * [System View](docs/system_view.md)
    * [Authorization Flow](docs/auth_flow.md)
* Features
    * [Service Identity X.509 Certificates - Copper Argos](docs/copper_argos.md)
* Developer Guide
    * [Centralized Access Control](docs/dev_centralized_access.md)
        * [Java Client/Servlet Example](docs/example_java_centralized_access.md)
        * [Go Client/Server Example](docs/example_go_centralized_access.md)
    * [Decentralized Access Control](docs/dev_decentralized_access.md)
        * [Java Client/Servlet Example](docs/example_java_decentralized_access.md)
* Customizing Athenz
    * [Principal Authentication](docs/principal_authentication.md)
    * [Private Key Store](docs/private_key_store.md)
    * [Certificate Signer](docs/cert_signer.md)
    * [Service Identity X.509 Certificate Support Requirements - Copper Argos](docs/copper_argos_dev.md)
* User Guide
    * [ZMS Client Utility](docs/zms_client.md)
    * [ZPU Utility](docs/setup_zpu.md)
    * [Registering ZMS Service Identity](docs/reg_service_guide.md)

## Contribute

Please refer to the [contributing file](docs/contributing.md) for information about how to get involved. We welcome issues, questions, and pull requests.

You can also contact us for any user and development discussions through our groups:

* [Athenz-Dev](https://groups.google.com/d/forum/athenz-dev) for development discussions
* [Athenz-Users](https://groups.google.com/d/forum/athenz-users) for users questions

## License

Copyright 2016 Yahoo Inc.

Licensed under the Apache License, Version 2.0: [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)
