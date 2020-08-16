Athenz is a set of services and libraries supporting service authentication and role-based authorization (RBAC) for provisioning and configuration (centralized authorization) use cases as well as serving/runtime (decentralized authorization) use cases. Athenz authorization system utilizes x.509 certificates and Access Tokens. The name "Athenz" is derived from "AuthNZ" (N for authentication and Z for authorization). It provides support for the following three major functional areas.

## Service Authentication

Athenz provides secure identity in the form of short lived X.509 certificate
and a certificate and IP-based distributed system to handle	for every workload or service deployed in private (e.g. Openstack, K8S, Screwdriver)
on-box enforcement.	or public cloud (e.g. AWS EC2, ECS, Fargate, Lambda). Using these X.509 certificates
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

## Role-Based Authorization (RBAC)

Once the client is authenticated with its x.509 certificate, the service
their own role-based access control systems that have no central store	can then check if the given client is authorized to carry out the requested
and often rely on network ACLs and manual updating.	action. Athenz provides fine-grained role-based access control (RBAC) support
for a centralized management system with support for control-plane access control
decisions and a decentralized enforcement mechanism suitable for data-plane
access control decisions. It also provides a delegated management model that
supports multi-tenant and self-service concepts.

## AWS Temporary Credentials Support

When working with AWS, Athenz provides support to access AWS services
from on-prem services with using AWS temporary credentials rather than
static credentials. Athenz ZTS server can be used to request AWS temporary
credentials for configured AWS IAM roles.
