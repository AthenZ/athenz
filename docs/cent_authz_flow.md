In this section, we're going to examine the centralized authorization flow.

## Subsystems

Before we go into the details of the authorization flow, it's important
to understand the subsystems involved. The authorization (AuthZ) system
shown in the figure below consists of several logical subsystems, which
we will elaborate on in the following section.

### ZMS (AuthZ Management System)

ZMS is where domains, roles, and policies are defined. This is Athenz's
centralized authorization system and is likely part of a larger
management system.
In addition to allowing CRUD operations on the basic entities, ZMS
provides an API to replicate the entities, per domain, to
ZTS. It also can directly support the access
check, both for internal management system checks, as well as a simple
centralized deployment.

ZMS is the source of truth for domains, roles, and policies for
centralized authorization. ZMS supports a centralized call to check if a
principal has access to a resource. Because ZMS supports service
identities, ZMS can authenticate services.

For centralized authorization, ZMS may be the only Athenz subsystem that
you need to interact with.

### SIA (Service Identity Agent)

SIA is required for authenticating existing unmanaged services. Any service that launches other
services should integrate SIA (or an equivalent system). To confirm a
service's identity, SIA communicates with ZTS.

## Centralized Access Control

A traditional centralized mechanism works as expected for services that
are not dealing with the decentralized authorization: the server with
resources can simply ask the ZMS directly about access, passing its
credentials (X.509 Cert) and resource/action information for a
given principal to get a simple boolean answer. In this model, the
Athenz Management Service is the only component that needs to be
deployed and managed within your environment.

This does not scale well enough for data-plane access, since a central
service must be consulted, but requires no local installation of other
components and related storage and synchronization logic, so it is suitable
for human interaction and control-plane provisioning uses where the number
of requests processed by the server is small and the latency for authorization
checks is not important.

### Principals

In Athenz, actors that can assume a role are called principals.
Principals can be users or services, and users can be those looking for
resources from a service or use the ZMS management console. 

The user or service must be configured with Athenz CA certificates and 
require mutual client authentication to accept and validate the service's X.509 certificate.
Once validated, it can extract the CN field from the certificate would be the service's
identity. Finally, just like the user case, it which would perform an identical
check with ZMS to confirm access passing the action, resource and service
name to ZMS.

![Authenticated Service as Principal](images/centralized_authz_for_services.png)
