Athenz is a set of services and libraries supporting role-based authorization (RBAC) for provisioning and configuration (centralized authorization) use cases as well as serving/runtime (decentralized authorization) use cases. Athenz authorization system utilizes two types of tokens: Principal Tokens (N-Tokens) and RoleTokens (Z-Tokens). The name "Athenz" is derived from "Auth" and the 'N' and 'Z' tokens.

## Main features
----------------

Athenz provides both the functionality of a centralized system
and a certificate and IP-based distributed system to handle
on-box enforcement.

You get the following advantages using Athenz:

-   **Service-based security profile:** Security definitions that
    automatically trickle down to hosts within the service.
-   **Dynamic provisioning:** Scale fast or move workloads around
    without manual intervention (IP-less configuration).
-   **Single source of truth:** Consolidated service profile serving
    various downstream security implementations, including support for
    non-user entities.
-   **Self-Service:** Real-time configuration and enforcement of
    resource-based access control (dynamic manageability).

More importantly, we want engineers to use Athenz and **not** build
their own role-based access control systems that have no central store
and often rely on network ACLs and manual updating.
