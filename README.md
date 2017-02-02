<!-- ![logo](images/athenz.png) -->

[![Build Status](https://travis-ci.org/yahoo/athenz.svg?branch=master)](https://travis-ci.org/yahoo/athenz)

Athenz is a set of services and libraries supporting role-based
authorization (RBAC) for provisioning and configuration (centralized
authorization) use cases as well as serving/runtime (decentralized
authorization) use cases. Athenz authorization system utilizes two
types of tokens: Principal Tokens (N-Tokens) and RoleTokens (Z-Tokens).
The name "Athenz" is derived from "Auth" and the 'N' and 'Z' tokens.

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

## Documentation
----------------

* Getting Started
    * [Development Enviornment](docs/dev_environment.md)
    * Local/Development Environment Setup
        * [ZMS Server](docs/setup_zms.md)
        * [ZTS Server](docs/setup_zts.md)
        * [UI Server](docs/setup_ui.md)
    * Production Environment Setup
        * [ZMS Server](docs/setup_zms_prod.md)
        * [ZTS Server](docs/setup_zts_prod.md)
        * [UI Server](docs/setup_ui_prod.md)
* Architecture
    * [Data Model](docs/data_model.md)
    * [System View](docs/system_view.md)
    * [Authorization Flow](docs/auth_flow.md)
* Developer Guide
    * [Centralized Access Control](docs/dev_centralized_access.md)
        * [Java Client/Servlet Example](docs/example_java_centralized_access.md)
        * [Go Client/Server Example](docs/example_go_centralized_access.md)
    * [Decentralized Access Control](docs/dev_decentralized_access.md)
        * [Java Client/Servlet Example](docs/example_java_decentralized_access.md)
    * [System Properties](docs/system_properties.md)
* Customizing Athenz
    * [Principal Authentication](docs/principal_authentication.md)
    * [Private Key Store](docs/private_key_store.md)
* User Guide
    * [ZMS Client Utility](docs/zms_client.md)
    * [ZPU Utility](docs/setup_zpu.md)
    * [Registering ZMS Service Identity](docs/reg_service_guide.md)

## Contact
----------

* [Athenz-Dev](https://groups.google.com/d/forum/athenz-dev) for
  development discussions
* [Athenz-Users](https://groups.google.com/d/forum/athenz-users) for
  users questions

## License
----------

Copyright 2016 Yahoo Inc.

Licensed under the Apache License, Version 2.0: [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)
