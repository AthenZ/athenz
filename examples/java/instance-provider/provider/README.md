Athenz Bootstrap Instance Provider Example
==========================================

This project provides a reference implementation of the
InstanceProvider interface. This is required if the provider wants
to bootstrap instances with Athenz Identities (TLS Certificates).
It implements the /instance endpoint as required by the InstanceProvider
rdl (out of zts-core). It uses signed JWTs for attestation data.

Copyright 2017 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
