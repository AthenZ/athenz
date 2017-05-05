Athenz Bootstrap Instance Client Example
========================================

This IntanceClientRegister example demonstrates a sample instance client
that uses a signed attestation data from the provider (in this we're
generated one ourselves - signed JWT) and submits a instance
register request to ZTS. ZTS will contacts the configured provider's
verification service to validate the request and, if successful,
will generate a TLS Certificate based on the given CSR and return
it to the client. The certificate along with its private key must
be stored in a keystore to be used by the refresh example.

The InstanceClientRefresh example shows how to refresh the TLS
certificate retrieved from the register call. It uses the orginal
certificate along with its private key stored in the keystore
to generate a new CSR and submit the request to ZTS Server to
refresh and receive new TLS certificates (valid for another 30 days).

Copyright 2017 Yahoo Inc.

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
