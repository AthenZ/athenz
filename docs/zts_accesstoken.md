* [Overview](#overview)
* [Getting Software](#getting-software)
* [Prerequisites](#prerequisites)
* [Usage](#usage)

## Overview
----------

ZTS OAuth2 Access Token Client application in Go to request an access token from
ZTS Server for the given identity to access a role in a provider domain.

## Getting Software
-------------------

Download latest ZTS OAuth2 Access Token Client package from
[Maven Central](https://search.maven.org/artifact/com.yahoo.athenz/athenz-utils):
click on the `Browse` button, choose the latest version directory and then
download the `athenz-utils-<latest-version>-bin.tar.gz`.

```shell
$ tar xvfz athenz-utils-X.Y-bin.tar.gz
```

## Prerequisites
----------------

Before you can use the ZTS AccessToken utility, you need to have
asked the Athenz administrators to create your top level domain.

## Usage
--------

An access token from ZTS service can be fetched using Service Identity x.509 certificates.

The optional `expire-time` argument specifies how long the access
token should be valid for. The value must be specified in minutes. The
default if no value is specified is 120 minutes.

The optional `roles` argument requests an access token for the given roles
only (comma separated) as opposed to all the roles the service identity has
access to in the requested domain.

The optional `service` argument requests an id token for the given service.
The full `domain.service` value will be set as the audience for the id token.

### Using Athenz Identity X.509 Certificates

```
$ zts-accesstoken -domain <domain> [-roles <roles>] [-service <service>] -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts <ZTS url> [-expire-time <expire-time-in-mins>]
```

### Requesting DPoP-Bound Access Tokens

The optional `-dpop` flag requests an access token bound to a DPoP key
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)). The utility signs a fresh
DPoP proof for the token request and sends it in the `DPoP` header. ZTS then
returns `"token_type":"DPoP"` and adds the key's SHA-256 JWK thumbprint to the
token's `cnf.jkt` claim. When the request is also authenticated with an X.509
certificate, the token keeps the `cnf.x5t#S256` certificate binding as well.

By default, the proof is signed with the service identity key from
`-svc-key-file`. Use `-dpop-key-file` to sign with a separate RSA or EC private
key. `-dpop-key-file` is required when authenticating with `-ntoken-file`.

```
$ zts-accesstoken -domain <domain> [-roles <roles>] -svc-key-file <private-key-file> -svc-cert-file <service-cert-file> -zts <ZTS url> -dpop [-dpop-key-file <dpop-private-key-file>]
```

The flag applies to the client credentials, access token exchange
(`-grant-type token-exchange -requested-token-type access_token`) and ID-JAG
exchange (`-grant-type jwt-bearer`) flows. It is rejected for ID-JAG issue
requests because the ID-JAG is not a DPoP-bound access token.

The utility exits with a non-zero status, and does not print the token, if the
server returns any `token_type` other than `DPoP` (for example, when DPoP
support is not enabled on the ZTS server). With `-token-only`, the token type
is printed to stderr.

To check the binding, validate the token with `-claims`. The `cnf` claim shows
the `jkt` value:

```
$ zts-accesstoken -validate -access-token <access-token> -conf <athenz-conf-path> -claims
```

Note: a DPoP-bound access token gives extra protection only when the resource
server enforces the DPoP binding. Resource servers that don't check `cnf.jkt`
accept the token as a plain bearer token.