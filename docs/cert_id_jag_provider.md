# Service Identity Provider for ID-JAG Tokens
---------------------------------------------

The document describes support for issuing Athenz Identity X.509 certificates to workloads - typically AI agents -
that authenticate with an Identity Assertion JWT Authorization Grant (ID-JAG) token issued by an external
Identity Provider.

The provider is implemented by the `com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider` class as an
in-service class based provider, and it runs as part of the ZTS Server deployment. No changes are required for the
current deployment model.

## Request Attestation Data

The attestation data for the X.509 certificate identity registration request is the ID-JAG token itself, passed
as the raw JWT string in the `attestationData` field of the instance register request.

An ID-JAG token is a signed JWT that carries the `oauth-id-jag+jwt` value in its `typ` header field, and includes
an `act` claim describing the delegation chain that led to the request. Here is a sample payload of an ID-JAG token:

```json
{
    "iss": "https://issuer.athenz.io/oauth2/default",
    "aud": "https://audience.athenz.io",
    "sub": "user1234",
    "client_id": "aiclientid12tsy8084bo8FU1d8",
    "act": {
        "act": {
            "sub": "clientsvcid1234355",
            "sub_profile": "service"
        },
        "sub": "aiclientid12tsy8084bo8FU1d8",
        "sub_profile": "ai_agent"
    },
    "jti": "15a2c4d7-f60e-460d-b034-dbd49e757a0a",
    "nbf": 1706833037,
    "exp": 1706833937,
    "iat": 1706833637
}
```

The `act` claim is nested: the outermost object identifies the actor that is directly requesting the identity,
and each nested `act` object identifies the party that the actor is itself acting on behalf of. The provider only
enforces its checks against the outermost actor; the rest of the chain is carried in the token but not validated
by the provider.

## Athenz Identities For ID-JAG Workloads

The provider issues identities in a single, configured Athenz domain, and the service name within that domain must
be the `client_id` of the workload as asserted by the identity provider. This means the domain administrator must
register a service whose name matches the client id of the agent before any certificate can be issued.

For example, for the sample token above and a provider configured with the domain `sports`, the workload can only
obtain the identity `sports.aiclientid12tsy8084bo8fu1d8`. Note that ZTS converts all incoming domain and service
names to lower case, so the provider compares the requested service name against the token's `client_id` value
without regard to case.

Since the identity is fully determined by the configured domain and the client id in the token, the provider does
not carry out any additional Athenz authorization check. The launch authorization for the provider service itself
still applies as it does for every Copper Argos provider.

## Service Identity ID-JAG Provider

### Register Instance

The provider carries out the following checks during the instance registration process:

- The domain in the instance confirmation object must match the configured domain
  (`athenz.zts.id_jag.domain`). The comparison ignores case.
- The certificate request must not include any `sanIP` addresses.
- The certificate request must not include any hostname values.
- If the request includes any `sanURI` values, they must only be `spiffe://` or `athenz://instanceid/` URIs.
- The attestation data must be present.
- Obtain the public keys from the configured issuer to validate the ID-JAG token signature. The keys are cached to
  avoid unnecessary calls, and the frequency of key fetches is limited. Only the RS256, RS384, RS512, ES256, ES384
  and ES512 signature algorithms are accepted.
- Validate the signature of the token and parse the claims. As part of this validation, the library verifies that
  the token type (`typ` header) is `oauth-id-jag+jwt` and that the token is not expired.
- Validate the following claims from the token:
    - Issuer (`iss`) - must match the configured issuer (`athenz.zts.id_jag.issuer`)
    - Audience (`aud`) - must match the configured audience (`athenz.zts.id_jag.audience`)
    - Issue Time (`iat`) - the timestamp must be within the configured number of seconds (default 5 mins)
    - Actor (`act`) - the claim must be present and must be a JSON object
    - Actor Profile (`act.sub_profile`) - must match the configured profile value
      (`athenz.zts.id_jag.act_sub_profile`), which defaults to `ai_agent`
    - Actor Subject (`act.sub`) - must be present
    - Client Id (`client_id`) - must be present and must match the `act.sub` value
- The service name in the instance confirmation object must be the `client_id` value from the token. The
  comparison ignores case.
- Validate the `sanDNS` entries in the certificate request. Each entry must be in the format
  `<service-name>.<domain-name-with-dashes>.<dns-domain-suffix>` where the suffix is one of the configured
  values (`athenz.zts.id_jag.provider_dns_suffix`). The request must also carry an instance id, either as an
  `instanceid` `sanDNS` entry or as the ZTS provided instance id attribute.

If all the checks pass, the provider returns the confirmation object with the following certificate attributes:

- `certRefresh` is set to `false` - the issued certificate cannot be refreshed
- `certUsage` is set to `client` - the issued certificate can only be used by clients and not servers
- `certExpiryTime` is set to the configured value (default 6 hours)

The identity is issued for the min(requested number of minutes, max expiry) where max expiry has a default
configuration value of 6 hours.

### Refresh Instance

The provider does not support refreshing identity X.509 certificates. The workload must present a new ID-JAG token
and register again every time it needs a certificate.

### SSH Host Certificates

The provider does not support ssh host certificates.

## ZTS Server Configuration Changes

The following system properties configure the provider. The `athenz.zts.id_jag.domain`,
`athenz.zts.id_jag.audience` and `athenz.zts.id_jag.issuer` settings are required - the provider will throw an
`IllegalArgumentException` during initialization if any of them is not specified, since accepting any value for
those checks would defeat their purpose. The `athenz.zts.id_jag.act_sub_profile` setting has a default value, but
it is rejected the same way if it is explicitly configured with an empty value.

| Property | Required | Default | Description |
| --- | --- | --- | --- |
| `athenz.zts.id_jag.domain` | yes | none | The only Athenz domain that this provider will issue identities in. |
| `athenz.zts.id_jag.issuer` | yes | none | The expected `iss` claim value. Also used to look up the issuer's JWKS uri from its `/.well-known/openid-configuration` document if the jwks uri is not configured explicitly. |
| `athenz.zts.id_jag.audience` | yes | none | The expected `aud` claim value. |
| `athenz.zts.id_jag.act_sub_profile` | no | `ai_agent` | The expected `sub_profile` value of the outermost actor in the `act` claim. Must not be configured with an empty value. |
| `athenz.zts.id_jag.jwks_uri` | no | none | The JWKS uri used to fetch the issuer's public keys. If not specified, the uri is extracted from the issuer's openid configuration document. |
| `athenz.zts.id_jag.provider_dns_suffix` | no | `id-jag.athenz.io` | Comma separated list of dns suffixes allowed in the `sanDNS` entries of the certificate request. |
| `athenz.zts.id_jag.issue_time_offset` | no | `300` | How many seconds in the past the token may have been issued (`iat` claim) and still be accepted. This is a dynamic configuration value and can be updated without restarting the server. |
| `athenz.zts.id_jag.cert_expiry_time` | no | `360` | Default/max expiry time in minutes for the issued certificates. |

In addition, ZTS enforces IP ranges where services are authorized to request identities from a given provider, so
the IP addresses that the workloads will be connecting from must be authorized for the provider.

## ZMS Server Configuration Changes

The following changes are necessary for the ZMS server to support the ID-JAG provider:

- Register `sys.auth.id-jag` as a service with the class provider endpoint pointing to the implementation of the
  ID-JAG provider class:
  `class://com.yahoo.athenz.instance.provider.impl.InstanceIDJAGProvider`
- Add the provider identity (e.g. `sys.auth.id-jag`) to the providers role in the `sys.auth` domain to be
  authorized as an official provider.
- Create a role called `provider.sys.auth.id-jag` that includes `sys.auth.id-jag` as a member and create a policy
  that allows the `launch` action to that role on the resource `dns.<dns-domain-suffix>`. This allows adding
  `sanDNS` values in the certificate in the format `<service-name>.<domain-name>.<dns-domain-suffix>`.
- In the configured tenant domain, register a service for each agent using the agent's client id as the service
  name, and authorize the provider to launch it.
