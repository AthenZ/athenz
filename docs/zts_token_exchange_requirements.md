# ZTS Token Exchange Requirements
---------------------------------

## JWT Authorization Grant Token Issue
Specification: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/

The JAG token issue feature in Athenz ZTS allows a service or user to exchange an existing
ID token for a new JWT Authorization Grant (JAG) token. The JAG token then could be used
by, for example, an AI agent to request the appropriate access token for the principal and
a given service. To perform this exchange, the requesting principal must be authorized to
do so based on policies defined in Athenz.

Requirements:

- The token request must have the `grant_type` parameter set to `urn:ietf:params:oauth:grant-type:token-exchange`
- The token request must have the `requested_token_type` parameter set to `urn:ietf:params:oauth:token-type:id-jag`
- The token request must have a subject_token parameter included with a valid ID token and the `subject_token_type`
  parameter set to `urn:ietf:params:oauth:token-type:id-token`
- The token request must have the `scope` parameter set to the list of roles being requested in the
  format: `{domainName}:role.{roleName} {domainName}:role.{roleName} ...`
- The token request must have a valid `audience` parameter specified
- The requesting principal (service or user) must be authorized to perform the JAG token exchange
  for each role in the requested scope.

1. Subject Token Validation

- Checks if the subject token audience matches the principal name
- If not, retrieves the service client ID assigned to the principal. If an external identity
  provider is used, it fetches the token audience and validates that the client ID matches the token audience

2. Role Names Validation

- Extracts requested roles from the scope (at least one role must be present)
- Extracts the subject identity. For ZTS-issued tokens, uses the token's subject directly.
  For external provider tokens, uses the identity provider's getTokenIdentity() method.
- Validates that the subject identity has access to at least one of the requested roles
  The generated token will only include roles that the subject identity has access to.
- For each subject identity access role, checks if the authenticated principal is authorized
  to perform JAG token exchange. For this authorization the following assertion must be
  present in the domain:
    action: `zts.jag_exchange`
    resource: `{domainName}:role.{roleName}`

## JWT Authorization Grant Token Exchange
Specification: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/

The JAG token exchange feature in Athenz ZTS allows a service
or user to exchange an existing ID JAG token with an appropriate
access token for the principal and a given service. To perform this
exchange, the requesting principal must be authorized to do so based
on policies defined in Athenz.

Requirements:

- The token request must have the `grant_type` parameter set to `urn:ietf:params:oauth:grant-type:jwt-bearer`
- The token request must have an assertion parameter included with a valid ID-JAG token issued by either
  Athenz ZTS or an external identity provider.

1. JAG Token Validation

- Checks that the JAG token's audience claim matches either ztsOpenIDIssuer (OIDC issuer) or
  ztsOAuthIssuer (OAuth issuer) values configured in the ZTS Server
- Checks that the JAG token's client_id matches the authenticated client principal name
   or the registered service client ID for the principal
- Checks that the JAG token has a non-empty scope claim. If the scope claim in the access token
  request is provided, then it must match the scope claim in the JAG token or be a subset of it.

2. Role Names Validation

- Extracts the subject identity. For ZTS-issued tokens, uses the token's subject directly.
  For external provider tokens, uses the identity provider's getTokenIdentity() method.
- Validates that the subject identity has access to at least one of the requested roles
  The generated token will only include roles that the subject identity has access to.

## Access Token Exchange (Impersonation)
Specification: https://datatracker.ietf.org/doc/html/rfc8693

The JWT Token exchange feature allows a service or user to exchange an existing
access token for a given domain to obtain a new access token that impersonates
the same principal for a different domain (audience).

Requirements:

- The token request must have the `grant_type` parameter set to `urn:ietf:params:oauth:grant-type:token-exchange`
- The token request must have the `requested_token_type` parameter set to `urn:ietf:params:oauth:token-type:id-access-token`
  or it's not specified (default)
- The token request must have a subject_token parameter included with a valid ID/Access token and the `subject_token_type`
  parameter set to `urn:ietf:params:oauth:token-type:id-token`, `urn:ietf:params:oauth:token-type:id-access-token` or
  `urn:ietf:params:oauth:token-type:jwt`
- The token request must have a valid `audience` parameter specified
- The token request must have the `scope` parameter set to the list of roles being requested in the
  format: `{domainName}:role.{roleName} {domainName}:role.{roleName} ...`

1. Role Names Validation

- Checks that the subject token has a non-empty scope claim. If the scope claim in the access token
  request is provided, then it must match the scope claim in the token or be a subset of it.
- Validates that the subject identity has access to at least one of the requested roles

2. Impersonation Authorization Check

- Verifies the calling principal is authorized to perform token impersonation from the source
  domain to the target domain based on the following assertion:
    action: `zts.token_source_exchange`
    resource: `{sourceDomain}:{targetDomain}`
- For each subject identity access role, checks if the authenticated principal is authorized
  to perform token exchange based on the following assertion:
    action: `zts.token_target_exchange`
    resource: `{targetDomain}:{sourceDomain}:role.{roleName}`

## Access Token Exchange (Delegation)
Specification: https://datatracker.ietf.org/doc/html/rfc8693

The JWT Token exchange feature allows a service or user to exchange an existing
access token for a given domain to obtain a new access token that delegates
the token to a different domain (audience).

Requirements:

- The token request must have the `grant_type` parameter set to `urn:ietf:params:oauth:grant-type:token-exchange`
- The token request must have the `requested_token_type` parameter set to `urn:ietf:params:oauth:token-type:id-access-token`
  or it's not specified (default)
- The token request must have a subject_token parameter included with a valid ID/Access token and the `subject_token_type`
  parameter set to `urn:ietf:params:oauth:token-type:id-token`, `urn:ietf:params:oauth:token-type:id-access-token` or
  `urn:ietf:params:oauth:token-type:jwt`
- The token request must have a valid `audience` parameter specified
- The token request must have the `scope` parameter set to the list of roles being requested in the
  format: `{domainName}:role.{roleName} {domainName}:role.{roleName} ...`
- The token request must have an actor_token parameter included with a valid ID/Access token and the `actor_token_type`
  parameter set to `urn:ietf:params:oauth:token-type:id-token`, `urn:ietf:params:oauth:token-type:id-access-token` or
  `urn:ietf:params:oauth:token-type:jwt`
- The subject_token must have a valid `may_act` claim that includes a `sub` claim that matches the actor_token's subject

1. Role Names Validation

- Checks that the subject token has a non-empty scope claim. If the scope claim in the access token
  request is provided, then it must match the scope claim in the token or be a subset of it.
- Validates that the subject identity has access to at least one of the requested roles

2. Delegation Authorization Check

- For each subject identity access role, checks if the authenticated principal (identity from the
  actor token) is authorized to perform token exchange based on the following assertion:
    action: `zts.token_target_exchange`
    resource: `{targetDomain}:{sourceDomain}:role.{roleName}`

## External Token Exchange Provider Support

Athenz ZTS allows the integration of external token exchange providers to support exchange
of tokens issued by external identity providers to JWT Authorization Grant tokens. To support
an external token exchange provider, the following requirements must be met:

- The external token exchange provider must implement the `com.yahoo.athenz.auth.TokenExchangeIdentityProvider`
  interface
- The external token exchange provider must be configured in the ZTS Server configuration
  using the `athenz.zts.oauth_provider_config_file` property. The value of the property
  must point to a configuration file in JSON format that specifies the class name of the
  provider implementation and any additional configuration properties required by the provider.
  An example of the configuration file is shown below:
  ```json
  [
    {
      "issuerUri": "https://external-provider.athenz.io/oauth2/default",
      "jwksUri": "https://external-provider.athenz.io/oauth2/default/keys",
      "providerClassName": "com.yahoo.athenz.auth.ExternalTokenExchangeIdentityProvider"
    }
  ]
  ```
