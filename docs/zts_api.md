# ZTS API

## Introduction

The Authorization Token Service (ZTS) API

This API has the following attributes:

| Attribute | Value |
| --- | --- |
| namespace | com.yahoo.auth.zts |
| version | 1 |

## Authentication

### X.509 Certificate Support

All ZMS API commands require that the client use a TLS certificate issued by Athenz.
Services can use their Athenz Issued Service Identity certificates when communicating
with ZMS.

## Authorization

Limited number of ZTS API endpoints are authorized against the configured
policy data to verify that the principal has been given the rights to make
the requested change. Each request description below gives the authorization command
that includes the action and resource that the ZTS Server will run the authorization
check against. For example, to delete an instance from the local database we have
the following authorize statement:

``` sourceCode
authorize("delete", "{domain}:instance.{instanceId}");
```

This indicates that the principal requesting to delete instance id host001 from
athenz.ci domain must have grant rights to action "delete" for resource called
"instance.host001" in domain "athenz.ci".

## Types

### Access

Access can be checked and returned as this resource.

`Access` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| granted | Bool | | | |

### AccessTokenResponse

OAuth2 Access Token response.

`AccessTokenResponse` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| access_token | String | | Oauth2 Access token in JWT format | |
| token_type | String | | | For Athenz this will always be Bearer |
| expires_in | Int32 | | Number of seconds the access token is valid for | |
| scope | List<String> | | List of roles the principal has access to | |
| refresh_token | String | | Not issued by Athenz | |
| id_token | String | | ID token valid for 1 hour | Returned only if openid/service-name scopes provided as part of the request |

### ActionName

An action (operation) name.

`ActionName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### AuthorityName

Used as the prefix in a signed assertion. This uniquely identifies a signing authority. i.e. ^user^

`AuthorityName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### AWSArnRoleName

AWS full role name with path

`AWSArnRoleName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `({AWSRolePath})*{AWSRoleName}` | |

### AWSRoleName

AWS role name without the path

`AWSRoleName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9-\\._=+@,]*` | |

### AWSRolePath

AWS role path

`AWSRolePath` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `({AWSRolePathElement}/)+` | |

### AWSRolePathElement

AWS role path single element

`AWSRolePathElement` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9][a-zA-Z0-9-\\._]*` | |

### AWSTemporaryCredentials

AWS Temporary credentials

`AWSTemporaryCredentials` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| accessKeyId | String | | | |
| secretAccessKey | String | | | |
| sessionToken | String | | | |
| expiration | Timestamp | | | |

### CompoundName

A compound name. Most names in this API are compound names.

`CompoundName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | ({SimpleName}*\.)*{SimpleName}* | |

### DomainName

A domain name is the general qualifier prefix, as its uniqueness is managed.

`DomainName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### EntityName

An entity name is a short form of a resource name, including only the domain and entity.

`EntityName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### Identity

A signed identity object that is a client certificate.

`Identity` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | CompoundName | | Name of the identity | |
| certificate | String | optional | TLS Certificate | |
| caCertBundle | String | optional | CA certificate chain | |
| sshServerCert | String | optional | SSH server certificate | |
| attributes | Map&lt;String, String&gt; | optional | config like attributes | |

### InstanceIdentity

A signed instance identity object that includes client certificate

`InstanceIdentity` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| provider | ServiceName | | provider service name | |
| name | ServiceName | | Name of the identity | |
| instanceId | PathElement | | unique instance id | |
| x509Certificate | String | optional | TLS Certificate | |
| x509CertificateSigner | String | optional | CA certificate chain | |
| sshCertificate | String | optional | SSH server certificate | |
| sshCertificateSigner | String | optional | SSH server certificate signer pubilc key | |
| attributes | Map&lt;String, String&gt; | optional | config like attributes | |

### InstanceRefreshRequest

A certificate refresh request.

`InstanceRefreshRequest` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| csr | String | optional | cert CSR if requesting TLS certificate | |
| expiryTime | Int32 | optional | In seconds how long certificate should be valid for | |
| keyId | String | optional | public key identifier | |

### InstanceRegisterInformation

Request to request an instance with ZTS and request X.509 Certificate
for the service.

`InstanceRegisterInformation` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| provider | ServiceName | | provider service name | e.g. athenz.aws.us-west-2 |
| domain | DomainName | | instance domain name | |
| service | ServiceName | | instance service name | |
| attestationData | String | | identity attestation data | |
| csr | String | | cert CSR if requesting TLS certificate | |
| ssh | String | optional | ssh CSR if requesting SSH certificate | |

### JWK

Json Web Key.

`JWK` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| kty | String | | key type | e.g. EC or RSA |
| kid | String | | key id | |
| alg | String | | key algorithm | e.g. RS256 or ES256 |
| use | String | | key usage | e.g. sig for signing or enc for encryption |
| crv | String | | EC curve name | e.g. prime256v1, P-256 |
| x | String | | EC key x value | |
| y | String | | EC key y value | |
| n | String | | RSA key modulus value | |
| e | String | | RSA key public exponent value | |

### JWKList

Json Web Key List

`JWKList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| keys | Array<JWK> | | List of JWKs | |

### PathElement

A uri safe path element

`PathElement` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9-\\._~=+@$,:]*` | |

### ResourceName

A shorthand for a YRN with no service or location. The 'tail' of a YRN,
just the domain:entity. Note that the EntityName part is optional, that is,
a domain name followed by a colon is valid resource name.

`ResourceName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {DomainName}(:{EntityName})? | |

### RoleAccess

RoleAccess is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| roles | Array&lt;EntityName&gt; | | list of roles principal has access to | |

### RoleCertificateRequest

A role certificate request.

`RoleCertificateRequest` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| csr | String | optional | cert CSR if requesting TLS certificate | |
| expiryTime | Int32 | optional | In seconds how long certificate should be valid for | |

### ServiceName

A service name will generally be a unique subdomain

`ServiceName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### SignedToken

A signed assertion if identity. For example: the YBY cookie value. This token will
only make sense to the authority that generated it, so it is beneficial to have
something in the value that is cheaply recognized to quickly reject if it belongs
to another authority.

`SignedToken` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9\\._%=;,-]*` | |

### SimpleName

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9_][a-zA-Z0-9_-]*` | |

### YBase64

The Y-specific URL-safe Base64 variant.

`YBase64` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9\._-]+` | |

### YEncoded

YEncoded includes ybase64 chars, as well as - and %. This can represent a YBY cookie and URL-encoded values

`YEncoded` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9\._%--]*` | |

### YRN

A full Resource name (YRN)

`YRN` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | (yrn:({ServiceName})?:({LocationName})?:)?{ResourceName} | |

## Resources

### Access

#### GET /access/{action}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Check access for the specified operation/action on the specified resource for the currently authenticated user
if the principal query parameter is not specified. If the principal query parameter is specified, the
access check verifies if that principal has access for the specified action on the resource.
This is the slow centralized access for control-plane purposes.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| action | ActionName | path | | |
| domain | DomainName | query: domain | optional | |
| principal | EntityName | query: principal | optional | |
| resource | String | query: resource | required | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Access |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### AccessToken

#### POST "/oauth2/token"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Return an oauth2 access token for the specific set of roles in the namespace that the user can assume.
To request an access token from ZTS Server, the client will send a POST
request with `application/x-www-form-urlencoded` content-type and the request body must
contain the following parameters:

```
grant_type : Value MUST be set to "client_credentials"
scope : list of scopes/roles requested in the access token. The caller
        can either specify to include all roles the principal has access
        to in a specific domain (e.g. <domain-name>:domain) or ask for
        specific roles only (e.g. <domain-name>:role.<role1>). Scopes
        are separated by spaces.
        To request an ID token, the scope must include 'openid' and audience
        service name (e.g. <domain-name>:service.<service-name>). The domain
        name in id token request match the domain name in the access token
        scope.
expires_in : requested expiry time for access token in seconds
```
##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| req | String | body | | request to fetch access token (see above) |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | AccessTokenResponse |
| 403 FORBIDDEN | Principal does not have access to any roles in this domain |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### AWS Temporary Credentials

#### GET "/domain/{domainName}/role/{roleName}/creds"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Perform an AWS AssumeRole of the target role and return the credentials. ZTS
must have been granted the ability to assume the role in IAM, and granted
the ability to assume_aws_role in Athenz for this to succeed. There are two
optional query parameters to specify the duration in seconds for the requested
credentials and the external id. Both of these options require the role to be
configured accordingly in AWS IAM.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| durationSeconds | Integer | query: durationSeconds | optional | Duration in seconds - min: 900, max: 43200. Must be configured in IAM |
| externalId | String | query: externalId | optional | External ID configured in IAM for the given role |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Access |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### IdentityRefresh

#### POST "/instance/{domain}/{service}/refresh"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Refresh self identity if the original identity was issued by ZTS. The token must
include the original requestor's name and the server will verify that the service
still has authorization to grant inception to the current service requesting to
refresh its identity

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | SimpleName | path | | |
| req | InstanceRefreshRequest | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Identity |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### InstanceDelete

#### DELETE "/instance/{provider}/{domain}/{service}/{instanceId}"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize("delete", "{domain}:instance.{instanceId}");

Delete the specified instance and no longer allow certificate refresh.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| provider | ServiceName | path | | |
| service | SimpleName | path | | |
| instanceId | PathElement | path | | unique instance id in provider's namespace |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |
| 500 Internal Server Error | ResourceError |

### InstanceRefresh

#### POST "/instance/{provider}/{domain}/{service}/{instanceId}"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Refresh the current certificate for this instance.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| provider | ServiceName | path | | |
| service | SimpleName | path | | |
| instanceId | PathElement | path | | unique instance id in provider's namespace |
| info | InstanceRefreshInformation | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | InstanceIdentity |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |
| 500 Internal Server Error | ResourceError |

### InstanceRegister

#### POST "/instance"

-   [Authentication](#authentication): None
-   [Authorization](#authorization): None

Register the instance for a given provider and return x.509 certificate
for the service to identity itself against other Athenz enabled services.

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 201 CREATED | InstanceIdentity |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |
| 500 Internal Server Error | ResourceError |

### JWKList

#### GET "/oauth2/keys"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Returns list of Json Web Keys (JWKs) that can be used by the ZTS Server
to sign OAuth2 Access/Id Tokens. If the optional rfc=true query argument
is specified, then we return the EC key curve names strictly based
on the JWK RFC - e.g. P-256.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| rfc | Boolean | query: rfc | optional | if true then use rfc defined curve names - e.g. P-256 |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | JWKList |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |

### RoleAccess

#### GET "/access/domain/{domainName}/principal/{principal}"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

List the roles that the given principal has in the domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| principal | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | RoleAccess |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### RoleCertificate

#### POST "/domain/{domainName}/role/{roleName}/token"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Return a TLS certificate for the specific role in the namespace that
the principal can assume. Role certificates are valid for 30 days
by default.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| req | RoleCertificateRequest | body | | csr request |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | RoleToken |
| 403 FORBIDDEN | Principal does not have access to any roles in this domain |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### RoleCheckAccess

#### GET "/access/domain/{domainName}/role/{roleName}/principal/{principal}"

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Check whether or not the given principal is included in the given role in the specified domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| principal | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Access |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |