# ZMS API

## Introduction

The Authorization Management Service (ZMS) API

This API has the following attributes:

| Attribute | Value |
| --- | --- |
| namespace | com.yahoo.auth.zms |
| version | 1 |

## Authentication

### X.509 Certificate Support

All ZMS API commands require that the client use a TLS certificate issued by Athenz.
Services can use their Athenz Issued Service Identity certificates when communicating
with ZMS.

## Authorization

Every write request against ZMS server is authorized against the configured
policy data to verify that the principal has been given the rights to make
the requested change. Each request description below gives the authorization command
that includes the action and resource that the ZMS Server will run the authorization
check against. For example, the create subdomain command has the following authorize statement:

``` sourceCode
authorize ("create", "{parent}:domain");
```

This indicates that the principal requesting to create subdomain called athens.ci
must have grant rights to action "create" for resource called "domain" in domain "athens".

## Types

### Access

Access can be checked and returned as this resource.

`Access` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| granted | Bool | | | |

### ActionName

An action (operation) name.

`ActionName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### Assertion

A representation for the encapsulation of an action to be performed on a resource by a principal.

`Assertion` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| role | String | | the subject  of the  assertion, a role | |
| resource | String | | the object of the assertion. Must be in the local namespace. Can contain wildcard | |
| action | String | | the predicate of the assertion. Can contain wildcard | |
| effect | AssertionEffect | optional, default-ALLOW | the effect of the assertion in the policy language | |
| id | Int64 | optional | The server assigned id for the assertion | |

### AssertionEffect

Every assertion can have the effect of ALLOW or DENY.

`AssertionEffect` is an `Enum` of the following values:

| Value | Description |
| --- | --- |
| ALLOW | |
| DENY | |

### AuthorityName

Used as the prefix in a signed assertion. This uniquely identifies a signing authority. i.e. ^user^

`AuthorityName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### CompoundName

A compound name. Most names in this API are compound names.

`CompoundName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | ({SimpleName}*\.)*{SimpleName}* | |

### DefaultAdmins

`DefaultAdmins` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| admins | Array&lt;ResourceName&gt; | | | |

### Domain

A domain is an independent partition of users, roles, and resources. It's name
represents the definition of a namespace; the only way a new namespace can be
created, from the top, is by creating Domains. Administration of a domain is
governed by the parent domain (using reverse-DNS namespaces). The top level
domains are governed by the special ^sys.auth^ domain.

`Domain` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | DomainName | | immutable. This is the common name to be referred to, the symbolic id. | |
| modified | Timestamp | optional | | |
| id | UUID | optional | generated</code> on create, never reused | |
| description | String | optional | | |
| org | ResourceName | optional | a reference to an Organization. Auth doesn't use it, but it provides external hook (i.e. org:media) | |
| enabled | Bool | optional, default-true | | |

### DomainData

`DomainData` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | DomainName | | | |
| enabled | Bool | | | |
| account | String | | AWS account id | |
| ypmid | Int32 | | OPM product id | |
| roles | Array&lt;Role role&gt;&gt; | | | |
| policies | Array&lt;Policy&gt; | | | |
| serviceIds | Array&lt;ServiceIdentity&gt; | | | |
| modified | Timestamp | | | |

### DomainList

A paginated list of domains.

`DomainList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| names | Array&lt;DomainName&gt; | | | |
| next | String | optional | | |

### DomainMeta

All domains have metadata that can be changed.

`DomainMeta` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| description | String | optional | a description of the domain | |
| org | ResourceName | optional | a reference to an Organization. Auth doesn't use it, but it provides external hook (i.e. org:media) | |
| enabled | Bool | optional, default-true | | |

### DomainName

A domain name is the general qualifier prefix, as its uniqueness is managed.

`DomainName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### DomainPolicies

`DomainPolicies` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| domain | DomainName | | | |
| policies | Array&lt;Policy&gt; | | | |
| modified | Timestamp | | when the domain itself was last modified | |
| expires | Timestamp | | how long this snapshot can be used | |

### DomainTemplateList

List of solution templates to be applied to a domain

`DomainTemplateList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| templateNames | Array&lt;SimpleName&gt; | | | |

### Entity

An entity is a name and a structured value some entity names/prefixes are
reserved (i.e., `role`, `policy`, `meta`, `domain`)

`Entity` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | EntityName | | | |
| value | Struct | | | |

### EntityName

An entity name is a short form of a resource name, including only the domain and entity.

`EntityName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### LocationName

A location name is not yet defined, but will be a dotted name like everything else.

`LocationName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### Membership

`Membership` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| memberName | ResourceName | | | |
| isMember | Bool | optional, default-true | | |
| roleName | ResourceName | optional | | |

### Policies

`Policiies` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| list | Array&lt;Policy&gt; | | | |

### Policy

The representation for a named set of assertions, given a name and a version number that increments.

`Policy` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | ResourceName | | | |
| modified | Timestamp | optional | | |
| assertions | Array&lt;Assertion&gt; | | | |

### PolicyList

The representation for an enumeration of policies in the namespace, with pagination

`PolicyList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| names | Array&lt;EntityName&gt; | | | |
| next | String | optional | | |

### PublicKeyEntry

`PublicKeyEntry` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| key | String | | the public key for the service | |
| id | String | | used to specify the id/version of the key (for GET operation only) | |

### ResourceName

A shorthand for a YRN with no service or location. The 'tail' of a YRN, just the
domain:entity. Note that the EntityName part is optional, that is, a domain name
followed by a colon is valid resource name.

`ResourceName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {DomainName}(:{EntityName})? | |

### Role

`Role` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | ResourceName | | | |
| modified | Timestamp | optional | | |
| members | Array&lt;ResourceName&gt; | optional | an explicit list of members. Might be empty or null, if trust is set. | |
| trust | DomainName | optional | a trusted domain to delegate membership decisions to. | |
| auditLog | Array&lt;RoleAuditLog&gt; | optional | an explicit list of audit log entries if requested. | |

### RoleAuditLog

`RoleAuditLog` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| member | ResourceName | | | |
| admin | ResourceName | | | |
| created | Timestamp | | | |
| action | String ADD or DELETE | | | |
| auditRef | String | optional | | |

### RoleList

`RoleList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| names | Array&lt;EntityName&gt; | | | |
| next | String | optional | | |

### Roles

`Roles` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| list | Array&lt;Role&gt; | | | |

### ServerTemplateList

List of solution templates available in the server

`ServerTemplateList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| templateNames | Array&lt;SimpleName&gt; | | | |

### ServiceIdentities

`ServiceIdentities` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| list | Array&lt;ServiceIdentity&gt; | | | |

### ServiceName

A service name will generally be a unique subdomain

`ServiceName` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | {CompoundName} | |

### ServiceIdentity

`ServiceIdentity` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| name | ServiceName | | the full name, i.e. ^vespa.storage^ | |
| publicKey | String | optional | the public key for the service | |
| publicKeys | Array&lt;PublicKeyEntry&gt; | optional | array of public keys for key rotation | |
| providerEndpoint | URI | optional | if present, then this service can provision tenants via this endpoint. | |
| modified | Timestamp | optional | the time this entry was modified | |
| executable | String | optional | the path of the executable that runs the service | |
| hosts | Array&lt;String&gt; | optional | host names of hosts this service can run on | |
| user | String | optional | local (unix) user name this service can run as | |
| group | String | optional | local (unix) group name this service can run as | |

### ServiceIdentityList

`ServiceIdentityList` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| names | Array&lt;EntityName&gt; | | | |
| next | String | optional | | |

### ServicePrincipal

`ServicePrincipal` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| domain | DomainName | | | |
| service | EntityName | | | |
| token | SignedToken | | | |

### SimpleName

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9_][a-zA-Z0-9_-]*` | |

### SignedDomain

If the get signed domain api is called with meta only flag set to true then
the data returned from the ZMS Server is not signed thus signature and keyId
are marked as optional for that use case.

`SignedDomain` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| domain | DomainData | | | |
| signature | String | optional | | |
| keyId | String | optional | the version/id of the key used to sign the domain data | |

### SignedDomains

`SignedDomains` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| domains | Array&lt;SignedDomain&gt; | | | |

### SignedToken

A signed assertion if identity. For example: the YBY cookie value. This token will 
only make sense to the authority that generated it, so it is beneficial to have something
in the value that is cheaply recognized to quickly reject if it belongs to another authority.

`SignedToken` is a `String` type with the following options:

| Option | Value | Notes |
| --- | --- | --- |
| pattern | `[a-zA-Z0-9\\._%=;,-]*` | |

### SubDomain

A Subdomain is a TopLevelDomain, except it has a parent.

`SubDomain` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| description | String | optional | a description of the domain | |
| org | ResourceName | optional | a reference to an Organization. Auth doesn't use it, but it provides external hook (i.e. org:media) | |
| enabled | Bool | optional, default-true | | |
| name | SimpleName | | | |
| adminUsers | Array&lt;ResourceName&gt; | | | |
| parent | DomainName | | | |

### Template

The representation for a solution template object defined on the server

`Template` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| roles | Array&lt;Role&gt; | | | |
| policies | Array&lt;Policy&gt; | | | |

### Tenancy

`Tenancy` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| domain | DomainName | | the domain that is to get a tenancy | |
| service | ServiceName | | the provider service on which the tenancy is to reside | |

### TenancyResourceGroup

`TenancyResourceGroup` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| domain | DomainName | | the domain that is to get a tenancy | |
| service | ServiceName | | the provider service on which the tenancy is to reside | |
| resourceGroup | | Tenant Resource Group | | resource group (e.g. table) allocated for tenant | |

### TenantDomains

`TenantDomains` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| tenantDomainNames | Array&lt;DomainName&gt; | | | |

### TenantRoleAction

`TenantRoleAction` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| role | SimpleName | | | |
| action | String | | | |

### TopLevelDomain

The required attributes to create a top level domain. Probably need an Organization or CostCenter or something...

`TopLevelDomain` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| description | String | optional | a description of the domain | |
| org | ResourceName | optional | a reference to an Organization. Auth doesn't use it, but it provides external hook (i.e. org:media) | |
| enabled | Bool | optional, default-true | | |
| name | SimpleName | | | |
| adminUsers | Array&lt;ResourceName&gt; | | | |

### UserToken

`UserToken` is a `Struct` type with the following fields:

| Name | Type | Options | Description | Notes |
| --- | --- | --- | --- | --- |
| token | SignedToken | | | |

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

### Assertion

#### GET /domain/{domainName}/policy/{policyName}/assertion/{assertionId}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Read the specified assertion from the policy.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| policyName | EntityName | path | | |
| assertionId | Int64 | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Assertion |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### PUT /domain/{domainName}/policy/{policyName}/assertion

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize("update", "{domainName}:policy.{policyName}")

Add the provided assertion to the specified policy.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| policyName | EntityName | path | | |
| assertion | Assertion | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domainName}/policy/{policyName}/assertion/{assertionId}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize("update", "{domainName}:policy.{policyName}")

Delete the assertion with the given id from the specified policy.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| policyName | EntityName | path | | |
| assertionId | Int64 | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### DefaultAdmins

#### PUT /domain/{domainName}/admins

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "sys.auth:domain");

Verify and, if necessary, fix domain roles and policies to make sure the given set
of users have administrative access to the domain. This request is only restricted
to "sys.auth" domain administrators and can be used when the domain administrators
incorrectly have blocked their own access to their domains.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| defaultAdmins | DefaultName | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### Domain

#### GET /domain/{domain}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get info for the specified domain, by name.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Domain |

Exception:

| Code | Type |
| --- | --- |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### POST /domain

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("create", "sys.auth:domain")

Create a new top level domain. This is a privileged action for the ^sys.auth^ administrators

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| detail | TopLevelDomain | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Domain |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |

#### DELETE /domain/{name}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("delete", "sys.auth:domain")

Delete the specified domain. This is a privileged action for the `sys.auth` administrators.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |

#### PUT /domain/{name}/meta

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{name}:")

Update the specified domain metadata. Note that entities in the domain are not
affected. you need update privileges on the domain itself.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| name | DomainName | path | | |
| detail | DomainMeta | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |

### DomainList

#### GET /domain

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Enumerate domains. Can be filtered by prefix and depth, and paginated. This operation
can be expensive, as it may span multiple domains.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| limit | Integer | query: limit | optional | |
| skip | String | query: skip | optional | |
| prefix | String | query: prefix | optional | |
| depth | Integer | query: depth | optional | |
| account | String | query: account | optional | AWS Account |
| ypmid | Integer | query: ypmid | optional | YPM Product ID |
| member | String | query: member | optional | |
| role| String | query: role| optional | |

Some of these options are mutually exclusive. If the request contains either the
account or ypmid query parameter, then the server carries out a domain lookup based
on that query parameter only and ignores all other parameters. If the request
contains no account and ypmid parameters, the server then looks for member and
role query parameters. The member field filters the domain list to only return
those where this user (e.g. user.userid) is member of any role and can be further
restricted by passing the role parameter. For example, by passing "user.john" for
member query parameter and "admin" for the role query parameter, the server will
return all domains where the given user.john is in the admin role. If the member
and role are not specified either, then the server carries out a standard domain
list operation constrained by the other query parameters (limit, skip, prefix and depth).

##### Responses

| Code | Type |
| --- | --- |
| 200 OK | DomainList |

Exception:

| Code | Type |
| --- | --- |
| 401 Unauthorized | ResourceError |

### Entity

#### PUT /domain/{domainName}/entity/{entityName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domainName}:{entityName}")

Put an entity into the domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| entityName | EntityName | path | | |
| entity | EntityName | body | | |
| domainName | DomainName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### GET /domain/{domainName}/entity/{entityName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get a entity from a domain open for all authenticated users to read

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| entityName | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Entity |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domainName}/entity/{entityName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("delete", "{domainName}:{entityName}")

Delete the entity from the domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| entityName | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### Membership

#### GET /domain/{domainName}/role/{roleName}/member/{memberName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get the specified role in the domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| memberName | ResourceName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Membership |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### PUT /domain/{domainName}/role/{roleName}/member/{memberName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domainName}:role.{roleName}"

Create/update the specified role membership.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| membership | Membership | body | | |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| memberName | ResourceName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domainName}/role/{roleName}/member/{memberName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domainName}:role.{roleName}"

Delete the specified role membership.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| memberName | ResourceName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### Policy

#### GET /domain/{domainName}/policy/{policyName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Read the specified policy.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| policyName | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Policy |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### PUT /domain/{domainName}/policy/{policyName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize("update", "{domainName}:policy.{policyName}")

Create or update the specified policy.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| policyName | EntityName | path | | |
| policy | Policy | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domainName}/policy/{policyName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize("delete", "{domainName}:policy.{policyName}")

Delete the specified policy.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| policyName | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### Policies

#### GET /domain/{domainName}/policies

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Enumerate policies provisioned in this domain and returns the list including
policy attributes (modified timestamp and assertions - if requested).

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| assertions | Bool | query: assertions | optional | |

If the assertions query parameter is set to true, the server will return the
list of assertions for all policies in the result set.

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Policies |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### PolicyList

#### GET /domain/{domainName}/policy

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

List policies provisioned in this namespace.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| limit | Integer | query: limit | optional | |
| skip | String | query: skip | optional | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | PolicyList |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### PublicKeyEntry

#### PUT /domain/{domain}/service/{service}/publickey/{id}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domain}:service.{service}")

Register the specified ServiceIdentity in the specified domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| detail | ServiceIdentity | body | | |
| domain | DomainName | path | | |
| service | EntityName | path | | |
| id | String | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |
| 409 Conflict | ResourceError |

#### GET /domain/{domain}/service/{service}/publickey/{id}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get public key info for the specified service and key id.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | EntityName | path | | |
| id | String | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | PublicKeyEntry |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domain}/service/{service}/publickey/{id}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domain}:service.{service}")

Delete the specified PublicKey for a service.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | EntityName | path | | |
| id | String | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |
| 409 Conflict | ResourceError |

### Resource

#### GET /resource

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Return list of resources through the defined assertions that the given principal
has access to. Even though the principal is marked as optional, it must be
specified unless the caller has authorization from sys.auth domain to check
access for all principals. If the query action specified is `assume_aws_role`,
then ZMS will automatically query only regular users and update the value of
the resource field in the assertion to generate an aws role value based on
the aws account id registered for the domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| action | ActionName | query: action | optional | |
| principal | EntityName | query: principal | optional | |

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

### Role

#### GET /domain/{domainName}/role/{roleName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get the specified role in the domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName| EntityName | path | | |
| auditLog | Bool | query: auditLog | optional | |
| expand | Bool | query: expand | optional | |

If the auditLog query parameter is set to true, the server will return the audit
log detailing all the membership changes in this role. If the role is a delegated/trust
role, then the expand query parameter will instruct the zms server to automatically
lookup the members of the role in the delegated domain and return the members as
part of the result set.

##### Responses

| Code | Type |
| --- | --- |
| 200 OK | Role |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### PUT /domain/{domainName}/role/{roleName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domainName}:role.{roleName}")

Create/update the specified role.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |
| role | Role | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domainName}/role/{roleName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("delete", "{domainName}:role.{roleName}")

Delete the specified role

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| roleName | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### RoleList

#### GET /domain/{domainName}/role

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Enumerate roles provisioned in this domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| limit | Integer | query: limit | optional | |
| skip | String | query: skip | optional | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | RoleList |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### Roles

#### GET /domain/{domainName}/roles

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Enumerate roles provisioned in this domain and returns the list including role
attributes (modified timestamp, delegated domain name and members - if requested).

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| members | Bool | query: members | optional | |

If the members query parmeter is set to true, the server will return the list of
members for all roles in the result set.

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Roles |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### ServiceIdentities

#### GET /domain/{domainName}/services

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Enumerate services provisioned in this domain and returns the list including service
attributes (modified timestamp, user, group, executable, endpoint, public keys
and hosts - if requested).

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| publickeys | Bool | query: publickeys | optional | |
| hosts | Bool | query: hosts | optional | |

If the publickeys query parameter is set to true, the server will return the list of
public keys for all services in the result set. Similarly, if the hosts query parameter
is set to true, the list of hosts configured per service will be returned in the result set.

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | ServiceIdentities |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### ServiceIdentity

#### PUT /domain/{domain}/service/{service}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domain}:service")

Register the specified ServiceIdentity in the specified domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| detail | ServiceIdentity | body | | |
| domain | DomainName | path | | |
| service | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### GET /domain/{domain}/service/{service}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get info for the specified ServiceIdentity.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | ServiceIdentity |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domain}/service/{service}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("delete", "{domain}:service")

Delete the specified ServiceIdentity.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | EntityName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### ServiceIdentityList

#### GET /domain/{domainName}/service

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Enumerate services provisioned in this domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domainName | DomainName | path | | |
| limit | Integer | query: limit | optional | |
| skip | String | query: skip | optional | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | ServiceIdentityList |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### ServicePrincipal

#### GET /principal

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Return a principal object if the serviceToken passed as part of the authentication header is valid.

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | ServicePrincipal |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### SignedDomains

#### GET /sys/modified\_domains

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Retrieve the list of modified domains since the specified timestamp. The server will
return the list of all modified domains and the latest modification timestamp as
the value of the ETag header. The client will need to use this value during its
next call to request the changes since the previous request. When metaonly set to
true, don't add roles, policies or services, don't sign

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| matchingTag | String | header: If-None-Match | | |
| domain | DomainName | query: domain | optional | |
| metaOnly | String | query: metaOnly | optional | true or false |

##### Response Parameters

| Name | Type | Destination | Description |
| --- | --- | --- | --- |
| tag | String | header: ETag | |

##### Responses

| Code | Type |
| --- | --- |
| 200 OK | SignedDomains |
| 304 Not Modified | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

### SubDomain

#### POST /subdomain/{parent}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("create", "{parent}:domain")

Create a new subdomain, The authorization is based on the parent domain.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| parent | DomainName | path | | |
| detail | SubDomain | body | | |

##### Responses

| Code | Type |
| --- | --- |
| 200 OK | Domain |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |

#### DELETE /subdomain/{parent}/{name}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("delete", "{parent}:domain")

Delete the specified subdomain. The {name} component in the URI must not include
the parent domain. For example, if the user wants to delete athens.ci subdomain,
then the URI for this request would be /subdomain/athens/ci.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| parent | DomainName | path | | |
| name | DomainName | path | | |

##### Responses

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |

### Templates

#### PUT /domain/{name}/template

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{name}:"

Update the given domain by applying the roles and policies defined in the specified
solution templates. Caller must have update privileges on the domain itself.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| name | DomainName | path | | |
| templates | DomainTemplateList | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### GET /domain/{name}/template

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get the list of solution templates applied to a domain

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| name | DomainName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | DomainTemplateList |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### GET /template

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get the list of solution templates defined in the server

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | ServerTemplateList |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

#### GET /template/{template}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

Get solution template details. Includes the roles and policies that will be automatically
provisioned when the template is applied to a domain

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| template | SimpleName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Template |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |

### Tenancy

#### PUT /domain/{domain}/tenancy/{service}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domain}:tenancy")

Add a tenant for the specified service.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | ServiceName | path | | |
| detail | Tenancy | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | Tenancy |
| 201 CREATED | Tenancy |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domain}/tenancy/{service}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("delete", "{domain}:tenancy")

Delete the tenant from the specified service. Upon successful completion of this
delete request, the server will return NO_CONTENT status code without any data
(no object will be returned).

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | ServiceName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### PUT /domain/{domain}/tenancy/{service}/resourceGroup/{resourceGroup}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domain}:tenancy.{service}")

Add a new resource group for the tenant for the specified service

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | ServiceName | path | | |
| resourceGroup | EntityName | path | | |
| detail | TenancyResourceGroup | body | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### DELETE /domain/{domain}/tenancy/{service}/resourceGroup/{resourceGroup}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): authorize ("update", "{domain}:tenancy.{service}")

Delete the specified resource group for tenant from the specified service.

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| domain | DomainName | path | | |
| service | ServiceName | path | | |
| resourceGroup | Resource Group name | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 204 No Content | |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 403 Forbidden | ResourceError |
| 404 Not Found | ResourceError |

#### GET /providerdomain/{providerDomainName}/user/{userName}?roleName={roleName}

-   [Authentication](#authentication): Certificate
-   [Authorization](#authorization): None

##### Request Parameters

| Name | Type | Source | Options | Description |
| --- | --- | --- | --- | --- |
| providerDomainName | DomainName | path | | |
| userName | SimpleName | path | | |
| roleName | SimpleName | path | | |

##### Responses

Expected:

| Code | Type |
| --- | --- |
| 200 OK | TenantDomains |

Exception:

| Code | Type |
| --- | --- |
| 400 Bad Request | ResourceError |
| 401 Unauthorized | ResourceError |
| 404 Not Found | ResourceError |
