# undefined

## API Methods

### getDomain(*obj, function(err, json, response) { });

`GET /domain/{domain}`
Get info for the specified domain, by name. This request only returns the configured domain attributes and not any domain objects like roles, policies or service identities. A paginated list of domains.

```
obj = {
	"domain": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDomainList(*obj, function(err, json, response) { });

`GET /domain`
Enumerate domains. Can be filtered by prefix and depth, and paginated. This operation can be expensive, as it may span multiple domains. Set of metadata attributes that all domains may have and can be changed.

```
obj = {
	"limit": "<Int32>", // (optional) restrict the number of results in this call
	"skip": "<String>", // (optional) restrict the set to those after the specified "next" token returned from a previous call
	"prefix": "<String>", // (optional) restrict to names that start with the prefix. Can include glob'ing style wildcards
	"depth": "<Int32>", // (optional) restrict the depth of the name, specifying the number of '.' characters that can appear.
	"account": "<String>", // (optional) restrict to domain names that have specified account name
	"roleMember": "<ResourceName>", // (optional) restrict the domain names where the specified user is in a role - see roleName
	"roleName": "<ResourceName>", // (optional) restrict the domain names where the specified user is in this role - see roleMember
	"modifiedSince": "<String>" // This header specifies to the server to return any domains modified since this HTTP date
};
```
*Types:* [`ResourceName <String>`](#resourcename-string)

### postDomain(*obj, function(err, json, response) { });

`POST /domain`
Create a new top level domain. This is a privileged action for the "sys.auth" administrators. Create a new subdomain. The domain administrators of the {parent} domain have the privilege to create subdomains.

```
obj = {
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<TopLevelDomain>" // TopLevelDomain object to be created
};
```
*Types:* [`TopLevelDomain <DomainMeta>`](#topleveldomain-domainmeta)

### postSubDomain(*obj, function(err, json, response) { });

`POST /subdomain/{parent}`
A UserDomain is the user's own top level domain in yby - e.g. yby.hga

```
obj = {
	"parent": "<DomainName>", // name of the parent domain
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<SubDomain>" // Subdomain object to be created
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SubDomain <TopLevelDomain>`](#subdomain-topleveldomain)

### postUserDomain(*obj, function(err, json, response) { });

`POST /userdomain/{name}`
Create a new user domain. The user domain will be created in the yby top level domain and the user himself will be set as the administrator for this domain. Delete the specified domain.  This is a privileged action for the "sys.auth" administrators. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"name": "<SimpleName>", // name of the domain which will be the user id
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<UserDomain>" // UserDomain object to be created
};
```
*Types:* [`SimpleName <String>`](#simplename-string), [`UserDomain <DomainMeta>`](#userdomain-domainmeta)

### deleteTopLevelDomain(*obj, function(err, json, response) { });

`DELETE /domain/{name}`
Delete the specified subdomain. Caller must have domain DELETE permissions in parent. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"name": "<DomainName>", // name of the domain to be deleted
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### deleteSubDomain(*obj, function(err, json, response) { });

`DELETE /subdomain/{parent}/{name}`
Delete the specified userdomain. Caller must have domain DELETE permissions in the domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"parent": "<DomainName>", // name of the parent domain
	"name": "<DomainName>", // name of the subdomain to be deleted
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### deleteUserDomain(*obj, function(err, json, response) { });

`DELETE /userdomain/{name}`
Update the specified top level domain metadata. Note that entities in the domain are not affected. Caller must have UPDATE privileges on the domain itself.

```
obj = {
	"name": "<SimpleName>", // name of the domain to be deleted which will be the user id
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### putDomain(*obj, function(err, json, response) { });

`PUT /domain/{name}/meta`
Update the given domain by applying the roles and policies defined in the specified solution template(s). Caller must have UPDATE privileges on the domain itself.

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<DomainMeta>" // DomainMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DomainMeta <Struct>`](#domainmeta-struct)

### putDomainTemplate(*obj, function(err, json, response) { });

`PUT /domain/{name}/template`
Get the list of solution templates applied to a domain

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"template": "<DomainTemplate>" // DomainTemplate object with solution template name(s)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DomainTemplate <TemplateList>`](#domaintemplate-templatelist)

### getDomainTemplateList(*obj, function(err, json, response) { });

`GET /domain/{name}/template`
Update the given domain by deleting the specified template from the domain template list. Cycles through the roles and policies defined in the template and deletes them. Caller must have DELETE privileges on the domain itself.

```
obj = {
	"name": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### deleteDomainTemplate(*obj, function(err, json, response) { });

`DELETE /domain/{name}/template/{template}`


```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"template": "<SimpleName>", // name of the solution template
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### getDomainDataCheck(*obj, function(err, json, response) { });

`GET /domain/{domainName}/check`
Carry out data check operation for the specified domain.

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### putEntity(*obj, function(err, json, response) { });

`PUT /domain/{dn}/entity/{en}`
Put an entity into the domain. Get a entity from a domain.

```
obj = {
	"dn": "<DomainName>", // name of the domain
	"en": "<EntityName>", // name of entity
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"entity": "<Entity>" // Entity object to be added to the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Entity <Struct>`](#entity-struct)

### getEntity(*obj, function(err, json, response) { });

`GET /domain/{dn}/entity/{en}`
open for all authenticated users to read Delete the entity from the domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"dn": "<DomainName>", // name of the domain
	"en": "<EntityName>" // name of entity
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### deleteEntity(*obj, function(err, json, response) { });

`DELETE /domain/{dn}/entity/{en}`
Enumerate entities provisioned in this domain.

```
obj = {
	"dn": "<DomainName>", // name of the domain
	"en": "<EntityName>", // name of entity
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getEntityList(*obj, function(err, json, response) { });

`GET /domain/{dn}/entity`


```
obj = {
	"dn": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getRoleList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/role`
Enumerate roles provisioned in this domain. Get the list of all roles in a domain with optional flag whether or not include members

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"limit": "<Int32>", // (optional) restrict the number of results in this call
	"skip": "<String>" // (optional) restrict the set to those after the specified "next" token returned from a previous call
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getRoles(*obj, function(err, json, response) { });

`GET /domain/{domainName}/roles`
Get the specified role in the domain.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"members": "<Bool>" // (optional) return list of members in the role
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getRole(*obj, function(err, json, response) { });

`GET /domain/{domainName}/role/{roleName}`
Create/update the specified role.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role to be retrieved
	"auditLog": "<Bool>", // (optional) flag to indicate whether or not to return role audit log
	"expand": "<Bool>" // (optional) expand delegated trust roles and return trusted members
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putRole(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}`
Delete the specified role. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role to be added/updated
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"role": "<Role>" // Role object to be added/updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Role <Struct>`](#role-struct)

### deleteRole(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/role/{roleName}`
Get the membership status for a specified user in a role.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role to be deleted
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getMembership(*obj, function(err, json, response) { });

`GET /domain/{domainName}/role/{roleName}/member/{memberName}`
Add the specified user to the role's member list.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<ResourceName>" // user name to be checked for membership
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`ResourceName <String>`](#resourcename-string)

### putMembership(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/member/{memberName}`
Delete the specified role membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<ResourceName>", // name of the user to be added as a member
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"membership": "<Membership>" // Membership object (must contain role/member names as specified in the URI)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`ResourceName <String>`](#resourcename-string), [`Membership <Struct>`](#membership-struct)

### deleteMembership(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/role/{roleName}/member/{memberName}`
Verify and, if necessary, fix domain roles and policies to make sure the given set of users have administrative access to the domain. This request is only restricted to "sys.auth" domain administrators and can be used when the domain administrators incorrectly have blocked their own access to their domains.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<ResourceName>", // name of the user to be removed as a member
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`ResourceName <String>`](#resourcename-string)

### putDefaultAdmins(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/admins`


```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"defaultAdmins": "<DefaultAdmins>" // list of domain administrators
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DefaultAdmins <Struct>`](#defaultadmins-struct)

### getPolicyList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy`
List policies provisioned in this namespace. List policies provisioned in this namespace.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"limit": "<Int32>", // (optional) restrict the number of results in this call
	"skip": "<String>" // (optional) restrict the set to those after the specified "next" token returned from a previous call
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getPolicies(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policies`
Read the specified policy.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"assertions": "<Bool>" // (optional) return list of assertions in the policy
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getPolicy(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy/{policyName}`
Create or update the specified policy.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>" // name of the policy to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putPolicy(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}`
Delete the specified policy. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy to be added/updated
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"policy": "<Policy>" // Policy object to be added or updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Policy <Struct>`](#policy-struct)

### deletePolicy(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}`
Get the assertion details with specified id in the given policy

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy to be deleted
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getAssertion(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy/{policyName}/assertion/{assertionId}`
Add the specified assertion to the given policy

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>" // assertion id
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putAssertion(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}/assertion`
Delete the specified policy assertion. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"assertion": "<Assertion>" // Assertion object to be added to the given policy
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Assertion <Struct>`](#assertion-struct)

### deleteAssertion(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}/assertion/{assertionId}`


```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>", // assertion id
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putServiceIdentity(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}`
Register the specified ServiceIdentity in the specified domain Get info for the specified ServiceIdentity.

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<ServiceIdentity>" // ServiceIdentity object to be added/updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`ServiceIdentity <Struct>`](#serviceidentity-struct)

### getServiceIdentity(*obj, function(err, json, response) { });

`GET /domain/{domain}/service/{service}`
Delete the specified ServiceIdentity. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>" // name of the service to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### deleteServiceIdentity(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}`
Retrieve list of service identities

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service to be deleted
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### getServiceIdentities(*obj, function(err, json, response) { });

`GET /domain/{domainName}/services`
Enumerate services provisioned in this domain.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"publickeys": "<Bool>", // (optional) return list of public keys in the service
	"hosts": "<Bool>" // (optional) return list of hosts in the service
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getServiceIdentityList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/service`
Retrieve the specified public key from the service.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"limit": "<Int32>", // (optional) restrict the number of results in this call
	"skip": "<String>" // (optional) restrict the set to those after the specified "next" token returned from a previous call
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getPublicKeyEntry(*obj, function(err, json, response) { });

`GET /domain/{domain}/service/{service}/publickey/{id}`
Add the specified public key to the service.

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"id": "<String>" // the identifier of the public key to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### putPublicKeyEntry(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}/publickey/{id}`
Remove the specified public key from the service. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"id": "<String>", // the identifier of the public key to be added
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"publicKeyEntry": "<PublicKeyEntry>" // PublicKeyEntry object to be added/updated in the service
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`PublicKeyEntry <Struct>`](#publickeyentry-struct)

### deletePublicKeyEntry(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}/publickey/{id}`
Enumerate services provisioned on a specific host

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"id": "<String>", // the identifier of the public key to be deleted
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### getHostServices(*obj, function(err, json, response) { });

`GET /host/{host}/services`


```
obj = {
	"host": "<String>" // name of the host
};
```

### putTenancy(*obj, function(err, json, response) { });

`PUT /domain/{domain}/tenancy/{service}`
Add a tenant for the specified service. Retrieve the specified tenant.

```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>", // name of the provider service
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<Tenancy>" // tenancy object
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string), [`Tenancy <Struct>`](#tenancy-struct)

### getTenancy(*obj, function(err, json, response) { });

`GET /domain/{domain}/tenancy/{service}`
Delete the tenant from the specified service. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>" // name of the provider service
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string)

### deleteTenancy(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/tenancy/{service}`
Add a new resource group for the tenant for the specified service.

```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>", // name of the provider service
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string)

### putTenancyResourceGroup(*obj, function(err, json, response) { });

`PUT /domain/{domain}/tenancy/{service}/resourceGroup/{resourceGroup}`
Delete the specified resource group for tenant from the specified service.

```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>", // name of the provider service
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<TenancyResourceGroup>" // tenancy resource group object
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string), [`EntityName <String>`](#entityname-string), [`TenancyResourceGroup <Struct>`](#tenancyresourcegroup-struct)

### deleteTenancyResourceGroup(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/tenancy/{service}/resourceGroup/{resourceGroup}`


```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>", // name of the provider service
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string), [`EntityName <String>`](#entityname-string)

### getTenantDomains(*obj, function(err, json, response) { });

`GET /providerdomain/{providerDomainName}/user/{userName}`
Get list of tenant domains user has access to for specified provider domain. provider resource in tenant domain

```
obj = {
	"providerDomainName": "<DomainName>", // name of the provider domain
	"userName": "<SimpleName>", // name of the user to retrieve tenant domain access for
	"roleName": "<SimpleName>" // (optional) role name to filter on when looking for the tenants in provider and
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### putTenantRoles(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}/tenant/{tenantDomain}`
Create/update set of roles for a given tenant. Retrieve the configured set of roles for the tenant.

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<TenantRoles>" // list of roles to be added/updated for the tenant
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`TenantRoles <Struct>`](#tenantroles-struct)

### getTenantRoles(*obj, function(err, json, response) { });

`GET /domain/{domain}/service/{service}/tenant/{tenantDomain}`
Delete the configured set of roles for the tenant. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>" // name of the tenant domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### deleteTenantRoles(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}/tenant/{tenantDomain}`
Create/update set of roles for a given tenant and resource group

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### putTenantResourceGroupRoles(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}`
Retrieve the configured set of roles for the tenant and resource group

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<TenantResourceGroupRoles>" // list of roles to be added/updated for the tenant
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string), [`TenantResourceGroupRoles <Struct>`](#tenantresourcegrouproles-struct)

### getTenantResourceGroupRoles(*obj, function(err, json, response) { });

`GET /domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}`
Delete the configured set of roles for the tenant and resource group

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"resourceGroup": "<EntityName>" // tenant resource group
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string)

### deleteTenantResourceGroupRoles(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}`
Create/update set of roles for a given provider and resource group

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string)

### putProviderResourceGroupRoles(*obj, function(err, json, response) { });

`PUT /domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}`
Retrieve the configured set of roles for the provider and resource group

```
obj = {
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"provDomain": "<DomainName>", // name of the provider domain
	"provService": "<SimpleName>", // name of the provider service
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>", // Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<ProviderResourceGroupRoles>" // list of roles to be added/updated for the provider
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string), [`ProviderResourceGroupRoles <Struct>`](#providerresourcegrouproles-struct)

### getProviderResourceGroupRoles(*obj, function(err, json, response) { });

`GET /domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}`
Delete the configured set of roles for the provider and resource group

```
obj = {
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"provDomain": "<DomainName>", // name of the provider domain
	"provService": "<SimpleName>", // name of the provider service
	"resourceGroup": "<EntityName>" // tenant resource group
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string)

### deleteProviderResourceGroupRoles(*obj, function(err, json, response) { });

`DELETE /domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}`


```
obj = {
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"provDomain": "<DomainName>", // name of the provider domain
	"provService": "<SimpleName>", // name of the provider service
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>" // Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string)

### getAccess(*obj, function(err, json, response) { });

`GET /access/{action}/{resource}`
Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes. Use distributed mechanisms for decentralized (data-plane) access by fetching signed policies and role tokens for users. If the authenticated user has READ access to the {domain}:access resource, then he/she can carry out access checks for any other user in the domain by specifying the optional checkPrincipal query parameter.

```
obj = {
	"action": "<ActionName>", // action as specified in the policy assertion, i.e. UPDATE or READ
	"resource": "<YRN>", // the resource to check access against, i.e. "yrn:sports::weather:table.zipcodes" or "media.news:articles"
	"domain": "<DomainName>", // (optional) usually null. If present, it specifies an alternate domain for cross-domain trust relation
	"checkPrincipal": "<EntityName>" // (optional) usually null. If present, carry out the access check for this principal
};
```
*Types:* [`ActionName <String>`](#actionname-string), [`YRN <String>`](#yrn-string), [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getResourceAccessList(*obj, function(err, json, response) { });

`GET /resource`
Return list of resources that the given principal has access to. Even though the principal is marked as optional, it must be specified unless the caller has authorization from sys.auth domain to check access for all yby principals.

```
obj = {
	"principal": "<EntityName>", // (optional) specifies principal to query the resource list for
	"action": "<ActionName>" // (optional) action as specified in the policy assertion
};
```
*Types:* [`EntityName <String>`](#entityname-string), [`ActionName <String>`](#actionname-string)

### getSignedDomains(*obj, function(err, json, response) { });

`GET /sys/modified_domains`
Retrieve the list of modified domains since the specified timestamp. The server will return the list of all modified domains and the latest modification timestamp as the value of the ETag header. The client will need to use this value during its next call to request the changes since the previous request. When metaonly set to true, dont add roles, policies or services, dont sign

```
obj = {
	"domain": "<DomainName>", // (optional) filter the domain list only to the specified name
	"metaOnly": "<String>", // (optional) valid values are "true" or "false"
	"matchingTag": "<String>" // Retrieved from the previous request, this timestamp specifies to the server to return any domains modified since this time
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getUserToken(*obj, function(err, json, response) { });

`GET /user/{userName}/token`
Return a user/principal token for the specified authenticated user. Authenticated users are not allowed to carry out any update operations with their credentials. They must first obtain a UserToken and then use that token for authentication and authorization of their update requests. CORS (Cross-Origin Resource Sharing) support to allow Provider Services to obtain AuthorizedService Tokens on behalf of Tenant administrators

```
obj = {
	"userName": "<SimpleName>", // name of the user
	"serviceNames": "<String>" // (optional) comma separated list of on-behalf-of service names
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### optionsUserToken(*obj, function(err, json, response) { });

`OPTIONS /user/{userName}/token`
A service principal object identifying a given service.

```
obj = {
	"userName": "<SimpleName>", // name of the user
	"serviceNames": "<String>" // (optional) comma separated list of on-behalf-of service names
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### getServicePrincipal(*obj, function(err, json, response) { });

`GET /principal`
Return a ServicePrincipal object if the serviceToken is valid. This request provides a simple operation that an external application can execute to validate a service token.


### getServerTemplateList(*obj, function(err, json, response) { });

`GET /template`
Get the list of solution templates defined in the server Get solution template details. Includes the roles and policies that will be automatically provisioned when the template is applied to a domain


### getTemplate(*obj, function(err, json, response) { });

`GET /template/{template}`


```
obj = {
	"template": "<SimpleName>" // name of the solution template
};
```
*Types:* [`SimpleName <String>`](#simplename-string)


## API Types

### SimpleName `<String>`

A simple identifier, an element of compound name.


```
{
    "name": "SimpleName",
    "type": "String",
    "comment": "A simple identifier, an element of compound name.",
    "pattern": "[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### CompoundName `<String>`

A compound name. Most names in this API are compound names.


```
{
    "name": "CompoundName",
    "type": "String",
    "comment": "A compound name. Most names in this API are compound names.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### DomainName `<String>`

A domain name is the general qualifier prefix, as its uniqueness is managed.


```
{
    "name": "DomainName",
    "type": "String",
    "comment": "A domain name is the general qualifier prefix, as its uniqueness is managed.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### EntityName `<String>`

An entity name is a short form of a resource name, including only the domain and entity.


```
{
    "name": "EntityName",
    "type": "String",
    "comment": "An entity name is a short form of a resource name, including only the domain and entity.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ServiceName `<String>`

A service name will generally be a unique subdomain.


```
{
    "name": "ServiceName",
    "type": "String",
    "comment": "A service name will generally be a unique subdomain.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### LocationName `<String>`

A location name is not yet defined, but will be a dotted name like everything else.


```
{
    "name": "LocationName",
    "type": "String",
    "comment": "A location name is not yet defined, but will be a dotted name like everything else.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ActionName `<String>`

An action (operation) name.


```
{
    "name": "ActionName",
    "type": "String",
    "comment": "An action (operation) name.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ResourceName `<String>`

A shorthand for a YRN with no service or location. The 'tail' of a YRN, just the domain:entity. Note that the EntityName part is optional, that is, a domain name followed by a colon is valid resource name.


```
{
    "name": "ResourceName",
    "type": "String",
    "comment": "A shorthand for a YRN with no service or location. The 'tail' of a YRN, just the domain:entity. Note that the EntityName part is optional, that is, a domain name followed by a colon is valid resource name.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(:([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?"
}
```

### YRN `<String>`

A full Yahoo Resource name (YRN).


```
{
    "name": "YRN",
    "type": "String",
    "comment": "A full Yahoo Resource name (YRN).",
    "pattern": "(yrn:(([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?:(([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?:)?([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(:([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?"
}
```

### YBase64 `<String>`

The Y-specific URL-safe Base64 variant.


```
{
    "name": "YBase64",
    "type": "String",
    "comment": "The Y-specific URL-safe Base64 variant.",
    "pattern": "[a-zA-Z0-9\\._-]+"
}
```

### YEncoded `<String>`

YEncoded includes ybase64 chars, as well as = and %. This can represent a YBY cookie and URL-encoded values.


```
{
    "name": "YEncoded",
    "type": "String",
    "comment": "YEncoded includes ybase64 chars, as well as = and %. This can represent a YBY cookie and URL-encoded values.",
    "pattern": "[a-zA-Z0-9\\._%=-]*"
}
```

### AuthorityName `<String>`

Used as the prefix in a signed assertion. This uniquely identifies a signing authority.


```
{
    "name": "AuthorityName",
    "type": "String",
    "comment": "Used as the prefix in a signed assertion. This uniquely identifies a signing authority.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### SignedToken `<String>`

i.e. "yby" A signed assertion if identity. i.e. the YBY cookie value. This token will only make sense to the authority that generated it, so it is beneficial to have something in the value that is cheaply recognized to quickly reject if it belongs to another authority. In addition to the YEncoded set our token includes ; to separate components and , to separate roles and : for IPv6 addresses


```
{
    "name": "SignedToken",
    "type": "String",
    "comment": "i.e. \"yby\" A signed assertion if identity. i.e. the YBY cookie value. This token will only make sense to the authority that generated it, so it is beneficial to have something in the value that is cheaply recognized to quickly reject if it belongs to another authority. In addition to the YEncoded set our token includes ; to separate components and , to separate roles and : for IPv6 addresses",
    "pattern": "[a-zA-Z0-9\\._%=:;,-]*"
}
```

### Domain `<Struct>`

A domain is an independent partition of users, roles, and resources. Its name represents the definition of a namespace; the only way a new namespace can be created, from the top, is by creating Domains. Administration of a domain is governed by the parent domain (using reverse-DNS namespaces). The top level domains are governed by the special "sys.auth" domain. The org (Organization) is optional, but would refer to another domain.


```
{
    "name": "Domain",
    "type": "Struct",
    "comment": "A domain is an independent partition of users, roles, and resources. Its name represents the definition of a namespace; the only way a new namespace can be created, from the top, is by creating Domains. Administration of a domain is governed by the parent domain (using reverse-DNS namespaces). The top level domains are governed by the special \"sys.auth\" domain. The org (Organization) is optional, but would refer to another domain.",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "comment": "the common name to be referred to, the symbolic id. It is immutable"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": true,
            "comment": "the last modification timestamp of any object or attribute in this domain"
        },
        {
            "name": "id",
            "type": "UUID",
            "optional": true,
            "comment": "unique identifier of the domain. generated on create, never reused"
        },
        {
            "name": "description",
            "type": "String",
            "optional": true,
            "comment": "description of the domain"
        },
        {
            "name": "org",
            "type": "ResourceName",
            "optional": true,
            "comment": "a reference to an Organization. Athenz doesn't use it, but it provides external hook (i.e. org:media)"
        },
        {
            "name": "enabled",
            "type": "Bool",
            "optional": true,
            "default": true,
            "comment": "Future use only, currently not used"
        },
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "default": false,
            "comment": "Flag indicates whether or not domain modifications should be logged for SOX+Auditing. If true, the auditRef parameter must be supplied(not empty) for any API defining it."
        },
        {
            "name": "account",
            "type": "String",
            "optional": true,
            "comment": "associated cloud (i.e. aws) account id"
        }
    ]
}
```

### RoleList `<Struct>`

The representation for an enumeration of roles in the namespace, with pagination.


```
{
    "name": "RoleList",
    "type": "Struct",
    "comment": "The representation for an enumeration of roles in the namespace, with pagination.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "items": "EntityName",
            "comment": "list of role names"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next role list request as the value for the skip query parameter."
        }
    ]
}
```

### RoleAuditLog `<Struct>`

An audit log entry for role membership change.


```
{
    "name": "RoleAuditLog",
    "type": "Struct",
    "comment": "An audit log entry for role membership change.",
    "fields": [
        {
            "name": "member",
            "type": "ResourceName",
            "comment": "name of the role member"
        },
        {
            "name": "admin",
            "type": "ResourceName",
            "comment": "name of the principal executing the change"
        },
        {
            "name": "created",
            "type": "Timestamp",
            "comment": "timestamp of the entry"
        },
        {
            "name": "action",
            "type": "String",
            "comment": "log action - either add or delete"
        },
        {
            "name": "auditRef",
            "type": "String",
            "optional": true,
            "comment": "audit reference string for the change as supplied by admin"
        }
    ]
}
```

### Role `<Struct>`

The representation for a Role with set of members.


```
{
    "name": "Role",
    "type": "Struct",
    "comment": "The representation for a Role with set of members.",
    "fields": [
        {
            "name": "name",
            "type": "ResourceName",
            "comment": "name of the role"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": true,
            "comment": "last modification timestamp of the role"
        },
        {
            "name": "members",
            "type": "Array",
            "optional": true,
            "items": "ResourceName",
            "comment": "an explicit list of members. Might be empty or null, if trust is set"
        },
        {
            "name": "trust",
            "type": "DomainName",
            "optional": true,
            "comment": "a trusted domain to delegate membership decisions to"
        },
        {
            "name": "auditLog",
            "type": "Array",
            "optional": true,
            "items": "RoleAuditLog",
            "comment": "an audit log for role membership changes"
        }
    ]
}
```

### Roles `<Struct>`

The representation for a list of roles with full details


```
{
    "name": "Roles",
    "type": "Struct",
    "comment": "The representation for a list of roles with full details",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "items": "Role",
            "comment": "list of role objects"
        }
    ]
}
```

### Membership `<Struct>`

The representation for a role membership.


```
{
    "name": "Membership",
    "type": "Struct",
    "comment": "The representation for a role membership.",
    "fields": [
        {
            "name": "memberName",
            "type": "ResourceName",
            "comment": "name of the member"
        },
        {
            "name": "isMember",
            "type": "Bool",
            "optional": true,
            "default": true,
            "comment": "flag to indicate whether or the user is a member or not"
        },
        {
            "name": "roleName",
            "type": "ResourceName",
            "optional": true,
            "comment": "name of the role"
        }
    ]
}
```

### DefaultAdmins `<Struct>`

The list of domain administrators.


```
{
    "name": "DefaultAdmins",
    "type": "Struct",
    "comment": "The list of domain administrators.",
    "fields": [
        {
            "name": "admins",
            "type": "Array",
            "items": "ResourceName",
            "comment": "list of domain administrators"
        }
    ]
}
```

### AssertionEffect `<Enum>`

```
{
    "name": "AssertionEffect",
    "type": "Enum",
    "values": [
        "ALLOW",
        "DENY"
    ]
}
```

### Assertion `<Struct>`

A representation for the encapsulation of an action to be performed on a resource by a principal.


```
{
    "name": "Assertion",
    "type": "Struct",
    "comment": "A representation for the encapsulation of an action to be performed on a resource by a principal.",
    "fields": [
        {
            "name": "role",
            "type": "String",
            "comment": "the subject of the assertion - a role"
        },
        {
            "name": "resource",
            "type": "String",
            "comment": "the object of the assertion. Must be in the local namespace. Can contain wildcards"
        },
        {
            "name": "action",
            "type": "String",
            "comment": "the predicate of the assertion. Can contain wildcards"
        },
        {
            "name": "effect",
            "type": "AssertionEffect",
            "optional": true,
            "default": "ALLOW",
            "comment": "the effect of the assertion in the policy language"
        },
        {
            "name": "id",
            "type": "Int64",
            "optional": true,
            "comment": "assertion id - auto generated by server. Not required during put operations."
        }
    ]
}
```

### Policy `<Struct>`

The representation for a Policy with set of assertions.


```
{
    "name": "Policy",
    "type": "Struct",
    "comment": "The representation for a Policy with set of assertions.",
    "fields": [
        {
            "name": "name",
            "type": "ResourceName",
            "comment": "name of the policy"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": true,
            "comment": "last modification timestamp of this policy"
        },
        {
            "name": "assertions",
            "type": "Array",
            "items": "Assertion",
            "comment": "list of defined assertions for this policy"
        }
    ]
}
```

### Policies `<Struct>`

The representation of list of policy objects


```
{
    "name": "Policies",
    "type": "Struct",
    "comment": "The representation of list of policy objects",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "items": "Policy",
            "comment": "list of policy objects"
        }
    ]
}
```

### Template `<Struct>`

Solution Template object defined on the server


```
{
    "name": "Template",
    "type": "Struct",
    "comment": "Solution Template object defined on the server",
    "fields": [
        {
            "name": "roles",
            "type": "Array",
            "items": "Role",
            "comment": "list of roles in the template"
        },
        {
            "name": "policies",
            "type": "Array",
            "items": "Policy",
            "comment": "list of policies defined in this template"
        }
    ]
}
```

### TemplateList `<Struct>`

List of template names that is the base struct for server and domain templates


```
{
    "name": "TemplateList",
    "type": "Struct",
    "comment": "List of template names that is the base struct for server and domain templates",
    "fields": [
        {
            "name": "templateNames",
            "type": "Array",
            "items": "SimpleName",
            "comment": "list of template names"
        }
    ]
}
```

### DomainTemplate `<TemplateList>`

solution template(s) to be applied to a domain


```
{
    "name": "DomainTemplate",
    "type": "TemplateList",
    "comment": "solution template(s) to be applied to a domain"
}
```

### DomainTemplateList `<TemplateList>`

List of solution templates to be applied to a domain


```
{
    "name": "DomainTemplateList",
    "type": "TemplateList",
    "comment": "List of solution templates to be applied to a domain"
}
```

### ServerTemplateList `<TemplateList>`

List of solution templates available in the server


```
{
    "name": "ServerTemplateList",
    "type": "TemplateList",
    "comment": "List of solution templates available in the server"
}
```

### DomainList `<Struct>`

```
{
    "name": "DomainList",
    "type": "Struct",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "items": "DomainName",
            "comment": "list of domain names"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next domain list request as the value for the skip query parameter."
        }
    ]
}
```

### DomainMeta `<Struct>`

```
{
    "name": "DomainMeta",
    "type": "Struct",
    "fields": [
        {
            "name": "description",
            "type": "String",
            "optional": true,
            "comment": "a description of the domain"
        },
        {
            "name": "org",
            "type": "ResourceName",
            "optional": true,
            "comment": "a reference to an Organization. Athenz doesn't use it, but it provides external hook (i.e. org:media)"
        },
        {
            "name": "enabled",
            "type": "Bool",
            "optional": true,
            "default": true,
            "comment": "Future use only, currently not used"
        },
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "default": false,
            "comment": "Flag indicates whether or not domain modifications should be logged for SOX+Auditing. If true, the auditRef parameter must be supplied(not empty) for any API defining it."
        },
        {
            "name": "account",
            "type": "String",
            "optional": true,
            "comment": "associated cloud (i.e. aws) account id"
        }
    ]
}
```

### TopLevelDomain `<DomainMeta>`

Top Level Domain object. The required attributes include the name of the domain and list of domain administrators.


```
{
    "name": "TopLevelDomain",
    "type": "DomainMeta",
    "comment": "Top Level Domain object. The required attributes include the name of the domain and list of domain administrators.",
    "fields": [
        {
            "name": "name",
            "type": "SimpleName",
            "comment": "name of the domain"
        },
        {
            "name": "adminUsers",
            "type": "Array",
            "items": "ResourceName",
            "comment": "list of domain administrators"
        },
        {
            "name": "templates",
            "type": "DomainTemplateList",
            "optional": true,
            "comment": "list of solution template names"
        }
    ]
}
```

### SubDomain `<TopLevelDomain>`

A Subdomain is a TopLevelDomain, except it has a parent.


```
{
    "name": "SubDomain",
    "type": "TopLevelDomain",
    "comment": "A Subdomain is a TopLevelDomain, except it has a parent.",
    "fields": [
        {
            "name": "parent",
            "type": "DomainName",
            "comment": "name of the parent domain"
        }
    ]
}
```

### UserDomain `<DomainMeta>`

```
{
    "name": "UserDomain",
    "type": "DomainMeta",
    "fields": [
        {
            "name": "name",
            "type": "SimpleName",
            "comment": "user id which will be the domain name"
        },
        {
            "name": "templates",
            "type": "DomainTemplateList",
            "optional": true,
            "comment": "list of solution template names"
        }
    ]
}
```

### DanglingPolicy `<Struct>`

A dangling policy where the assertion is referencing a role name that doesn't exist in the domain


```
{
    "name": "DanglingPolicy",
    "type": "Struct",
    "comment": "A dangling policy where the assertion is referencing a role name that doesn't exist in the domain",
    "fields": [
        {
            "name": "policyName",
            "type": "EntityName"
        },
        {
            "name": "roleName",
            "type": "EntityName"
        }
    ]
}
```

### DomainDataCheck `<Struct>`

Domain data object representing the results of a check operation looking for dangling roles, policies and trust relationships that are set either on tenant or provider side only


```
{
    "name": "DomainDataCheck",
    "type": "Struct",
    "comment": "Domain data object representing the results of a check operation looking for dangling roles, policies and trust relationships that are set either on tenant or provider side only",
    "fields": [
        {
            "name": "danglingRoles",
            "type": "Array",
            "optional": true,
            "items": "EntityName",
            "comment": "Names of roles not specified in any assertion. Might be empty or null if no dangling roles."
        },
        {
            "name": "danglingPolicies",
            "type": "Array",
            "optional": true,
            "items": "DanglingPolicy",
            "comment": "Policy+role tuples where role doesnt exist. Might be empty or null if no dangling policies."
        },
        {
            "name": "policyCount",
            "type": "Int32",
            "comment": "total number of policies"
        },
        {
            "name": "assertionCount",
            "type": "Int32",
            "comment": "total number of assertions"
        },
        {
            "name": "roleWildCardCount",
            "type": "Int32",
            "comment": "total number of assertions containing roles as wildcards"
        },
        {
            "name": "providersWithoutTrust",
            "type": "Array",
            "optional": true,
            "items": "ServiceName",
            "comment": "Service names (domain.service) that dont contain trust role if this is a tenant domain. Might be empty or null, if not a tenant or if all providers support this tenant."
        },
        {
            "name": "tenantsWithoutAssumeRole",
            "type": "Array",
            "optional": true,
            "items": "DomainName",
            "comment": "Names of Tenant domains that dont contain assume role assertions if this is a provider domain. Might be empty or null, if not a provider or if all tenants support use this provider."
        }
    ]
}
```

### Entity `<Struct>`

An entity is a name and a structured value. some entity names/prefixes are reserved (i.e. "role",  "policy", "meta", "domain", "service")


```
{
    "name": "Entity",
    "type": "Struct",
    "comment": "An entity is a name and a structured value. some entity names/prefixes are reserved (i.e. \"role\",  \"policy\", \"meta\", \"domain\", \"service\")",
    "fields": [
        {
            "name": "name",
            "type": "EntityName",
            "comment": "name of the entity object"
        },
        {
            "name": "value",
            "type": "Struct",
            "comment": "value of the entity"
        }
    ]
}
```

### EntityList `<Struct>`

The representation for an enumeration of entities in the namespace


```
{
    "name": "EntityList",
    "type": "Struct",
    "comment": "The representation for an enumeration of entities in the namespace",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "items": "EntityName",
            "comment": "list of entity names"
        }
    ]
}
```

### PolicyList `<Struct>`

The representation for an enumeration of policies in the namespace, with pagination.


```
{
    "name": "PolicyList",
    "type": "Struct",
    "comment": "The representation for an enumeration of policies in the namespace, with pagination.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "items": "EntityName",
            "comment": "list of policy names"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next policy list request as the value for the skip query parameter."
        }
    ]
}
```

### PublicKeyEntry `<Struct>`

The representation of the public key in a service identity object.


```
{
    "name": "PublicKeyEntry",
    "type": "Struct",
    "comment": "The representation of the public key in a service identity object.",
    "fields": [
        {
            "name": "key",
            "type": "String",
            "comment": "the public key for the service"
        },
        {
            "name": "id",
            "type": "String",
            "comment": "the key identifier (version or zone name)"
        }
    ]
}
```

### ServiceIdentity `<Struct>`

The representation of the service identity object.


```
{
    "name": "ServiceIdentity",
    "type": "Struct",
    "comment": "The representation of the service identity object.",
    "fields": [
        {
            "name": "name",
            "type": "ServiceName",
            "comment": "the full name of the service, i.e. \"sports.storage\""
        },
        {
            "name": "publicKeys",
            "type": "Array",
            "optional": true,
            "items": "PublicKeyEntry",
            "comment": "array of public keys for key rotation"
        },
        {
            "name": "providerEndpoint",
            "type": "URI",
            "optional": true,
            "comment": "if present, then this service can provision tenants via this endpoint."
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": true,
            "comment": "the timestamp when this entry was last modified"
        },
        {
            "name": "executable",
            "type": "String",
            "optional": true,
            "comment": "the path of the executable that runs the service"
        },
        {
            "name": "hosts",
            "type": "Array",
            "optional": true,
            "items": "String",
            "comment": "list of host names that this service can run on"
        },
        {
            "name": "user",
            "type": "String",
            "optional": true,
            "comment": "local (unix) user name this service can run as"
        },
        {
            "name": "group",
            "type": "String",
            "optional": true,
            "comment": "local (unix) group name this service can run as"
        }
    ]
}
```

### ServiceIdentities `<Struct>`

The representation of list of services


```
{
    "name": "ServiceIdentities",
    "type": "Struct",
    "comment": "The representation of list of services",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "items": "ServiceIdentity",
            "comment": "list of services"
        }
    ]
}
```

### ServiceIdentityList `<Struct>`

The representation for an enumeration of services in the namespace, with pagination.


```
{
    "name": "ServiceIdentityList",
    "type": "Struct",
    "comment": "The representation for an enumeration of services in the namespace, with pagination.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "items": "EntityName",
            "comment": "list of service names"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next service list request as the value for the skip query parameter."
        }
    ]
}
```

### HostServices `<Struct>`

The representation for an enumeration of services authorized to run on a specific host.


```
{
    "name": "HostServices",
    "type": "Struct",
    "comment": "The representation for an enumeration of services authorized to run on a specific host.",
    "fields": [
        {
            "name": "host",
            "type": "String",
            "comment": "name of the host"
        },
        {
            "name": "names",
            "type": "Array",
            "items": "EntityName",
            "comment": "list of service names authorized to run on this host"
        }
    ]
}
```

### Tenancy `<Struct>`

A representation of tenant.


```
{
    "name": "Tenancy",
    "type": "Struct",
    "comment": "A representation of tenant.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "the domain that is to get a tenancy"
        },
        {
            "name": "service",
            "type": "ServiceName",
            "comment": "the provider service on which the tenancy is to reside"
        },
        {
            "name": "resourceGroups",
            "type": "Array",
            "optional": true,
            "items": "EntityName",
            "comment": "registered resource groups for this tenant"
        }
    ]
}
```

### TenancyResourceGroup `<Struct>`

```
{
    "name": "TenancyResourceGroup",
    "type": "Struct",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "the domain that is to get a tenancy"
        },
        {
            "name": "service",
            "type": "ServiceName",
            "comment": "the provider service on which the tenancy is to reside"
        },
        {
            "name": "resourceGroup",
            "type": "EntityName",
            "comment": "registered resource group for this tenant"
        }
    ]
}
```

### TenantDomains `<Struct>`

```
{
    "name": "TenantDomains",
    "type": "Struct",
    "fields": [
        {
            "name": "tenantDomainNames",
            "type": "Array",
            "items": "DomainName"
        }
    ]
}
```

### TenantRoleAction `<Struct>`

A representation of tenant role action.


```
{
    "name": "TenantRoleAction",
    "type": "Struct",
    "comment": "A representation of tenant role action.",
    "fields": [
        {
            "name": "role",
            "type": "SimpleName",
            "comment": "name of the role"
        },
        {
            "name": "action",
            "type": "String",
            "comment": "action value for the generated policy assertion"
        }
    ]
}
```

### TenantRoles `<Struct>`

A representation of tenant roles to be provisioned.


```
{
    "name": "TenantRoles",
    "type": "Struct",
    "comment": "A representation of tenant roles to be provisioned.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "name of the provider domain"
        },
        {
            "name": "service",
            "type": "SimpleName",
            "comment": "name of the provider service"
        },
        {
            "name": "tenant",
            "type": "DomainName",
            "comment": "name of the tenant domain"
        },
        {
            "name": "roles",
            "type": "Array",
            "items": "TenantRoleAction",
            "comment": "the role/action pairs to provision"
        }
    ]
}
```

### TenantResourceGroupRoles `<Struct>`

A representation of tenant roles for resource groups to be provisioned.


```
{
    "name": "TenantResourceGroupRoles",
    "type": "Struct",
    "comment": "A representation of tenant roles for resource groups to be provisioned.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "name of the provider domain"
        },
        {
            "name": "service",
            "type": "SimpleName",
            "comment": "name of the provider service"
        },
        {
            "name": "tenant",
            "type": "DomainName",
            "comment": "name of the tenant domain"
        },
        {
            "name": "roles",
            "type": "Array",
            "items": "TenantRoleAction",
            "comment": "the role/action pairs to provision"
        },
        {
            "name": "resourceGroup",
            "type": "EntityName",
            "comment": "tenant resource group"
        }
    ]
}
```

### ProviderResourceGroupRoles `<Struct>`

A representation of provider roles to be provisioned.


```
{
    "name": "ProviderResourceGroupRoles",
    "type": "Struct",
    "comment": "A representation of provider roles to be provisioned.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "name of the provider domain"
        },
        {
            "name": "service",
            "type": "SimpleName",
            "comment": "name of the provider service"
        },
        {
            "name": "tenant",
            "type": "DomainName",
            "comment": "name of the tenant domain"
        },
        {
            "name": "roles",
            "type": "Array",
            "items": "TenantRoleAction",
            "comment": "the role/action pairs to provision"
        },
        {
            "name": "resourceGroup",
            "type": "EntityName",
            "comment": "tenant resource group"
        }
    ]
}
```

### Access `<Struct>`

Access can be checked and returned as this resource.


```
{
    "name": "Access",
    "type": "Struct",
    "comment": "Access can be checked and returned as this resource.",
    "fields": [
        {
            "name": "granted",
            "type": "Bool",
            "comment": "true (allowed) or false (denied)"
        }
    ]
}
```

### ResourceAccess `<Struct>`

```
{
    "name": "ResourceAccess",
    "type": "Struct",
    "fields": [
        {
            "name": "principal",
            "type": "EntityName"
        },
        {
            "name": "assertions",
            "type": "Array",
            "items": "Assertion"
        }
    ]
}
```

### ResourceAccessList `<Struct>`

```
{
    "name": "ResourceAccessList",
    "type": "Struct",
    "fields": [
        {
            "name": "resources",
            "type": "Array",
            "items": "ResourceAccess"
        }
    ]
}
```

### DomainModified `<Struct>`

Tuple of domain-name and modification time-stamps. This object is returned when the caller has requested list of domains modified since a specific timestamp.


```
{
    "name": "DomainModified",
    "type": "Struct",
    "comment": "Tuple of domain-name and modification time-stamps. This object is returned when the caller has requested list of domains modified since a specific timestamp.",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "comment": "name of the domain"
        },
        {
            "name": "modified",
            "type": "Int64",
            "comment": "last modified timestamp of the domain"
        }
    ]
}
```

### DomainModifiedList `<Struct>`

A list of {domain, modified-timestamp} tuples.


```
{
    "name": "DomainModifiedList",
    "type": "Struct",
    "comment": "A list of {domain, modified-timestamp} tuples.",
    "fields": [
        {
            "name": "nameModList",
            "type": "Array",
            "items": "DomainModified",
            "comment": "list of modified domains"
        }
    ]
}
```

### DomainPolicies `<Struct>`

We need to include the name of the domain in this struct since this data will be passed back to ZPU through ZTS so we need to sign not only the list of policies but also the corresponding domain name that the policies belong to.


```
{
    "name": "DomainPolicies",
    "type": "Struct",
    "comment": "We need to include the name of the domain in this struct since this data will be passed back to ZPU through ZTS so we need to sign not only the list of policies but also the corresponding domain name that the policies belong to.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "name of the domain"
        },
        {
            "name": "policies",
            "type": "Array",
            "items": "Policy",
            "comment": "list of policies defined in this server"
        }
    ]
}
```

### SignedPolicies `<Struct>`

A signed bulk transfer of policies. The data is signed with server's private key.


```
{
    "name": "SignedPolicies",
    "type": "Struct",
    "comment": "A signed bulk transfer of policies. The data is signed with server's private key.",
    "fields": [
        {
            "name": "contents",
            "type": "DomainPolicies",
            "comment": "list of policies defined in a domain"
        },
        {
            "name": "signature",
            "type": "String",
            "comment": "signature generated based on the domain policies object"
        },
        {
            "name": "keyId",
            "type": "String",
            "comment": "the identifier of the key used to generate the signature"
        }
    ]
}
```

### DomainData `<Struct>`

A domain object that includes its roles, policies and services.


```
{
    "name": "DomainData",
    "type": "Struct",
    "comment": "A domain object that includes its roles, policies and services.",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "comment": "name of the domain"
        },
        {
            "name": "account",
            "type": "String",
            "optional": true,
            "comment": "associated cloud (i.e. aws) account id"
        },
        {
            "name": "roles",
            "type": "Array",
            "items": "Role",
            "comment": "list of roles in the domain"
        },
        {
            "name": "policies",
            "type": "SignedPolicies",
            "comment": "list of policies in the domain signed with ZMS private key"
        },
        {
            "name": "services",
            "type": "Array",
            "items": "ServiceIdentity",
            "comment": "list of services in the domain"
        },
        {
            "name": "entities",
            "type": "Array",
            "items": "Entity",
            "comment": "list of entities in the domain"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "comment": "last modification timestamp"
        }
    ]
}
```

### SignedDomain `<Struct>`

A domain object signed with server's private key


```
{
    "name": "SignedDomain",
    "type": "Struct",
    "comment": "A domain object signed with server's private key",
    "fields": [
        {
            "name": "domain",
            "type": "DomainData",
            "comment": "domain object with its roles, policies and services"
        },
        {
            "name": "signature",
            "type": "String",
            "comment": "signature generated based on the domain object"
        },
        {
            "name": "keyId",
            "type": "String",
            "comment": "the identifier of the key used to generate the signature"
        }
    ]
}
```

### SignedDomains `<Struct>`

A list of signed domain objects


```
{
    "name": "SignedDomains",
    "type": "Struct",
    "comment": "A list of signed domain objects",
    "fields": [
        {
            "name": "domains",
            "type": "Array",
            "items": "SignedDomain"
        }
    ]
}
```

### UserToken `<Struct>`

A user token generated based on user's credentials


```
{
    "name": "UserToken",
    "type": "Struct",
    "comment": "A user token generated based on user's credentials",
    "fields": [
        {
            "name": "token",
            "type": "SignedToken",
            "comment": "Signed user token identifying a specific authenticated user"
        }
    ]
}
```

### ServicePrincipal `<Struct>`

```
{
    "name": "ServicePrincipal",
    "type": "Struct",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "comment": "name of the domain"
        },
        {
            "name": "service",
            "type": "EntityName",
            "comment": "name of the service"
        },
        {
            "name": "token",
            "type": "SignedToken",
            "comment": "service's signed token"
        }
    ]
}
```


*generated on Wed Aug 03 2016 13:13:21 GMT-0700 (PDT)*
