# Copyright 2016 Yahoo Inc. Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. The Authorization Management Service (ZMS) Classes

## API Methods

### getDomain(*obj, function(err, json, response) { });

`GET /domain/{domain}`
Get info for the specified domain, by name. This request only returns the configured domain attributes and not any domain objects like roles, policies or service identities.

```
obj = {
	"domain": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDomainList(*obj, function(err, json, response) { });

`GET /domain`
Enumerate domains. Can be filtered by prefix and depth, and paginated. This operation can be expensive, as it may span multiple domains.

```
obj = {
	"limit": "<Int32>", // (optional) restrict the number of results in this call
	"skip": "<String>", // (optional) restrict the set to those after the specified "next" token returned from a previous call
	"prefix": "<String>", // (optional) restrict to names that start with the prefix
	"depth": "<Int32>", // (optional) restrict the depth of the name, specifying the number of '.' characters that can appear
	"account": "<String>", // (optional) restrict to domain names that have specified account name
	"productId": "<Int32>", // (optional) restrict the domain names that have specified product id
	"roleMember": "<ResourceName>", // (optional) restrict the domain names where the specified user is in a role - see roleName
	"roleName": "<ResourceName>", // (optional) restrict the domain names where the specified user is in this role - see roleMember
	"modifiedSince": "<String>" // (optional) This header specifies to the server to return any domains modified since this HTTP date
};
```
*Types:* [`ResourceName <String>`](#resourcename-string)

### postTopLevelDomain(*obj, function(err, json, response) { });

`POST /domain`
Create a new top level domain. This is a privileged action for the "sys.auth" administrators.

```
obj = {
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<TopLevelDomain>" // TopLevelDomain object to be created
};
```
*Types:* [`TopLevelDomain <DomainMeta>`](#topleveldomain-domainmeta)

### postSubDomain(*obj, function(err, json, response) { });

`POST /subdomain/{parent}`
Create a new subdomain. The domain administrators of the {parent} domain have the privilege to create subdomains.

```
obj = {
	"parent": "<DomainName>", // name of the parent domain
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<SubDomain>" // Subdomain object to be created
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SubDomain <TopLevelDomain>`](#subdomain-topleveldomain)

### postUserDomain(*obj, function(err, json, response) { });

`POST /userdomain/{name}`
Create a new user domain. The user domain will be created in the user top level domain and the user himself will be set as the administrator for this domain.

```
obj = {
	"name": "<SimpleName>", // name of the domain which will be the user id
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<UserDomain>" // UserDomain object to be created
};
```
*Types:* [`SimpleName <String>`](#simplename-string), [`UserDomain <DomainMeta>`](#userdomain-domainmeta)

### deleteTopLevelDomain(*obj, function(err, json, response) { });

`DELETE /domain/{name}`
Delete the specified domain.  This is a privileged action for the "sys.auth" administrators. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"name": "<SimpleName>", // name of the domain to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### deleteSubDomain(*obj, function(err, json, response) { });

`DELETE /subdomain/{parent}/{name}`
Delete the specified subdomain. Caller must have domain delete permissions in parent. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"parent": "<DomainName>", // name of the parent domain
	"name": "<SimpleName>", // name of the subdomain to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### deleteUserDomain(*obj, function(err, json, response) { });

`DELETE /userdomain/{name}`
Delete the specified userdomain. Caller must have domain delete permissions in the domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"name": "<SimpleName>", // name of the domain to be deleted which will be the user id
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### putDomainMeta(*obj, function(err, json, response) { });

`PUT /domain/{name}/meta`
Update the specified top level domain metadata. Note that entities in the domain are not affected. Caller must have update privileges on the domain itself.

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<DomainMeta>" // DomainMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DomainMeta <Struct>`](#domainmeta-struct)

### putDomainMeta(*obj, function(err, json, response) { });

`PUT /domain/{name}/meta/system/{attribute}`
Set the specified top level domain metadata. Note that entities in the domain are not affected. Caller must have update privileges on the domain itself. If the system attribute is one of the string attributes, then the caller must also have delete action on the same resource in order to reset the configured value

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"attribute": "<SimpleName>", // name of the system attribute to be modified
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<DomainMeta>" // DomainMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`DomainMeta <Struct>`](#domainmeta-struct)

### putDomainTemplate(*obj, function(err, json, response) { });

`PUT /domain/{name}/template`
Update the given domain by applying the roles and policies defined in the specified solution template(s). Caller must have UPDATE privileges on the domain itself.

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"domainTemplate": "<DomainTemplate>" // DomainTemplate object with solution template name(s)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DomainTemplate <TemplateList>`](#domaintemplate-templatelist)

### putDomainTemplate(*obj, function(err, json, response) { });

`PUT /domain/{name}/template/{template}`
Update the given domain by applying the roles and policies defined in the specified solution template(s). Caller must have UPDATE privileges on the domain itself.

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"template": "<SimpleName>", // name of the solution template
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"domainTemplate": "<DomainTemplate>" // DomainTemplate object with a single template name to match URI
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`DomainTemplate <TemplateList>`](#domaintemplate-templatelist)

### getDomainTemplateList(*obj, function(err, json, response) { });

`GET /domain/{name}/template`
Get the list of solution templates applied to a domain

```
obj = {
	"name": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### deleteDomainTemplate(*obj, function(err, json, response) { });

`DELETE /domain/{name}/template/{template}`
Update the given domain by deleting the specified template from the domain template list. Cycles through the roles and policies defined in the template and deletes them. Caller must have delete privileges on the domain itself.

```
obj = {
	"name": "<DomainName>", // name of the domain to be updated
	"template": "<SimpleName>", // name of the solution template
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
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

`PUT /domain/{domainName}/entity/{entityName}`
Put an entity into the domain.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"entityName": "<EntityName>", // name of entity
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"entity": "<Entity>" // Entity object to be added to the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Entity <Struct>`](#entity-struct)

### getEntity(*obj, function(err, json, response) { });

`GET /domain/{domainName}/entity/{entityName}`
Get a entity from a domain. open for all authenticated users to read

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"entityName": "<EntityName>" // name of entity
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### deleteEntity(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/entity/{entityName}`
Delete the entity from the domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"entityName": "<EntityName>", // name of entity
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getEntityList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/entity`
Enumerate entities provisioned in this domain.

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getRoleList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/role`
Enumerate roles provisioned in this domain.

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
Get the list of all roles in a domain with optional flag whether or not include members

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"members": "<Bool>" // return list of members in the role
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getRole(*obj, function(err, json, response) { });

`GET /domain/{domainName}/role/{roleName}`
Get the specified role in the domain.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role to be retrieved
	"auditLog": "<Bool>", // flag to indicate whether or not to return role audit log
	"expand": "<Bool>", // expand delegated trust roles and return trusted members
	"pending": "<Bool>" // include pending members
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putRole(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}`
Create/update the specified role.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role to be added/updated
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"role": "<Role>" // Role object to be added/updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Role <RoleMeta>`](#role-rolemeta)

### deleteRole(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/role/{roleName}`
Delete the specified role. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getMembership(*obj, function(err, json, response) { });

`GET /domain/{domainName}/role/{roleName}/member/{memberName}`
Get the membership status for a specified user in a role.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<MemberName>", // user name to be checked for membership
	"expiration": "<String>" // (optional) the expiration timestamp
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`MemberName <String>`](#membername-string)

### getDomainRoleMembers(*obj, function(err, json, response) { });

`GET /domain/{domainName}/member`
Get list of principals defined in roles in the given domain

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### putMembership(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/member/{memberName}`
Add the specified user to the role's member list. If the role is neither auditEnabled nor selfserve, then it will use authorize ("update", "{domainName}:role.{roleName}") otherwise membership will be sent for approval to either designated delegates ( in case of auditEnabled roles ) or to domain admins ( in case of selfserve roles )

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<MemberName>", // name of the user to be added as a member
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"membership": "<Membership>" // Membership object (must contain role/member names as specified in the URI)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`MemberName <String>`](#membername-string), [`Membership <Struct>`](#membership-struct)

### deleteMembership(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/role/{roleName}/member/{memberName}`
Delete the specified role membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<MemberName>", // name of the user to be removed as a member
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`MemberName <String>`](#membername-string)

### deleteMembership(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/role/{roleName}/pendingmember/{memberName}`
Delete the specified pending role membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). Authorization will be completed within the server itself since there are two possibilities: 1) The domain admins can delete any pending requests 2) the requestor can also delete his/her own pending request.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<MemberName>", // name of the user to be removed as a pending member
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`MemberName <String>`](#membername-string)

### putDefaultAdmins(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/admins`
Verify and, if necessary, fix domain roles and policies to make sure the given set of users have administrative access to the domain. This request is only restricted to "sys.auth" domain administrators and can be used when the domain administrators incorrectly have blocked their own access to their domains.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"defaultAdmins": "<DefaultAdmins>" // list of domain administrators
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DefaultAdmins <Struct>`](#defaultadmins-struct)

### putRoleSystemMeta(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/meta/system/{attribute}`
Set the specified role metadata. Caller must have update privileges on the sys.auth domain. If the system attribute is one of the string attributes, then the caller must also have delete action on the same resource in order to reset the configured value

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"attribute": "<SimpleName>", // name of the system attribute to be modified
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<RoleSystemMeta>" // RoleSystemMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`SimpleName <String>`](#simplename-string), [`RoleSystemMeta <Struct>`](#rolesystemmeta-struct)

### putRoleMeta(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/meta`
Update the specified role metadata. Caller must have update privileges on the domain itself.

```
obj = {
	"domainName": "<DomainName>", // name of the domain to be updated
	"roleName": "<EntityName>", // name of the role
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<RoleMeta>" // RoleMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`RoleMeta <Struct>`](#rolemeta-struct)

### putMembership(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/member/{memberName}/decision`
Approve or Reject the request to add specified user to role membership. This endpoint will be used by 2 use cases: 1. Audit enabled roles with authorize ("update", "sys.auth:meta.role.{attribute}.{domainName}") 2. Selfserve roles in any domain with authorize ("update", "{domainName}:")

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<MemberName>", // name of the user to be added as a member
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"membership": "<Membership>" // Membership object (must contain role/member names as specified in the URI)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`MemberName <String>`](#membername-string), [`Membership <Struct>`](#membership-struct)

### putRole(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/review`
Review role membership and take action to either extend and/or delete existing members.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"role": "<Role>" // Role object with updated and/or deleted members
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Role <RoleMeta>`](#role-rolemeta)

### getPolicyList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy`
List policies provisioned in this namespace.

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
List policies provisioned in this namespace.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"assertions": "<Bool>" // return list of assertions in the policy
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getPolicy(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy/{policyName}`
Read the specified policy.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>" // name of the policy to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putPolicy(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}`
Create or update the specified policy.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy to be added/updated
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"policy": "<Policy>" // Policy object to be added or updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Policy <Struct>`](#policy-struct)

### deletePolicy(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}`
Delete the specified policy. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getAssertion(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy/{policyName}/assertion/{assertionId}`
Get the assertion details with specified id in the given policy

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
Add the specified assertion to the given policy

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"assertion": "<Assertion>" // Assertion object to be added to the given policy
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Assertion <Struct>`](#assertion-struct)

### deleteAssertion(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}/assertion/{assertionId}`
Delete the specified policy assertion. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>", // assertion id
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putServiceIdentity(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}`
Register the specified ServiceIdentity in the specified domain

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<ServiceIdentity>" // ServiceIdentity object to be added/updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`ServiceIdentity <Struct>`](#serviceidentity-struct)

### getServiceIdentity(*obj, function(err, json, response) { });

`GET /domain/{domain}/service/{service}`
Get info for the specified ServiceIdentity.

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>" // name of the service to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### deleteServiceIdentity(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}`
Delete the specified ServiceIdentity. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### getServiceIdentities(*obj, function(err, json, response) { });

`GET /domain/{domainName}/services`
Retrieve list of service identities

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"publickeys": "<Bool>", // return list of public keys in the service
	"hosts": "<Bool>" // return list of hosts in the service
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getServiceIdentityList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/service`
Enumerate services provisioned in this domain.

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
Retrieve the specified public key from the service.

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
Add the specified public key to the service.

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"id": "<String>", // the identifier of the public key to be added
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"publicKeyEntry": "<PublicKeyEntry>" // PublicKeyEntry object to be added/updated in the service
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`PublicKeyEntry <Struct>`](#publickeyentry-struct)

### deletePublicKeyEntry(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}/publickey/{id}`
Remove the specified public key from the service. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"id": "<String>", // the identifier of the public key to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### putServiceIdentitySystemMeta(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}/meta/system/{attribute}`
Set the specified service metadata. Caller must have update privileges on the sys.auth domain.

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"attribute": "<SimpleName>", // name of the system attribute to be modified
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<ServiceIdentitySystemMeta>" // ServiceIdentitySystemMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`ServiceIdentitySystemMeta <Struct>`](#serviceidentitysystemmeta-struct)

### putTenancy(*obj, function(err, json, response) { });

`PUT /domain/{domain}/tenancy/{service}`
Register the provider service in the tenant's domain.

```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>", // name of the provider service
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<Tenancy>" // tenancy object
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string), [`Tenancy <Struct>`](#tenancy-struct)

### deleteTenancy(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/tenancy/{service}`
Delete the provider service from the specified tenant domain. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the tenant domain
	"service": "<ServiceName>", // name of the provider service
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string)

### putTenancy(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}/tenant/{tenantDomain}`
Register a tenant domain for given provider service

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<Tenancy>" // tenancy object
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`Tenancy <Struct>`](#tenancy-struct)

### deleteTenancy(*obj, function(err, json, response) { });

`DELETE /domain/{domain}/service/{service}/tenant/{tenantDomain}`
Delete the tenant domain from the provider service. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### putTenantResourceGroupRoles(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}`
Create/update set of roles for a given tenant and resource group

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<TenantResourceGroupRoles>" // list of roles to be added/updated for the tenant
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string), [`TenantResourceGroupRoles <Struct>`](#tenantresourcegrouproles-struct)

### getTenantResourceGroupRoles(*obj, function(err, json, response) { });

`GET /domain/{domain}/service/{service}/tenant/{tenantDomain}/resourceGroup/{resourceGroup}`
Retrieve the configured set of roles for the tenant and resource group

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
Delete the configured set of roles for the tenant and resource group

```
obj = {
	"domain": "<DomainName>", // name of the provider domain
	"service": "<SimpleName>", // name of the provider service
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string)

### putProviderResourceGroupRoles(*obj, function(err, json, response) { });

`PUT /domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}`
Create/update set of roles for a given provider and resource group

```
obj = {
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"provDomain": "<DomainName>", // name of the provider domain
	"provService": "<SimpleName>", // name of the provider service
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<ProviderResourceGroupRoles>" // list of roles to be added/updated for the provider
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string), [`ProviderResourceGroupRoles <Struct>`](#providerresourcegrouproles-struct)

### getProviderResourceGroupRoles(*obj, function(err, json, response) { });

`GET /domain/{tenantDomain}/provDomain/{provDomain}/provService/{provService}/resourceGroup/{resourceGroup}`
Retrieve the configured set of roles for the provider and resource group

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
Delete the configured set of roles for the provider and resource group

```
obj = {
	"tenantDomain": "<DomainName>", // name of the tenant domain
	"provDomain": "<DomainName>", // name of the provider domain
	"provService": "<SimpleName>", // name of the provider service
	"resourceGroup": "<EntityName>", // tenant resource group
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string), [`EntityName <String>`](#entityname-string)

### getAccess(*obj, function(err, json, response) { });

`GET /access/{action}/{resource}`
Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes. Use distributed mechanisms for decentralized (data-plane) access by fetching signed policies and role tokens for users. With this endpoint the resource is part of the uri and restricted to its strict definition of resource name. If needed, you can use the GetAccessExt api that allows resource name to be less restrictive.

```
obj = {
	"action": "<ActionName>", // action as specified in the policy assertion, i.e. update or read
	"resource": "<ResourceName>", // the resource to check access against, i.e. "media.news:articles"
	"domain": "<DomainName>", // (optional) usually null. If present, it specifies an alternate domain for cross-domain trust relation
	"checkPrincipal": "<EntityName>" // (optional) usually null. If present, carry out the access check for this principal
};
```
*Types:* [`ActionName <String>`](#actionname-string), [`ResourceName <String>`](#resourcename-string), [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getAccess(*obj, function(err, json, response) { });

`GET /access/{action}`
Check access for the specified operation on the specified resource for the currently authenticated user. This is the slow centralized access for control-plane purposes.

```
obj = {
	"action": "<ActionName>", // action as specified in the policy assertion, i.e. update or read
	"resource": "<String>", // (optional) the resource to check access against, i.e. "media.news:articles"
	"domain": "<DomainName>", // (optional) usually null. If present, it specifies an alternate domain for cross-domain trust relation
	"checkPrincipal": "<EntityName>" // (optional) usually null. If present, carry out the access check for this principal
};
```
*Types:* [`ActionName <String>`](#actionname-string), [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getResourceAccessList(*obj, function(err, json, response) { });

`GET /resource`
Return list of resources that the given principal has access to. Even though the principal is marked as optional, it must be specified unless the caller has authorization from sys.auth domain to check access for all user principals. (action: access, resource: resource-lookup-all)

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
	"metaAttr": "<SimpleName>", // (optional) domain meta attribute to filter/return, valid values "account", "ypmId", or "all"
	"master": "<Bool>", // (optional) for system principals only - request data from master data store and not read replicas if any are configured
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any domains modified since this time
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### getJWSDomain(*obj, function(err, json, response) { });

`GET /domain/{name}/signed`


```
obj = {
	"name": "<DomainName>" // name of the domain to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getUserToken(*obj, function(err, json, response) { });

`GET /user/{userName}/token`
Return a user/principal token for the specified authenticated user. Typical authenticated users with their native credentials are not allowed to update their domain data. They must first obtain a UserToken and then use that token for authentication and authorization of their update requests.

```
obj = {
	"userName": "<SimpleName>", // name of the user
	"serviceNames": "<String>", // (optional) comma separated list of on-behalf-of service names
	"header": "<Bool>" // include Authorization header name in response
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### optionsUserToken(*obj, function(err, json, response) { });

`OPTIONS /user/{userName}/token`
CORS (Cross-Origin Resource Sharing) support to allow Provider Services to obtain AuthorizedService Tokens on behalf of Tenant administrators

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
Get the list of solution templates defined in the server


### getTemplate(*obj, function(err, json, response) { });

`GET /template/{template}`
Get solution template details. Includes the roles and policies that will be automatically provisioned when the template is applied to a domain

```
obj = {
	"template": "<SimpleName>" // name of the solution template
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### getUserList(*obj, function(err, json, response) { });

`GET /user`
Enumerate users that are registered as principals in the system This will return only the principals with "<user-domain>." prefix


### deleteUser(*obj, function(err, json, response) { });

`DELETE /user/{name}`
Delete the specified user. This command will delete the home.<name> domain and all of its sub-domains (if they exist) and remove the user.<name> from all the roles in the system that it's member of. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"name": "<SimpleName>", // name of the user
	"auditRef": "<String>" // (optional) Audit reference
};
```
*Types:* [`SimpleName <String>`](#simplename-string)

### deleteDomainRoleMember(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/member/{memberName}`
Delete the specified role member from the given domain. This command will remove the member from all the roles in the domain that it's member of. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"memberName": "<MemberName>", // name of the role member/principal
	"auditRef": "<String>" // (optional) Audit reference
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`MemberName <String>`](#membername-string)

### getQuota(*obj, function(err, json, response) { });

`GET /domain/{name}/quota`
Retrieve the quota object defined for the domain

```
obj = {
	"name": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### putQuota(*obj, function(err, json, response) { });

`PUT /domain/{name}/quota`
Update the specified domain's quota object

```
obj = {
	"name": "<DomainName>", // name of the domain
	"auditRef": "<String>", // (optional) Audit reference
	"quota": "<Quota>" // Quota object with limits for the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`Quota <Struct>`](#quota-struct)

### deleteQuota(*obj, function(err, json, response) { });

`DELETE /domain/{name}/quota`
Delete the specified domain's quota

```
obj = {
	"name": "<DomainName>", // name of the domain
	"auditRef": "<String>" // (optional) Audit reference
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getStatus(*obj, function(err, json, response) { });

`GET /status`
Retrieve the server status


### getDomainRoleMembership(*obj, function(err, json, response) { });

`GET /pending_members`
List of domains containing roles and corresponding members to be approved by either calling or specified principal

```
obj = {
	"principal": "<EntityName>" // (optional) If present, return pending list for this principal
};
```
*Types:* [`EntityName <String>`](#entityname-string)


## API Types

### SimpleName `<String>`

Copyright 2016 Yahoo Inc. Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. Common name types used by several API definitions A simple identifier, an element of compound name.


```
{
    "type": "String",
    "name": "SimpleName",
    "comment": "Copyright 2016 Yahoo Inc. Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. Common name types used by several API definitions A simple identifier, an element of compound name.",
    "pattern": "[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### CompoundName `<String>`

A compound name. Most names in this API are compound names.


```
{
    "type": "String",
    "name": "CompoundName",
    "comment": "A compound name. Most names in this API are compound names.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### DomainName `<String>`

A domain name is the general qualifier prefix, as its uniqueness is managed.


```
{
    "type": "String",
    "name": "DomainName",
    "comment": "A domain name is the general qualifier prefix, as its uniqueness is managed.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### EntityName `<String>`

An entity name is a short form of a resource name, including only the domain and entity.


```
{
    "type": "String",
    "name": "EntityName",
    "comment": "An entity name is a short form of a resource name, including only the domain and entity.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ServiceName `<String>`

A service name will generally be a unique subdomain.


```
{
    "type": "String",
    "name": "ServiceName",
    "comment": "A service name will generally be a unique subdomain.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### LocationName `<String>`

A location name is not yet defined, but will be a dotted name like everything else.


```
{
    "type": "String",
    "name": "LocationName",
    "comment": "A location name is not yet defined, but will be a dotted name like everything else.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ActionName `<String>`

An action (operation) name.


```
{
    "type": "String",
    "name": "ActionName",
    "comment": "An action (operation) name.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### ResourceName `<String>`

A resource name Note that the EntityName part is optional, that is, a domain name followed by a colon is valid resource name.


```
{
    "type": "String",
    "name": "ResourceName",
    "comment": "A resource name Note that the EntityName part is optional, that is, a domain name followed by a colon is valid resource name.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(:([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?"
}
```

### ResourceNames `<String>`

A comma separated list of resource names


```
{
    "type": "String",
    "name": "ResourceNames",
    "comment": "A comma separated list of resource names",
    "pattern": "(([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(:([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?,)*([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(:([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*)?"
}
```

### YBase64 `<String>`

The Y-specific URL-safe Base64 variant.


```
{
    "type": "String",
    "name": "YBase64",
    "comment": "The Y-specific URL-safe Base64 variant.",
    "pattern": "[a-zA-Z0-9\\._-]+"
}
```

### YEncoded `<String>`

YEncoded includes ybase64 chars, as well as = and %. This can represent a user cookie and URL-encoded values.


```
{
    "type": "String",
    "name": "YEncoded",
    "comment": "YEncoded includes ybase64 chars, as well as = and %. This can represent a user cookie and URL-encoded values.",
    "pattern": "[a-zA-Z0-9\\._%=-]*"
}
```

### AuthorityName `<String>`

Used as the prefix in a signed assertion. This uniquely identifies a signing authority.


```
{
    "type": "String",
    "name": "AuthorityName",
    "comment": "Used as the prefix in a signed assertion. This uniquely identifies a signing authority.",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### SignedToken `<String>`

A signed assertion if identity. i.e. the user cookie value. This token will only make sense to the authority that generated it, so it is beneficial to have something in the value that is cheaply recognized to quickly reject if it belongs to another authority. In addition to the YEncoded set our token includes ; to separate components and , to separate roles and : for IPv6 addresses


```
{
    "type": "String",
    "name": "SignedToken",
    "comment": "A signed assertion if identity. i.e. the user cookie value. This token will only make sense to the authority that generated it, so it is beneficial to have something in the value that is cheaply recognized to quickly reject if it belongs to another authority. In addition to the YEncoded set our token includes ; to separate components and , to separate roles and : for IPv6 addresses",
    "pattern": "[a-zA-Z0-9\\._%=:;,-]*"
}
```

### MemberName `<String>`

Role Member name - could be one of three values: *, DomainName.* or ServiceName[*]


```
{
    "type": "String",
    "name": "MemberName",
    "comment": "Role Member name - could be one of three values: *, DomainName.* or ServiceName[*]",
    "pattern": "\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*\\.\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(\\*)?"
}
```

### DomainMeta `<Struct>`

Set of metadata attributes that all domains may have and can be changed.


```
{
    "type": "Struct",
    "name": "DomainMeta",
    "comment": "Set of metadata attributes that all domains may have and can be changed.",
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
            "comment": "a reference to an Organization. (i.e. org:media)"
        },
        {
            "name": "enabled",
            "type": "Bool",
            "optional": true,
            "comment": "Future use only, currently not used",
            "default": true
        },
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not domain modifications should be logged for SOX+Auditing. If true, the auditRef parameter must be supplied(not empty) for any API defining it.",
            "default": false
        },
        {
            "name": "account",
            "type": "String",
            "optional": true,
            "comment": "associated cloud (i.e. aws) account id (system attribute - uniqueness check)"
        },
        {
            "name": "ypmId",
            "type": "Int32",
            "optional": true,
            "comment": "associated product id (system attribute - uniqueness check)"
        },
        {
            "name": "applicationId",
            "type": "String",
            "optional": true,
            "comment": "associated application id"
        },
        {
            "name": "certDnsDomain",
            "type": "String",
            "optional": true,
            "comment": "domain certificate dns domain (system attribute)"
        },
        {
            "name": "memberExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all user members in the domain will have specified max expiry days"
        },
        {
            "name": "tokenExpiryMins",
            "type": "Int32",
            "optional": true,
            "comment": "tokens issued for this domain will have specified max timeout in mins"
        },
        {
            "name": "serviceCertExpiryMins",
            "type": "Int32",
            "optional": true,
            "comment": "service identity certs issued for this domain will have specified max timeout in mins"
        },
        {
            "name": "roleCertExpiryMins",
            "type": "Int32",
            "optional": true,
            "comment": "role certs issued for this domain will have specified max timeout in mins"
        },
        {
            "name": "signAlgorithm",
            "type": "SimpleName",
            "optional": true,
            "comment": "rsa or ec signing algorithm to be used for tokens"
        },
        {
            "name": "serviceExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all services in the domain will have specified max expiry days"
        }
    ],
    "closed": false
}
```

### Domain `<DomainMeta>`

A domain is an independent partition of users, roles, and resources. Its name represents the definition of a namespace; the only way a new namespace can be created, from the top, is by creating Domains. Administration of a domain is governed by the parent domain (using reverse-DNS namespaces). The top level domains are governed by the special "sys.auth" domain.


```
{
    "type": "DomainMeta",
    "name": "Domain",
    "comment": "A domain is an independent partition of users, roles, and resources. Its name represents the definition of a namespace; the only way a new namespace can be created, from the top, is by creating Domains. Administration of a domain is governed by the parent domain (using reverse-DNS namespaces). The top level domains are governed by the special \"sys.auth\" domain.",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "optional": false,
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
        }
    ],
    "closed": false
}
```

### DomainMetaList `<Struct>`

A list of domain objects with their meta attributes.


```
{
    "type": "Struct",
    "name": "DomainMetaList",
    "comment": "A list of domain objects with their meta attributes.",
    "fields": [
        {
            "name": "domains",
            "type": "Array",
            "optional": false,
            "comment": "list of domain objects",
            "items": "Domain"
        }
    ],
    "closed": false
}
```

### RoleList `<Struct>`

The representation for an enumeration of roles in the namespace, with pagination.


```
{
    "type": "Struct",
    "name": "RoleList",
    "comment": "The representation for an enumeration of roles in the namespace, with pagination.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "optional": false,
            "comment": "list of role names",
            "items": "EntityName"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next role list request as the value for the skip query parameter."
        }
    ],
    "closed": false
}
```

### RoleAuditLog `<Struct>`

An audit log entry for role membership change.


```
{
    "type": "Struct",
    "name": "RoleAuditLog",
    "comment": "An audit log entry for role membership change.",
    "fields": [
        {
            "name": "member",
            "type": "MemberName",
            "optional": false,
            "comment": "name of the role member"
        },
        {
            "name": "admin",
            "type": "ResourceName",
            "optional": false,
            "comment": "name of the principal executing the change"
        },
        {
            "name": "created",
            "type": "Timestamp",
            "optional": false,
            "comment": "timestamp of the entry"
        },
        {
            "name": "action",
            "type": "String",
            "optional": false,
            "comment": "log action - e.g. add, delete, approve, etc"
        },
        {
            "name": "auditRef",
            "type": "String",
            "optional": true,
            "comment": "audit reference string for the change as supplied by admin"
        }
    ],
    "closed": false
}
```

### RoleMember `<Struct>`

```
{
    "type": "Struct",
    "name": "RoleMember",
    "fields": [
        {
            "name": "memberName",
            "type": "MemberName",
            "optional": false,
            "comment": "name of the member"
        },
        {
            "name": "expiration",
            "type": "Timestamp",
            "optional": true,
            "comment": "the expiration timestamp"
        },
        {
            "name": "active",
            "type": "Bool",
            "optional": true,
            "comment": "Flag to indicate whether membership is active",
            "default": true
        },
        {
            "name": "approved",
            "type": "Bool",
            "optional": true,
            "comment": "Flag to indicate whether membership is approved either by delegates ( in case of auditEnabled roles ) or by domain admins ( in case of selfserve roles )",
            "default": true
        },
        {
            "name": "auditRef",
            "type": "String",
            "optional": true,
            "comment": "audit reference string for the change as supplied by admin"
        },
        {
            "name": "requestTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "for pending membership requests, the request time"
        },
        {
            "name": "lastNotifiedTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "for pending membership requests, time when last notification was sent"
        },
        {
            "name": "requestPrincipal",
            "type": "ResourceName",
            "optional": true,
            "comment": "pending members only - name of the principal requesting the change"
        }
    ],
    "closed": false
}
```

### RoleMeta `<Struct>`

Set of metadata attributes that all roles may have and can be changed by domain admins.


```
{
    "type": "Struct",
    "name": "RoleMeta",
    "comment": "Set of metadata attributes that all roles may have and can be changed by domain admins.",
    "fields": [
        {
            "name": "selfServe",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not role allows self service. Users can add themselves in the role, but it has to be approved by domain admins to be effective.",
            "default": false
        },
        {
            "name": "memberExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all user members in the role will have specified max expiry days"
        },
        {
            "name": "tokenExpiryMins",
            "type": "Int32",
            "optional": true,
            "comment": "tokens issued for this role will have specified max timeout in mins"
        },
        {
            "name": "certExpiryMins",
            "type": "Int32",
            "optional": true,
            "comment": "certs issued for this role will have specified max timeout in mins"
        },
        {
            "name": "signAlgorithm",
            "type": "SimpleName",
            "optional": true,
            "comment": "rsa or ec signing algorithm to be used for tokens"
        },
        {
            "name": "serviceExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all services in the role will have specified max expiry days"
        },
        {
            "name": "reviewEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not role updates require another review and approval",
            "default": false
        },
        {
            "name": "notifyRoles",
            "type": "ResourceNames",
            "optional": true,
            "comment": "list of roles whose members should be notified for member review/approval"
        }
    ],
    "closed": false
}
```

### Role `<RoleMeta>`

The representation for a Role with set of members.


```
{
    "type": "RoleMeta",
    "name": "Role",
    "comment": "The representation for a Role with set of members.",
    "fields": [
        {
            "name": "name",
            "type": "ResourceName",
            "optional": false,
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
            "comment": "an explicit list of members. Might be empty or null, if trust is set",
            "items": "MemberName"
        },
        {
            "name": "roleMembers",
            "type": "Array",
            "optional": true,
            "comment": "members with expiration",
            "items": "RoleMember"
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
            "comment": "an audit log for role membership changes",
            "items": "RoleAuditLog"
        },
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not role updates should require GRC approval. If true, the auditRef parameter must be supplied(not empty) for any API defining it",
            "default": false
        },
        {
            "name": "lastReviewedDate",
            "type": "Timestamp",
            "optional": true,
            "comment": "last review timestamp of the role"
        }
    ],
    "closed": false
}
```

### Roles `<Struct>`

The representation for a list of roles with full details


```
{
    "type": "Struct",
    "name": "Roles",
    "comment": "The representation for a list of roles with full details",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "optional": false,
            "comment": "list of role objects",
            "items": "Role"
        }
    ],
    "closed": false
}
```

### Membership `<Struct>`

The representation for a role membership.


```
{
    "type": "Struct",
    "name": "Membership",
    "comment": "The representation for a role membership.",
    "fields": [
        {
            "name": "memberName",
            "type": "MemberName",
            "optional": false,
            "comment": "name of the member"
        },
        {
            "name": "isMember",
            "type": "Bool",
            "optional": true,
            "comment": "flag to indicate whether or the user is a member or not",
            "default": true
        },
        {
            "name": "roleName",
            "type": "ResourceName",
            "optional": true,
            "comment": "name of the role"
        },
        {
            "name": "expiration",
            "type": "Timestamp",
            "optional": true,
            "comment": "the expiration timestamp"
        },
        {
            "name": "active",
            "type": "Bool",
            "optional": true,
            "comment": "Flag to indicate whether membership is active",
            "default": true
        },
        {
            "name": "approved",
            "type": "Bool",
            "optional": true,
            "comment": "Flag to indicate whether membership is approved either by delegates ( in case of auditEnabled roles ) or by domain admins ( in case of selfserve roles )",
            "default": true
        },
        {
            "name": "auditRef",
            "type": "String",
            "optional": true,
            "comment": "audit reference string for the change as supplied by admin"
        },
        {
            "name": "requestPrincipal",
            "type": "ResourceName",
            "optional": true,
            "comment": "pending members only - name of the principal requesting the change"
        }
    ],
    "closed": false
}
```

### DefaultAdmins `<Struct>`

The list of domain administrators.


```
{
    "type": "Struct",
    "name": "DefaultAdmins",
    "comment": "The list of domain administrators.",
    "fields": [
        {
            "name": "admins",
            "type": "Array",
            "optional": false,
            "comment": "list of domain administrators",
            "items": "ResourceName"
        }
    ],
    "closed": false
}
```

### MemberRole `<Struct>`

```
{
    "type": "Struct",
    "name": "MemberRole",
    "fields": [
        {
            "name": "roleName",
            "type": "ResourceName",
            "optional": false,
            "comment": "name of the role"
        },
        {
            "name": "domainName",
            "type": "DomainName",
            "optional": true,
            "comment": "name of the domain"
        },
        {
            "name": "memberName",
            "type": "MemberName",
            "optional": true,
            "comment": "name of the member"
        },
        {
            "name": "expiration",
            "type": "Timestamp",
            "optional": true,
            "comment": "the expiration timestamp"
        },
        {
            "name": "active",
            "type": "Bool",
            "optional": true,
            "comment": "Flag to indicate whether membership is active",
            "default": true
        },
        {
            "name": "auditRef",
            "type": "String",
            "optional": true,
            "comment": "audit reference string for the change as supplied by admin"
        },
        {
            "name": "requestPrincipal",
            "type": "EntityName",
            "optional": true,
            "comment": "pending members only - name of the principal requesting the change"
        },
        {
            "name": "requestTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "for pending membership requests, the request time"
        }
    ],
    "closed": false
}
```

### DomainRoleMember `<Struct>`

```
{
    "type": "Struct",
    "name": "DomainRoleMember",
    "fields": [
        {
            "name": "memberName",
            "type": "MemberName",
            "optional": false,
            "comment": "name of the member"
        },
        {
            "name": "memberRoles",
            "type": "Array",
            "optional": false,
            "comment": "roles for this member",
            "items": "MemberRole"
        }
    ],
    "closed": false
}
```

### DomainRoleMembers `<Struct>`

```
{
    "type": "Struct",
    "name": "DomainRoleMembers",
    "fields": [
        {
            "name": "domainName",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "members",
            "type": "Array",
            "optional": false,
            "comment": "role members",
            "items": "DomainRoleMember"
        }
    ],
    "closed": false
}
```

### RoleSystemMeta `<Struct>`

Set of system metadata attributes that all roles may have and can be changed by system admins.


```
{
    "type": "Struct",
    "name": "RoleSystemMeta",
    "comment": "Set of system metadata attributes that all roles may have and can be changed by system admins.",
    "fields": [
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not role updates should be approved by GRC. If true, the auditRef parameter must be supplied(not empty) for any API defining it.",
            "default": false
        }
    ],
    "closed": false
}
```

### AssertionEffect `<Enum>`

Every assertion can have the effect of ALLOW or DENY.


```
{
    "type": "Enum",
    "name": "AssertionEffect",
    "comment": "Every assertion can have the effect of ALLOW or DENY.",
    "elements": [
        {
            "symbol": "ALLOW"
        },
        {
            "symbol": "DENY"
        }
    ]
}
```

### Assertion `<Struct>`

A representation for the encapsulation of an action to be performed on a resource by a principal.


```
{
    "type": "Struct",
    "name": "Assertion",
    "comment": "A representation for the encapsulation of an action to be performed on a resource by a principal.",
    "fields": [
        {
            "name": "role",
            "type": "String",
            "optional": false,
            "comment": "the subject of the assertion - a role"
        },
        {
            "name": "resource",
            "type": "String",
            "optional": false,
            "comment": "the object of the assertion. Must be in the local namespace. Can contain wildcards"
        },
        {
            "name": "action",
            "type": "String",
            "optional": false,
            "comment": "the predicate of the assertion. Can contain wildcards"
        },
        {
            "name": "effect",
            "type": "AssertionEffect",
            "optional": true,
            "comment": "the effect of the assertion in the policy language",
            "default": "ALLOW"
        },
        {
            "name": "id",
            "type": "Int64",
            "optional": true,
            "comment": "assertion id - auto generated by server. Not required during put operations."
        }
    ],
    "closed": false
}
```

### Policy `<Struct>`

The representation for a Policy with set of assertions.


```
{
    "type": "Struct",
    "name": "Policy",
    "comment": "The representation for a Policy with set of assertions.",
    "fields": [
        {
            "name": "name",
            "type": "ResourceName",
            "optional": false,
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
            "optional": false,
            "comment": "list of defined assertions for this policy",
            "items": "Assertion"
        }
    ],
    "closed": false
}
```

### Policies `<Struct>`

The representation of list of policy objects


```
{
    "type": "Struct",
    "name": "Policies",
    "comment": "The representation of list of policy objects",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "optional": false,
            "comment": "list of policy objects",
            "items": "Policy"
        }
    ],
    "closed": false
}
```

### PublicKeyEntry `<Struct>`

The representation of the public key in a service identity object.


```
{
    "type": "Struct",
    "name": "PublicKeyEntry",
    "comment": "The representation of the public key in a service identity object.",
    "fields": [
        {
            "name": "key",
            "type": "String",
            "optional": false,
            "comment": "the public key for the service"
        },
        {
            "name": "id",
            "type": "String",
            "optional": false,
            "comment": "the key identifier (version or zone name)"
        }
    ],
    "closed": false
}
```

### ServiceIdentity `<Struct>`

The representation of the service identity object.


```
{
    "type": "Struct",
    "name": "ServiceIdentity",
    "comment": "The representation of the service identity object.",
    "fields": [
        {
            "name": "name",
            "type": "ServiceName",
            "optional": false,
            "comment": "the full name of the service, i.e. \"sports.storage\""
        },
        {
            "name": "description",
            "type": "String",
            "optional": true,
            "comment": "description of the service"
        },
        {
            "name": "publicKeys",
            "type": "Array",
            "optional": true,
            "comment": "array of public keys for key rotation",
            "items": "PublicKeyEntry"
        },
        {
            "name": "providerEndpoint",
            "type": "String",
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
            "comment": "list of host names that this service can run on",
            "items": "String"
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
    ],
    "closed": false
}
```

### ServiceIdentities `<Struct>`

The representation of list of services


```
{
    "type": "Struct",
    "name": "ServiceIdentities",
    "comment": "The representation of list of services",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "optional": false,
            "comment": "list of services",
            "items": "ServiceIdentity"
        }
    ],
    "closed": false
}
```

### ServiceIdentityList `<Struct>`

The representation for an enumeration of services in the namespace, with pagination.


```
{
    "type": "Struct",
    "name": "ServiceIdentityList",
    "comment": "The representation for an enumeration of services in the namespace, with pagination.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "optional": false,
            "comment": "list of service names",
            "items": "EntityName"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next service list request as the value for the skip query parameter."
        }
    ],
    "closed": false
}
```

### ServiceIdentitySystemMeta `<Struct>`

Set of system metadata attributes that all services may have and can be changed by system admins.


```
{
    "type": "Struct",
    "name": "ServiceIdentitySystemMeta",
    "comment": "Set of system metadata attributes that all services may have and can be changed by system admins.",
    "fields": [
        {
            "name": "providerEndpoint",
            "type": "String",
            "optional": true,
            "comment": "provider callback endpoint"
        }
    ],
    "closed": false
}
```

### Template `<Struct>`

Solution Template object defined on the server


```
{
    "type": "Struct",
    "name": "Template",
    "comment": "Solution Template object defined on the server",
    "fields": [
        {
            "name": "roles",
            "type": "Array",
            "optional": false,
            "comment": "list of roles in the template",
            "items": "Role"
        },
        {
            "name": "policies",
            "type": "Array",
            "optional": false,
            "comment": "list of policies defined in this template",
            "items": "Policy"
        },
        {
            "name": "services",
            "type": "Array",
            "optional": true,
            "comment": "list of services defined in this template",
            "items": "ServiceIdentity"
        }
    ],
    "closed": false
}
```

### TemplateList `<Struct>`

List of template names that is the base struct for server and domain templates


```
{
    "type": "Struct",
    "name": "TemplateList",
    "comment": "List of template names that is the base struct for server and domain templates",
    "fields": [
        {
            "name": "templateNames",
            "type": "Array",
            "optional": false,
            "comment": "list of template names",
            "items": "SimpleName"
        }
    ],
    "closed": false
}
```

### TemplateParam `<Struct>`

```
{
    "type": "Struct",
    "name": "TemplateParam",
    "fields": [
        {
            "name": "name",
            "type": "SimpleName",
            "optional": false,
            "comment": "name of the parameter"
        },
        {
            "name": "value",
            "type": "CompoundName",
            "optional": false,
            "comment": "value of the parameter"
        }
    ],
    "closed": false
}
```

### DomainTemplate `<TemplateList>`

solution template(s) to be applied to a domain


```
{
    "type": "TemplateList",
    "name": "DomainTemplate",
    "comment": "solution template(s) to be applied to a domain",
    "fields": [
        {
            "name": "params",
            "type": "Array",
            "optional": true,
            "comment": "optional template parameters",
            "items": "TemplateParam"
        }
    ],
    "closed": false
}
```

### DomainTemplateList `<TemplateList>`

List of solution templates to be applied to a domain


```
{
    "type": "TemplateList",
    "name": "DomainTemplateList",
    "comment": "List of solution templates to be applied to a domain",
    "fields": [],
    "closed": false
}
```

### ServerTemplateList `<TemplateList>`

List of solution templates available in the server


```
{
    "type": "TemplateList",
    "name": "ServerTemplateList",
    "comment": "List of solution templates available in the server",
    "fields": [],
    "closed": false
}
```

### DomainList `<Struct>`

A paginated list of domains.


```
{
    "type": "Struct",
    "name": "DomainList",
    "comment": "A paginated list of domains.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "optional": false,
            "comment": "list of domain names",
            "items": "DomainName"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next domain list request as the value for the skip query parameter."
        }
    ],
    "closed": false
}
```

### TopLevelDomain `<DomainMeta>`

Top Level Domain object. The required attributes include the name of the domain and list of domain administrators.


```
{
    "type": "DomainMeta",
    "name": "TopLevelDomain",
    "comment": "Top Level Domain object. The required attributes include the name of the domain and list of domain administrators.",
    "fields": [
        {
            "name": "name",
            "type": "SimpleName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "adminUsers",
            "type": "Array",
            "optional": false,
            "comment": "list of domain administrators",
            "items": "ResourceName"
        },
        {
            "name": "templates",
            "type": "DomainTemplateList",
            "optional": true,
            "comment": "list of solution template names"
        }
    ],
    "closed": false
}
```

### SubDomain `<TopLevelDomain>`

A Subdomain is a TopLevelDomain, except it has a parent.


```
{
    "type": "TopLevelDomain",
    "name": "SubDomain",
    "comment": "A Subdomain is a TopLevelDomain, except it has a parent.",
    "fields": [
        {
            "name": "parent",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the parent domain"
        }
    ],
    "closed": false
}
```

### UserDomain `<DomainMeta>`

A UserDomain is the user's own top level domain in user - e.g. user.hga


```
{
    "type": "DomainMeta",
    "name": "UserDomain",
    "comment": "A UserDomain is the user's own top level domain in user - e.g. user.hga",
    "fields": [
        {
            "name": "name",
            "type": "SimpleName",
            "optional": false,
            "comment": "user id which will be the domain name"
        },
        {
            "name": "templates",
            "type": "DomainTemplateList",
            "optional": true,
            "comment": "list of solution template names"
        }
    ],
    "closed": false
}
```

### DanglingPolicy `<Struct>`

A dangling policy where the assertion is referencing a role name that doesn't exist in the domain


```
{
    "type": "Struct",
    "name": "DanglingPolicy",
    "comment": "A dangling policy where the assertion is referencing a role name that doesn't exist in the domain",
    "fields": [
        {
            "name": "policyName",
            "type": "EntityName",
            "optional": false
        },
        {
            "name": "roleName",
            "type": "EntityName",
            "optional": false
        }
    ],
    "closed": false
}
```

### DomainDataCheck `<Struct>`

Domain data object representing the results of a check operation looking for dangling roles, policies and trust relationships that are set either on tenant or provider side only


```
{
    "type": "Struct",
    "name": "DomainDataCheck",
    "comment": "Domain data object representing the results of a check operation looking for dangling roles, policies and trust relationships that are set either on tenant or provider side only",
    "fields": [
        {
            "name": "danglingRoles",
            "type": "Array",
            "optional": true,
            "comment": "Names of roles not specified in any assertion. Might be empty or null if no dangling roles.",
            "items": "EntityName"
        },
        {
            "name": "danglingPolicies",
            "type": "Array",
            "optional": true,
            "comment": "Policy+role tuples where role doesnt exist. Might be empty or null if no dangling policies.",
            "items": "DanglingPolicy"
        },
        {
            "name": "policyCount",
            "type": "Int32",
            "optional": false,
            "comment": "total number of policies"
        },
        {
            "name": "assertionCount",
            "type": "Int32",
            "optional": false,
            "comment": "total number of assertions"
        },
        {
            "name": "roleWildCardCount",
            "type": "Int32",
            "optional": false,
            "comment": "total number of assertions containing roles as wildcards"
        },
        {
            "name": "providersWithoutTrust",
            "type": "Array",
            "optional": true,
            "comment": "Service names (domain.service) that dont contain trust role if this is a tenant domain. Might be empty or null, if not a tenant or if all providers support this tenant.",
            "items": "ServiceName"
        },
        {
            "name": "tenantsWithoutAssumeRole",
            "type": "Array",
            "optional": true,
            "comment": "Names of Tenant domains that dont contain assume role assertions if this is a provider domain. Might be empty or null, if not a provider or if all tenants support use this provider.",
            "items": "DomainName"
        }
    ],
    "closed": false
}
```

### Entity `<Struct>`

An entity is a name and a structured value. some entity names/prefixes are reserved (i.e. "role",  "policy", "meta", "domain", "service")


```
{
    "type": "Struct",
    "name": "Entity",
    "comment": "An entity is a name and a structured value. some entity names/prefixes are reserved (i.e. \"role\",  \"policy\", \"meta\", \"domain\", \"service\")",
    "fields": [
        {
            "name": "name",
            "type": "EntityName",
            "optional": false,
            "comment": "name of the entity object"
        },
        {
            "name": "value",
            "type": "Struct",
            "optional": false,
            "comment": "value of the entity"
        }
    ],
    "closed": false
}
```

### EntityList `<Struct>`

The representation for an enumeration of entities in the namespace


```
{
    "type": "Struct",
    "name": "EntityList",
    "comment": "The representation for an enumeration of entities in the namespace",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "optional": false,
            "comment": "list of entity names",
            "items": "EntityName"
        }
    ],
    "closed": false
}
```

### PolicyList `<Struct>`

The representation for an enumeration of policies in the namespace, with pagination.


```
{
    "type": "Struct",
    "name": "PolicyList",
    "comment": "The representation for an enumeration of policies in the namespace, with pagination.",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "optional": false,
            "comment": "list of policy names",
            "items": "EntityName"
        },
        {
            "name": "next",
            "type": "String",
            "optional": true,
            "comment": "if the response is a paginated list, this attribute specifies the value to be used in the next policy list request as the value for the skip query parameter."
        }
    ],
    "closed": false
}
```

### Tenancy `<Struct>`

A representation of tenant.


```
{
    "type": "Struct",
    "name": "Tenancy",
    "comment": "A representation of tenant.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "the domain that is to get a tenancy"
        },
        {
            "name": "service",
            "type": "ServiceName",
            "optional": false,
            "comment": "the provider service on which the tenancy is to reside"
        },
        {
            "name": "resourceGroups",
            "type": "Array",
            "optional": true,
            "comment": "registered resource groups for this tenant",
            "items": "EntityName"
        }
    ],
    "closed": false
}
```

### TenantRoleAction `<Struct>`

A representation of tenant role action.


```
{
    "type": "Struct",
    "name": "TenantRoleAction",
    "comment": "A representation of tenant role action.",
    "fields": [
        {
            "name": "role",
            "type": "SimpleName",
            "optional": false,
            "comment": "name of the role"
        },
        {
            "name": "action",
            "type": "String",
            "optional": false,
            "comment": "action value for the generated policy assertion"
        }
    ],
    "closed": false
}
```

### TenantResourceGroupRoles `<Struct>`

A representation of tenant roles for resource groups to be provisioned.


```
{
    "type": "Struct",
    "name": "TenantResourceGroupRoles",
    "comment": "A representation of tenant roles for resource groups to be provisioned.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the provider domain"
        },
        {
            "name": "service",
            "type": "SimpleName",
            "optional": false,
            "comment": "name of the provider service"
        },
        {
            "name": "tenant",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the tenant domain"
        },
        {
            "name": "roles",
            "type": "Array",
            "optional": false,
            "comment": "the role/action pairs to provision",
            "items": "TenantRoleAction"
        },
        {
            "name": "resourceGroup",
            "type": "EntityName",
            "optional": false,
            "comment": "tenant resource group"
        }
    ],
    "closed": false
}
```

### ProviderResourceGroupRoles `<Struct>`

A representation of provider roles to be provisioned.


```
{
    "type": "Struct",
    "name": "ProviderResourceGroupRoles",
    "comment": "A representation of provider roles to be provisioned.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the provider domain"
        },
        {
            "name": "service",
            "type": "SimpleName",
            "optional": false,
            "comment": "name of the provider service"
        },
        {
            "name": "tenant",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the tenant domain"
        },
        {
            "name": "roles",
            "type": "Array",
            "optional": false,
            "comment": "the role/action pairs to provision",
            "items": "TenantRoleAction"
        },
        {
            "name": "resourceGroup",
            "type": "EntityName",
            "optional": false,
            "comment": "tenant resource group"
        }
    ],
    "closed": false
}
```

### Access `<Struct>`

Access can be checked and returned as this resource.


```
{
    "type": "Struct",
    "name": "Access",
    "comment": "Access can be checked and returned as this resource.",
    "fields": [
        {
            "name": "granted",
            "type": "Bool",
            "optional": false,
            "comment": "true (allowed) or false (denied)"
        }
    ],
    "closed": false
}
```

### ResourceAccess `<Struct>`

```
{
    "type": "Struct",
    "name": "ResourceAccess",
    "fields": [
        {
            "name": "principal",
            "type": "EntityName",
            "optional": false
        },
        {
            "name": "assertions",
            "type": "Array",
            "optional": false,
            "items": "Assertion"
        }
    ],
    "closed": false
}
```

### ResourceAccessList `<Struct>`

```
{
    "type": "Struct",
    "name": "ResourceAccessList",
    "fields": [
        {
            "name": "resources",
            "type": "Array",
            "optional": false,
            "items": "ResourceAccess"
        }
    ],
    "closed": false
}
```

### DomainPolicies `<Struct>`

We need to include the name of the domain in this struct since this data will be passed back to ZPU through ZTS so we need to sign not only the list of policies but also the corresponding domain name that the policies belong to.


```
{
    "type": "Struct",
    "name": "DomainPolicies",
    "comment": "We need to include the name of the domain in this struct since this data will be passed back to ZPU through ZTS so we need to sign not only the list of policies but also the corresponding domain name that the policies belong to.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "policies",
            "type": "Array",
            "optional": false,
            "comment": "list of policies defined in this server",
            "items": "Policy"
        }
    ],
    "closed": false
}
```

### SignedPolicies `<Struct>`

A signed bulk transfer of policies. The data is signed with server's private key.


```
{
    "type": "Struct",
    "name": "SignedPolicies",
    "comment": "A signed bulk transfer of policies. The data is signed with server's private key.",
    "fields": [
        {
            "name": "contents",
            "type": "DomainPolicies",
            "optional": false,
            "comment": "list of policies defined in a domain"
        },
        {
            "name": "signature",
            "type": "String",
            "optional": false,
            "comment": "signature generated based on the domain policies object"
        },
        {
            "name": "keyId",
            "type": "String",
            "optional": false,
            "comment": "the identifier of the key used to generate the signature"
        }
    ],
    "closed": false
}
```

### DomainData `<DomainMeta>`

A domain object that includes its roles, policies and services.


```
{
    "type": "DomainMeta",
    "name": "DomainData",
    "comment": "A domain object that includes its roles, policies and services.",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "roles",
            "type": "Array",
            "optional": false,
            "comment": "list of roles in the domain",
            "items": "Role"
        },
        {
            "name": "policies",
            "type": "SignedPolicies",
            "optional": false,
            "comment": "list of policies in the domain signed with ZMS private key"
        },
        {
            "name": "services",
            "type": "Array",
            "optional": false,
            "comment": "list of services in the domain",
            "items": "ServiceIdentity"
        },
        {
            "name": "entities",
            "type": "Array",
            "optional": false,
            "comment": "list of entities in the domain",
            "items": "Entity"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": false,
            "comment": "last modification timestamp"
        }
    ],
    "closed": false
}
```

### SignedDomain `<Struct>`

A domain object signed with server's private key. The signature and keyid are optional if the metaonly flag is set to true in the getSignedDomains api call


```
{
    "type": "Struct",
    "name": "SignedDomain",
    "comment": "A domain object signed with server's private key. The signature and keyid are optional if the metaonly flag is set to true in the getSignedDomains api call",
    "fields": [
        {
            "name": "domain",
            "type": "DomainData",
            "optional": false,
            "comment": "domain object with its roles, policies and services"
        },
        {
            "name": "signature",
            "type": "String",
            "optional": true,
            "comment": "signature generated based on the domain object"
        },
        {
            "name": "keyId",
            "type": "String",
            "optional": true,
            "comment": "the identifier of the key used to generate the signature"
        }
    ],
    "closed": false
}
```

### SignedDomains `<Struct>`

A list of signed domain objects


```
{
    "type": "Struct",
    "name": "SignedDomains",
    "comment": "A list of signed domain objects",
    "fields": [
        {
            "name": "domains",
            "type": "Array",
            "optional": false,
            "items": "SignedDomain"
        }
    ],
    "closed": false
}
```

### JWSDomain `<Struct>`

SignedDomain using flattened JWS JSON Serialization syntax. https://tools.ietf.org/html/rfc7515#section-7.2.2


```
{
    "type": "Struct",
    "name": "JWSDomain",
    "comment": "SignedDomain using flattened JWS JSON Serialization syntax. https://tools.ietf.org/html/rfc7515#section-7.2.2",
    "fields": [
        {
            "name": "payload",
            "type": "String",
            "optional": false
        },
        {
            "name": "protectedHeader",
            "type": "String",
            "optional": false
        },
        {
            "name": "header",
            "type": "Map",
            "optional": false,
            "items": "String",
            "keys": "String"
        },
        {
            "name": "signature",
            "type": "String",
            "optional": false
        }
    ],
    "closed": false
}
```

### UserToken `<Struct>`

A user token generated based on user's credentials


```
{
    "type": "Struct",
    "name": "UserToken",
    "comment": "A user token generated based on user's credentials",
    "fields": [
        {
            "name": "token",
            "type": "SignedToken",
            "optional": false,
            "comment": "Signed user token identifying a specific authenticated user"
        },
        {
            "name": "header",
            "type": "String",
            "optional": true,
            "comment": "Authorization header name for the token"
        }
    ],
    "closed": false
}
```

### ServicePrincipal `<Struct>`

A service principal object identifying a given service.


```
{
    "type": "Struct",
    "name": "ServicePrincipal",
    "comment": "A service principal object identifying a given service.",
    "fields": [
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "service",
            "type": "EntityName",
            "optional": false,
            "comment": "name of the service"
        },
        {
            "name": "token",
            "type": "SignedToken",
            "optional": false,
            "comment": "service's signed token"
        }
    ],
    "closed": false
}
```

### User `<Struct>`

The representation for a user


```
{
    "type": "Struct",
    "name": "User",
    "comment": "The representation for a user",
    "fields": [
        {
            "name": "name",
            "type": "SimpleName",
            "optional": false,
            "comment": "name of the user"
        }
    ],
    "closed": false
}
```

### UserList `<Struct>`

```
{
    "type": "Struct",
    "name": "UserList",
    "fields": [
        {
            "name": "names",
            "type": "Array",
            "optional": false,
            "comment": "list of user names",
            "items": "SimpleName"
        }
    ],
    "closed": false
}
```

### Quota `<Struct>`

The representation for a quota object


```
{
    "type": "Struct",
    "name": "Quota",
    "comment": "The representation for a quota object",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain object"
        },
        {
            "name": "subdomain",
            "type": "Int32",
            "optional": false,
            "comment": "number of subdomains allowed (applied at top level domain level)"
        },
        {
            "name": "role",
            "type": "Int32",
            "optional": false,
            "comment": "number of roles allowed"
        },
        {
            "name": "roleMember",
            "type": "Int32",
            "optional": false,
            "comment": "number of members a role may have"
        },
        {
            "name": "policy",
            "type": "Int32",
            "optional": false,
            "comment": "number of policies allowed"
        },
        {
            "name": "assertion",
            "type": "Int32",
            "optional": false,
            "comment": "total number of assertions a policy may have"
        },
        {
            "name": "entity",
            "type": "Int32",
            "optional": false,
            "comment": "total number of entity objects"
        },
        {
            "name": "service",
            "type": "Int32",
            "optional": false,
            "comment": "number of services allowed"
        },
        {
            "name": "serviceHost",
            "type": "Int32",
            "optional": false,
            "comment": "number of hosts allowed per service"
        },
        {
            "name": "publicKey",
            "type": "Int32",
            "optional": false,
            "comment": "number of public keys per service"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": true,
            "comment": "the last modification timestamp of the quota object"
        }
    ],
    "closed": false
}
```

### Status `<Struct>`

The representation for a status object


```
{
    "type": "Struct",
    "name": "Status",
    "comment": "The representation for a status object",
    "fields": [
        {
            "name": "code",
            "type": "Int32",
            "optional": false,
            "comment": "status message code"
        },
        {
            "name": "message",
            "type": "String",
            "optional": false,
            "comment": "status message of the server"
        }
    ],
    "closed": false
}
```

### DomainRoleMembership `<Struct>`

```
{
    "type": "Struct",
    "name": "DomainRoleMembership",
    "fields": [
        {
            "name": "domainRoleMembersList",
            "type": "Array",
            "optional": false,
            "items": "DomainRoleMembers"
        }
    ],
    "closed": false
}
```


*generated on Tue Apr 07 2020 09:54:12 GMT-0700 (Pacific Daylight Time)*