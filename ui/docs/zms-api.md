# Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. The Authorization Management Service (ZMS) Classes

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
Enumerate domains. Can be filtered by prefix and depth, and paginated. Most of the query options that are looking for specific domain attributes (e.g. aws account, azure subscriptions, gcp project, business service, tags, etc) are mutually exclusive. The server will only process the first query argument and ignore the others.

```
obj = {
	"limit": "<Int32>", // (optional) restrict the number of results in this call
	"skip": "<String>", // (optional) restrict the set to those after the specified "next" token returned from a previous call
	"prefix": "<String>", // (optional) restrict to names that start with the prefix
	"depth": "<Int32>", // (optional) restrict the depth of the name, specifying the number of '.' characters that can appear
	"account": "<String>", // (optional) restrict to domain names that have specified account name
	"productNumber": "<Int32>", // (optional) restrict the domain names that have specified product number
	"roleMember": "<ResourceName>", // (optional) restrict the domain names where the specified user is in a role - see roleName
	"roleName": "<ResourceName>", // (optional) restrict the domain names where the specified user is in this role - see roleMember
	"subscription": "<String>", // (optional) restrict to domain names that have specified azure subscription name
	"project": "<String>", // (optional) restrict to domain names that have specified gcp project name
	"tagKey": "<CompoundName>", // (optional) flag to query all domains that have a given tagName
	"tagValue": "<CompoundName>", // (optional) flag to query all domains that have a given tag name and value
	"businessService": "<String>", // (optional) restrict to domain names that have specified business service name
	"productId": "<String>", // (optional) restrict the domain names that have specified product id
	"modifiedSince": "<String>" // (optional) This header specifies to the server to return any domains modified since this HTTP date
};
```
*Types:* [`ResourceName <String>`](#resourcename-string), [`CompoundName <String>`](#compoundname-string)

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

### getDomainMetaStoreValidValuesList(*obj, function(err, json, response) { });

`GET /domain/metastore`
List all valid values for the given attribute and user

```
obj = {
	"attributeName": "<String>", // (optional) name of attribute
	"userName": "<String>" // (optional) restrict to values associated with the given user
};
```

### getAuthHistoryDependencies(*obj, function(err, json, response) { });

`GET /domain/{domainName}/history/auth`
Get the authorization and token requests history for the domain

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### deleteExpiredMembers(*obj, function(err, json, response) { });

`DELETE /expired-members`
Delete expired principals This command will purge expired members of the following resources based on the purgeResources value 0 - none of them will be purged 1 - only roles will be purged 2 - only groups will be purged default/3 - both of them will be purged

```
obj = {
	"purgeResources": "<Int32>", // (optional) defining which resources will be purged. by default all resources will be purged
	"auditRef": "<String>", // (optional) Audit reference
	"returnObj": "<Bool>" // (optional) Return object param updated object back.
};
```

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
	"members": "<Bool>", // return list of members in the role
	"tagKey": "<CompoundName>", // (optional) flag to query all roles that have a given tagName
	"tagValue": "<CompoundName>" // (optional) flag to query all roles that have a given tag name and value
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`CompoundName <String>`](#compoundname-string)

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
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
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

`GET /domain/{domainName}/overdue`
Get members with overdue review

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDomainRoleMembers(*obj, function(err, json, response) { });

`GET /domain/{domainName}/member`
Get list of principals defined in roles in the given domain

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDomainRoleMember(*obj, function(err, json, response) { });

`GET /role`
Fetch all the roles across domains by either calling or specified principal The optional expand argument will include all direct and indirect roles, however, it will force authorization that you must be either the principal or for service accounts have update access to the service identity: 1. authenticated principal is the same as the check principal 2. system authorized ("access", "sys.auth:meta.role.lookup") 3. service admin ("update", "{principal}")

```
obj = {
	"principal": "<ResourceName>", // (optional) If not present, will return roles for the user making the call
	"domainName": "<DomainName>", // (optional) If not present, will return roles from all domains
	"expand": "<Bool>" // expand to include group and delegated trust role membership
};
```
*Types:* [`ResourceName <String>`](#resourcename-string), [`DomainName <String>`](#domainname-string)

### putMembership(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/role/{roleName}/member/{memberName}`
Add the specified user to the role's member list. If the role is neither auditEnabled nor selfserve, then it will use authorize ("update", "{domainName}:role.{roleName}") or ("update_members", "{domainName}:role.{roleName}"). This only allows access to members and not role attributes. otherwise membership will be sent for approval to either designated delegates ( in case of auditEnabled roles ) or to domain admins ( in case of selfserve roles )

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"roleName": "<EntityName>", // name of the role
	"memberName": "<MemberName>", // name of the user to be added as a member
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
	"membership": "<Membership>" // Membership object (must contain role/member names as specified in the URI)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`MemberName <String>`](#membername-string), [`Membership <Struct>`](#membership-struct)

### deleteMembership(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/role/{roleName}/member/{memberName}`
Delete the specified role membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). The required authorization includes three options: 1. ("update", "{domainName}:role.{roleName}") 2. ("update_members", "{domainName}:role.{roleName}") 3. principal matches memberName

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
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
	"role": "<Role>" // Role object with updated and/or deleted members
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Role <RoleMeta>`](#role-rolemeta)

### getGroups(*obj, function(err, json, response) { });

`GET /domain/{domainName}/groups`
Get the list of all groups in a domain with optional flag whether or not include members

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"members": "<Bool>", // return list of members in the group
	"tagKey": "<CompoundName>", // (optional) flag to query all groups that have a given tagName
	"tagValue": "<CompoundName>" // (optional) flag to query all groups that have a given tag name and value
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`CompoundName <String>`](#compoundname-string)

### getGroup(*obj, function(err, json, response) { });

`GET /domain/{domainName}/group/{groupName}`
Get the specified group in the domain.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group to be retrieved
	"auditLog": "<Bool>", // flag to indicate whether or not to return group audit log
	"pending": "<Bool>" // include pending members
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### putGroup(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/group/{groupName}`
Create/update the specified group.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group to be added/updated
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
	"group": "<Group>" // Group object to be added/updated in the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Group <GroupMeta>`](#group-groupmeta)

### deleteGroup(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/group/{groupName}`
Delete the specified group. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getGroupMembership(*obj, function(err, json, response) { });

`GET /domain/{domainName}/group/{groupName}/member/{memberName}`
Get the membership status for a specified user in a group.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"memberName": "<GroupMemberName>", // user name to be checked for membership
	"expiration": "<String>" // (optional) the expiration timestamp
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`GroupMemberName <String>`](#groupmembername-string)

### getDomainGroupMember(*obj, function(err, json, response) { });

`GET /group`
Fetch all the groups across domains by either calling or specified principal

```
obj = {
	"principal": "<EntityName>", // (optional) If not present, will return groups for the user making the call
	"domainName": "<DomainName>" // (optional) If not present, will return groups from all domains
};
```
*Types:* [`EntityName <String>`](#entityname-string), [`DomainName <String>`](#domainname-string)

### putGroupMembership(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/group/{groupName}/member/{memberName}`
Add the specified user to the group's member list. If the group is neither auditEnabled nor selfserve, then it will use authorize ("update", "{domainName}:group.{groupName}") otherwise membership will be sent for approval to either designated delegates ( in case of auditEnabled groups ) or to domain admins ( in case of selfserve groups )

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"memberName": "<GroupMemberName>", // name of the user to be added as a member
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
	"membership": "<GroupMembership>" // Membership object (must contain group/member names as specified in the URI)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`GroupMemberName <String>`](#groupmembername-string), [`GroupMembership <Struct>`](#groupmembership-struct)

### deleteGroupMembership(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/group/{groupName}/member/{memberName}`
Delete the specified group membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). The required authorization includes three options: 1. ("update", "{domainName}:group.{groupName}") 2. ("update_members", "{domainName}:group.{groupName}") 3. principal matches memberName

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"memberName": "<GroupMemberName>", // name of the user to be removed as a member
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`GroupMemberName <String>`](#groupmembername-string)

### deleteGroupMembership(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/group/{groupName}/pendingmember/{memberName}`
Delete the specified pending group membership. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned). Authorization will be completed within the server itself since there are two possibilities: 1) The domain admins can delete any pending requests 2) the requestor can also delete his/her own pending request.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"memberName": "<GroupMemberName>", // name of the user to be removed as a pending member
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`GroupMemberName <String>`](#groupmembername-string)

### putGroupSystemMeta(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/group/{groupName}/meta/system/{attribute}`
Set the specified group metadata. Caller must have update privileges on the sys.auth domain. If the system attribute is one of the string attributes, then the caller must also have delete action on the same resource in order to reset the configured value

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"attribute": "<SimpleName>", // name of the system attribute to be modified
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<GroupSystemMeta>" // GroupSystemMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`SimpleName <String>`](#simplename-string), [`GroupSystemMeta <Struct>`](#groupsystemmeta-struct)

### putGroupMeta(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/group/{groupName}/meta`
Update the specified group metadata. Caller must have update privileges on the domain itself.

```
obj = {
	"domainName": "<DomainName>", // name of the domain to be updated
	"groupName": "<EntityName>", // name of the group
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"detail": "<GroupMeta>" // GroupMeta object with updated attribute values
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`GroupMeta <Struct>`](#groupmeta-struct)

### putGroupMembership(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/group/{groupName}/member/{memberName}/decision`
Approve or Reject the request to add specified user to group membership. This endpoint will be used by 2 use cases: 1. Audit enabled groups with authorize ("update", "sys.auth:meta.group.{attribute}.{domainName}") 2. Selfserve groups in any domain with authorize ("update", "{domainName}:")

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"memberName": "<GroupMemberName>", // name of the user to be added as a member
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"membership": "<GroupMembership>" // GroupMembership object (must contain group/member names as specified in the URI)
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`GroupMemberName <String>`](#groupmembername-string), [`GroupMembership <Struct>`](#groupmembership-struct)

### putGroup(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/group/{groupName}/review`
Review group membership and take action to either extend and/or delete existing members.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"groupName": "<EntityName>", // name of the group
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
	"group": "<Group>" // Group object with updated and/or deleted members
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`Group <GroupMeta>`](#group-groupmeta)

### getDomainGroupMembership(*obj, function(err, json, response) { });

`GET /pending_group_members`
List of domains containing groups and corresponding members to be approved by either calling or specified principal

```
obj = {
	"principal": "<EntityName>", // (optional) If present, return pending list for this principal
	"domainName": "<String>" // (optional) If present, return pending list for this domain
};
```
*Types:* [`EntityName <String>`](#entityname-string)

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
	"assertions": "<Bool>", // return list of assertions in the policy
	"includeNonActive": "<Bool>", // include non-active policy versions
	"tagKey": "<CompoundName>", // (optional) flag to query all policies that have a given tagName
	"tagValue": "<CompoundName>" // (optional) flag to query all policies that have a given tag name and value
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`CompoundName <String>`](#compoundname-string)

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
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
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

### putAssertion(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}/version/{version}/assertion`
Add the specified assertion to the given policy version

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"version": "<SimpleName>", // name of the version
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"assertion": "<Assertion>" // Assertion object to be added to the given policy version
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`SimpleName <String>`](#simplename-string), [`Assertion <Struct>`](#assertion-struct)

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

### deleteAssertion(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}/version/{version}/assertion/{assertionId}`
Delete the specified policy version assertion. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"version": "<SimpleName>", // name of the version
	"assertionId": "<Int64>", // assertion id
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`SimpleName <String>`](#simplename-string)

### putAssertionConditions(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}/assertion/{assertionId}/conditions`
Add the specified conditions to the given assertion

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>", // assertion id
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"assertionConditions": "<AssertionConditions>" // Assertion conditions object to be added to the given assertion
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`AssertionConditions <Struct>`](#assertionconditions-struct)

### putAssertionCondition(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}/assertion/{assertionId}/condition`
Add the specified condition to the existing assertion conditions of an assertion

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>", // assertion id
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"assertionCondition": "<AssertionCondition>" // Assertion conditions object to be added to the given assertion
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`AssertionCondition <Struct>`](#assertioncondition-struct)

### deleteAssertionConditions(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}/assertion/{assertionId}/conditions`
Delete all assertion conditions for specified assertion id. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>", // assertion id
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### deleteAssertionCondition(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}/assertion/{assertionId}/condition/{conditionId}`
Delete the assertion condition(s) for specified assertion id and condition id. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"assertionId": "<Int64>", // assertion id
	"conditionId": "<Int32>", // condition id
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getPolicyList(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy/{policyName}/version`
List policy versions.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>" // name of the policy
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string)

### getPolicy(*obj, function(err, json, response) { });

`GET /domain/{domainName}/policy/{policyName}/version/{version}`
Get the specified policy version.

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"version": "<SimpleName>" // name of the version to be retrieved
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`SimpleName <String>`](#simplename-string)

### putPolicyOptions(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}/version/create`
Create a new disabled policy version based on active policy

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy to be added/updated
	"policyOptions": "<PolicyOptions>", // name of the source version to copy from and name of new version
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"returnObj": "<Bool>" // (optional) Return object param updated object back.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`PolicyOptions <Struct>`](#policyoptions-struct)

### putPolicyOptions(*obj, function(err, json, response) { });

`PUT /domain/{domainName}/policy/{policyName}/version/active`
Mark the specified policy version as active

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"policyOptions": "<PolicyOptions>", // name of the version
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`PolicyOptions <Struct>`](#policyoptions-struct)

### deletePolicy(*obj, function(err, json, response) { });

`DELETE /domain/{domainName}/policy/{policyName}/version/{version}`
Delete the specified policy version. Upon successful completion of this delete request, the server will return NO_CONTENT status code without any data (no object will be returned).

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"policyName": "<EntityName>", // name of the policy
	"version": "<SimpleName>", // name of the version to be deleted
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`EntityName <String>`](#entityname-string), [`SimpleName <String>`](#simplename-string)

### putServiceIdentity(*obj, function(err, json, response) { });

`PUT /domain/{domain}/service/{service}`
Register the specified ServiceIdentity in the specified domain

```
obj = {
	"domain": "<DomainName>", // name of the domain
	"service": "<SimpleName>", // name of the service
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"returnObj": "<Bool>", // (optional) Return object param updated object back.
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
	"hosts": "<Bool>", // return list of hosts in the service
	"tagKey": "<CompoundName>", // (optional) flag to query all services that have a given tagName
	"tagValue": "<CompoundName>" // (optional) flag to query all services that have a given tag name and value
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`CompoundName <String>`](#compoundname-string)

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
Return list of resources that the given principal has access to. Even though the principal is marked as optional, it must be specified

```
obj = {
	"principal": "<ResourceName>", // (optional) specifies principal to query the resource list for
	"action": "<ActionName>" // (optional) action as specified in the policy assertion
};
```
*Types:* [`ResourceName <String>`](#resourcename-string), [`ActionName <String>`](#actionname-string)

### getSignedDomains(*obj, function(err, json, response) { });

`GET /sys/modified_domains`
Retrieve the list of modified domains since the specified timestamp. The server will return the list of all modified domains and the latest modification timestamp as the value of the ETag header. The client will need to use this value during its next call to request the changes since the previous request. When metaonly set to true, don't add roles, policies or services, don't sign

```
obj = {
	"domain": "<DomainName>", // (optional) filter the domain list only to the specified name
	"metaOnly": "<String>", // (optional) valid values are "true" or "false"
	"metaAttr": "<SimpleName>", // (optional) domain meta attribute to filter/return, valid values "account", "ypmId", or "all"
	"master": "<Bool>", // (optional) for system principals only - request data from master data store and not read replicas if any are configured
	"conditions": "<Bool>", // (optional) for specific purpose only. If this flag is passed, assertion id and assertion conditions will be included in the response assertions if available
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return any domains modified since this time
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`SimpleName <String>`](#simplename-string)

### getJWSDomain(*obj, function(err, json, response) { });

`GET /domain/{name}/signed`


```
obj = {
	"name": "<DomainName>", // name of the domain to be retrieved
	"signatureP1363Format": "<Bool>", // (optional) true if signature must be in P1363 format instead of ASN.1 DER
	"matchingTag": "<String>" // (optional) Retrieved from the previous request, this timestamp specifies to the server to return if the domain was modified since this time
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

### getDomainTemplateDetailsList(*obj, function(err, json, response) { });

`GET /domain/{name}/templatedetails`
Get a list of Solution templates with meta data details given a domain name

```
obj = {
	"name": "<DomainName>" // List of templates given a domain name
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDomainTemplateDetailsList(*obj, function(err, json, response) { });

`GET /templatedetails`
Get a list of Solution templates with meta data details defined in the server


### getUserList(*obj, function(err, json, response) { });

`GET /user`
Enumerate users that are registered as principals in the system This will return only the principals with "<user-domain>." prefix

```
obj = {
	"domainName": "<DomainName>" // (optional) name of the allowed user-domains and/or aliases
};
```
*Types:* [`DomainName <String>`](#domainname-string)

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
	"principal": "<EntityName>", // (optional) If present, return pending list for this principal
	"domainName": "<String>" // (optional) If present, return pending list for this domain
};
```
*Types:* [`EntityName <String>`](#entityname-string)

### getUserAuthorityAttributeMap(*obj, function(err, json, response) { });

`GET /authority/user/attribute`
Map of type to attribute values for the user authority


### getStats(*obj, function(err, json, response) { });

`GET /domain/{name}/stats`
Retrieve the stats object defined for the domain

```
obj = {
	"name": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getStats(*obj, function(err, json, response) { });

`GET /sys/stats`
Retrieve the stats object defined for the system


### putDependentService(*obj, function(err, json, response) { });

`PUT /dependency/domain/{domainName}`
Register domain as a dependency to service There are two possible authorization checks for this endpoint: 1) System Administrator 2) Authorized Service Provider

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"auditRef": "<String>", // (optional) Audit param required(not empty) if domain auditEnabled is true.
	"service": "<DependentService>" // Dependent service provider details
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`DependentService <Struct>`](#dependentservice-struct)

### deleteServiceName(*obj, function(err, json, response) { });

`DELETE /dependency/domain/{domainName}/service/{service}`
De-register domain as a dependency to service There are two possible authorization checks for this endpoint: 1) System Administrator 2) Authorized Service Provider

```
obj = {
	"domainName": "<DomainName>", // name of the domain
	"service": "<ServiceName>", // name of the service
	"auditRef": "<String>" // (optional) Audit param required(not empty) if domain auditEnabled is true.
};
```
*Types:* [`DomainName <String>`](#domainname-string), [`ServiceName <String>`](#servicename-string)

### getServiceIdentityList(*obj, function(err, json, response) { });

`GET /dependency/domain/{domainName}`
List registered services for domain

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDependentServiceResourceGroupList(*obj, function(err, json, response) { });

`GET /dependency/domain/{domainName}/resourceGroup`
List registered services and resource groups for domain

```
obj = {
	"domainName": "<DomainName>" // name of the domain
};
```
*Types:* [`DomainName <String>`](#domainname-string)

### getDomainList(*obj, function(err, json, response) { });

`GET /dependency/service/{service}`
List dependent domains for service

```
obj = {
	"service": "<ServiceName>" // name of the service
};
```
*Types:* [`ServiceName <String>`](#servicename-string)

### getInfo(*obj, function(err, json, response) { });

`GET /sys/info`
Retrieve the server info. Since we're exposing server version details, the request will require authorization


### getRdl.Schema(*obj, function(err, json, response) { });

`GET /schema`
Get RDL Schema



## API Types

### SimpleName `<String>`

Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. Common name types used by several API definitions A simple identifier, an element of compound name.


```
{
    "type": "String",
    "name": "SimpleName",
    "comment": "Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. Common name types used by several API definitions A simple identifier, an element of compound name.",
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

### GroupName `<String>`

A group name


```
{
    "type": "String",
    "name": "GroupName",
    "comment": "A group name",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*:group\\.([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### GroupMemberName `<String>`

A group member name


```
{
    "type": "String",
    "name": "GroupMemberName",
    "comment": "A group member name",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### MemberName `<String>`

Role Member name - could be one of four values: *, DomainName.* or ServiceName[*], or GroupNames


```
{
    "type": "String",
    "name": "MemberName",
    "comment": "Role Member name - could be one of four values: *, DomainName.* or ServiceName[*], or GroupNames",
    "pattern": "\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*\\.\\*|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*(\\*)?|([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*:group\\.([a-zA-Z0-9_][a-zA-Z0-9_-]*\\.)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### AuthorityKeyword `<String>`

A comma separated list of authority keywords


```
{
    "type": "String",
    "name": "AuthorityKeyword",
    "comment": "A comma separated list of authority keywords",
    "pattern": "[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### AuthorityKeywords `<String>`

```
{
    "type": "String",
    "name": "AuthorityKeywords",
    "pattern": "([a-zA-Z0-9_][a-zA-Z0-9_-]*,)*[a-zA-Z0-9_][a-zA-Z0-9_-]*"
}
```

### TagValue `<String>`

TagValue to contain generic string patterns


```
{
    "type": "String",
    "name": "TagValue",
    "comment": "TagValue to contain generic string patterns",
    "pattern": "[a-zA-Z0-9_:,\\/][a-zA-Z0-9_:,\\/-]*"
}
```

### TagCompoundValue `<String>`

A compound value of TagValue


```
{
    "type": "String",
    "name": "TagCompoundValue",
    "comment": "A compound value of TagValue",
    "pattern": "([a-zA-Z0-9_:,\\/][a-zA-Z0-9_:,\\/-]*\\.)*[a-zA-Z0-9_:,\\/][a-zA-Z0-9_:,\\/-]*"
}
```

### TagValueList `<Struct>`

```
{
    "type": "Struct",
    "name": "TagValueList",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "optional": false,
            "comment": "list of tag values",
            "items": "TagCompoundValue"
        }
    ],
    "closed": false
}
```

### AssertionConditionKeyPattern `<String>`

```
{
    "type": "String",
    "name": "AssertionConditionKeyPattern",
    "pattern": "[a-zA-Z][a-zA-Z0-9_-]+"
}
```

### AssertionConditionKey `<String>`

```
{
    "type": "String",
    "name": "AssertionConditionKey",
    "pattern": "([a-zA-Z][a-zA-Z0-9_-]+\\.)*[a-zA-Z][a-zA-Z0-9_-]+"
}
```

### AssertionConditionValuePattern `<String>`

```
{
    "type": "String",
    "name": "AssertionConditionValuePattern",
    "pattern": "[a-zA-Z0-9\\*][a-zA-Z0-9_\\.\\*-]*"
}
```

### AssertionConditionValue `<String>`

```
{
    "type": "String",
    "name": "AssertionConditionValue",
    "pattern": "([a-zA-Z0-9\\*][a-zA-Z0-9_\\.\\*-]*,)*[a-zA-Z0-9\\*][a-zA-Z0-9_\\.\\*-]*"
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
            "comment": "a reference to an audit organization defined in athenz"
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
            "comment": "associated aws account id (system attribute - uniqueness check - if enabled)"
        },
        {
            "name": "ypmId",
            "type": "Int32",
            "optional": true,
            "comment": "associated product id (system attribute - uniqueness check - if enabled)"
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
            "comment": "all services in the domain roles will have specified max expiry days"
        },
        {
            "name": "groupExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all groups in the domain roles will have specified max expiry days"
        },
        {
            "name": "userAuthorityFilter",
            "type": "String",
            "optional": true,
            "comment": "membership filtered based on user authority configured attributes"
        },
        {
            "name": "azureSubscription",
            "type": "String",
            "optional": true,
            "comment": "associated azure subscription id (system attribute - uniqueness check - if enabled)"
        },
        {
            "name": "gcpProject",
            "type": "String",
            "optional": true,
            "comment": "associated gcp project id (system attribute - uniqueness check - if enabled)"
        },
        {
            "name": "gcpProjectNumber",
            "type": "String",
            "optional": true,
            "comment": "associated gcp project number (system attribute)"
        },
        {
            "name": "tags",
            "type": "Map",
            "optional": true,
            "comment": "key-value pair tags, tag might contain multiple values",
            "items": "TagValueList",
            "keys": "CompoundName"
        },
        {
            "name": "businessService",
            "type": "String",
            "optional": true,
            "comment": "associated business service with domain"
        },
        {
            "name": "memberPurgeExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "purge role/group members with expiry date configured days in the past"
        },
        {
            "name": "productId",
            "type": "String",
            "optional": true,
            "comment": "associated product id (system attribute - uniqueness check - if enabled)"
        },
        {
            "name": "featureFlags",
            "type": "Int32",
            "optional": true,
            "comment": "features enabled per domain (system attribute)"
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

### DomainAttributes `<Struct>`

A domain attributes for the changelog support


```
{
    "type": "Struct",
    "name": "DomainAttributes",
    "comment": "A domain attributes for the changelog support",
    "fields": [
        {
            "name": "fetchTime",
            "type": "Int64",
            "optional": false,
            "comment": "timestamp when the domain object was fetched from ZMS"
        }
    ],
    "closed": false
}
```

### DomainOptions `<Struct>`

A domain options for enforcing uniqueness checks


```
{
    "type": "Struct",
    "name": "DomainOptions",
    "comment": "A domain options for enforcing uniqueness checks",
    "fields": [
        {
            "name": "enforceUniqueProductIds",
            "type": "Bool",
            "optional": false,
            "comment": "enforce domains are associated with unique product ids"
        },
        {
            "name": "enforceUniqueAWSAccounts",
            "type": "Bool",
            "optional": false,
            "comment": "enforce domains are associated with unique aws accounts"
        },
        {
            "name": "enforceUniqueAzureSubscriptions",
            "type": "Bool",
            "optional": false,
            "comment": "enforce domains are associated with unique azure subscriptions"
        },
        {
            "name": "enforceUniqueGCPProjects",
            "type": "Bool",
            "optional": false,
            "comment": "enforce domains are associated with unique gcp projects"
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
            "name": "reviewReminder",
            "type": "Timestamp",
            "optional": true,
            "comment": "the review reminder timestamp"
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
        },
        {
            "name": "reviewLastNotifiedTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "for pending membership requests, time when last notification was sent (for file store)"
        },
        {
            "name": "systemDisabled",
            "type": "Int32",
            "optional": true,
            "comment": "user disabled by system based on configured role setting"
        },
        {
            "name": "principalType",
            "type": "Int32",
            "optional": true,
            "comment": "server use only - principal type: unknown(0), user(1), service(2), or group(3)"
        },
        {
            "name": "pendingState",
            "type": "String",
            "optional": true,
            "comment": "for pending membership requests, the request state - e.g. add, delete"
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
            "name": "memberReviewDays",
            "type": "Int32",
            "optional": true,
            "comment": "all user members in the role will have specified max review days"
        },
        {
            "name": "serviceReviewDays",
            "type": "Int32",
            "optional": true,
            "comment": "all services in the role will have specified max review days"
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
            "type": "String",
            "optional": true,
            "comment": "list of roles whose members should be notified for member review/approval"
        },
        {
            "name": "userAuthorityFilter",
            "type": "String",
            "optional": true,
            "comment": "membership filtered based on user authority configured attributes"
        },
        {
            "name": "userAuthorityExpiration",
            "type": "String",
            "optional": true,
            "comment": "expiration enforced by a user authority configured attribute"
        },
        {
            "name": "groupExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all groups in the domain roles will have specified max expiry days"
        },
        {
            "name": "groupReviewDays",
            "type": "Int32",
            "optional": true,
            "comment": "all groups in the domain roles will have specified max review days"
        },
        {
            "name": "tags",
            "type": "Map",
            "optional": true,
            "comment": "key-value pair tags, tag might contain multiple values",
            "items": "TagValueList",
            "keys": "CompoundName"
        },
        {
            "name": "description",
            "type": "String",
            "optional": true,
            "comment": "a description of the role"
        },
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not role updates should be approved by GRC. If true, the auditRef parameter must be supplied(not empty) for any API defining it.",
            "default": false
        },
        {
            "name": "deleteProtection",
            "type": "Bool",
            "optional": true,
            "comment": "If true, ask for delete confirmation in audit and review enabled roles.",
            "default": false
        }
    ],
    "closed": false
}
```

### Role `<RoleMeta>`

The representation for a Role with set of members. The members (Array<MemberName>) field is deprecated and not used in role objects since it incorrectly lists all the members in the role without taking into account if the member is expired or possibly disabled. Thus, using this attribute will result in incorrect authorization checks by the client and, thus, it's no longer being populated. All applications must use the roleMembers field and take into account all the attributes of the member.


```
{
    "type": "RoleMeta",
    "name": "Role",
    "comment": "The representation for a Role with set of members. The members (Array<MemberName>) field is deprecated and not used in role objects since it incorrectly lists all the members in the role without taking into account if the member is expired or possibly disabled. Thus, using this attribute will result in incorrect authorization checks by the client and, thus, it's no longer being populated. All applications must use the roleMembers field and take into account all the attributes of the member.",
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
            "comment": "deprecated and not used",
            "items": "MemberName"
        },
        {
            "name": "roleMembers",
            "type": "Array",
            "optional": true,
            "comment": "members with expiration and other member attributes. might be empty or null, if trust is set",
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
            "name": "reviewReminder",
            "type": "Timestamp",
            "optional": true,
            "comment": "the review reminder timestamp"
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
        },
        {
            "name": "systemDisabled",
            "type": "Int32",
            "optional": true,
            "comment": "user disabled by system based on configured role setting"
        },
        {
            "name": "pendingState",
            "type": "String",
            "optional": true,
            "comment": "for pending membership requests, the request state - e.g. add, delete"
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
            "name": "reviewReminder",
            "type": "Timestamp",
            "optional": true,
            "comment": "the review reminder timestamp"
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
        },
        {
            "name": "systemDisabled",
            "type": "Int32",
            "optional": true,
            "comment": "user disabled by system based on configured role setting"
        },
        {
            "name": "pendingState",
            "type": "String",
            "optional": true,
            "comment": "for pending membership requests, the request state - e.g. add, delete"
        },
        {
            "name": "trustRoleName",
            "type": "ResourceName",
            "optional": true,
            "comment": "name of the role that handles the membership delegation for the role specified in roleName"
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

### AssertionConditionOperator `<Enum>`

Allowed operators for assertion conditions


```
{
    "type": "Enum",
    "name": "AssertionConditionOperator",
    "comment": "Allowed operators for assertion conditions",
    "elements": [
        {
            "symbol": "EQUALS"
        }
    ]
}
```

### AssertionConditionData `<Struct>`

A representation of details associated with an assertion condition key


```
{
    "type": "Struct",
    "name": "AssertionConditionData",
    "comment": "A representation of details associated with an assertion condition key",
    "fields": [
        {
            "name": "operator",
            "type": "AssertionConditionOperator",
            "optional": false,
            "comment": "Operator for the assertion condition"
        },
        {
            "name": "value",
            "type": "AssertionConditionValue",
            "optional": false,
            "comment": "Value of the assertion condition"
        }
    ],
    "closed": false
}
```

### AssertionCondition `<Struct>`

A representation of condition associated with an assertion


```
{
    "type": "Struct",
    "name": "AssertionCondition",
    "comment": "A representation of condition associated with an assertion",
    "fields": [
        {
            "name": "id",
            "type": "Int32",
            "optional": true,
            "comment": "condition id - auto generated by server. Not required during put operations."
        },
        {
            "name": "conditionsMap",
            "type": "Map",
            "optional": false,
            "comment": "each key in the map represents a unique condition. All the keys present in the map form a logical condition with AND operation.",
            "items": "AssertionConditionData",
            "keys": "AssertionConditionKey"
        }
    ],
    "closed": false
}
```

### AssertionConditions `<Struct>`

The representation of list of assertion conditions


```
{
    "type": "Struct",
    "name": "AssertionConditions",
    "comment": "The representation of list of assertion conditions",
    "fields": [
        {
            "name": "conditionsList",
            "type": "Array",
            "optional": false,
            "comment": "list of assertion conditions.",
            "items": "AssertionCondition"
        }
    ],
    "closed": false
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
        },
        {
            "name": "caseSensitive",
            "type": "Bool",
            "optional": true,
            "comment": "If true, we should store action and resource in their original case"
        },
        {
            "name": "conditions",
            "type": "AssertionConditions",
            "optional": true,
            "comment": "optional list of assertion conditions associated with given assertion"
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
        },
        {
            "name": "caseSensitive",
            "type": "Bool",
            "optional": true,
            "comment": "If true, we should store action and resource in their original case"
        },
        {
            "name": "version",
            "type": "SimpleName",
            "optional": true,
            "comment": "optional version string, defaults to 0"
        },
        {
            "name": "active",
            "type": "Bool",
            "optional": true,
            "comment": "if multi-version policy then indicates active version"
        },
        {
            "name": "description",
            "type": "String",
            "optional": true,
            "comment": "a description of the policy"
        },
        {
            "name": "tags",
            "type": "Map",
            "optional": true,
            "comment": "key-value pair tags, tag might contain multiple values",
            "items": "TagValueList",
            "keys": "CompoundName"
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

### PolicyOptions `<Struct>`

Options for Policy Management Requests


```
{
    "type": "Struct",
    "name": "PolicyOptions",
    "comment": "Options for Policy Management Requests",
    "fields": [
        {
            "name": "version",
            "type": "SimpleName",
            "optional": false,
            "comment": "policy version"
        },
        {
            "name": "fromVersion",
            "type": "SimpleName",
            "optional": true,
            "comment": "optional source version used when creating a new version, defaults to 0"
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
        },
        {
            "name": "tags",
            "type": "Map",
            "optional": true,
            "comment": "key-value pair tags, tag might contain multiple values",
            "items": "TagValueList",
            "keys": "CompoundName"
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

### TemplateMetaData `<Struct>`

MetaData for template.


```
{
    "type": "Struct",
    "name": "TemplateMetaData",
    "comment": "MetaData for template.",
    "fields": [
        {
            "name": "templateName",
            "type": "String",
            "optional": true,
            "comment": "name of the template"
        },
        {
            "name": "description",
            "type": "String",
            "optional": true,
            "comment": "description of the template"
        },
        {
            "name": "currentVersion",
            "type": "Int32",
            "optional": true,
            "comment": "Version from DB(zms_store->domain_template->version)"
        },
        {
            "name": "latestVersion",
            "type": "Int32",
            "optional": true,
            "comment": "Bumped up version from solutions-template.json when there is a change"
        },
        {
            "name": "keywordsToReplace",
            "type": "String",
            "optional": true,
            "comment": "placeholders in the template roles/policies to replace (ex:_service_)"
        },
        {
            "name": "timestamp",
            "type": "Timestamp",
            "optional": true,
            "comment": "the updated timestamp of the template(solution_templates.json)"
        },
        {
            "name": "autoUpdate",
            "type": "Bool",
            "optional": true,
            "comment": "flag to automatically update the roles/policies that belongs to the template"
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
        },
        {
            "name": "metadata",
            "type": "TemplateMetaData",
            "optional": true,
            "comment": "list of services defined in this template"
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

### DomainTemplateDetailsList `<Struct>`

List of templates with metadata details given a domain


```
{
    "type": "Struct",
    "name": "DomainTemplateDetailsList",
    "comment": "List of templates with metadata details given a domain",
    "fields": [
        {
            "name": "metaData",
            "type": "Array",
            "optional": false,
            "comment": "list of template metadata",
            "items": "TemplateMetaData"
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

### DomainMetaStoreValidValuesList `<Struct>`

List of valid domain meta attribute values


```
{
    "type": "Struct",
    "name": "DomainMetaStoreValidValuesList",
    "comment": "List of valid domain meta attribute values",
    "fields": [
        {
            "name": "validValues",
            "type": "Array",
            "optional": false,
            "comment": "list of valid values for attribute",
            "items": "String"
        }
    ],
    "closed": false
}
```

### AuthHistory `<Struct>`

```
{
    "type": "Struct",
    "name": "AuthHistory",
    "fields": [
        {
            "name": "uriDomain",
            "type": "DomainName",
            "optional": false,
            "comment": "Name of the domain from URI"
        },
        {
            "name": "principalDomain",
            "type": "DomainName",
            "optional": false,
            "comment": "Principal domain"
        },
        {
            "name": "principalName",
            "type": "SimpleName",
            "optional": false,
            "comment": "Principal name"
        },
        {
            "name": "timestamp",
            "type": "Timestamp",
            "optional": false,
            "comment": "Last authorization event timestamp"
        },
        {
            "name": "endpoint",
            "type": "String",
            "optional": false,
            "comment": "Last authorization endpoint used"
        },
        {
            "name": "ttl",
            "type": "Int64",
            "optional": false,
            "comment": "Time until the record will expire"
        }
    ],
    "closed": false
}
```

### AuthHistoryDependencies `<Struct>`

```
{
    "type": "Struct",
    "name": "AuthHistoryDependencies",
    "fields": [
        {
            "name": "incomingDependencies",
            "type": "Array",
            "optional": false,
            "comment": "list of incoming auth dependencies for domain",
            "items": "AuthHistory"
        },
        {
            "name": "outgoingDependencies",
            "type": "Array",
            "optional": false,
            "comment": "list of incoming auth dependencies for domain",
            "items": "AuthHistory"
        }
    ],
    "closed": false
}
```

### ExpiryMember `<Struct>`

```
{
    "type": "Struct",
    "name": "ExpiryMember",
    "fields": [
        {
            "name": "domainName",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the domain"
        },
        {
            "name": "collectionName",
            "type": "EntityName",
            "optional": false,
            "comment": "name of the collection"
        },
        {
            "name": "principalName",
            "type": "ResourceName",
            "optional": false,
            "comment": "name of the principal"
        },
        {
            "name": "expiration",
            "type": "Timestamp",
            "optional": false,
            "comment": "the expiration timestamp"
        }
    ],
    "closed": false
}
```

### ExpiredMembers `<Struct>`

```
{
    "type": "Struct",
    "name": "ExpiredMembers",
    "fields": [
        {
            "name": "expiredRoleMembers",
            "type": "Array",
            "optional": false,
            "comment": "list of deleted expired role members",
            "items": "ExpiryMember"
        },
        {
            "name": "expiredGroupMembers",
            "type": "Array",
            "optional": false,
            "comment": "list of deleted expired groups members",
            "items": "ExpiryMember"
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
            "type": "ResourceName",
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

### GroupAuditLog `<Struct>`

An audit log entry for group membership change.


```
{
    "type": "Struct",
    "name": "GroupAuditLog",
    "comment": "An audit log entry for group membership change.",
    "fields": [
        {
            "name": "member",
            "type": "GroupMemberName",
            "optional": false,
            "comment": "name of the group member"
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

### GroupMember `<Struct>`

```
{
    "type": "Struct",
    "name": "GroupMember",
    "fields": [
        {
            "name": "memberName",
            "type": "GroupMemberName",
            "optional": true,
            "comment": "name of the member"
        },
        {
            "name": "groupName",
            "type": "ResourceName",
            "optional": true,
            "comment": "name of the group"
        },
        {
            "name": "domainName",
            "type": "DomainName",
            "optional": true,
            "comment": "name of the domain"
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
            "comment": "Flag to indicate whether membership is approved either by delegates ( in case of auditEnabled groups ) or by domain admins ( in case of selfserve groups )",
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
        },
        {
            "name": "reviewLastNotifiedTime",
            "type": "Timestamp",
            "optional": true,
            "comment": "for pending membership requests, time when last notification was sent (for file store)"
        },
        {
            "name": "systemDisabled",
            "type": "Int32",
            "optional": true,
            "comment": "user disabled by system based on configured group setting"
        },
        {
            "name": "principalType",
            "type": "Int32",
            "optional": true,
            "comment": "server use only - principal type: unknown(0), user(1) or service(2)"
        },
        {
            "name": "pendingState",
            "type": "String",
            "optional": true,
            "comment": "for pending membership requests, the request state - e.g. add, delete"
        }
    ],
    "closed": false
}
```

### GroupMembership `<Struct>`

The representation for a group membership.


```
{
    "type": "Struct",
    "name": "GroupMembership",
    "comment": "The representation for a group membership.",
    "fields": [
        {
            "name": "memberName",
            "type": "GroupMemberName",
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
            "name": "groupName",
            "type": "ResourceName",
            "optional": true,
            "comment": "name of the group"
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
            "comment": "Flag to indicate whether membership is approved either by delegates ( in case of auditEnabled groups ) or by domain admins ( in case of selfserve groups )",
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
        },
        {
            "name": "systemDisabled",
            "type": "Int32",
            "optional": true,
            "comment": "user disabled by system based on configured group setting"
        },
        {
            "name": "pendingState",
            "type": "String",
            "optional": true,
            "comment": "for pending membership requests, the request state - e.g. add, delete"
        }
    ],
    "closed": false
}
```

### GroupMeta `<Struct>`

Set of metadata attributes that all groups may have and can be changed by domain admins.


```
{
    "type": "Struct",
    "name": "GroupMeta",
    "comment": "Set of metadata attributes that all groups may have and can be changed by domain admins.",
    "fields": [
        {
            "name": "selfServe",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not group allows self service. Users can add themselves in the group, but it has to be approved by domain admins to be effective.",
            "default": false
        },
        {
            "name": "reviewEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not group updates require another review and approval",
            "default": false
        },
        {
            "name": "notifyRoles",
            "type": "String",
            "optional": true,
            "comment": "list of roles whose members should be notified for member review/approval"
        },
        {
            "name": "userAuthorityFilter",
            "type": "String",
            "optional": true,
            "comment": "membership filtered based on user authority configured attributes"
        },
        {
            "name": "userAuthorityExpiration",
            "type": "String",
            "optional": true,
            "comment": "expiration enforced by a user authority configured attribute"
        },
        {
            "name": "memberExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all user members in the group will have specified max expiry days"
        },
        {
            "name": "serviceExpiryDays",
            "type": "Int32",
            "optional": true,
            "comment": "all services in the group will have specified max expiry days"
        },
        {
            "name": "tags",
            "type": "Map",
            "optional": true,
            "comment": "key-value pair tags, tag might contain multiple values",
            "items": "TagValueList",
            "keys": "CompoundName"
        },
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not group updates should require GRC approval. If true, the auditRef parameter must be supplied(not empty) for any API defining it",
            "default": false
        },
        {
            "name": "deleteProtection",
            "type": "Bool",
            "optional": true,
            "comment": "If true, ask for delete confirmation in audit and review enabled groups.",
            "default": false
        }
    ],
    "closed": false
}
```

### Group `<GroupMeta>`

The representation for a Group with set of members.


```
{
    "type": "GroupMeta",
    "name": "Group",
    "comment": "The representation for a Group with set of members.",
    "fields": [
        {
            "name": "name",
            "type": "ResourceName",
            "optional": false,
            "comment": "name of the group"
        },
        {
            "name": "modified",
            "type": "Timestamp",
            "optional": true,
            "comment": "last modification timestamp of the group"
        },
        {
            "name": "groupMembers",
            "type": "Array",
            "optional": true,
            "comment": "members with expiration",
            "items": "GroupMember"
        },
        {
            "name": "auditLog",
            "type": "Array",
            "optional": true,
            "comment": "an audit log for group membership changes",
            "items": "GroupAuditLog"
        },
        {
            "name": "lastReviewedDate",
            "type": "Timestamp",
            "optional": true,
            "comment": "last review timestamp of the group"
        }
    ],
    "closed": false
}
```

### Groups `<Struct>`

The representation for a list of groups with full details


```
{
    "type": "Struct",
    "name": "Groups",
    "comment": "The representation for a list of groups with full details",
    "fields": [
        {
            "name": "list",
            "type": "Array",
            "optional": false,
            "comment": "list of group objects",
            "items": "Group"
        }
    ],
    "closed": false
}
```

### DomainGroupMember `<Struct>`

```
{
    "type": "Struct",
    "name": "DomainGroupMember",
    "fields": [
        {
            "name": "memberName",
            "type": "GroupMemberName",
            "optional": false,
            "comment": "name of the member"
        },
        {
            "name": "memberGroups",
            "type": "Array",
            "optional": false,
            "comment": "groups for this member",
            "items": "GroupMember"
        }
    ],
    "closed": false
}
```

### DomainGroupMembers `<Struct>`

```
{
    "type": "Struct",
    "name": "DomainGroupMembers",
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
            "comment": "group members",
            "items": "DomainGroupMember"
        }
    ],
    "closed": false
}
```

### DomainGroupMembership `<Struct>`

```
{
    "type": "Struct",
    "name": "DomainGroupMembership",
    "fields": [
        {
            "name": "domainGroupMembersList",
            "type": "Array",
            "optional": false,
            "items": "DomainGroupMembers"
        }
    ],
    "closed": false
}
```

### GroupSystemMeta `<Struct>`

Set of system metadata attributes that all groups may have and can be changed by system admins.


```
{
    "type": "Struct",
    "name": "GroupSystemMeta",
    "comment": "Set of system metadata attributes that all groups may have and can be changed by system admins.",
    "fields": [
        {
            "name": "auditEnabled",
            "type": "Bool",
            "optional": true,
            "comment": "Flag indicates whether or not group updates should be approved by GRC. If true, the auditRef parameter must be supplied(not empty) for any API defining it.",
            "default": false
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
        },
        {
            "name": "createAdminRole",
            "type": "Bool",
            "optional": true,
            "comment": "optional flag indicating whether to create a default tenancy admin role",
            "default": true
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
        },
        {
            "name": "createAdminRole",
            "type": "Bool",
            "optional": true,
            "comment": "optional flag indicating whether to create a default tenancy admin role",
            "default": true
        },
        {
            "name": "skipPrincipalMember",
            "type": "Bool",
            "optional": true,
            "comment": "optional flag indicating to skip adding the caller principal into the resource role",
            "default": false
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
            "type": "ResourceName",
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
            "comment": "signature generated based on the domain active policies object"
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
            "name": "groups",
            "type": "Array",
            "optional": false,
            "comment": "list of groups in the domain",
            "items": "Group"
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
            "name": "protected",
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
            "name": "group",
            "type": "Int32",
            "optional": false,
            "comment": "number of groups per domain"
        },
        {
            "name": "groupMember",
            "type": "Int32",
            "optional": false,
            "comment": "number of members a group may have"
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

### UserAuthorityAttributes `<Struct>`

Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.


```
{
    "type": "Struct",
    "name": "UserAuthorityAttributes",
    "comment": "Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.",
    "fields": [
        {
            "name": "values",
            "type": "Array",
            "optional": false,
            "items": "String"
        }
    ],
    "closed": false
}
```

### UserAuthorityAttributeMap `<Struct>`

Map of user authority attributes


```
{
    "type": "Struct",
    "name": "UserAuthorityAttributeMap",
    "comment": "Map of user authority attributes",
    "fields": [
        {
            "name": "attributes",
            "type": "Map",
            "optional": false,
            "comment": "map of type to attribute values",
            "items": "UserAuthorityAttributes",
            "keys": "SimpleName"
        }
    ],
    "closed": false
}
```

### Stats `<Struct>`

The representation for a stats object


```
{
    "type": "Struct",
    "name": "Stats",
    "comment": "The representation for a stats object",
    "fields": [
        {
            "name": "name",
            "type": "DomainName",
            "optional": true,
            "comment": "name of the domain object, null for system stats"
        },
        {
            "name": "subdomain",
            "type": "Int32",
            "optional": false,
            "comment": "number of subdomains in this domain (all levels)"
        },
        {
            "name": "role",
            "type": "Int32",
            "optional": false,
            "comment": "number of roles"
        },
        {
            "name": "roleMember",
            "type": "Int32",
            "optional": false,
            "comment": "number of members in all the roles"
        },
        {
            "name": "policy",
            "type": "Int32",
            "optional": false,
            "comment": "number of policies"
        },
        {
            "name": "assertion",
            "type": "Int32",
            "optional": false,
            "comment": "total number of assertions in all policies"
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
            "comment": "number of services"
        },
        {
            "name": "serviceHost",
            "type": "Int32",
            "optional": false,
            "comment": "number of hosts defined in all services"
        },
        {
            "name": "publicKey",
            "type": "Int32",
            "optional": false,
            "comment": "number of public keys in all services"
        },
        {
            "name": "group",
            "type": "Int32",
            "optional": false,
            "comment": "number of groups"
        },
        {
            "name": "groupMember",
            "type": "Int32",
            "optional": false,
            "comment": "number of members in all the groups"
        }
    ],
    "closed": false
}
```

### DependentService `<Struct>`

Dependent service provider details


```
{
    "type": "Struct",
    "name": "DependentService",
    "comment": "Dependent service provider details",
    "fields": [
        {
            "name": "service",
            "type": "ServiceName",
            "optional": false,
            "comment": "name of the service"
        }
    ],
    "closed": false
}
```

### DependentServiceResourceGroup `<Struct>`

```
{
    "type": "Struct",
    "name": "DependentServiceResourceGroup",
    "fields": [
        {
            "name": "service",
            "type": "ServiceName",
            "optional": false,
            "comment": "name of the service"
        },
        {
            "name": "domain",
            "type": "DomainName",
            "optional": false,
            "comment": "name of the dependent domain"
        },
        {
            "name": "resourceGroups",
            "type": "Array",
            "optional": true,
            "comment": "registered resource groups for this service and domain",
            "items": "EntityName"
        }
    ],
    "closed": false
}
```

### DependentServiceResourceGroupList `<Struct>`

```
{
    "type": "Struct",
    "name": "DependentServiceResourceGroupList",
    "fields": [
        {
            "name": "serviceAndResourceGroups",
            "type": "Array",
            "optional": false,
            "comment": "collection of dependent services and resource groups for tenant domain",
            "items": "DependentServiceResourceGroup"
        }
    ],
    "closed": false
}
```

### Info `<Struct>`

Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. The representation for an info object


```
{
    "type": "Struct",
    "name": "Info",
    "comment": "Copyright The Athenz Authors Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms. The representation for an info object",
    "fields": [
        {
            "name": "buildJdkSpec",
            "type": "String",
            "optional": true,
            "comment": "jdk build version"
        },
        {
            "name": "implementationTitle",
            "type": "String",
            "optional": true,
            "comment": "implementation title - e.g. athenz-zms-server"
        },
        {
            "name": "implementationVersion",
            "type": "String",
            "optional": true,
            "comment": "implementation version - e.g. 1.11.1"
        },
        {
            "name": "implementationVendor",
            "type": "String",
            "optional": true,
            "comment": "implementation vendor - Athenz"
        }
    ],
    "closed": false
}
```

### rdl.Identifier `<String>`

All names need to be of this restricted string type


```
{
    "type": "String",
    "name": "rdl.Identifier",
    "comment": "All names need to be of this restricted string type",
    "pattern": "[a-zA-Z_]+[a-zA-Z_0-9]*"
}
```

### rdl.NamespacedIdentifier `<String>`

A Namespace is a dotted compound name, using reverse domain name order (i.e. "com.yahoo.auth")


```
{
    "type": "String",
    "name": "rdl.NamespacedIdentifier",
    "comment": "A Namespace is a dotted compound name, using reverse domain name order (i.e. \"com.yahoo.auth\")",
    "pattern": "([a-zA-Z_]+[a-zA-Z_0-9]*)(\\.[a-zA-Z_]+[a-zA-Z_0-9])*"
}
```

### rdl.BaseType `<Enum>`

```
{
    "type": "Enum",
    "name": "rdl.BaseType",
    "elements": [
        {
            "symbol": "Bool"
        },
        {
            "symbol": "Int8"
        },
        {
            "symbol": "Int16"
        },
        {
            "symbol": "Int32"
        },
        {
            "symbol": "Int64"
        },
        {
            "symbol": "Float32"
        },
        {
            "symbol": "Float64"
        },
        {
            "symbol": "Bytes"
        },
        {
            "symbol": "String"
        },
        {
            "symbol": "Timestamp"
        },
        {
            "symbol": "Symbol"
        },
        {
            "symbol": "UUID"
        },
        {
            "symbol": "Array"
        },
        {
            "symbol": "Map"
        },
        {
            "symbol": "Struct"
        },
        {
            "symbol": "Enum"
        },
        {
            "symbol": "Union"
        },
        {
            "symbol": "Any"
        }
    ]
}
```

### rdl.ExtendedAnnotation `<String>`

ExtendedAnnotation - parsed and preserved, but has no defined meaning in RDL. Such annotations must begin with "x_", and may have an associated string literal value (the value will be "" if the annotation is just a flag).


```
{
    "type": "String",
    "name": "rdl.ExtendedAnnotation",
    "comment": "ExtendedAnnotation - parsed and preserved, but has no defined meaning in RDL. Such annotations must begin with \"x_\", and may have an associated string literal value (the value will be \"\" if the annotation is just a flag).",
    "pattern": "x_[a-zA-Z_0-9]*"
}
```

### rdl.TypeDef `<Struct>`

TypeDef is the basic type definition.


```
{
    "type": "Struct",
    "name": "rdl.TypeDef",
    "comment": "TypeDef is the basic type definition.",
    "fields": [
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type this type is derived from. For base types, it is the same as the name"
        },
        {
            "name": "name",
            "type": "rdl.TypeName",
            "optional": false,
            "comment": "The name of the type"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The comment for the type"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.AliasTypeDef `<rdl.TypeDef>`

AliasTypeDef is used for type definitions that add no additional attributes, and thus just create an alias


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.AliasTypeDef",
    "comment": "AliasTypeDef is used for type definitions that add no additional attributes, and thus just create an alias",
    "fields": [],
    "closed": false
}
```

### rdl.BytesTypeDef `<rdl.TypeDef>`

Bytes allow the restriction by fixed size, or min/max size.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.BytesTypeDef",
    "comment": "Bytes allow the restriction by fixed size, or min/max size.",
    "fields": [
        {
            "name": "size",
            "type": "Int32",
            "optional": true,
            "comment": "Fixed size"
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "Min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "Max size"
        }
    ],
    "closed": false
}
```

### rdl.StringTypeDef `<rdl.TypeDef>`

Strings allow the restriction by regular expression pattern or by an explicit set of values. An optional maximum size may be asserted


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.StringTypeDef",
    "comment": "Strings allow the restriction by regular expression pattern or by an explicit set of values. An optional maximum size may be asserted",
    "fields": [
        {
            "name": "pattern",
            "type": "String",
            "optional": true,
            "comment": "A regular expression that must be matched. Mutually exclusive with values"
        },
        {
            "name": "values",
            "type": "Array",
            "optional": true,
            "comment": "A set of allowable values",
            "items": "String"
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "Min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "Max size"
        }
    ],
    "closed": false
}
```

### rdl.Number `<Union>`

A numeric is any of the primitive numeric types


```
{
    "type": "Union",
    "name": "rdl.Number",
    "comment": "A numeric is any of the primitive numeric types",
    "variants": [
        "Int8",
        "Int16",
        "Int32",
        "Int64",
        "Float32",
        "Float64"
    ]
}
```

### rdl.NumberTypeDef `<rdl.TypeDef>`

A number type definition allows the restriction of numeric values.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.NumberTypeDef",
    "comment": "A number type definition allows the restriction of numeric values.",
    "fields": [
        {
            "name": "min",
            "type": "rdl.Number",
            "optional": true,
            "comment": "Min value"
        },
        {
            "name": "max",
            "type": "rdl.Number",
            "optional": true,
            "comment": "Max value"
        }
    ],
    "closed": false
}
```

### rdl.ArrayTypeDef `<rdl.TypeDef>`

Array types can be restricted by item type and size


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.ArrayTypeDef",
    "comment": "Array types can be restricted by item type and size",
    "fields": [
        {
            "name": "items",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the items, default to any type"
        },
        {
            "name": "size",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the fixed size."
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the max size"
        }
    ],
    "closed": false
}
```

### rdl.MapTypeDef `<rdl.TypeDef>`

Map types can be restricted by key type, item type and size


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.MapTypeDef",
    "comment": "Map types can be restricted by key type, item type and size",
    "fields": [
        {
            "name": "keys",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the keys, default to String."
        },
        {
            "name": "items",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the items, default to Any type"
        },
        {
            "name": "size",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicates the fixed size."
        },
        {
            "name": "minSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the min size"
        },
        {
            "name": "maxSize",
            "type": "Int32",
            "optional": true,
            "comment": "If present, indicate the max size"
        }
    ],
    "closed": false
}
```

### rdl.StructFieldDef `<Struct>`

Each field in a struct_field_spec is defined by this type


```
{
    "type": "Struct",
    "name": "rdl.StructFieldDef",
    "comment": "Each field in a struct_field_spec is defined by this type",
    "fields": [
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "The name of the field"
        },
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the field"
        },
        {
            "name": "optional",
            "type": "Bool",
            "optional": false,
            "comment": "The field may be omitted even if specified",
            "default": false
        },
        {
            "name": "default",
            "type": "Any",
            "optional": true,
            "comment": "If field is absent, what default value should be assumed."
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The comment for the field"
        },
        {
            "name": "items",
            "type": "rdl.TypeRef",
            "optional": true,
            "comment": "For map or array fields, the type of the items"
        },
        {
            "name": "keys",
            "type": "rdl.TypeRef",
            "optional": true,
            "comment": "For map type fields, the type of the keys"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.StructTypeDef `<rdl.TypeDef>`

A struct can restrict specific named fields to specific types. By default, any field not specified is allowed, and can be of any type. Specifying closed means only those fields explicitly


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.StructTypeDef",
    "comment": "A struct can restrict specific named fields to specific types. By default, any field not specified is allowed, and can be of any type. Specifying closed means only those fields explicitly",
    "fields": [
        {
            "name": "fields",
            "type": "Array",
            "optional": false,
            "comment": "The fields in this struct. By default, open Structs can have any fields in addition to these",
            "items": "rdl.StructFieldDef"
        },
        {
            "name": "closed",
            "type": "Bool",
            "optional": false,
            "comment": "indicates that only the specified fields are acceptable. Default is open (any fields)",
            "default": false
        }
    ],
    "closed": false
}
```

### rdl.EnumElementDef `<Struct>`

EnumElementDef defines one of the elements of an Enum


```
{
    "type": "Struct",
    "name": "rdl.EnumElementDef",
    "comment": "EnumElementDef defines one of the elements of an Enum",
    "fields": [
        {
            "name": "symbol",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "The identifier representing the value"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "the comment for the element"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.EnumTypeDef `<rdl.TypeDef>`

Define an enumerated type. Each value of the type is represented by a symbolic identifier.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.EnumTypeDef",
    "comment": "Define an enumerated type. Each value of the type is represented by a symbolic identifier.",
    "fields": [
        {
            "name": "elements",
            "type": "Array",
            "optional": false,
            "comment": "The enumeration of the possible elements",
            "items": "rdl.EnumElementDef"
        }
    ],
    "closed": false
}
```

### rdl.UnionTypeDef `<rdl.TypeDef>`

Define a type as one of any other specified type.


```
{
    "type": "rdl.TypeDef",
    "name": "rdl.UnionTypeDef",
    "comment": "Define a type as one of any other specified type.",
    "fields": [
        {
            "name": "variants",
            "type": "Array",
            "optional": false,
            "comment": "The type names of constituent types. Union types get expanded, this is a flat list",
            "items": "rdl.TypeRef"
        }
    ],
    "closed": false
}
```

### rdl.Type `<Union>`

A Type can be specified by any of the above specialized Types, determined by the value of the the 'type' field


```
{
    "type": "Union",
    "name": "rdl.Type",
    "comment": "A Type can be specified by any of the above specialized Types, determined by the value of the the 'type' field",
    "variants": [
        "rdl.BaseType",
        "rdl.StructTypeDef",
        "rdl.MapTypeDef",
        "rdl.ArrayTypeDef",
        "rdl.EnumTypeDef",
        "rdl.UnionTypeDef",
        "rdl.StringTypeDef",
        "rdl.BytesTypeDef",
        "rdl.NumberTypeDef",
        "rdl.AliasTypeDef"
    ]
}
```

### rdl.ResourceInput `<Struct>`

ResourceOutput defines input characteristics of a Resource


```
{
    "type": "Struct",
    "name": "rdl.ResourceInput",
    "comment": "ResourceOutput defines input characteristics of a Resource",
    "fields": [
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "the formal name of the input"
        },
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the input"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The optional comment"
        },
        {
            "name": "pathParam",
            "type": "Bool",
            "optional": false,
            "comment": "true of this input is a path parameter",
            "default": false
        },
        {
            "name": "queryParam",
            "type": "String",
            "optional": true,
            "comment": "if present, the name of the query param name"
        },
        {
            "name": "header",
            "type": "String",
            "optional": true,
            "comment": "If present, the name of the header the input is associated with"
        },
        {
            "name": "pattern",
            "type": "String",
            "optional": true,
            "comment": "If present, the pattern associated with the pathParam (i.e. wildcard path matches)"
        },
        {
            "name": "default",
            "type": "Any",
            "optional": true,
            "comment": "If present, the default value for optional params"
        },
        {
            "name": "optional",
            "type": "Bool",
            "optional": false,
            "comment": "If present, indicates that the input is optional",
            "default": false
        },
        {
            "name": "flag",
            "type": "Bool",
            "optional": false,
            "comment": "If present, indicates the queryparam is of flag style (no value)",
            "default": false
        },
        {
            "name": "context",
            "type": "String",
            "optional": true,
            "comment": "If present, indicates the parameter comes form the implementation context"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.ResourceOutput `<Struct>`

ResourceOutput defines output characteristics of a Resource


```
{
    "type": "Struct",
    "name": "rdl.ResourceOutput",
    "comment": "ResourceOutput defines output characteristics of a Resource",
    "fields": [
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": false,
            "comment": "the formal name of the output"
        },
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the output"
        },
        {
            "name": "header",
            "type": "String",
            "optional": false,
            "comment": "the name of the header associated with this output"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The optional comment for the output"
        },
        {
            "name": "optional",
            "type": "Bool",
            "optional": false,
            "comment": "If present, indicates that the output is optional (the server decides)",
            "default": false
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```

### rdl.ResourceAuth `<Struct>`

ResourceAuth defines authentication and authorization attributes of a resource. Presence of action, resource, or domain implies authentication; the authentication flag alone is required only when no authorization is done.


```
{
    "type": "Struct",
    "name": "rdl.ResourceAuth",
    "comment": "ResourceAuth defines authentication and authorization attributes of a resource. Presence of action, resource, or domain implies authentication; the authentication flag alone is required only when no authorization is done.",
    "fields": [
        {
            "name": "authenticate",
            "type": "Bool",
            "optional": false,
            "comment": "if present and true, then the requester must be authenticated",
            "default": false
        },
        {
            "name": "action",
            "type": "String",
            "optional": true,
            "comment": "the action to authorize access to. This forces authentication"
        },
        {
            "name": "resource",
            "type": "String",
            "optional": true,
            "comment": "the resource identity to authorize access to"
        },
        {
            "name": "domain",
            "type": "String",
            "optional": true,
            "comment": "if present, the alternate domain to check access to. This is rare."
        }
    ],
    "closed": false
}
```

### rdl.ExceptionDef `<Struct>`

ExceptionDef describes the exception a symbolic response code maps to.


```
{
    "type": "Struct",
    "name": "rdl.ExceptionDef",
    "comment": "ExceptionDef describes the exception a symbolic response code maps to.",
    "fields": [
        {
            "name": "type",
            "type": "String",
            "optional": false,
            "comment": "The type of the exception"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "the optional comment for the exception"
        }
    ],
    "closed": false
}
```

### rdl.Resource `<Struct>`

A Resource of a REST service


```
{
    "type": "Struct",
    "name": "rdl.Resource",
    "comment": "A Resource of a REST service",
    "fields": [
        {
            "name": "type",
            "type": "rdl.TypeRef",
            "optional": false,
            "comment": "The type of the resource"
        },
        {
            "name": "method",
            "type": "String",
            "optional": false,
            "comment": "The method for the action (typically GET, POST, etc for HTTP access)"
        },
        {
            "name": "path",
            "type": "String",
            "optional": false,
            "comment": "The resource path template"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The optional comment"
        },
        {
            "name": "inputs",
            "type": "Array",
            "optional": true,
            "comment": "An Array named inputs",
            "items": "rdl.ResourceInput"
        },
        {
            "name": "outputs",
            "type": "Array",
            "optional": true,
            "comment": "An Array of named outputs",
            "items": "rdl.ResourceOutput"
        },
        {
            "name": "auth",
            "type": "rdl.ResourceAuth",
            "optional": true,
            "comment": "The optional authentication or authorization directive"
        },
        {
            "name": "expected",
            "type": "String",
            "optional": false,
            "comment": "The expected symbolic response code",
            "default": "OK"
        },
        {
            "name": "alternatives",
            "type": "Array",
            "optional": true,
            "comment": "The set of alternative but non-error response codes",
            "items": "String"
        },
        {
            "name": "exceptions",
            "type": "Map",
            "optional": true,
            "comment": "A map of symbolic response code to Exception definitions",
            "items": "rdl.ExceptionDef",
            "keys": "String"
        },
        {
            "name": "async",
            "type": "Bool",
            "optional": true,
            "comment": "A hint to server implementations that this resource would be better implemented with async I/O"
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        },
        {
            "name": "consumes",
            "type": "Array",
            "optional": true,
            "comment": "Optional hint for resource acceptable input types",
            "items": "String"
        },
        {
            "name": "produces",
            "type": "Array",
            "optional": true,
            "comment": "Optional hint for resource output content types",
            "items": "String"
        },
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": true,
            "comment": "The optional name of the resource"
        }
    ],
    "closed": false
}
```

### rdl.Schema `<Struct>`

A Schema is a container for types and resources. It is self-contained (no external references). and is the output of the RDL parser.


```
{
    "type": "Struct",
    "name": "rdl.Schema",
    "comment": "A Schema is a container for types and resources. It is self-contained (no external references). and is the output of the RDL parser.",
    "fields": [
        {
            "name": "namespace",
            "type": "rdl.NamespacedIdentifier",
            "optional": true,
            "comment": "The namespace for the schema"
        },
        {
            "name": "name",
            "type": "rdl.Identifier",
            "optional": true,
            "comment": "The name of the schema"
        },
        {
            "name": "version",
            "type": "Int32",
            "optional": true,
            "comment": "The version of the schema"
        },
        {
            "name": "comment",
            "type": "String",
            "optional": true,
            "comment": "The comment for the entire schema"
        },
        {
            "name": "types",
            "type": "Array",
            "optional": true,
            "comment": "The types this schema defines.",
            "items": "rdl.Type"
        },
        {
            "name": "resources",
            "type": "Array",
            "optional": true,
            "comment": "The resources for a service this schema defines",
            "items": "rdl.Resource"
        },
        {
            "name": "base",
            "type": "String",
            "optional": true,
            "comment": "the base path for resources in the schema."
        },
        {
            "name": "annotations",
            "type": "Map",
            "optional": true,
            "comment": "additional annotations starting with \"x_\"",
            "items": "String",
            "keys": "rdl.ExtendedAnnotation"
        }
    ],
    "closed": false
}
```


*generated on Wed Sep 27 2023 11:23:58 GMT-0700 (Pacific Daylight Time)*