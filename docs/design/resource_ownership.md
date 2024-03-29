# Resource Ownership in Athenz

The following are the use cases that we’re trying to solve with the introduction of resource ownership in Athenz:

- The domain administrator is using TF to manage domain data (could be using a personal account or some service identity).
  - The administrator wants to block access to those resources to be modified using Athenz UI and/or zms-cli since that will
create a drift in TF state.
  - The administrator should have the capability to override the ownership and make changes in case of emergency
situations (e.g. TF deleted a service identity from a role but it needs to be re-added asap).
    - This capability must be available using zms-cli and preferably from Athenz UI as well.
    - In Athenz UI I should be prompted that the user should not proceed with the move unless explicitly specified.
- The roles/policies are created and managed by another service built on-top of Athenz.
  - The operator wants those resources not to be visible in Athenz UI based on the ownership state and only make them
available in their respective solution UIs.
- Resource ownership should support partial ownership. For example, with roles and groups, TF can manage either members or
meta so the server must support and enforce ownership at that level and not just at the object level.
  - This indicates that there might be multiple owners of the same resources

Questionable ones:

- List resources (roles/groups/services/policies) in a domain by the specified ownership field - is there a use case for
this?
  - UI should be able to retrieve all objects, look at the resource owner field and make a decision to display or not

## Design

### RDL Struct Updates

```rdl
type ResourceDomainOwnership Struct {
    SimpleName metaOwner (optional); //owner of the object's meta attribute
    SimpleName objectOwner (optional); //owner of the object itself - checked for object deletion
}

type ResourceRoleOwnership Struct {
    SimpleName metaOwner (optional); //owner of the object's meta attribute
    SimpleName membersOwner (optional); //owner of the object's members attribute
    SimpleName objectOwner (optional); //owner of the object itself - checked for object deletion
}

type ResourceGroupOwnership Struct {
    SimpleName metaOwner (optional); //owner of the object's meta attribute
    SimpleName membersOwner (optional); //owner of the object's members attribute
    SimpleName objectOwner (optional); //owner of the object itself - checked for object deletion
}

type ResourceServiceIdentityOwnership Struct {
    SimpleName publicKeysOwner (optional); //owner of the object's public keys attribute
    SimpleName hostsOwner (optional); //owner of the object's hosts attribute
    SimpleName objectOwner (optional); //owner of the object itself - checked for object deletion
}

type ResourcePolicyOwnership Struct {
    SimpleName assertionsOwner (optional); //owner of the object's assertions attribute
    SimpleName objectOwner (optional); //owner of the object itself - checked for object deletion
}

type DomainMeta Struct {
    String description (optional); //a description of the domain
    …
    String environment (optional, x_allowempty="true"); //domain environment e.g. production, staging, etc
    ResourceDomainOwnership resourceOwnership (optional); // read-only attribute containing list of resource owners
}

type RoleMeta Struct {
    Bool selfServe (optional, default=false); //Flag indicates whether or not role allows self service. Users can add themselves in the role, but it has to be approved by domain admins to be effective.
    …
    Int32 maxMembers (optional); //Maximum number of members allowed in the group
    ResourceRoleOwnership resourceOwnership (optional); // read-only attribute containing list of resource owners
}

type GroupMeta Struct {
    Bool selfServe (optional, default=false); //Flag indicates whether or not a group allows self service. Users can add themselves in the group, but it has to be approved by domain admins to be effective.
    …
    Int32 maxMembers (optional); //Maximum number of members allowed in the group
    ResourceGroupOwnership resourceOwnership (optional); // read-only attribute containing list of resource owners
}

type Policy Struct {
    ResourceName name; //name of the policy
    …
    Map<TagKey,TagValueList> tags (optional); //key-value pair tags, tag might contain multiple values
    ResourcePolicyOwnership resourceOwnership (optional); // read-only attribute containing list of resource owners
}

type ServiceIdentity Struct {
    ServiceName name; //the full name of the service, i.e. "sports.storage"
    ….
    Map<TagKey,TagValueList> tags (optional); //key-value pair tags, tag might contain multiple values
    ResourceServiceOwnership resourceOwnership (optional); // read-only attribute containing list of resource owners.
}
```

### API Changes

The ownership is passed using `Athenz-Resource-Owner` header value. The owner has the syntax of `SimpleName`
as defined in the ZMS RDL and must less than 32 characters. For example, all the PUT apis for the objects listed
above will be updated accordingly.

```rdl
resource Membership PUT "/domain/{domainName}/role/{roleName}/member/{memberName}" {
    DomainName domainName; //name of the domain
    EntityName roleName; //name of the role
    MemberName memberName; //name of the user to be added as a member
    String auditRef (header="Y-Audit-Ref"); //Audit param required(not empty) if domain auditEnabled is true.
    Bool returnObj (optional, default=false, header="Athenz-Return-Object"); //Return object param updated object back.
    String resourceOwner (header="Athenz-Resource-Owner"); //Resource owner for the object type or component
    Membership membership; //Membership object (must contain role/member names as specified in the URI)
    authenticate;
    expected NO_CONTENT, OK;
    exceptions {
        ResourceError NOT_FOUND;
        ResourceError BAD_REQUEST;
        ResourceError FORBIDDEN;
        ResourceError UNAUTHORIZED;
        ResourceError CONFLICT;
        ResourceError TOO_MANY_REQUESTS;
    }
}
```

### Resource Ownership

There is a corresponding API for each of the object types: domain, role, group, service and policy.
Here is the example for roles:

```rdl
// Set the resource ownership for the given role
resource ResourceRoleOwnership PUT "/domain/{domainName}/role/{roleName}/ownership" {
    DomainName domainName; //name of the domain
    EntityName roleName; //name of the role
    ResourceRoleOwnership resourceOwnership; //resource ownership to be set for the given role
    authorize ("update", "{domainName}:meta.role.ownership.{roleName}");
    expected NO_CONTENT;
    exceptions {
        ResourceError BAD_REQUEST;
        ResourceError NOT_FOUND;
        ResourceError FORBIDDEN;
        ResourceError UNAUTHORIZED;
        ResourceError TOO_MANY_REQUESTS;
    }
}
```

### Resource Ownership Set

Resource Ownership can be set in two ways:

- Using the putResourceOwnership API. Using this api, the domain administrator can set or update any of the existing
  resource owners set for a given object
- Set by the server when the appropriate api is called with the `Athenz-Resource-Owner` header set and
  there is no current owner set
  - For example, the caller issues putMembership call against `sports:role.readers` role and includes the
    header `Athenz-Resource-Owner: TF`. The server will process the request if the role readers does not
    have the resource ownership set for members field, it will update the resource ownership and set
    the membersOwner to TF.

### Resource Ownership Verification

When processing an API for an object that may have a resource ownership set, the server will extract the object first
and see if the given resource ownership field is set.
- If the resource ownership is not set the request is processed
- If the resource ownership is set and the request does not include the `Athenz-Resource-Owner` header then the
  request is rejected.
- If the resource ownership is set and the request includes the `Athenz-Resource-Owner` header then the
  request is processed if the values match otherwise it is rejected.
When the request is rejected due to resource ownership verification failure, the server will respond with `HTTP 409
Conflict` status code.

#### Resource Ownership Verification Override

As mentioned above, there might be cases where the resource ownership should be ignored and the change should be applied
to the domain.

If the request includes the `Athenz-Resource-Owner: ignore` header, then the request is processed regardless or not the
resource ownership is set. So the `ignore` is treated as a special value indicating to the server to skip any resource
ownership checks.

### UI Changes

The Athenz UI will need to be updated to provide the following functionality:

- Provide a configuration option by default to exclude objects with the given ownership from the list views.
  For example,  if I enable ownerObject: TF to be excluded from the list, then the UI will retrieve all the
  objects, but by default do not display any objects that have the resourceOwnership set with the
  ownerObject set to TF. However, it must provide the capability to display all entries if requested.
- Handling of entries that have resource ownership set. A couple of options present:
  - Handle errors after request rejection
    - If the UI tries to update an object and ZMS rejects the request with ownership error (HTTP 409 status code),
      the UI should clearly notify the user that the request was rejected due to ownership error and provide
      the option to override the ownership.
    - If the ownership override option was selected, the request must be submitted to ZMS with the
      `Athenz-Resource-Owner: ignore` header.
- Check resource ownership in advance
  - The UI can look at the current resourceOwnership attribute of the entry and let the user know in advance
    that they’re modifying an entry that they shouldn’t modify.
  - If the user still wants to modify the entry and override the current ownership, the request must be
    submitted to ZMS with the `Athenz-Resource-Owner: ignore` header.
