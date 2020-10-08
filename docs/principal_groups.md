To simplify management of principals in roles, the users and services can be included
in Groups. Then, the Group can be added as a principal to any role
within Athenz thus granting the members of that group access to the configured
resources.

For example, if you need to add your development team members to
multiple roles in your domain, you can create a group called `dev-team`, add
those users into that group and then include the group as a member in the
corresponding roles. When you need to remove or add a member, then you only
need to modify the membership of your `dev-team` group. The groups cannot
contain other groups.

## Resource URI

The groups are identified in Athenz with the following resource uri:

```
<domain>:group.<group-name>
```

## Group Management

The group name can only include alpha numeric characters including - and _. Currently,
groups can only be provisioned with `zms-cli` command line utility:

```
zms-cli -d <domain-name> add-group <group-name> <member> [<member> ...]
```
    
Once provisioned, they can be added to any role as a regular member. For example,
if I need to create a group called `dev-team` in my `sports` domain and add it to
my `readers` role in `fantasy` domain, I would execute the following zms-cli commands:

```
zms-cli -d sports add-group dev-team user.hga user.pgote
zms-cli -d fantasy add-member readers sports:group.dev-team
```

Similar to roles api, groups can be managed by adding and removing members:

```
zms-cli -d <domain-name> add-group-member <group-name> <member> [<member> ...]
zms-cli -d <domain-name> delete-group-member <group-name> <member> [<member> ...]
```

To enforce the least privilege access principle, there are several restrictions placed on groups:

- You cannot use wildcards `*` when adding members to a group.
- The ZMS Server will verify that all users and services are valid before
  they can be added to a group.
- Groups are not allowed to be added to admin groups. We strongly recommend limiting
  the number of users who are identified as domain administrators.
- Groups cannot include other groups (no inheritance). However, a role can include
  multiple groups as a member, and those groups could be from different domains.
- Groups cannot be references in policies. They can only be added as members of a role.
- Groups cannot be deleted if they're referenced in other roles. The domain
  administrator must first remove the group as a member (the role might be in a different
  domain) before deleting it.
- Groups do not support temporary members. If you need to give temporary access to
  a specific principal, that principal with expiration must be added to the role directly.
  
## Governance / Audit Support

Similar to roles, groups support multiple features to satisfy auditing and governance requirements:

### Audit Enabled Mode

If the domain is marked as audit enabled, then specific groups within that domain can
also be set in audit enabled mode thus requiring an explicit approval process for any
member addition to that group.

```
zms-cli -d <domain-name> set-group-audit-enabled <group-name> true
```

Unlike a regular group, when any one of the domain administrators adds a user
in an audit enabled group, it will be added in pending/inactive state until it is
approved by one of the organization approvers configured for the domain.

### Review Enabled Mode

The domain administrator can also mark a group as review enabled thus requiring two
domain administrator approvals before a principal is added to a group.

```
zms-cli -d <domain-name> set-group-review-enabled <group-name> true
```

### Self Service Mode

The users can only add themselves to any self-served groups. Their access is not active
until one of the domain administrators approves the request.

```
zms-cli -d <domain-name> set-group-self-serve <group-name> true
```
