# Audit Template

## Overview

Athenz supports marking domains, roles and groups as `audit enabled`, which requires that
every membership change in those objects goes through an approval workflow. However, being
audit enabled by itself does not guarantee that the memberships are short-lived or regularly
reviewed - an administrator can still create an audit enabled role with no expiry at all.

The audit template feature allows a ZMS operator to define a set of maximum expiry and review
day settings that are automatically imposed on any domain, role or group that is audit enabled.
The template acts as a ceiling: administrators are free to configure stricter (smaller) values,
but the server silently reduces any value that exceeds the configured limit - or sets the limit
value when the setting is not specified at all.

Because these settings are a security control, the server treats the template as mandatory
configuration once it has been enabled: if the template file is configured but cannot be read,
parsed or validated, the ZMS server fails to start.

## Configuration

The feature is disabled by default and is enabled by pointing the following property at a
json template file:

```
athenz.zms.audit_template_fname=/opt/athenz/zms/conf/zms_server/audit_template.json
```

The template contains three sections - `domain`, `role` and `group` - and only the expiry and
review day fields are honored from each. Each object type supports the subset of fields that
exist on that object:

| Section | Supported settings |
| ------- | ------------------ |
| domain  | `memberExpiryDays`, `serviceExpiryDays`, `groupExpiryDays` |
| role    | `memberExpiryDays`, `serviceExpiryDays`, `groupExpiryDays`, `memberReviewDays`, `serviceReviewDays`, `groupReviewDays` |
| group   | `memberExpiryDays`, `serviceExpiryDays` |

A sample template is included as `servers/zms/conf/audit_template.json`:

```json
{
    "domain": {
        "memberExpiryDays": 90,
        "serviceExpiryDays": 90,
        "groupExpiryDays": 90
    },
    "role": {
        "memberExpiryDays": 90,
        "serviceExpiryDays": 90,
        "groupExpiryDays": 90,
        "memberReviewDays": 90,
        "serviceReviewDays": 90,
        "groupReviewDays": 90
    },
    "group": {
        "memberExpiryDays": 90,
        "serviceExpiryDays": 90
    }
}
```

A missing section, a missing field, or a field set to `0` all indicate that there is no limit
for that setting. Negative values are rejected during startup validation.

## Semantics

The core of the feature is the `applyLimit` operation, defined in
[AuditTemplate.java](../../servers/zms/src/main/java/com/yahoo/athenz/zms/config/AuditTemplate.java):

| Template limit | Object value | Result |
| -------------- | ------------ | ------ |
| not set or 0   | any          | value unchanged |
| N              | not set      | N |
| N              | 0 (no expiry)| N |
| N              | > N          | N |
| N              | <= N         | value unchanged |

For `*Meta` objects (`DomainMeta`, `RoleMeta`, `GroupMeta`) there is an additional subtlety: a
`null` field in a meta request means "do not change the current value" rather than "no expiry".
The `applyMetaLimit` operation therefore evaluates the limit against the *effective* value - the
meta value if one was supplied, otherwise the object's current value - and only writes a value
into the meta object if the limit actually needs to be imposed. This ensures that a meta update
that touches an unrelated attribute does not accidentally clear or rewrite settings that are
already compliant, while still correcting settings that are not.

The template is only applied when the object is (or is being made) audit enabled. Turning the
audit enabled flag off does not restore any previously relaxed values.

## Enforcement Points

The template is evaluated at every point where an object can become audit enabled or where an
audit enabled object's settings can be modified:

**[ZMSImpl.java](../../servers/zms/src/main/java/com/yahoo/athenz/zms/ZMSImpl.java)**

- `postTopLevelDomain`, `postSubDomain` and `postUserDomain` - via
  `applyAuditTemplateDomainSettings`, applied to domains created with the audit enabled flag set.
  Sub-domains inherit the audit enabled flag from their parent, so a sub-domain of an audit
  enabled domain also picks up the template settings at creation time.
- `putDomainMeta` - applied when the existing domain is audit enabled.
- `putRole` - applied when the submitted role is audit enabled.
- `putRoleMeta` - applied when the role is, or is being set as, audit enabled. Note that
  `validateRoleMetaAuditEnabledFlag` copies the role's current flag into the meta object when the
  request does not specify one, so already audit enabled roles are covered as well.
- `putGroup` and `putGroupMeta` - the group equivalents of the above.

**[DBService.java](../../servers/zms/src/main/java/com/yahoo/athenz/zms/DBService.java)**

The system meta handlers are the path used by system administrators to flip the audit enabled
flag on an existing object. In each case the template is applied at the moment the flag is
turned on:

- `updateSystemMetaFields` for `auditenabled` on a domain - `applyDomainSettings`.
- `updateRoleSystemMetaFields` - `applyRoleSettings`.
- `updateGroupSystemMetaFields` - `applyGroupSettings`.

Since setting the audit enabled flag on a role or group can reduce the configured expiry and
review days, `executePutRoleSystemMeta` and `executePutGroupSystemMeta` now also invoke
`updateRoleMembersDueDates` / `updateGroupMembersDueDates` so that the existing members of the
object have their expiration and review dates brought in line with the newly imposed settings,
rather than only applying to members added afterwards.

## Startup Behavior

`ZMSImpl.loadAuditTemplate` runs during server initialization, before the object store is
created, and the parsed template is stored in `ZMSConfig` so that `DBService` can access it:

1. If `athenz.zms.audit_template_fname` is not set, the feature is disabled and no requirements
   are imposed.
2. If the file cannot be read or does not parse into an `AuditTemplate`, the server logs the
   error and throws `IllegalArgumentException("Invalid audit template file")`, failing startup.
3. `AuditTemplate.validate()` rejects any negative expiry or review day value with an
   `IllegalArgumentException` naming the offending field.

The template is read once at startup; unlike solution templates there is no dynamic reload, so
changing the template requires a server restart.

## Operational Notes

- Because the server silently lowers non-compliant values rather than rejecting the request,
  clients should re-read the object after an update if they need to know the effective settings.
- Introducing or lowering a template limit affects existing audit enabled objects only when they
  are next modified (or re-flagged as audit enabled); there is no background job that sweeps
  existing objects.
- Domain-level settings continue to be combined with role and group settings by the existing
  `MemberDueDays` logic - the audit template simply constrains the values that can be stored on
  each object.
