# User Identity Certificate and Token Timeout Configuration

Athenz ZTS server supports configurable timeout values for user identity
X.509 certificates and ID tokens. Administrators can control these timeouts
at two levels: server-wide defaults via system properties, and per-user
granularity via role tags in the user domain. This allows organizations to
enforce shorter certificate and token lifetimes for general users while
granting longer lifetimes to specific groups of users based on their role
membership.

## How It Works

The `UserIdentityTimeout` component in ZTS manages timeout resolution for
user certificate and token requests. When a user requests an identity
certificate or an OIDC ID token, ZTS determines the effective timeout by:

1. Looking up all roles the user belongs to in the user domain (e.g. `user`).
2. Checking each role for a timeout tag (`zts.UserCertTimeout` for certificates,
   `zts.UserTokenTimeout` for tokens).
3. Selecting the **maximum** timeout value across all matching roles.
4. If no roles have the tag configured, falling back to the server default.
5. If the user requested a **smaller** timeout, honoring that request.
6. Capping the final value at the server-configured maximum.

## Server-Level Configuration (System Properties)

These properties are set in `zts.properties` and control the global defaults
and limits.

### Certificate Timeout Properties

| Property | Unit | Default | Description |
|---|---|---|---|
| `athenz.zts.user_cert_default_timeout` | minutes | 60 (1 hour) | Default expiry for user certificates when no role tag is configured |
| `athenz.zts.user_cert_max_timeout` | minutes | 60 (1 hour) | Absolute maximum expiry for user certificates; no role tag or user request can exceed this |

Example configuration in `zts.properties`:

```
athenz.zts.user_cert_default_timeout=60
athenz.zts.user_cert_max_timeout=120
```

This sets the default certificate lifetime to 1 hour and allows role tags to
extend it up to 2 hours.

### Token Timeout Properties

| Property | Unit | Default | Description |
|---|---|---|---|
| `athenz.zts.id_token_default_timeout` | seconds | 3600 (1 hour) | Default expiry for user ID tokens when no role tag is configured |
| `athenz.zts.id_token_max_timeout` | seconds | 43200 (12 hours) | Absolute maximum expiry for user ID tokens; no role tag or user request can exceed this |

Example configuration in `zts.properties`:

```
athenz.zts.id_token_default_timeout=3600
athenz.zts.id_token_max_timeout=43200
```

### Refresh Interval

| Property | Unit | Default | Description |
|---|---|---|---|
| `athenz.zts.user_identity_timeout_refresh_interval` | minutes | 10 | How often ZTS checks the user domain for role tag changes and updates its internal timeout maps |

The timeout maps are refreshed only when the user domain's modification
timestamp has changed, so this polling interval is lightweight.

### Validation Rules

The server validates the configured values at startup:

- If `user_cert_default_timeout` or `user_cert_max_timeout` is zero or
  negative, the server logs an error and resets to the default (60 minutes).
- If `user_cert_max_timeout` is less than `user_cert_default_timeout`, the
  server sets max equal to default.
- The same validation rules apply to the token timeout properties.

## Role-Based Configuration Using Tags

Administrators can assign different timeout values to groups of users by
adding tags to roles in the **user domain**. Users who are members of tagged
roles receive the timeout value specified by the tag.

### Tag Names

| Tag Name | Unit | Applies To |
|---|---|---|
| `zts.UserCertTimeout` | minutes | User identity X.509 certificates |
| `zts.UserTokenTimeout` | seconds | User OIDC ID tokens |

### Setting Tags via zms-cli

To set a certificate timeout on a role in the user domain:

```
zms-cli -d user set-role-tag <role-name> zts.UserCertTimeout <timeout-in-minutes>
```

To set a token timeout on a role in the user domain:

```
zms-cli -d user set-role-tag <role-name> zts.UserTokenTimeout <timeout-in-seconds>
```

### Example: Granting Extended Certificate Lifetime

Suppose you want engineers in the `user:role.engineers` role to receive
certificates valid for 90 minutes instead of the default 60 minutes.
First ensure the server max allows it:

```
# In zts.properties
athenz.zts.user_cert_max_timeout=120
```

Then tag the role:

```
zms-cli -d user set-role-tag engineers zts.UserCertTimeout 90
```

Any user who is a member of `user:role.engineers` will now receive
certificates with a 90-minute lifetime (assuming they don't request a
shorter one and the server max is at least 90).

### Example: Granting Extended Token Lifetime

To allow users in the `user:role.oncall` role to request ID tokens valid
for up to 6 hours (21600 seconds):

```
zms-cli -d user set-role-tag oncall zts.UserTokenTimeout 21600
```

### Removing a Tag

To remove a timeout tag from a role, delete the tag:

```
zms-cli -d user delete-role-tag <role-name> zts.UserCertTimeout
zms-cli -d user delete-role-tag <role-name> zts.UserTokenTimeout
```

Once the tag is removed and the timeout map is refreshed, users in that role
will fall back to the server default timeout.

## Timeout Resolution Algorithm

The following describes the exact resolution logic for both certificate
and token timeouts.

### Step 1: Determine the Role-Based Timeout

ZTS looks up the user's accessible roles in the user domain and finds the
**maximum** timeout value from all roles that have the relevant tag
(`zts.UserCertTimeout` or `zts.UserTokenTimeout`).

- If a user belongs to `user:role.engineers` (tagged with 90 minutes) and
  `user:role.admins` (tagged with 120 minutes), the role-based timeout is
  **120 minutes**.
- If a user belongs to no tagged roles, the role-based timeout is the
  **server default** (`user_cert_default_timeout` or
  `id_token_default_timeout`).

### Step 2: Honor User-Requested Timeout

If the user's request includes a timeout value that is **smaller** than the
role-based timeout determined in Step 1, the requested value is used instead.
A user can always request a shorter lifetime but never a longer one via the
API request.

### Step 3: Cap at Server Maximum

The final timeout is capped at the server-configured maximum
(`user_cert_max_timeout` or `id_token_max_timeout`). Even if a role tag
specifies a value larger than the server max, the server max prevails.

### Summary Formula

```
effective_timeout = min(
    max(role_tag_timeouts...) or server_default,
    user_requested_timeout or infinity,
    server_max_timeout
)
```

### Example Walkthrough

Given the following configuration:

- `athenz.zts.user_cert_default_timeout=60` (minutes)
- `athenz.zts.user_cert_max_timeout=120` (minutes)
- `user:role.engineers` tagged with `zts.UserCertTimeout=90`
- `user:role.admins` tagged with `zts.UserCertTimeout=150`

| User's Roles | User Requested | Effective Timeout | Reason |
|---|---|---|---|
| engineers | (none) | 90 min | Role tag value used |
| admins | (none) | 120 min | Role tag (150) capped at server max (120) |
| engineers, admins | (none) | 120 min | Max of role tags (150) capped at server max (120) |
| engineers | 30 min | 30 min | User requested smaller than role tag |
| (no tagged roles) | (none) | 60 min | Falls back to server default |
| (no tagged roles) | 45 min | 45 min | User requested smaller than server default |
| (no tagged roles) | 200 min | 60 min | Server default (60) is less than server max (120) |

## Integration Points

### User Certificate Requests

When a user requests an identity X.509 certificate via the ZTS
`postUserCertificateRequest` API, ZTS calls
`UserIdentityTimeout.getUserCertTimeout()` to determine the certificate
expiry in minutes. The computed value is passed to the certificate signer.

### OIDC ID Token Requests

When a user principal requests an OIDC ID token, ZTS calls
`UserIdentityTimeout.getUserTokenTimeout()` to determine the token expiry
in seconds. This applies only when the requesting principal belongs to the
user domain; service principals use the standard `id_token_max_timeout`
limit.

## Periodic Refresh

The `UserIdentityTimeout` component runs a background thread that
periodically checks the user domain for modifications (default: every 10
minutes, configurable via `athenz.zts.user_identity_timeout_refresh_interval`).
When the domain's modification timestamp changes, the component re-scans all
roles in the user domain and rebuilds its internal timeout maps. This means
tag changes take effect within the configured refresh interval without
requiring a server restart.
