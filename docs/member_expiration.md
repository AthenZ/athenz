When adding principals to a role, the domain administrator can specify
an optional expiry date for the principal. Athenz also provides the capability to automatically
assign an expiry date for any principal for a configured role or all roles if the expiry
day is configured at the domain level.

There are separate limits for user and service principals. The administrator may decide to configure
a limit only for user members but not for service principals to avoid any possible
service outages when they fail to review and extend service principals' memberships.

Athenz can send email notifications to all principals and the domain administrators
when access is about to expire. See the [Email Notifications](email_notifications.md) section to enable notifications.

## Role Level Expiry Support

The domain administrator may specify a maximum expiry day setting for a specific role:

```
zms-cli -d <domain-name> set-role-member-expiry-days <role-name> <user-member-expiry-days>
zms-cli -d <domain-name> set-role-service-expiry-days <role-name> <service-member-expiry-days>
```

If the domain administrator has specified a user max expiry days of 30 to `db_reader_access` role,
then all user members will automatically have an expiration value of 30 days from the
current time. If the domain administrator has specified a value longer than 30 days or
no expiry, then it will be reduced to 30 days from the current time. However, if the
domain administrator specified expiration of fewer than 30 days (e.g. 7 days), then
it will be honored and not extended to 30 days.

If the domain administrator specifies a shorter limit on an already configured role, for example
reducing from 30 to 15 days, then the server will iterate through all members and reduce
the expiration to 15 days from the current time based on the configured limit (either user or service
principals depending on the setting being changed). Again, if the current expiry
is already less than 15 days, the expiration value will not be changed. However, if the
domain administrator extends the configuration setting from 30 to 60 days, then no changes
will be made to existing users - they will not be automatically extended. All new members
will be enforced with a 60 day expiry period, but old members will continue to have their
original 30-day expiration values until those values are extended.

If the domain administrator specifies an expiration at both role and domain levels, then
the role level always overrides the domain setting for the role - regardless if it's shorter
or longer than the domain configured value.

You can look at the currently configured value for a specific role using
`zms-cli -d <domain-name> show-role <role-name>` command.

## Domain Level Expiry Support

The domain administrator may specify maximum expiry day setting for the full domain:

```
zms-cli -d <domain-name> set-domain-member-expiry-days <user-member-expiry-days>
zms-cli -d <domain-name> set-domain-service-expiry-days <service-member-expiry-days>
```

If the domain administrator has specified a max expiry days of 90 to `sports` domain,
then all members in all roles in that domain will automatically have an expiration value
of 30 days from the current time. Check the section above to understand how the server
automatically assigns an expiration date to all role members.

You can look at the currently configured value for a specific domain using
`zms-cli -d <domain-name> show-domain` command.

** Important **

When setting an expiry days at a domain level, the limit is also imposed on all domain
administrators in the `admin` role. Thus, the domain administrator must be careful to
extend their expiry days before they lose access to the domain.

## Email Notifications

Athenz automatically monitors all role members and notifies both principals and domain
administrators when access to a role is about to expire and can send email notifications.

There are 2 types of email notifications you might get. The email notifications are
sent when the expiry is `1, 7, 14, 21, and 28` days away.

### Role Member Expiration

The principal (if human) or the principal's domain administrators (if service) will get
a notification when the principal's access in a role is about to expiry. The email
notification will include the domain and role name that the principal is a member of.
The principal must contact the administrators of that role/domain to request their
access to be extended.

### Domain Administrator Notification

The domain administrators will receive a single email notification listing all the members
that are about to expire in their domain. It is their responsibility to access their
domain in Athenz UI and extend those member's expiration, if necessary.

### Managing Role Member Expiry Reminder Recipients

By default, both the role members and the domain administrators will receive notifications as described above.
You can change this behavior by adding a tag to the role:

```
zms-cli -d <domain-name> add-role-tag <role-name> zms.DisableExpirationNotifications <one of the following: 0 - non-disabled, 1 - User disabled, 2 - Admin disabled, 3 - both admin and user disabled
```

For example, to prevent administrators from receiving notifications for the "write" role in the domain "sports", run the following:

```
zms-cli -d sports add-role-tag write zms.DisableExpirationNotifications 2
```