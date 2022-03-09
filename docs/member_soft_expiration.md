When adding principals to a role, the domain administrator can specify
an optional reminder date (aka soft expiry) to review the principal. Athenz also provides the capability to automatically
assign a reminder review date for any principal for a configured role.

There are separate limits for user and service principals. The administrator may decide to configure
a limit only for user members but not for service principals.

Athenz can send email notifications to all principals and the domain administrators
when the review date is approaching. See the [Email Notifications](email_notifications.md) section to enable notifications.

## Role Level Review Reminder Support

The domain administrator may specify a maximum review day setting for a specific role:

```
zms-cli -d <domain-name> set-role-member-review-days <role-name> <user-member-review-days>
zms-cli -d <domain-name> set-role-service-review-days <role-name> <service-member-review-days>
```

If the domain administrator has specified a user max review days of 30 to `db_reader_access` role,
then all user members will automatically have a review value of 30 days from the
current time. If the domain administrator has specified a value longer than 30 days or
no review date, then it will be reduced to 30 days from the current time. However, if the
domain administrator specified a review date of fewer than 30 days (e.g. 7 days), then
it will be honored and not extended to 30 days.

If the domain administrator specifies a shorter limit on an already configured role, for example
reducing from 30 to 15 days, then the server will iterate through all members and reduce
the review to 15 days from the current time based on the configured limit (either user or service
principals depending on the setting being changed). Again, if the current review date
is already less than 15 days, the review value will not be changed. However, if the
domain administrator extends the configuration setting from 30 to 60 days, then no changes
will be made to existing users - they will not be automatically extended. All new members
will be enforced with a 60 day review period, but old members will continue to have their
original 30-day review values until those values are extended.

You can look at the currently configured value for a specific role using
`zms-cli -d <domain-name> show-role <role-name>` command.

## Email Notifications

Athenz automatically monitors all role members and notifies both principals and domain
administrators when role membership review is approaching and can send email notifications.

There are 2 types of email notifications you might get. The email notifications are
sent when the review is `1, 7, 14, 21, and 28` days away.

### Role Member Review

The principal (if human) or the principal's domain administrators (if service) will get
a notification when the principal's role membership review date is approaching. The email
notification will include the domain and role name that the principal is a member of.
The principal must contact the administrators of that role/domain to request their
access to be extended.

### Domain Administrator Notification

The domain administrators will receive a single email notification listing all the members
with approaching review dates in their domain. It is their responsibility to access their
domain in Athenz UI and extend those member's review, if necessary.

### Role Members with Overdue Review

The domain administrator or the paranoids team may review the list of members with overdue review dates:

```
zms-cli overdue-review <domain-name>
```

### Managing Soft Expiry Reminder Recipients

By default, both the role members and the domain administrators will receive notifications as described above.
You can change this behavior by adding a tag to the role:

```
zms-cli -d <domain-name> add-role-tag <role-name> zms.DisableReminderNotifications <one of the following: 0 - non-disabled, 1 - User disabled, 2 - Admin disabled, 3 - both admin and user disabled
```

For example, to prevent administrators from receiving notifications for the "write" role in the domain "sports", run the following:

```
zms-cli -d sports add-role-tag write zms.DisableReminderNotifications 2
```