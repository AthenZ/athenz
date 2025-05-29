Athenz can send email notifications for events such as a role member with access that about to expire.

Athenz supports Amazon Simple Email Service (Amazon SES) out of the box. This requires Athenz to be deployed on AWS.
Users may use other Email Providers by following the steps
to [Enable Notifications using other Providers](#enable-notifications-using-other-providers)

## Enable Email Notifications using Amazon Simple Email Service (Amazon SES)

Enable Email Notifications for ZMS server by editing the zms.properties file:

```
# Notification: Factory class using AWS SES implementation to send out email notifications
athenz.zms.notification_service_factory_class=io.athenz.server.aws.common.notification.impl.SESNotificationServiceFactory

# Notification: Email domain from
athenz.notification_email_domain_from=from.domain.com

# Notification: Email from
athenz.notification_email_from=sender.name

# Notification: Email domain to
athenz.notification_email_domain_to=to.domain.com

# Notification: Workflow url for approvers to click from within email body to take action on the notification
athenz.notification_workflow_url=https://your.athenz.ui/athenz/workflow

# Notification: Athenz UI Link included in Expiry Reminder Emails
athenz.notification_athenz_ui_url=https://your.athenz.ui/athenz
```

## Enable Notifications using other Providers

To use other providers, create a Jar file on the Athenz classpath with implementations for the following Interface:

```
com.yahoo.athenz.common.server.notification.NotificationServiceFactory
```

You may use the existing com.yahoo.athenz.common.server.notification.impl.EmailNotificationService and inject a new
provider or implement a completely new Notifications Provider that will notify users by means other than email.

If you do plan on sending email notifications, implement the following interface:

```
com.yahoo.athenz.common.server.notification.EmailProvider
```

For example, to enable Email Notifications with your provider, you may implement
com.yahoo.athenz.common.server.notification.NotificationServiceFactory like so:

```java
package your.packge;

import com.yahoo.athenz.common.server.notification.impl.EmailNotificationService;

public class YourNotificationServiceFactory implements NotificationServiceFactory {
    @Override
    public NotificationService create() {
        return new EmailNotificationService(new YourEmailProvider());
    }
}
```

Once the jar is ready, change the value of athenz.zms.notification_service_factory_class in the zms.properties file to
your factory class:

```
athenz.zms.notification_service_factory_class=your.packge.YourNotificationServiceFactory
```

We can also send notifications to more than one service by specifying all service factories.
For example, if we would like notifications to be sent via `your.packge.YourNotificationServiceFactory` and
`their.packge.TheirNotificationServiceFactory`, specify both values in the property using `,` as a delimiter:

```
athenz.zms.notification_service_factory_class=your.packge.YourNotificationServiceFactory,their.packge.TheirNotificationServiceFactory
```

## Notification Object Store Implementation for Role/Group Review Support

By default, Athenz generates and sends notifications for any configured notification service factory. The
expectation is that the domain administrator will review the notifications and take action on them. In the
Athenz UI, the domain administrator can click on the Notification icon in the top right corner to see all
the roles and groups that require their attention.

Athenz also provides support where specific set of users in a role that are not domain administrators are
authorized to manage role membership for another role and/or group. For example, the domain administrator can
configure a role called `pe-admin`, however, the domain administrator may not be the one who is responsible for
managing the membership of that role. In this case, the domain administrator can configure another role called
`pe-admin-manager` and set the appropriate policy to allow the users in that role to manage the membership of
`pe-admin` role. With the following setup, the users in `pe-admin-manager` role get notifications for any
users in the `pe-admin` role that are about to expire and can take action on them. However, in the Athenz UI,
when the click on the Notification icon, they will only see the notifications as if they're domain administrators.

To enable the capability to see what roles and groups require their attention without being domain administrators,
Athenz provides a Notification Object Store implementation that will store the notifications in a database.
When the user clicks on the Notification icon in the Athenz UI, the Athenz ZMS server will query the object
store to determine all the roles and groups that require the user's attention as a domain administrator, and then
it will query the notification object store to determine if the user also received notifications for any other
roles and groups.

If you would like to enable this feature, you need to implement the following interfaces:

```
com.yahoo.athenz.common.notification.NotificationObjectStore
com.yahoo.athenz.common.notification.NotificationObjectStoreFactory
```

The Athenz team provides a default implementation of the NotificationObjectStoreFactory that uses
Amazon DynamoDB as the object store. This is useful if your Athenz instance is deployed in AWS.
To enable this implementation, you need to set the following property in the zms.properties file:

```
athenz.zms.notification_object_store_factory_class=io.athenz.server.aws.common.notification.impl.DynamoDBNotificationObjectStoreFactory
```

You also need to create a DynamoDB table with the following name: `Athenz-Notification-Object-Store`.
The table must have a primary key called `principalName` of type `String` and a sort key called `objectArn`
of type `String`. The table must also have a Global Secondary Index (GSI) called `objectArn-Index` with the
partition key `objectArn` of type `String`.
