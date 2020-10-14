Athenz can send email notifications for events such as a role member with access that about to expire.

Athenz supports Amazon Simple Email Service (Amazon SES) out of the box. This requires Athenz to be deployed on AWS.
Users may use other Email Providers by following the steps to [Enable Notifications using other Providers](#enable-notifications-using-other-providers)

## Enable Email Notifications using Amazon Simple Email Service (Amazon SES)

Enable Email Notifications for ZMS server by editing the zms.properties file:

```
# Notification: Factory class using AWS SES implementation to send out email notifications
athenz.zms.notification_service_factory_class=com.yahoo.athenz.common.server.notification.impl.NotificationServiceFactoryImpl

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
com.yahoo.athenz.common.server.notification.NotificationServiceFactory - A factory that creates a Notification Service based on a Notifications Provider.
```

You may use the existing com.yahoo.athenz.common.server.notification.impl.EmailNotificationService and inject a new provider or implement a compleley new Notifications Provider that will notify users by means other than email.

If you do plan on sending email notifications, implement the following interface:

```
com.yahoo.athenz.common.server.notification.EmailProvider
```

For example, to enable Email Notifications with your provider, you may implement com.yahoo.athenz.common.server.notification.NotificationServiceFactory like so:

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
Once the jar is ready, change the value of athenz.zms.notification_service_factory_class in the zms.properties file to your factory class:
```
athenz.zms.notification_service_factory_class=your.packge.YourNotificationServiceFactory
```

We can also send notifications to more than one service by specifying all service factories.
For example, if we would like notifications to be sent via `your.packge.YourNotificationServiceFactory` and
`their.packge.TheirNotificationServiceFactory`, specify both values in the property using `,` as a delimiter:
```
athenz.zms.notification_service_factory_class=your.packge.YourNotificationServiceFactory, their.packge.TheirNotificationServiceFactory
```
