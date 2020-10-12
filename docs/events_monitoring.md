Athenz can be monitored by capturing events using an Event monitoring service. 

## Athenz Events
The following events can be sent by Athenz

- API HTTP Requests - Name of API method, status and duration 
- Certificate Requests
- Email Reminders and Notifications

## Enable ZMS Event Monitoring in Prometheus
Enable ZMS Event Monitoring in Prometheus for ZMS server by performing the following steps:

1. Build the `athenz_metrics_prometheus` Java project located in `contributions/metric/prometheus`
2. Place it in the ZMS Server classpath
3. Edit the zms.properties file:

```
# Specifies the factory class that implements the Metrics interface
# used by the ZMS Server to report stats
athenz.zms.metric_factory_class=com.yahoo.athenz.common.metrics.impl.prometheus.PrometheusMetricFactory
```

## Enable ZTS Event Monitoring in Prometheus
Enable ZTS Event Monitoring in Prometheus for ZTS server by performing the following steps:

1. Build the `athenz_metrics_prometheus` Java project located in `contributions/metric/prometheus`
2. Place it in the ZTS Server classpath
3. Edit the zts.properties file:

```
# Specifies the factory class that implements the Metrics interface
# used by the ZTS Server to report stats
athenz.zts.metric_factory_class=com.yahoo.athenz.common.metrics.impl.prometheus.PrometheusMetricFactory
```

## Enable Email Notifications Monitoring
You may also choose to enable Email Notifications and record the notifications sent in an Event Monitoring Service.
The Event Monitoring Service may be the same one used to record other Athenz Events or can be a dedicated
service that captures Notification Events only.

To enable Notification Events for Prometheus, perform the following steps:

1. Enable Email Notifications by following the steps in [Email Notifications](email_notifications.md)
2. Edit the `athenz.zms.notification_service_factory_class` property to also include the `MetricNotificationServiceFactory` class.
For example, if the NotificationServiceFactory used is `com.yahoo.athenz.common.server.notification.impl.NotificationServiceFactoryImpl`
(the default AWS Email Notification Service Factory), then the property should be:
```
athenz.zms.notification_service_factory_class=com.yahoo.athenz.common.server.notification.impl.NotificationServiceFactoryImpl, com.yahoo.athenz.common.server.notification.impl.MetricNotificationServiceFactory
```

3. Build the `athenz_metrics_prometheus` Java project located in `contributions/metric/prometheus`
4. Place it in the ZMS / ZTS Server classpath
5. Edit the zts.properties file for ZTS and zms.properties file to ZMS:

```
# Specifies the factory class that implements the Metrics interface
# used to record Notification Events
athenz.notification.metric_factory_class=com.yahoo.athenz.common.metrics.impl.prometheus.PrometheusMetricFactory
```

## Enable Event Monitoring using other Event Monitoring Services

To use Monitoring Services other than Prometheus, create a Jar file on the Athenz classpath with implementations for the following Interface:

```
com.yahoo.athenz.common.metrics.MetricFactory - A factory that creates a Notification Service based on a Notifications Provider.
```

