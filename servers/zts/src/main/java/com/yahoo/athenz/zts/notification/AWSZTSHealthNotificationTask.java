/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.notification;

import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zts.ZTSClientNotification;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.rdl.Timestamp;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class AWSZTSHealthNotificationTask implements NotificationTask {
    private final static String DESCRIPTION = "ZTS On AWS Health Notification";
    private final NotificationCommon notificationCommon;
    private final ZTSClientNotification ztsClientNotification;
    private final String serverName;
    private final String athenzAdminDomain;

    private final AWSZTSHealthNotificationToEmailConverter awsZTSHealthNotificationToEmailConverter;
    private final AWSZTSHealthNotificationToMetricConverter awsztsHealthNotificationToMetricConverter;

    public AWSZTSHealthNotificationTask(ZTSClientNotification ztsClientNotification,
                                        RolesProvider rolesProvider,
                                        String userDomainPrefix,
                                        String serverName,
                                        NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.awsZTSHealthNotificationToEmailConverter = new AWSZTSHealthNotificationToEmailConverter(notificationToEmailConverterCommon);
        this.awsztsHealthNotificationToMetricConverter = new AWSZTSHealthNotificationToMetricConverter();
        this.ztsClientNotification = ztsClientNotification;
        this.serverName = serverName;
        this.athenzAdminDomain = System.getProperty(ZTSConsts.ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN, ATHENZ_SYS_DOMAIN);
    }

    @Override
    public List<Notification> getNotifications() {
        List<Notification> notificationList = new ArrayList<>();
        Map<String, String> details = getNotificationDetails();

        Notification notification = notificationCommon.createNotification(
                ResourceUtils.roleResourceName(athenzAdminDomain, ADMIN_ROLE_NAME),
                details,
                awsZTSHealthNotificationToEmailConverter,
                awsztsHealthNotificationToMetricConverter);
        if (notification != null) {
            notificationList.add(notification);
        }

        return notificationList;
    }

    private Map<String, String> getNotificationDetails() {
        Map<String, String> details = new HashMap<>();
        StringBuilder awsZtsDetails = new StringBuilder(256);
        Timestamp expiration = Timestamp.fromMillis(ztsClientNotification.getExpiration() * 1000);
        awsZtsDetails.append(
                ztsClientNotification.getZtsURL()).append(';')
                .append(ztsClientNotification.getDomain()).append(';')
                .append(ztsClientNotification.getRole()).append(';')
                .append(expiration).append(';')
                .append(ztsClientNotification.getMessage());

        details.put(NOTIFICATION_DETAILS_AWS_ZTS_HEALTH, awsZtsDetails.toString());
        details.put(NOTIFICATION_DETAILS_AFFECTED_ZTS, serverName);
        return details;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class AWSZTSHealthNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_AWS_ZTS_HEALTH = "messages/aws-zts-health.html";
        private static final String AWS_ZTS_HEALTH_SUBJECT = "athenz.notification.email.aws.zts.health.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private final String emailAwsZtsHealthBody;

        public AWSZTSHealthNotificationToEmailConverter(NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
            this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
            emailAwsZtsHealthBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_NOTIFICATION_AWS_ZTS_HEALTH);
        }

        String getAwsZtsHealthBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailAwsZtsHealthBody,
                    NOTIFICATION_DETAILS_AFFECTED_ZTS,
                    NOTIFICATION_DETAILS_AWS_ZTS_HEALTH,
                    5, null);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(AWS_ZTS_HEALTH_SUBJECT);
            String body = getAwsZtsHealthBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class AWSZTSHealthNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "aws_zts_health";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon = new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            String[] details = notification.getDetails().get(NOTIFICATION_DETAILS_AWS_ZTS_HEALTH).split(";");

            String[] record = new String[]{
                    METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                    METRIC_NOTIFICATION_ZTS_KEY, details[0],
                    METRIC_NOTIFICATION_DOMAIN_KEY, details[1],
                    METRIC_NOTIFICATION_ROLE_KEY, details[2],
                    METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTime.toString(), details[3]),
                    METRIC_NOTIFICATION_ZTS_HEALTH_MSG_KEY, details[4]
            };

            List<String[]> attributes = new ArrayList<>();
            attributes.add(record);

            return new NotificationMetric(attributes);
        }
    }
}
