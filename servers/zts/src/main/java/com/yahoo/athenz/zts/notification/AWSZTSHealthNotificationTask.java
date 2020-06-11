/*
 *  Copyright 2020 Verizon Media
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

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.zts.ZTSConsts.ATHENZ_SYS_DOMAIN;

public class AWSZTSHealthNotificationTask implements NotificationTask {
    private final static String DESCRIPTION = "ZTS On AWS Health Notification";
    private final NotificationCommon notificationCommon;
    private final ZTSClientNotification ztsClientNotification;
    private final String serverName;

    private final AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter awsZTSHealthNotificationToEmailConverter;


    public AWSZTSHealthNotificationTask(ZTSClientNotification ztsClientNotification,
                                        RolesProvider rolesProvider,
                                        String userDomainPrefix,
                                        String serverName) {
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(rolesProvider, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.awsZTSHealthNotificationToEmailConverter = new AWSZTSHealthNotificationTask.AWSZTSHealthNotificationToEmailConverter();
        this.ztsClientNotification = ztsClientNotification;
        this.serverName = serverName;
    }

    @Override
    public List<Notification> getNotifications() {
        List<Notification> notificationList = new ArrayList<>();
        Map<String, String> details = getNotificationDetails();

        Notification notification = notificationCommon.createNotification(
                ResourceUtils.roleResourceName(ATHENZ_SYS_DOMAIN, ADMIN_ROLE_NAME),
                details,
                awsZTSHealthNotificationToEmailConverter);
        if (notification != null) {
            notificationList.add(notification);
        }

        return notificationList;
    }

    private Map<String, String> getNotificationDetails() {
        Map<String, String> details = new HashMap<>();
        StringBuilder awsZtsDetails = new StringBuilder(256);
        awsZtsDetails.append(ztsClientNotification.getZtsURL()).append(';')
                .append(ztsClientNotification.getDomain()).append(';')
                .append(ztsClientNotification.getRole()).append(';')
                .append(ztsClientNotification.getExpiration()).append(';')
                .append(ztsClientNotification.getMessage()).append(';')
                .append(serverName);

        details.put(NOTIFICATION_DETAILS_AWS_ZTS_HEALTH, awsZtsDetails.toString());
        details.put(NOTIFICATION_DETAILS_AFFECTED_ZTS, ztsClientNotification.getDomain());
        return details;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class AWSZTSHealthNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_AWS_ZTS_HEALTH = "messages/aws-zts-health.html";
        private static final String AWS_ZTS_HEALTH_SUBJECT = "athenz.notification.email.aws.zts.health.subject";
        private static final String AWS_ZTS_HEALTH_BODY_ENTRY = "athenz.notification.email.aws.zts.health.body.entry";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailAwsZtsHealthBody;

        public AWSZTSHealthNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
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
                    5,
                    AWS_ZTS_HEALTH_BODY_ENTRY);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(AWS_ZTS_HEALTH_SUBJECT);
            String body = getAwsZtsHealthBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }
}
