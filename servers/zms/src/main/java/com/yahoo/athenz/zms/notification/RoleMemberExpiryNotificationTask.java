/*
 * Copyright 2020 Verizon Media
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_DETAILS_MEMBERS_LIST;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class RoleMemberExpiryNotificationTask implements NotificationTask {
    private final DBService dbService;
    private final RoleMemberNotificationCommon roleMemberNotificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberExpiryNotificationTask.class);
    private final static String DESCRIPTION = "membership expiration reminders";
    private final RoleExpiryDomainNotificationToEmailConverter roleExpiryDomainNotificationToEmailConverter;
    private final RoleExpiryPrincipalNotificationToEmailConverter roleExpiryPrincipalNotificationToEmailConverter;
    private final RoleExpiryDomainNotificationToMetricConverter roleExpiryDomainNotificationToMetricConverter;
    private final RoleExpiryPrincipalNotificationToMetricConverter roleExpiryPrincipalNotificationToMetricConverter;

    public RoleMemberExpiryNotificationTask(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        this.roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbService, userDomainPrefix);
        this.roleExpiryPrincipalNotificationToEmailConverter = new RoleExpiryPrincipalNotificationToEmailConverter();
        this.roleExpiryDomainNotificationToEmailConverter = new RoleExpiryDomainNotificationToEmailConverter();
        this.roleExpiryPrincipalNotificationToMetricConverter = new RoleExpiryPrincipalNotificationToMetricConverter();
        this.roleExpiryDomainNotificationToMetricConverter = new RoleExpiryDomainNotificationToMetricConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        Map<String, DomainRoleMember> expiryMembers = dbService.getRoleExpiryMembers(1);
        if (expiryMembers == null || expiryMembers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No expiry members available to send notifications");
            }
            return new ArrayList<>();
        }

        return roleMemberNotificationCommon.getNotificationDetails(
                expiryMembers,
                roleExpiryPrincipalNotificationToEmailConverter,
                roleExpiryDomainNotificationToEmailConverter,
                new ExpiryRoleMemberDetailStringer(),
                roleExpiryPrincipalNotificationToMetricConverter,
                roleExpiryDomainNotificationToMetricConverter);
    }

    static class ExpiryRoleMemberDetailStringer implements RoleMemberNotificationCommon.RoleMemberDetailStringer {

        @Override
        public StringBuilder getDetailString(MemberRole memberRole) {
            StringBuilder detailsRow = new StringBuilder(256);
            detailsRow.append(memberRole.getRoleName()).append(';');
            detailsRow.append(memberRole.getExpiration());
            return detailsRow;
        }
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class RoleExpiryPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_EXPIRY = "messages/role-member-expiry.html";
        private static final String PRINCIPAL_EXPIRY_SUBJECT = "athenz.notification.email.role_member.expiry.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailPrincipalExpiryBody;

        public RoleExpiryPrincipalNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailPrincipalExpiryBody =  notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_PRINCIPAL_EXPIRY);
        }

        private String getPrincipalExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailPrincipalExpiryBody,
                    NOTIFICATION_DETAILS_MEMBER,
                    NOTIFICATION_DETAILS_ROLES_LIST,
                    3);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(PRINCIPAL_EXPIRY_SUBJECT);
            String body = getPrincipalExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleExpiryDomainNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/domain-role-member-expiry.html";
        private static final String DOMAIN_MEMBER_EXPIRY_SUBJECT = "athenz.notification.email.domain.role_member.expiry.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailDomainMemberExpiryBody;

        public RoleExpiryDomainNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailDomainMemberExpiryBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        private String getDomainMemberExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailDomainMemberExpiryBody,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_MEMBERS_LIST,
                    3);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(DOMAIN_MEMBER_EXPIRY_SUBJECT);
            String body = getDomainMemberExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleExpiryPrincipalNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "principal_role_membership_expiry";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon = new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            Map<String, String> details = notification.getDetails();

            String memberName = details.get(NOTIFICATION_DETAILS_MEMBER);

            List<String[]> attributes = new ArrayList<>();
            String[] records = details.get(NOTIFICATION_DETAILS_ROLES_LIST).split("\\|");
            for (String record: records) {
                String[] recordAttributes = record.split(";");
                if (recordAttributes.length != 3) {
                    // Bad entry, skip
                    continue;
                }
                String[] metricRecord = new String[] {
                        METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                        METRIC_NOTIFICATION_MEMBER_KEY, memberName,
                        METRIC_NOTIFICATION_DOMAIN_KEY, recordAttributes[0],
                        METRIC_NOTIFICATION_ROLE_KEY, recordAttributes[1],
                        METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTime.toString(), recordAttributes[2])
                };

                attributes.add(metricRecord);
            }

            return new NotificationMetric(attributes);
        }
    }

    public static class RoleExpiryDomainNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "domain_role_membership_expiry";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon = new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            Map<String, String> details = notification.getDetails();
            String domain = details.get(NOTIFICATION_DETAILS_DOMAIN);
            List<String[]> attributes = new ArrayList<>();
            String[] records = details.get(NOTIFICATION_DETAILS_MEMBERS_LIST).split("\\|");
            for (String record: records) {
                String[] recordAttributes = record.split(";");
                if (recordAttributes.length != 3) {
                    // Bad entry, skip
                    continue;
                }
                String[] metricRecord = new String[] {
                        METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                        METRIC_NOTIFICATION_DOMAIN_KEY, domain,
                        METRIC_NOTIFICATION_MEMBER_KEY, recordAttributes[0],
                        METRIC_NOTIFICATION_ROLE_KEY, recordAttributes[1],
                        METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTime.toString(), recordAttributes[2])
                };

                attributes.add(metricRecord);
            }

            return new NotificationMetric(attributes);
        }
    }
}
