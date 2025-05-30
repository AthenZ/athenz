/*
 * Copyright The Athenz Authors
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

import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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
    private final RoleExpiryDomainNotificationToSlackConverter roleExpiryDomainNotificationToSlackConverter;
    private final RoleExpiryPrincipalNotificationToSlackConverter roleExpiryPrincipalNotificationToSlackConverter;


    private final static String[] TEMPLATE_COLUMN_NAMES = { "DOMAIN", "ROLE", "MEMBER", "EXPIRATION", "NOTES" };

    public RoleMemberExpiryNotificationTask(DBService dbService, String userDomainPrefix,
                                            NotificationConverterCommon notificationConverterCommon) {
        this.dbService = dbService;
        this.roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbService, userDomainPrefix);
        this.roleExpiryPrincipalNotificationToEmailConverter
                = new RoleExpiryPrincipalNotificationToEmailConverter(notificationConverterCommon);
        this.roleExpiryDomainNotificationToEmailConverter
                = new RoleExpiryDomainNotificationToEmailConverter(notificationConverterCommon);
        this.roleExpiryPrincipalNotificationToMetricConverter = new RoleExpiryPrincipalNotificationToMetricConverter();
        this.roleExpiryDomainNotificationToMetricConverter = new RoleExpiryDomainNotificationToMetricConverter();
        this.roleExpiryDomainNotificationToSlackConverter = new RoleExpiryDomainNotificationToSlackConverter(notificationConverterCommon);
        this.roleExpiryPrincipalNotificationToSlackConverter = new RoleExpiryPrincipalNotificationToSlackConverter(notificationConverterCommon);
    }

    @Override
    public List<Notification> getNotifications() {
        return getNotifications(null);
    }

    @Override
    public List<Notification> getNotifications(NotificationObjectStore notificationObjectStore) {
        Map<String, DomainRoleMember> expiryMembers = dbService.getRoleExpiryMembers(1);
        if (expiryMembers == null || expiryMembers.isEmpty()) {
            LOGGER.info("No expiry members available to send email notifications");
            return Collections.emptyList();
        }

        List<Notification> notificationList = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY,
                Notification.ConsolidatedBy.PRINCIPAL,
                expiryMembers,
                roleExpiryPrincipalNotificationToEmailConverter,
                roleExpiryDomainNotificationToEmailConverter,
                new ExpiryRoleMemberDetailStringer(),
                roleExpiryPrincipalNotificationToMetricConverter,
                roleExpiryDomainNotificationToMetricConverter,
                new ReviewDisableRoleMemberNotificationFilter(),
                roleExpiryPrincipalNotificationToSlackConverter,
                roleExpiryDomainNotificationToSlackConverter,
                notificationObjectStore);

        notificationList.addAll(roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_EXPIRY,
                Notification.ConsolidatedBy.DOMAIN,
                expiryMembers,
                roleExpiryPrincipalNotificationToEmailConverter,
                roleExpiryDomainNotificationToEmailConverter,
                new ExpiryRoleMemberDetailStringer(),
                roleExpiryPrincipalNotificationToMetricConverter,
                roleExpiryDomainNotificationToMetricConverter,
                new ReviewDisableRoleMemberNotificationFilter(),
                roleExpiryPrincipalNotificationToSlackConverter,
                roleExpiryDomainNotificationToSlackConverter,
                notificationObjectStore));

        return notificationList;
    }

    static class ExpiryRoleMemberDetailStringer implements RoleMemberNotificationCommon.RoleMemberDetailStringer {

        @Override
        public StringBuilder getDetailString(MemberRole memberRole) {
            StringBuilder detailsRow = new StringBuilder(256);
            detailsRow.append(memberRole.getDomainName()).append(';');
            detailsRow.append(memberRole.getRoleName()).append(';');
            detailsRow.append(memberRole.getMemberName()).append(';');
            detailsRow.append(memberRole.getExpiration()).append(';');
            detailsRow.append(memberRole.getNotifyDetails() == null ?
                    "" : URLEncoder.encode(memberRole.getNotifyDetails(), StandardCharsets.UTF_8));
            return detailsRow;
        }

        @Override
        public Timestamp getNotificationTimestamp(MemberRole memberRole) {
            return memberRole.getExpiration();
        }
    }

    class ReviewDisableRoleMemberNotificationFilter implements RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter {

        @Override
        public EnumSet<DisableNotificationEnum> getDisabledNotificationState(MemberRole memberRole) {

            Role role = dbService.getRole(memberRole.getDomainName(), memberRole.getRoleName(), false, false, false);
            try {
                return DisableNotificationEnum.getDisabledNotificationState(role, Role::getTags,
                        ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG);
            } catch (NumberFormatException ex) {
                LOGGER.warn("Invalid mask value for {} in domain {}, role {}",
                        ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG,
                        memberRole.getDomainName(),
                        memberRole.getRoleName());
            }

            return DisableNotificationEnum.getEnumSet(0);
        }
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class RoleExpiryPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_EXPIRY = "messages/role-member-expiry.html";
        private static final String PRINCIPAL_EXPIRY_SUBJECT = "athenz.notification.email.role_member.expiry.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailPrincipalExpiryBody;

        public RoleExpiryPrincipalNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailPrincipalExpiryBody =  notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(), EMAIL_TEMPLATE_PRINCIPAL_EXPIRY);
        }

        private String getPrincipalExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailPrincipalExpiryBody,
                    NOTIFICATION_DETAILS_MEMBER,
                    NOTIFICATION_DETAILS_ROLES_LIST,
                    TEMPLATE_COLUMN_NAMES.length, TEMPLATE_COLUMN_NAMES);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(PRINCIPAL_EXPIRY_SUBJECT);
            String body = getPrincipalExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses =
                    notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleExpiryDomainNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/domain-role-member-expiry.html";
        private static final String DOMAIN_MEMBER_EXPIRY_SUBJECT = "athenz.notification.email.domain.role_member.expiry.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailDomainMemberExpiryBody;

        public RoleExpiryDomainNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailDomainMemberExpiryBody = notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(), EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        private String getDomainMemberExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailDomainMemberExpiryBody,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_MEMBERS_LIST,
                    TEMPLATE_COLUMN_NAMES.length, TEMPLATE_COLUMN_NAMES);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(DOMAIN_MEMBER_EXPIRY_SUBJECT);
            String body = getDomainMemberExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses =
                    notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleExpiryPrincipalNotificationToMetricConverter implements NotificationToMetricConverter {

        private final static String NOTIFICATION_TYPE = "principal_role_membership_expiry";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon =
                new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {

            return NotificationUtils.getNotificationAsMetrics(notification, currentTime, NOTIFICATION_TYPE,
                    NOTIFICATION_DETAILS_ROLES_LIST, METRIC_NOTIFICATION_ROLE_KEY, METRIC_NOTIFICATION_EXPIRY_DAYS_KEY,
                    notificationToMetricConverterCommon);
        }
    }

    public static class RoleExpiryDomainNotificationToMetricConverter implements NotificationToMetricConverter {

        private final static String NOTIFICATION_TYPE = "domain_role_membership_expiry";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon =
                new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {

            return NotificationUtils.getNotificationAsMetrics(notification, currentTime, NOTIFICATION_TYPE,
                    NOTIFICATION_DETAILS_MEMBERS_LIST, METRIC_NOTIFICATION_ROLE_KEY, METRIC_NOTIFICATION_EXPIRY_DAYS_KEY,
                    notificationToMetricConverterCommon);
        }
    }

    public static class RoleExpiryPrincipalNotificationToSlackConverter implements NotificationToSlackMessageConverter {
        private static final String SLACK_TEMPLATE_PRINCIPAL_MEMBER_EXPIRY = "messages/slack-role-member-expiry.ftl";
        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackPrincipalExpiryTemplate;

        public RoleExpiryPrincipalNotificationToSlackConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            slackPrincipalExpiryTemplate = notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(), SLACK_TEMPLATE_PRINCIPAL_MEMBER_EXPIRY);
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = notificationConverterCommon.getSlackMessageFromTemplate(notification.getDetails(), slackPrincipalExpiryTemplate, NOTIFICATION_DETAILS_ROLES_LIST, TEMPLATE_COLUMN_NAMES.length, ServerCommonConsts.OBJECT_ROLE);
            if (StringUtil.isEmpty(slackMessageContent)) {
                return null;
            }
            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }

    public static class RoleExpiryDomainNotificationToSlackConverter implements NotificationToSlackMessageConverter {

        private static final String SLACK_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/slack-domain-role-member-expiry.ftl";
        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackDomainExpiryTemplate;

        public RoleExpiryDomainNotificationToSlackConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            slackDomainExpiryTemplate = notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(), SLACK_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = notificationConverterCommon.getSlackMessageFromTemplate(notification.getDetails(), slackDomainExpiryTemplate, NOTIFICATION_DETAILS_MEMBERS_LIST, TEMPLATE_COLUMN_NAMES.length, ServerCommonConsts.OBJECT_ROLE);
            if (StringUtil.isEmpty(slackMessageContent)) {
                return null;
            }
            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }
}
