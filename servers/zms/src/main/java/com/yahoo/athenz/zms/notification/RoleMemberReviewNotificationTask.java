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

package com.yahoo.athenz.zms.notification;

import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class RoleMemberReviewNotificationTask implements NotificationTask {
    private final DBService dbService;
    private final RoleMemberNotificationCommon roleMemberNotificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberReviewNotificationTask.class);
    private final static String DESCRIPTION = "Periodic Review Reminder";
    private final RoleReviewPrincipalNotificationToEmailConverter roleReviewPrincipalNotificationToEmailConverter;
    private final RoleReviewDomainNotificationToEmailConverter roleReviewDomainNotificationToEmailConverter;
    private final RoleReviewPrincipalNotificationToMetricConverter roleReviewPrincipalNotificationToMetricConverter;
    private final RoleReviewDomainNotificationToMetricConverter roleReviewDomainNotificationToMetricConverter;
    private final RoleReviewDomainNotificationToSlackConverter roleReviewDomainNotificationToSlackMessageConverter;
    private final RoleReviewPrincipalNotificationToSlackConverter roleReviewPrincipalNotificationToSlackMessageConverter;

    private final static String[] TEMPLATE_COLUMN_NAMES = { "DOMAIN", "ROLE", "MEMBER", "REVIEW", "NOTES" };

    public RoleMemberReviewNotificationTask(DBService dbService, String userDomainPrefix,
                                            NotificationConverterCommon notificationConverterCommon) {

        this.dbService = dbService;
        this.roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbService, userDomainPrefix);
        this.roleReviewDomainNotificationToEmailConverter =
                new RoleReviewDomainNotificationToEmailConverter(notificationConverterCommon);
        this.roleReviewPrincipalNotificationToEmailConverter =
                new RoleReviewPrincipalNotificationToEmailConverter(notificationConverterCommon);
        this.roleReviewDomainNotificationToMetricConverter = new RoleReviewDomainNotificationToMetricConverter();
        this.roleReviewPrincipalNotificationToMetricConverter = new RoleReviewPrincipalNotificationToMetricConverter();
        this.roleReviewDomainNotificationToSlackMessageConverter =
                new RoleReviewDomainNotificationToSlackConverter(notificationConverterCommon);
        this.roleReviewPrincipalNotificationToSlackMessageConverter =
                new RoleReviewPrincipalNotificationToSlackConverter(notificationConverterCommon);
    }

    @Override
    public List<Notification> getNotifications() {
        Map<String, DomainRoleMember> reviewMembers = dbService.getRoleReviewMembers(1);
        if (reviewMembers == null || reviewMembers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No members require review reminders");
            }
            return new ArrayList<>();
        }

        List<Notification> notificationDetails = roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_REVIEW,
                Notification.ConsolidatedBy.PRINCIPAL,
                reviewMembers,
                roleReviewPrincipalNotificationToEmailConverter,
                roleReviewDomainNotificationToEmailConverter,
                new ReviewRoleMemberDetailStringer(),
                roleReviewPrincipalNotificationToMetricConverter,
                roleReviewDomainNotificationToMetricConverter,
                new ReviewDisableRoleMemberNotificationFilter(),
                roleReviewPrincipalNotificationToSlackMessageConverter,
                roleReviewDomainNotificationToSlackMessageConverter);

        notificationDetails.addAll(roleMemberNotificationCommon.getNotificationDetails(
                Notification.Type.ROLE_MEMBER_REVIEW,
                Notification.ConsolidatedBy.DOMAIN,
                reviewMembers,
                roleReviewPrincipalNotificationToEmailConverter,
                roleReviewDomainNotificationToEmailConverter,
                new ReviewRoleMemberDetailStringer(),
                roleReviewPrincipalNotificationToMetricConverter,
                roleReviewDomainNotificationToMetricConverter,
                new ReviewDisableRoleMemberNotificationFilter(),
                roleReviewPrincipalNotificationToSlackMessageConverter,
                roleReviewDomainNotificationToSlackMessageConverter));

        return roleMemberNotificationCommon.printNotificationDetailsToLog(notificationDetails, DESCRIPTION);
    }

    static class ReviewRoleMemberDetailStringer implements RoleMemberNotificationCommon.RoleMemberDetailStringer {

        @Override
        public StringBuilder getDetailString(MemberRole memberRole) {
            StringBuilder detailsRow = new StringBuilder(256);
            detailsRow.append(memberRole.getDomainName()).append(';');
            detailsRow.append(memberRole.getRoleName()).append(';');
            detailsRow.append(memberRole.getMemberName()).append(';');
            detailsRow.append(memberRole.getReviewReminder()).append(';');
            detailsRow.append(memberRole.getNotifyDetails() == null ?
                    "" : URLEncoder.encode(memberRole.getNotifyDetails(), StandardCharsets.UTF_8));
            return detailsRow;
        }

        @Override
        public Timestamp getNotificationTimestamp(MemberRole memberRole) {
            return memberRole.getReviewReminder();
        }
    }

    class ReviewDisableRoleMemberNotificationFilter implements RoleMemberNotificationCommon.DisableRoleMemberNotificationFilter {

        @Override
        public EnumSet<DisableNotificationEnum> getDisabledNotificationState(MemberRole memberRole) {
            Role role = dbService.getRole(memberRole.getDomainName(), memberRole.getRoleName(), false, false, false);

            try {
                return DisableNotificationEnum.getDisabledNotificationState(role, Role::getTags,
                        ZMSConsts.DISABLE_REMINDER_NOTIFICATIONS_TAG);
            } catch (NumberFormatException ex) {
                LOGGER.warn("Invalid mask value for zms.DisableReminderNotifications in domain {}, role {}",
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

    public static class RoleReviewPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_REVIEW = "messages/role-member-review.html";
        private static final String PRINCIPAL_REVIEW_SUBJECT = "athenz.notification.email.role_member.review.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailPrincipalReviewBody;

        public RoleReviewPrincipalNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailPrincipalReviewBody =  notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(),
                    EMAIL_TEMPLATE_PRINCIPAL_REVIEW);
        }

        private String getPrincipalReviewBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailPrincipalReviewBody,
                    NOTIFICATION_DETAILS_MEMBER,
                    NOTIFICATION_DETAILS_ROLES_LIST,
                    TEMPLATE_COLUMN_NAMES.length, TEMPLATE_COLUMN_NAMES);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(PRINCIPAL_REVIEW_SUBJECT);
            String body = getPrincipalReviewBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses =
                    notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleReviewDomainNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_REVIEW = "messages/domain-role-member-review.html";
        private static final String DOMAIN_MEMBER_REVIEW_SUBJECT = "athenz.notification.email.domain.role_member.review.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailDomainMemberReviewBody;

        public RoleReviewDomainNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailDomainMemberReviewBody = notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(),
                    EMAIL_TEMPLATE_DOMAIN_MEMBER_REVIEW);
        }

        private String getDomainMemberReviewBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailDomainMemberReviewBody,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_MEMBERS_LIST,
                    TEMPLATE_COLUMN_NAMES.length, TEMPLATE_COLUMN_NAMES);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(DOMAIN_MEMBER_REVIEW_SUBJECT);
            String body = getDomainMemberReviewBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses =
                    notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleReviewPrincipalNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "principal_role_membership_review";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon =
                new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {

            return NotificationUtils.getNotificationAsMetrics(notification, currentTime, NOTIFICATION_TYPE,
                    NOTIFICATION_DETAILS_ROLES_LIST, METRIC_NOTIFICATION_ROLE_KEY, METRIC_NOTIFICATION_REVIEW_DAYS_KEY,
                    notificationToMetricConverterCommon);
        }
    }

    public static class RoleReviewDomainNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "domain_role_membership_review";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon =
                new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {

            return NotificationUtils.getNotificationAsMetrics(notification, currentTime, NOTIFICATION_TYPE,
                    NOTIFICATION_DETAILS_MEMBERS_LIST, METRIC_NOTIFICATION_ROLE_KEY, METRIC_NOTIFICATION_REVIEW_DAYS_KEY,
                    notificationToMetricConverterCommon);
        }
    }

    public static class RoleReviewPrincipalNotificationToSlackConverter implements NotificationToSlackMessageConverter {
        private static final String SLACK_TEMPLATE_PRINCIPAL_REVIEW = "messages/slack-role-member-review.ftl";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackPrincipalReviewTemplate;

        public RoleReviewPrincipalNotificationToSlackConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            slackPrincipalReviewTemplate = notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(), SLACK_TEMPLATE_PRINCIPAL_REVIEW);
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = notificationConverterCommon.getSlackMessageFromTemplate(notification.getDetails(), slackPrincipalReviewTemplate, NOTIFICATION_DETAILS_ROLES_LIST, TEMPLATE_COLUMN_NAMES.length, ServerCommonConsts.OBJECT_ROLE);
            if (StringUtils.isEmpty(slackMessageContent)) {
                return null;
            }

            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }

    public static class RoleReviewDomainNotificationToSlackConverter implements NotificationToSlackMessageConverter {

        private static final String SLACK_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/slack-domain-role-member-review.ftl";
        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackDomainReviewTemplate;

        public RoleReviewDomainNotificationToSlackConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            slackDomainReviewTemplate = notificationConverterCommon.readContentFromFile(
                    getClass().getClassLoader(), SLACK_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = notificationConverterCommon.getSlackMessageFromTemplate(notification.getDetails(), slackDomainReviewTemplate, NOTIFICATION_DETAILS_MEMBERS_LIST, TEMPLATE_COLUMN_NAMES.length, ServerCommonConsts.OBJECT_ROLE);
            if (StringUtils.isEmpty(slackMessageContent)) {
                return null;
            }

            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }

}
