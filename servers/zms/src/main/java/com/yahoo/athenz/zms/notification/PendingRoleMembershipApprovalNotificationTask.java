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

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.rdl.Timestamp;

import java.text.MessageFormat;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.METRIC_NOTIFICATION_TYPE_KEY;

public class PendingRoleMembershipApprovalNotificationTask implements NotificationTask {

    private final DBService dbService;
    private final int pendingRoleMemberLifespan;
    private final String monitorIdentity;
    private final NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "pending role membership approvals reminders";
    private final PendingRoleMembershipApprovalNotificationToEmailConverter pendingMembershipApprovalNotificationToEmailConverter;
    private final PendingRoleMembershipApprovalNotificationToMetricConverter pendingRoleMembershipApprovalNotificationToMetricConverter;
    private final PendingRoleMembershipApprovalNotificationToSlackMessageConverter pendingRoleMembershipApprovalNotificationToSlackMessageConverter;

    public PendingRoleMembershipApprovalNotificationTask(DBService dbService, int pendingRoleMemberLifespan, String monitorIdentity, String userDomainPrefix, NotificationConverterCommon notificationConverterCommon) {
        this.dbService = dbService;
        this.pendingRoleMemberLifespan = pendingRoleMemberLifespan;
        this.monitorIdentity = monitorIdentity;
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, USER_DOMAIN_PREFIX);
        DomainMetaFetcher domainFetcher = new DomainMetaFetcher(dbService);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix, domainFetcher);
        this.pendingMembershipApprovalNotificationToEmailConverter = new PendingRoleMembershipApprovalNotificationToEmailConverter(notificationConverterCommon);
        this.pendingRoleMembershipApprovalNotificationToMetricConverter = new PendingRoleMembershipApprovalNotificationToMetricConverter();
        this.pendingRoleMembershipApprovalNotificationToSlackMessageConverter = new PendingRoleMembershipApprovalNotificationToSlackMessageConverter(notificationConverterCommon);
    }

    @Override
    public List<Notification> getNotifications() {
        dbService.processExpiredPendingMembers(pendingRoleMemberLifespan, monitorIdentity);

        // set of roles which needs to be notified for pending role membership approval
        // will have both audit roles and admin roles of domain
        Set<String> recipients = dbService.getPendingMembershipApproverRoles(1);

        List<Notification> notificationList = new ArrayList<>();
        notificationList.add(notificationCommon.createNotification(
                Notification.Type.PENDING_ROLE_APPROVAL,
                Notification.ConsolidatedBy.PRINCIPAL,
                recipients,
                null,
                pendingMembershipApprovalNotificationToEmailConverter,
                pendingRoleMembershipApprovalNotificationToMetricConverter,
                pendingRoleMembershipApprovalNotificationToSlackMessageConverter));
        notificationList.add(notificationCommon.createNotification(
                Notification.Type.PENDING_ROLE_APPROVAL,
                Notification.ConsolidatedBy.DOMAIN,
                recipients,
                null,
                pendingMembershipApprovalNotificationToEmailConverter,
                pendingRoleMembershipApprovalNotificationToMetricConverter,
                pendingRoleMembershipApprovalNotificationToSlackMessageConverter));


        return notificationList;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class PendingRoleMembershipApprovalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER = "messages/membership-approval-reminder.html";
        private static final String MEMBERSHIP_APPROVAL_REMINDER_SUBJECT = "athenz.notification.email.membership.reminder.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailMembershipApprovalReminderBody;

        public PendingRoleMembershipApprovalNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailMembershipApprovalReminderBody = notificationConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER);
        }

        private String getMembershipApprovalReminderBody() {
            String workflowUrl = notificationConverterCommon.getAdminWorkflowUrl();
            String athenzUIUrl = notificationConverterCommon.getAthenzUIUrl();
            String body = MessageFormat.format(emailMembershipApprovalReminderBody, workflowUrl, athenzUIUrl);
            return notificationConverterCommon.addCssStyleToBody(body);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(MEMBERSHIP_APPROVAL_REMINDER_SUBJECT);
            String body = getMembershipApprovalReminderBody();
            Set<String> fullyQualifiedEmailAddresses = notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class PendingRoleMembershipApprovalNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "pending_role_membership_approval";

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            String[] record = new String[] {
                    METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE
            };

            List<String[]> attributes = new ArrayList<>();
            attributes.add(record);
            // This notification doesn't contain any details. We should consider adding the recipients in their own tags.
            return new NotificationMetric(attributes);
        }
    }

    public static class PendingRoleMembershipApprovalNotificationToSlackMessageConverter implements NotificationToSlackMessageConverter {

        private static final String SLACK_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER = "messages/slack-role-membership-approval-reminder.ftl";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackMembershipApprovalReminderTemplate;

        public PendingRoleMembershipApprovalNotificationToSlackMessageConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            slackMembershipApprovalReminderTemplate = notificationConverterCommon.readContentFromFile(getClass().getClassLoader(), SLACK_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER);
        }

        private String getMembershipApprovalReminderSlackMessage() {
            Map<String, Object> dataModel = new HashMap<>();
            dataModel.put("workflowLink", notificationConverterCommon.getAdminWorkflowUrl());
            return notificationConverterCommon.generateSlackMessageFromTemplate(
                    dataModel,
                    slackMembershipApprovalReminderTemplate);
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = getMembershipApprovalReminderSlackMessage();
            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }
}
