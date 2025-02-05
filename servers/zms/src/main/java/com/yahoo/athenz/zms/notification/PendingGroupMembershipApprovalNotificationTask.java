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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.METRIC_NOTIFICATION_TYPE_KEY;

public class PendingGroupMembershipApprovalNotificationTask implements NotificationTask {

    private final DBService dbService;
    private final int pendingGroupMemberLifespan;
    private final String monitorIdentity;
    private final NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "pending group membership approvals reminders";
    private final PendingGroupMembershipApprovalNotificationToEmailConverter pendingMembershipApprovalNotificationToEmailConverter;
    private final PendingGroupMembershipApprovalNotificationToMetricConverter pendingGroupMembershipApprovalNotificationToMetricConverter;

    public PendingGroupMembershipApprovalNotificationTask(DBService dbService, int pendingGroupMemberLifespan, String monitorIdentity, String userDomainPrefix, NotificationConverterCommon notificationConverterCommon) {
        this.dbService = dbService;
        this.pendingGroupMemberLifespan = pendingGroupMemberLifespan;
        this.monitorIdentity = monitorIdentity;
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.pendingMembershipApprovalNotificationToEmailConverter = new PendingGroupMembershipApprovalNotificationToEmailConverter(notificationConverterCommon);
        this.pendingGroupMembershipApprovalNotificationToMetricConverter = new PendingGroupMembershipApprovalNotificationToMetricConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        dbService.processExpiredPendingGroupMembers(pendingGroupMemberLifespan, monitorIdentity);
        Set<String> recipients = dbService.getPendingGroupMembershipApproverRoles(1);
        return Collections.singletonList(notificationCommon.createNotification(
                Notification.Type.PENDING_GROUP_APPROVAL,
                recipients,
                null,
                pendingMembershipApprovalNotificationToEmailConverter,
                pendingGroupMembershipApprovalNotificationToMetricConverter));
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class PendingGroupMembershipApprovalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER = "messages/group-membership-approval-reminder.html";
        private static final String MEMBERSHIP_APPROVAL_REMINDER_SUBJECT = "athenz.notification.email.group_membership.reminder.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailMembershipApprovalReminderBody;

        public PendingGroupMembershipApprovalNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailMembershipApprovalReminderBody = notificationConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER);
        }

        private String getMembershipApprovalReminderBody() {
            String workflowUrl = notificationConverterCommon.getWorkflowUrl();
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

    public static class PendingGroupMembershipApprovalNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "pending_group_membership_approval";

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
}
