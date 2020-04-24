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

import java.text.MessageFormat;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;

public class PendingMembershipApprovalNotificationTask implements NotificationTask {

    private final DBService dbService;
    private final int pendingRoleMemberLifespan;
    private final String monitorIdentity;
    private NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "pending membership approvals reminders";
    private final PendingMembershipApprovalNotificationToEmailConverter pendingMembershipApprovalNotificationToEmailConverter;

    public PendingMembershipApprovalNotificationTask(DBService dbService, int pendingRoleMemberLifespan, String monitorIdentity, String userDomainPrefix) {
        this.dbService = dbService;
        this.pendingRoleMemberLifespan = pendingRoleMemberLifespan;
        this.monitorIdentity = monitorIdentity;
        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbService, USER_DOMAIN_PREFIX);
        this.notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, userDomainPrefix);
        this.pendingMembershipApprovalNotificationToEmailConverter = new PendingMembershipApprovalNotificationToEmailConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        dbService.processExpiredPendingMembers(pendingRoleMemberLifespan, monitorIdentity);
        Set<String> recipients = dbService.getPendingMembershipApproverRoles();
        return Collections.singletonList(notificationCommon.createNotification(
                recipients,
                null,
                pendingMembershipApprovalNotificationToEmailConverter));
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class PendingMembershipApprovalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER = "messages/membership-approval-reminder.html";
        private static final String MEMBERSHIP_APPROVAL_REMINDER_SUBJECT = "athenz.notification.email.membership.reminder.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailMembershipApprovalReminderBody;

        public PendingMembershipApprovalNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailMembershipApprovalReminderBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_NOTIFICATION_APPROVAL_REMINDER);
        }

        private String getMembershipApprovalReminderBody() {
            String workflowUrl = notificationToEmailConverterCommon.getWorkflowUrl();
            String athenzUIUrl = notificationToEmailConverterCommon.getAthenzUIUrl();
            String body = MessageFormat.format(emailMembershipApprovalReminderBody, workflowUrl, athenzUIUrl);
            return notificationToEmailConverterCommon.addCssStyleToBody(body);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(MEMBERSHIP_APPROVAL_REMINDER_SUBJECT);
            String body = getMembershipApprovalReminderBody();
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }
}
