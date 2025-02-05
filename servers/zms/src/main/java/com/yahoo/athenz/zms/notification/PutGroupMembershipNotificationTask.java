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
import com.yahoo.athenz.zms.Group;
import com.yahoo.rdl.Timestamp;

import java.text.MessageFormat;
import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class PutGroupMembershipNotificationTask implements NotificationTask {

    final String domain;
    final String org;
    final Group group;
    private final Map<String, String> details;
    private final NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "Group Membership Approval Notification";
    private final PutGroupMembershipNotificationToEmailConverter putGroupMembershipNotificationToEmailConverter;
    private final PutGroupMembershipNotificationToMetricConverter putGroupMembershipNotificationToMetricConverter;

    public PutGroupMembershipNotificationTask(String domain, String org, Group group, Map<String, String> details, DBService dbService, String userDomainPrefix, NotificationConverterCommon notificationConverterCommon) {
        this.domain = domain;
        this.org = org;
        this.group = group;
        this.details = details;
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.putGroupMembershipNotificationToEmailConverter = new PutGroupMembershipNotificationToEmailConverter(notificationConverterCommon);
        this.putGroupMembershipNotificationToMetricConverter = new PutGroupMembershipNotificationToMetricConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        // we need to generate the appropriate recipients for the notification
        // there are 2 possible use cases we need to handle here:
        // a) audit enabled role - we need to add the domain and org roles
        //          from the sys.auth.audit domain
        // b) review/self-serve roles - we need to look at the configured
        //          role list for notification and if not present then default
        //          to the admin role from the domain

        Set<String> recipients = NotificationUtils.getRecipientRoles(group.getAuditEnabled(),
                domain, org, group.getNotifyRoles());

        // create and process our notification

        return Collections.singletonList(notificationCommon.createNotification(
                Notification.Type.GROUP_MEMBER_APPROVAL,
                recipients,
                details,
                putGroupMembershipNotificationToEmailConverter,
                putGroupMembershipNotificationToMetricConverter));
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class PutGroupMembershipNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_APPROVAL = "messages/group-membership-approval.html";
        private static final String MEMBERSHIP_APPROVAL_SUBJECT = "athenz.notification.email.group_membership.approval.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailMembershipApprovalBody;

        public PutGroupMembershipNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailMembershipApprovalBody = notificationConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_NOTIFICATION_APPROVAL);
        }

        String getMembershipApprovalBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }
            String workflowUrl = notificationConverterCommon.getWorkflowUrl();
            String athenzUIUrl = notificationConverterCommon.getAthenzUIUrl();
            String body = MessageFormat.format(emailMembershipApprovalBody, metaDetails.get(NOTIFICATION_DETAILS_DOMAIN),
                    metaDetails.get(NOTIFICATION_DETAILS_GROUP), metaDetails.get(NOTIFICATION_DETAILS_MEMBER),
                    metaDetails.get(NOTIFICATION_DETAILS_REASON), metaDetails.get(NOTIFICATION_DETAILS_REQUESTER),
                    workflowUrl, athenzUIUrl);
            return notificationConverterCommon.addCssStyleToBody(body);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(MEMBERSHIP_APPROVAL_SUBJECT);
            String body = getMembershipApprovalBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class PutGroupMembershipNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "group_membership_approval";

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            String[] record = new String[] {
                    METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                    METRIC_NOTIFICATION_DOMAIN_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_DOMAIN),
                    METRIC_NOTIFICATION_GROUP_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_GROUP),
                    METRIC_NOTIFICATION_MEMBER_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER),
                    METRIC_NOTIFICATION_REASON_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_REASON),
                    METRIC_NOTIFICATION_REQUESTER_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_REQUESTER)
            };

            List<String[]> attributes = new ArrayList<>();
            attributes.add(record);
            return new NotificationMetric(attributes);
        }
    }
}
