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

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class PutGroupMembershipDecisionNotificationTask implements NotificationTask {

    private final Map<String, String> details;
    private final NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "Pending Group Membership Decision Notification";
    private final PutGroupMembershipDecisionNotificationToEmailConverter putMembershipNotificationToEmailConverter;
    private final PutGroupMembershipDecisionNotificationToMetricConverter putMembershipNotificationToMetricConverter;
    private final DBService dbService;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;
    private final String userDomainPrefix;

    public PutGroupMembershipDecisionNotificationTask(Map<String, String> details, Boolean approved, DBService dbService,
            String userDomainPrefix, NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
        this.details = details;
        this.userDomainPrefix = userDomainPrefix;
        this.domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.putMembershipNotificationToEmailConverter =
                new PutGroupMembershipDecisionNotificationToEmailConverter(notificationToEmailConverterCommon, approved);
        this.putMembershipNotificationToMetricConverter = new PutGroupMembershipDecisionNotificationToMetricConverter();
        this.dbService = dbService;
    }

    @Override
    public List<Notification> getNotifications() {
        if (details == null) {
            return new ArrayList<>();
        }

        // we need to send the notification to both the member whose pending membership was approved or rejected
        // and also the member who requested the pending member

        List<String> members = new ArrayList<>();
        members.add(details.getOrDefault(NOTIFICATION_DETAILS_MEMBER, ""));
        members.add(details.getOrDefault(NOTIFICATION_DETAILS_REQUESTER, ""));

        MembershipDecisionNotificationCommon membershipDecisionNotificationCommon
                = new MembershipDecisionNotificationCommon(dbService, domainRoleMembersFetcher, userDomainPrefix);
        Set<String> recipients = membershipDecisionNotificationCommon.getRecipients(members);

        return Collections.singletonList(notificationCommon.createNotification(
                Notification.Type.GROUP_MEMBER_DECISION,
                recipients,
                details,
                putMembershipNotificationToEmailConverter,
                putMembershipNotificationToMetricConverter));
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class PutGroupMembershipDecisionNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_APPROVAL = "messages/pending-group-membership-approve.html";
        private static final String PENDING_MEMBERSHIP_APPROVAL_SUBJECT = "athenz.notification.email.pending_group_membership.decision.approval.subject";

        private static final String EMAIL_TEMPLATE_NOTIFICATION_REJECT = "messages/pending-group-membership-reject.html";
        private static final String PENDING_MEMBERSHIP_REJECT_SUBJECT = "athenz.notification.email.pending_group_membership.decision.reject.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private final String emailMembershipDecisionBody;
        private final boolean pendingMemberApproved;

        public PutGroupMembershipDecisionNotificationToEmailConverter(
                NotificationToEmailConverterCommon notificationToEmailConverterCommon, boolean approved) {
            this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
            pendingMemberApproved = approved;
            emailMembershipDecisionBody = getEmailBody();
        }

        String getMembershipDecisionBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }
            String athenzUIUrl = notificationToEmailConverterCommon.getAthenzUIUrl();
            String body = MessageFormat.format(emailMembershipDecisionBody, metaDetails.get(NOTIFICATION_DETAILS_DOMAIN),
                    metaDetails.get(NOTIFICATION_DETAILS_GROUP), metaDetails.get(NOTIFICATION_DETAILS_MEMBER),
                    metaDetails.get(NOTIFICATION_DETAILS_REASON), metaDetails.get(NOTIFICATION_DETAILS_REQUESTER),
                    metaDetails.get(NOTIFICATION_DETAILS_PENDING_MEMBERSHIP_STATE),
                    metaDetails.get(NOTIFICATION_DETAILS_PENDING_MEMBERSHIP_DECISION_PRINCIPAL),
                    athenzUIUrl);
            return notificationToEmailConverterCommon.addCssStyleToBody(body);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(getNotificationSubjectProp());
            String body = getMembershipDecisionBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses =
                    notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }

        String getEmailBody() {
            if (pendingMemberApproved) {
                return notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(),
                        EMAIL_TEMPLATE_NOTIFICATION_APPROVAL);
            } else {
                return notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(),
                        EMAIL_TEMPLATE_NOTIFICATION_REJECT);
            }
        }

        String getNotificationSubjectProp() {
            if (pendingMemberApproved) {
                return PENDING_MEMBERSHIP_APPROVAL_SUBJECT;
            } else {
                return PENDING_MEMBERSHIP_REJECT_SUBJECT;
            }
        }
    }

    public static class PutGroupMembershipDecisionNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "pending_group_membership_decision";

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            String[] record = new String[] {
                    METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                    METRIC_NOTIFICATION_DOMAIN_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_DOMAIN),
                    METRIC_NOTIFICATION_GROUP_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_GROUP),
                    METRIC_NOTIFICATION_MEMBER_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER),
                    METRIC_NOTIFICATION_REASON_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_REASON),
                    METRIC_NOTIFICATION_REQUESTER_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_REQUESTER),
                    METRIC_NOTIFICATION_MEMBERSHIP_DECISION, notification.getDetails().get(NOTIFICATION_DETAILS_PENDING_MEMBERSHIP_DECISION)
            };

            List<String[]> attributes = new ArrayList<>();
            attributes.add(record);
            return new NotificationMetric(attributes);
        }
    }
}
