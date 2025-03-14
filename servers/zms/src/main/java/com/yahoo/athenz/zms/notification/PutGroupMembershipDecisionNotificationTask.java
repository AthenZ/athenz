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
    private final PutGroupMembershipDecisionNotificationToSlackConverter putMembershipNotificationToSlackConverter;
    private final DBService dbService;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;
    private final String userDomainPrefix;

    public PutGroupMembershipDecisionNotificationTask(Map<String, String> details, Boolean approved, DBService dbService,
            String userDomainPrefix, NotificationConverterCommon notificationConverterCommon) {
        this.details = details;
        this.userDomainPrefix = userDomainPrefix;
        this.domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(dbService);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix, domainMetaFetcher);
        this.putMembershipNotificationToEmailConverter =
                new PutGroupMembershipDecisionNotificationToEmailConverter(notificationConverterCommon, approved);
        this.putMembershipNotificationToMetricConverter = new PutGroupMembershipDecisionNotificationToMetricConverter();
        this.putMembershipNotificationToSlackConverter =
                new PutGroupMembershipDecisionNotificationToSlackConverter(notificationConverterCommon, approved);
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

        List<Notification.ConsolidatedBy> consolidationTypes = Arrays.asList(
                Notification.ConsolidatedBy.PRINCIPAL,
                Notification.ConsolidatedBy.DOMAIN
        );

        List<Notification> notificationList = new ArrayList<>();
        for (var consolidationType : consolidationTypes) {
            Set<String> recipients = consolidationType == Notification.ConsolidatedBy.PRINCIPAL
                    ? membershipDecisionNotificationCommon.getRecipients(members)
                    : membershipDecisionNotificationCommon.getRecipientsByDomain(members);

            notificationList.add(notificationCommon.createNotification(
                    Notification.Type.GROUP_MEMBER_DECISION,
                    consolidationType,
                    recipients,
                    details,
                    putMembershipNotificationToEmailConverter,
                    putMembershipNotificationToMetricConverter,
                    putMembershipNotificationToSlackConverter));
        }

        return notificationList;
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

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailMembershipDecisionBody;
        private final boolean pendingMemberApproved;

        public PutGroupMembershipDecisionNotificationToEmailConverter(
                NotificationConverterCommon notificationConverterCommon, boolean approved) {
            this.notificationConverterCommon = notificationConverterCommon;
            pendingMemberApproved = approved;
            emailMembershipDecisionBody = getEmailBody();
        }

        String getMembershipDecisionBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }
            String athenzUIUrl = notificationConverterCommon.getAthenzUIUrl();
            String body = MessageFormat.format(emailMembershipDecisionBody, metaDetails.get(NOTIFICATION_DETAILS_DOMAIN),
                    metaDetails.get(NOTIFICATION_DETAILS_GROUP), metaDetails.get(NOTIFICATION_DETAILS_MEMBER),
                    metaDetails.get(NOTIFICATION_DETAILS_REASON), metaDetails.get(NOTIFICATION_DETAILS_REQUESTER),
                    metaDetails.get(NOTIFICATION_DETAILS_PENDING_MEMBERSHIP_STATE),
                    metaDetails.get(NOTIFICATION_DETAILS_PENDING_MEMBERSHIP_DECISION_PRINCIPAL),
                    athenzUIUrl);
            return notificationConverterCommon.addCssStyleToBody(body);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationConverterCommon.getSubject(getNotificationSubjectProp());
            String body = getMembershipDecisionBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses =
                    notificationConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }

        String getEmailBody() {
            if (pendingMemberApproved) {
                return notificationConverterCommon.readContentFromFile(getClass().getClassLoader(),
                        EMAIL_TEMPLATE_NOTIFICATION_APPROVAL);
            } else {
                return notificationConverterCommon.readContentFromFile(getClass().getClassLoader(),
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

    public static class PutGroupMembershipDecisionNotificationToSlackConverter implements NotificationToSlackMessageConverter {
        private static final String SLACK_TEMPLATE_NOTIFICATION_APPROVAL = "messages/slack-pending-group-membership-approve.ftl";
        private static final String SLACK_TEMPLATE_NOTIFICATION_REJECT = "messages/slack-pending-group-membership-reject.ftl";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackMessageTemplate;
        private final boolean pendingMemberApproved;

        public PutGroupMembershipDecisionNotificationToSlackConverter(
                NotificationConverterCommon notificationConverterCommon, boolean approved) {
            this.notificationConverterCommon = notificationConverterCommon;
            pendingMemberApproved = approved;
            slackMessageTemplate = getSlackMessageTemplate();
        }

        String getMembershipDecisionMessage(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }
            Map<String, Object> dataModel = new HashMap<>(metaDetails);
            dataModel.put("groupLink", notificationConverterCommon.getGroupLink(metaDetails.get(NOTIFICATION_DETAILS_DOMAIN),
                    metaDetails.get(NOTIFICATION_DETAILS_GROUP)));
            dataModel.put("domainLink", notificationConverterCommon.getDomainLink(metaDetails.get(NOTIFICATION_DETAILS_DOMAIN)));
            return notificationConverterCommon.generateSlackMessageFromTemplate(dataModel, slackMessageTemplate);
        }

        String getSlackMessageTemplate() {
            if (pendingMemberApproved) {
                return notificationConverterCommon.readContentFromFile(getClass().getClassLoader(),
                        SLACK_TEMPLATE_NOTIFICATION_APPROVAL);
            } else {
                return notificationConverterCommon.readContentFromFile(getClass().getClassLoader(),
                        SLACK_TEMPLATE_NOTIFICATION_REJECT);
            }
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = getMembershipDecisionMessage(notification.getDetails());
            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }
}
