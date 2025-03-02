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
import com.yahoo.athenz.zms.Role;
import com.yahoo.rdl.Timestamp;

import java.text.MessageFormat;
import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class PutRoleMembershipNotificationTask implements NotificationTask {
    final String domain;
    final String org;
    final Role role;
    private final Map<String, String> details;
    private final NotificationCommon notificationCommon;
    private final static String DESCRIPTION = "Membership Approval Notification";
    private final PutMembershipNotificationToEmailConverter putMembershipNotificationToEmailConverter;
    private final PutMembershipNotificationToMetricConverter putMembershipNotificationToMetricConverter;
    private final PutMembershipNotificationToSlackMessageConverter putMembershipNotificationToSlackMessageConverter;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;

    public PutRoleMembershipNotificationTask(String domain, String org, Role role, Map<String, String> details, DBService dbService, String userDomainPrefix, NotificationConverterCommon notificationConverterCommon) {
        this.domain = domain;
        this.org = org;
        this.role = role;
        this.details = details;
        this.domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(dbService);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix, domainMetaFetcher);
        this.putMembershipNotificationToEmailConverter = new PutMembershipNotificationToEmailConverter(notificationConverterCommon);
        this.putMembershipNotificationToMetricConverter = new PutMembershipNotificationToMetricConverter();
        this.putMembershipNotificationToSlackMessageConverter = new PutMembershipNotificationToSlackMessageConverter(notificationConverterCommon);
    }

    @Override
    public List<Notification> getNotifications() {
        // we need to generate the appropriate recipients for the notification
        // there are 2 possible use cases we need to handle here:
        // a) audit enabled role - we need to add the domain and org roles
        //          from the sys.auth.audit domain
        // b) review/self-serve roles - we need to look at the configured
        //          role list for notification and if not present then default
        //          to the admin role from the domain (if consolidated by principal)
        //          or to the domain name (if consolidated by domain)
        // create and process our notification

        List<Notification> notificationList = new ArrayList<>();
        notificationList.add(notificationCommon.createNotification(
                Notification.Type.ROLE_MEMBER_APPROVAL,
                Notification.ConsolidatedBy.PRINCIPAL,
                NotificationUtils.getRecipientRoles(role.getAuditEnabled(),
                        domain, org, role.getNotifyRoles()),
                details,
                putMembershipNotificationToEmailConverter,
                putMembershipNotificationToMetricConverter,
                putMembershipNotificationToSlackMessageConverter));
        notificationList.add(notificationCommon.createNotification(
                Notification.Type.ROLE_MEMBER_APPROVAL,
                Notification.ConsolidatedBy.DOMAIN,
                NotificationUtils.getRecipientRolesByDomain(role.getAuditEnabled(),
                        domain, org, role.getNotifyRoles(), domainRoleMembersFetcher),
                details,
                putMembershipNotificationToEmailConverter,
                putMembershipNotificationToMetricConverter,
                putMembershipNotificationToSlackMessageConverter));
        return notificationList;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class PutMembershipNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_NOTIFICATION_APPROVAL = "messages/membership-approval.html";
        private static final String MEMBERSHIP_APPROVAL_SUBJECT = "athenz.notification.email.membership.approval.subject";

        private final NotificationConverterCommon notificationConverterCommon;
        private final String emailMembershipApprovalBody;

        public PutMembershipNotificationToEmailConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            emailMembershipApprovalBody = notificationConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_NOTIFICATION_APPROVAL);
        }

        String getMembershipApprovalBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }
            String workflowUrl = notificationConverterCommon.getAdminWorkflowUrl();
            String athenzUIUrl = notificationConverterCommon.getAthenzUIUrl();
            String body = MessageFormat.format(emailMembershipApprovalBody, metaDetails.get(NOTIFICATION_DETAILS_DOMAIN),
                    metaDetails.get(NOTIFICATION_DETAILS_ROLE), metaDetails.get(NOTIFICATION_DETAILS_MEMBER),
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

    public static class PutMembershipNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "role_membership_approval";

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {
            String[] record = new String[] {
                    METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                    METRIC_NOTIFICATION_DOMAIN_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_DOMAIN),
                    METRIC_NOTIFICATION_ROLE_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_ROLE),
                    METRIC_NOTIFICATION_MEMBER_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_MEMBER),
                    METRIC_NOTIFICATION_REASON_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_REASON),
                    METRIC_NOTIFICATION_REQUESTER_KEY, notification.getDetails().get(NOTIFICATION_DETAILS_REQUESTER)
            };

            List<String[]> attributes = new ArrayList<>();
            attributes.add(record);
            return new NotificationMetric(attributes);
        }
    }

    public static class PutMembershipNotificationToSlackMessageConverter implements NotificationToSlackMessageConverter {
        private static final String SLACK_TEMPLATE_NOTIFICATION_MEMBERSHIP_APPROVAL = "messages/slack-membership-approval.ftl";
        private final NotificationConverterCommon notificationConverterCommon;
        private final String slackMembershipApprovalTemplate;

        public PutMembershipNotificationToSlackMessageConverter(NotificationConverterCommon notificationConverterCommon) {
            this.notificationConverterCommon = notificationConverterCommon;
            slackMembershipApprovalTemplate = notificationConverterCommon.readContentFromFile(getClass().getClassLoader(), SLACK_TEMPLATE_NOTIFICATION_MEMBERSHIP_APPROVAL);
        }

        private String getMembershipApprovalReminderSlackMessage(Map<String, String> metaDetails) {
            String domainName = metaDetails.get(NOTIFICATION_DETAILS_DOMAIN);
            String roleName = metaDetails.get(NOTIFICATION_DETAILS_ROLE);

            Map<String, Object> dataModel = new HashMap<>();
            metaDetails.forEach(dataModel::put);
            dataModel.put("domainLink", notificationConverterCommon.getDomainLink(domainName));
            dataModel.put("roleLink", notificationConverterCommon.getRoleLink(domainName, roleName));
            dataModel.put("workflowLink", notificationConverterCommon.getDomainWorkflowUrl(domainName));

            return notificationConverterCommon.generateSlackMessageFromTemplate(
                    dataModel,
                    slackMembershipApprovalTemplate);
        }

        @Override
        public NotificationSlackMessage getNotificationAsSlackMessage(Notification notification) {
            String slackMessageContent = getMembershipApprovalReminderSlackMessage(notification.getDetails());
            Set<String> slackRecipients = notificationConverterCommon.getSlackRecipients(notification.getRecipients(), notification.getNotificationDomainMeta());
            return new NotificationSlackMessage(
                    slackMessageContent,
                    slackRecipients);
        }
    }
}
