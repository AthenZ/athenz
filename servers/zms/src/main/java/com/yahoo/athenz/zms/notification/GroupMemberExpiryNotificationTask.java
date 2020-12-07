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
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;

public class GroupMemberExpiryNotificationTask implements NotificationTask {
    private final DBService dbService;
    private final NotificationCommon notificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(GroupMemberExpiryNotificationTask.class);
    private final static String DESCRIPTION = "group membership expiration reminders";
    private final GroupExpiryDomainNotificationToEmailConverter groupExpiryDomainNotificationToEmailConverter;
    private final GroupExpiryPrincipalNotificationToEmailConverter groupExpiryPrincipalNotificationToEmailConverter;
    private final GroupExpiryDomainNotificationToMetricConverter groupExpiryDomainNotificationToMetricConverter;
    private final GroupExpiryPrincipalNotificationToToMetricConverter groupExpiryPrincipalNotificationToToMetricConverter;

    public GroupMemberExpiryNotificationTask(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.groupExpiryPrincipalNotificationToEmailConverter = new GroupExpiryPrincipalNotificationToEmailConverter();
        this.groupExpiryDomainNotificationToEmailConverter = new GroupExpiryDomainNotificationToEmailConverter();
        this.groupExpiryPrincipalNotificationToToMetricConverter = new GroupExpiryPrincipalNotificationToToMetricConverter();
        this.groupExpiryDomainNotificationToMetricConverter = new GroupExpiryDomainNotificationToMetricConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        Map<String, DomainGroupMember> expiryMembers = dbService.getGroupExpiryMembers(1);
        if (expiryMembers == null || expiryMembers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No expiry group members available to send notifications");
            }
            return new ArrayList<>();
        }

        return getNotificationDetails(
                expiryMembers,
                groupExpiryPrincipalNotificationToEmailConverter,
                groupExpiryDomainNotificationToEmailConverter,
                groupExpiryPrincipalNotificationToToMetricConverter,
                groupExpiryDomainNotificationToMetricConverter);
    }

    public StringBuilder getDetailString(GroupMember memberGroup) {
        StringBuilder detailsRow = new StringBuilder(256);
        detailsRow.append(memberGroup.getGroupName()).append(';');
        detailsRow.append(memberGroup.getExpiration());
        return detailsRow;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    private Map<String, String> processGroupReminder(Map<String, List<GroupMember>> domainAdminMap,
                                                     DomainGroupMember member) {

        Map<String, String> details = new HashMap<>();

        // each principal can have multiple groups in multiple domains that
        // it's part of thus multiple possible entries.
        // we're going to collect them into one string and separate
        // with | between those. The format will be:
        // memberGroupsDetails := <group-member-entry>[|<group-member-entry]*
        // group-member-entry := <domain-name>;<group-name>;<expiration>

        final List<GroupMember> memberGroups = member.getMemberGroups();
        if (memberGroups == null || memberGroups.isEmpty()) {
            return details;
        }

        StringBuilder memberGroupsDetails = new StringBuilder(256);
        for (GroupMember memberGroup : memberGroups) {

            final String domainName = memberGroup.getDomainName();

            // first we're going to update our expiry details string

            if (memberGroupsDetails.length() != 0) {
                memberGroupsDetails.append('|');
            }

            memberGroupsDetails.append(domainName).append(';');
            memberGroupsDetails.append(getDetailString(memberGroup));

            // next we're going to update our domain admin map

            List<GroupMember> domainGroupMembers = domainAdminMap.computeIfAbsent(domainName, k -> new ArrayList<>());
            domainGroupMembers.add(memberGroup);
        }

        details.put(NOTIFICATION_DETAILS_ROLES_LIST, memberGroupsDetails.toString());
        details.put(NOTIFICATION_DETAILS_MEMBER, member.getMemberName());

        return details;
    }

    private Map<String, String> processMemberReminder(final String domainName, List<GroupMember> memberGroups) {

        Map<String, String> details = new HashMap<>();

        // each domain can have multiple members that are about
        // to expire to we're going to collect them into one
        // string and separate with | between those. The format will be:
        // memberDetails := <member-entry>[|<member-entry]*
        // member-entry := <member-name>;<group-name>;<expiration>

        if (memberGroups == null || memberGroups.isEmpty()) {
            return details;
        }

        StringBuilder memberDetails = new StringBuilder(256);
        for (GroupMember memberGroup : memberGroups) {

            // first we're going to update our expiry details string

            if (memberDetails.length() != 0) {
                memberDetails.append('|');
            }

            memberDetails.append(memberGroup.getMemberName()).append(';');
            memberDetails.append(getDetailString(memberGroup));
        }

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST, memberDetails.toString());
        details.put(NOTIFICATION_DETAILS_DOMAIN, domainName);
        return details;
    }

    List<Notification> getNotificationDetails(Map<String, DomainGroupMember> members,
                                              NotificationToEmailConverter principalNotificationToEmailConverter,
                                              NotificationToEmailConverter domainAdminNotificationToEmailConverter,
                                              NotificationToMetricConverter principalNotificationToMetricConverter,
                                              NotificationToMetricConverter domainAdminNotificationToMetricConverter) {

        List<Notification> notificationList = new ArrayList<>();
        Map<String, List<GroupMember>> domainAdminMap = new HashMap<>();

        for (DomainGroupMember groupMember : members.values()) {

            // we're going to process the role member, update
            // our domain admin map accordingly and return
            // the details object that we need to send to the
            // notification agent for processing

            Map<String, String> details = processGroupReminder(domainAdminMap, groupMember);
            Notification notification = notificationCommon.createNotification(
                    groupMember.getMemberName(), details, principalNotificationToEmailConverter, principalNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        // now we're going to send reminders to all the domain administrators

        for (Map.Entry<String, List<GroupMember>> domainAdmin : domainAdminMap.entrySet()) {

            Map<String, String> details = processMemberReminder(domainAdmin.getKey(), domainAdmin.getValue());
            Notification notification = notificationCommon.createNotification(
                    ZMSUtils.roleResourceName(domainAdmin.getKey(), ADMIN_ROLE_NAME),
                    details, domainAdminNotificationToEmailConverter, domainAdminNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        return notificationList;
    }

    public static class GroupExpiryPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_EXPIRY = "messages/group-member-expiry.html";
        private static final String PRINCIPAL_EXPIRY_SUBJECT = "athenz.notification.email.group_member.expiry.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private final String emailPrincipalExpiryBody;

        public GroupExpiryPrincipalNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailPrincipalExpiryBody =  notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_PRINCIPAL_EXPIRY);
        }

        private String getPrincipalExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(metaDetails, emailPrincipalExpiryBody,
                    NOTIFICATION_DETAILS_MEMBER, NOTIFICATION_DETAILS_ROLES_LIST, 3);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(PRINCIPAL_EXPIRY_SUBJECT);
            String body = getPrincipalExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class GroupExpiryDomainNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/domain-group-member-expiry.html";
        private static final String DOMAIN_MEMBER_EXPIRY_SUBJECT = "athenz.notification.email.domain.group_member.expiry.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private final String emailDomainMemberExpiryBody;

        public GroupExpiryDomainNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailDomainMemberExpiryBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        private String getDomainMemberExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(metaDetails, emailDomainMemberExpiryBody,
                    NOTIFICATION_DETAILS_DOMAIN, NOTIFICATION_DETAILS_MEMBERS_LIST, 3);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(DOMAIN_MEMBER_EXPIRY_SUBJECT);
            String body = getDomainMemberExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class GroupExpiryPrincipalNotificationToToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "principal_group_membership_expiry";
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
                        METRIC_NOTIFICATION_GROUP_KEY, recordAttributes[1],
                        METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTime.toString(), recordAttributes[2])
                };

                attributes.add(metricRecord);
            }

            return new NotificationMetric(attributes);
        }
    }

    public static class GroupExpiryDomainNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "domain_group_membership_expiry";
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
                String[] metricRecord = new String[]{
                        METRIC_NOTIFICATION_TYPE_KEY, NOTIFICATION_TYPE,
                        METRIC_NOTIFICATION_DOMAIN_KEY, domain,
                        METRIC_NOTIFICATION_MEMBER_KEY, recordAttributes[0],
                        METRIC_NOTIFICATION_GROUP_KEY, recordAttributes[1],
                        METRIC_NOTIFICATION_EXPIRY_DAYS_KEY, notificationToMetricConverterCommon.getNumberOfDaysBetweenTimestamps(currentTime.toString(), recordAttributes[2])
                };

                attributes.add(metricRecord);
            }

            return new NotificationMetric(attributes);
        }
    }
}
