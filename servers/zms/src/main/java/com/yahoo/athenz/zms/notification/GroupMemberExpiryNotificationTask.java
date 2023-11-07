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

import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.common.server.util.ResourceUtils;
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
    private final String userDomainPrefix;
    private final boolean consolidatedNotifications;
    private final NotificationCommon notificationCommon;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;
    private static final Logger LOGGER = LoggerFactory.getLogger(GroupMemberExpiryNotificationTask.class);
    private final static String DESCRIPTION = "group membership expiration reminders";
    private final GroupExpiryDomainNotificationToEmailConverter groupExpiryDomainNotificationToEmailConverter;
    private final GroupExpiryPrincipalNotificationToEmailConverter groupExpiryPrincipalNotificationToEmailConverter;
    private final GroupExpiryDomainNotificationToMetricConverter groupExpiryDomainNotificationToMetricConverter;
    private final GroupExpiryPrincipalNotificationToToMetricConverter groupExpiryPrincipalNotificationToToMetricConverter;

    private final static String[] TEMPLATE_COLUMN_NAMES = { "DOMAIN", "GROUP", "MEMBER", "EXPIRATION" };

    public GroupMemberExpiryNotificationTask(DBService dbService, String userDomainPrefix,
            NotificationToEmailConverterCommon notificationToEmailConverterCommon, boolean consolidatedNotifications) {

        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
        this.consolidatedNotifications = consolidatedNotifications;
        this.domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
        this.groupExpiryPrincipalNotificationToEmailConverter =
                new GroupExpiryPrincipalNotificationToEmailConverter(notificationToEmailConverterCommon);
        this.groupExpiryDomainNotificationToEmailConverter =
                new GroupExpiryDomainNotificationToEmailConverter(notificationToEmailConverterCommon);
        this.groupExpiryPrincipalNotificationToToMetricConverter
                = new GroupExpiryPrincipalNotificationToToMetricConverter();
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

        List<Notification> notificationDetails = getNotificationDetails(
                expiryMembers,
                groupExpiryPrincipalNotificationToEmailConverter,
                groupExpiryDomainNotificationToEmailConverter,
                groupExpiryPrincipalNotificationToToMetricConverter,
                groupExpiryDomainNotificationToMetricConverter);
        return notificationCommon.printNotificationDetailsToLog(notificationDetails, DESCRIPTION, LOGGER);
    }

    public StringBuilder getDetailString(GroupMember memberGroup) {
        StringBuilder detailsRow = new StringBuilder(256);
        detailsRow.append(memberGroup.getDomainName()).append(';');
        detailsRow.append(memberGroup.getGroupName()).append(';');
        detailsRow.append(memberGroup.getMemberName()).append(';');
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
        if (ZMSUtils.isCollectionEmpty(memberGroups)) {
            return details;
        }

        StringBuilder memberGroupsDetails = new StringBuilder(256);
        for (GroupMember memberGroup : memberGroups) {
            EnumSet<DisableNotificationEnum> disabledNotificationState = getDisabledNotificationState(memberGroup);
            if (disabledNotificationState.containsAll(Arrays.asList(DisableNotificationEnum.ADMIN, DisableNotificationEnum.USER))) {
                LOGGER.info("Notification disabled for group {}, domain {}", memberGroup.getGroupName(), memberGroup.getDomainName());
                continue;
            }

            // check to see if the administrator has configured to generate notifications
            // only for members that are expiring in less than a week

            if (disabledNotificationState.contains(DisableNotificationEnum.OVER_ONE_WEEK)) {
                Timestamp notificationTimestamp = memberGroup.getExpiration();
                if (notificationTimestamp == null || notificationTimestamp.millis() - System.currentTimeMillis() > NotificationUtils.WEEK_EXPIRY_CHECK) {
                    LOGGER.info("Notification skipped for group {}, domain {}, notification date is more than a week way",
                            memberGroup.getGroupName(), memberGroup.getDomainName());
                    continue;
                }
            }

            final String domainName = memberGroup.getDomainName();

            // first we're going to update our expiry details string

            if (!disabledNotificationState.contains(DisableNotificationEnum.USER)) {
                if (memberGroupsDetails.length() != 0) {
                    memberGroupsDetails.append('|');
                }
                memberGroupsDetails.append(getDetailString(memberGroup));
            }

            // next we're going to update our domain admin map

            if (!disabledNotificationState.contains(DisableNotificationEnum.ADMIN)) {
                List<GroupMember> domainGroupMembers = domainAdminMap.computeIfAbsent(domainName, k -> new ArrayList<>());
                domainGroupMembers.add(memberGroup);
            }
        }
        if (memberGroupsDetails.length() > 0) {
            details.put(NOTIFICATION_DETAILS_ROLES_LIST, memberGroupsDetails.toString());
            details.put(NOTIFICATION_DETAILS_MEMBER, member.getMemberName());
        }

        return details;
    }

    EnumSet<DisableNotificationEnum> getDisabledNotificationState(GroupMember memberGroup) {

        Group group = dbService.getGroup(memberGroup.getDomainName(), memberGroup.getGroupName(), false, false);
        try {
            // for groups, we're going to check the disabled expiration notification tag, and
            // if it's not set, we're going to honor the disabled reminder notification tag

            EnumSet<DisableNotificationEnum> enumSet = DisableNotificationEnum.getDisabledNotificationState(
                    group, Group::getTags, ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG);
            if (enumSet.isEmpty()) {
                enumSet = DisableNotificationEnum.getDisabledNotificationState(group, Group::getTags,
                        ZMSConsts.DISABLE_REMINDER_NOTIFICATIONS_TAG);
            }
            return enumSet;
        } catch (NumberFormatException ex) {
            LOGGER.error("Invalid mask value for {}/{} tags in domain {}, group {}",
                    ZMSConsts.DISABLE_EXPIRATION_NOTIFICATIONS_TAG, ZMSConsts.DISABLE_REMINDER_NOTIFICATIONS_TAG,
                    memberGroup.getDomainName(), memberGroup.getGroupName());
        }

        return DisableNotificationEnum.getEnumSet(0);
    }

    Map<String, String> processMemberReminder(final String domainName, List<GroupMember> memberGroups) {

        Map<String, String> details = new HashMap<>();

        // each domain can have multiple members that are about
        // to expire to we're going to collect them into one
        // string and separate with | between those. The format will be:
        // memberDetails := <member-entry>[|<member-entry]*
        // member-entry := <member-name>;<group-name>;<expiration>

        if (ZMSUtils.isCollectionEmpty(memberGroups)) {
            return details;
        }

        StringBuilder memberDetails = new StringBuilder(256);
        for (GroupMember memberGroup : memberGroups) {

            // first we're going to update our expiry details string

            if (memberDetails.length() != 0) {
                memberDetails.append('|');
            }
            memberDetails.append(getDetailString(memberGroup));
        }

        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST, memberDetails.toString());
        if (domainName != null) {
            details.put(NOTIFICATION_DETAILS_DOMAIN, domainName);
        }
        return details;
    }

    List<Notification> getNotificationDetails(Map<String, DomainGroupMember> members,
            NotificationToEmailConverter principalNotificationToEmailConverter,
            NotificationToEmailConverter domainAdminNotificationToEmailConverter,
            NotificationToMetricConverter principalNotificationToMetricConverter,
            NotificationToMetricConverter domainAdminNotificationToMetricConverter) {

        if (consolidatedNotifications) {
            return getConsolidatedNotificationDetails(members, principalNotificationToEmailConverter,
                    domainAdminNotificationToEmailConverter, principalNotificationToMetricConverter,
                    domainAdminNotificationToMetricConverter);
        } else {
            return getIndividualNotificationDetails(members, principalNotificationToEmailConverter,
                    domainAdminNotificationToEmailConverter, principalNotificationToMetricConverter,
                    domainAdminNotificationToMetricConverter);
        }
    }

    List<Notification> getConsolidatedNotificationDetails(Map<String, DomainGroupMember> members,
            NotificationToEmailConverter principalNotificationToEmailConverter,
            NotificationToEmailConverter domainAdminNotificationToEmailConverter,
            NotificationToMetricConverter principalNotificationToMetricConverter,
            NotificationToMetricConverter domainAdminNotificationToMetricConverter) {

        // our members map contains three two of entries:
        //  1. human user: user.john-doe -> { expiring-roles }
        //  2. service-identity: athenz.api -> { expiring-roles }
        // So for service-identity accounts - we need to extract the list
        // of human domain admins and combine them with human users so the
        // human users gets only a single notification.

        Map<String, DomainGroupMember> consolidatedMembers = consolidateGroupMembers(members);

        List<Notification> notificationList = new ArrayList<>();
        Map<String, List<GroupMember>> domainAdminMap = new HashMap<>();

        for (String principal : consolidatedMembers.keySet()) {

            // we're going to process the role member, update
            // our domain admin map accordingly and return
            // the details object that we need to send to the
            // notification agent for processing

            Map<String, String> details = processGroupReminder(domainAdminMap, consolidatedMembers.get(principal));
            if (!details.isEmpty()) {
                Notification notification = notificationCommon.createNotification(
                        principal, details, principalNotificationToEmailConverter,
                        principalNotificationToMetricConverter);
                if (notification != null) {
                    notificationList.add(notification);
                }
            }
        }

        // now we're going to send reminders to all the domain administrators

        Map<String, DomainGroupMember> consolidatedDomainAdmins = consolidateDomainAdmins(domainAdminMap);

        for (String principal : consolidatedDomainAdmins.keySet()) {

            Map<String, String> details = processMemberReminder(null, consolidatedDomainAdmins.get(principal).getMemberGroups());
            Notification notification = notificationCommon.createNotification(
                    principal, details, domainAdminNotificationToEmailConverter,
                    domainAdminNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        return notificationList;
    }

    List<Notification> getIndividualNotificationDetails(Map<String, DomainGroupMember> members,
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
            if (!details.isEmpty()) {
                Notification notification = notificationCommon.createNotification(
                        groupMember.getMemberName(), details, principalNotificationToEmailConverter, principalNotificationToMetricConverter);
                if (notification != null) {
                    notificationList.add(notification);
                }
            }
        }

        // now we're going to send reminders to all the domain administrators

        for (Map.Entry<String, List<GroupMember>> domainAdmin : domainAdminMap.entrySet()) {

            Map<String, String> details = processMemberReminder(domainAdmin.getKey(), domainAdmin.getValue());
            Notification notification = notificationCommon.createNotification(
                    ResourceUtils.roleResourceName(domainAdmin.getKey(), ADMIN_ROLE_NAME),
                    details, domainAdminNotificationToEmailConverter, domainAdminNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        return notificationList;
    }

    Map<String, DomainGroupMember> consolidateGroupMembers(Map<String, DomainGroupMember> members) {

        Map<String, DomainGroupMember> consolidatedMembers = new HashMap<>();

        // iterate through each principal. if the principal is:
        // user -> as the roles to the list
        // service -> lookup domain admins for the service and add to the individual human users only

        for (String principal : members.keySet()) {

            final String domainName = AthenzUtils.extractPrincipalDomainName(principal);
            if (userDomainPrefix.equals(domainName + ".")) {
                addGroupMembers(principal, consolidatedMembers, members.get(principal).getMemberGroups());
            } else {
                // domain role fetcher only returns the human users

                Set<String> domainAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName,
                        ResourceUtils.roleResourceName(domainName, ADMIN_ROLE_NAME));
                if (ZMSUtils.isCollectionEmpty(domainAdminMembers)) {
                    continue;
                }
                for (String domainAdminMember : domainAdminMembers) {
                    addGroupMembers(domainAdminMember, consolidatedMembers, members.get(principal).getMemberGroups());
                }
            }
        }

        return consolidatedMembers;
    }

    Map<String, DomainGroupMember> consolidateDomainAdmins(Map<String, List<GroupMember>> domainGroupMembers) {

        Map<String, DomainGroupMember> consolidatedDomainAdmins = new HashMap<>();

        // iterate through each principal. if the principal is:
        // user -> as the roles to the list
        // service -> lookup domain admins for the service and add to the individual human users only
        // group -> skip

        for (String domainName : domainGroupMembers.keySet()) {

            // domain role fetcher only returns the human users

            Set<String> domainAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName,
                    ResourceUtils.roleResourceName(domainName, ADMIN_ROLE_NAME));
            if (ZMSUtils.isCollectionEmpty(domainAdminMembers)) {
                continue;
            }
            for (String domainAdminMember : domainAdminMembers) {
                addGroupMembers(domainAdminMember, consolidatedDomainAdmins, domainGroupMembers.get(domainName));
            }
        }

        return consolidatedDomainAdmins;
    }

    void addGroupMembers(final String consolidatedPrincipal, Map<String, DomainGroupMember> consolidatedMembers,
                        List<GroupMember> groupMemberList) {
        DomainGroupMember groupMembers = consolidatedMembers.computeIfAbsent(consolidatedPrincipal,
                k -> new DomainGroupMember().setMemberName(consolidatedPrincipal).setMemberGroups(new ArrayList<>()));
        if (!ZMSUtils.isCollectionEmpty(groupMemberList)) {
            groupMembers.getMemberGroups().addAll(groupMemberList);
        }
    }

    public static class GroupExpiryPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_EXPIRY = "messages/group-member-expiry.html";
        private static final String PRINCIPAL_EXPIRY_SUBJECT = "athenz.notification.email.group_member.expiry.subject";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private final String emailPrincipalExpiryBody;

        public GroupExpiryPrincipalNotificationToEmailConverter(NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
            this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
            emailPrincipalExpiryBody =  notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_PRINCIPAL_EXPIRY);
        }

        private String getPrincipalExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(metaDetails, emailPrincipalExpiryBody,
                    NOTIFICATION_DETAILS_MEMBER, NOTIFICATION_DETAILS_ROLES_LIST,
                    TEMPLATE_COLUMN_NAMES.length, TEMPLATE_COLUMN_NAMES);
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

        public GroupExpiryDomainNotificationToEmailConverter(NotificationToEmailConverterCommon notificationToEmailConverterCommon) {
            this.notificationToEmailConverterCommon = notificationToEmailConverterCommon;
            emailDomainMemberExpiryBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        private String getDomainMemberExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(metaDetails, emailDomainMemberExpiryBody,
                    NOTIFICATION_DETAILS_DOMAIN, NOTIFICATION_DETAILS_MEMBERS_LIST,
                    TEMPLATE_COLUMN_NAMES.length, TEMPLATE_COLUMN_NAMES);
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

            return NotificationUtils.getNotificationAsMetrics(notification, currentTime, NOTIFICATION_TYPE,
                    NOTIFICATION_DETAILS_ROLES_LIST, METRIC_NOTIFICATION_GROUP_KEY, METRIC_NOTIFICATION_EXPIRY_DAYS_KEY,
                    notificationToMetricConverterCommon);
        }
    }

    public static class GroupExpiryDomainNotificationToMetricConverter implements NotificationToMetricConverter {
        private final static String NOTIFICATION_TYPE = "domain_group_membership_expiry";
        private final NotificationToMetricConverterCommon notificationToMetricConverterCommon = new NotificationToMetricConverterCommon();

        @Override
        public NotificationMetric getNotificationAsMetrics(Notification notification, Timestamp currentTime) {

            return NotificationUtils.getNotificationAsMetrics(notification, currentTime, NOTIFICATION_TYPE,
                    NOTIFICATION_DETAILS_MEMBERS_LIST, METRIC_NOTIFICATION_GROUP_KEY, METRIC_NOTIFICATION_EXPIRY_DAYS_KEY,
                    notificationToMetricConverterCommon);
        }
    }
}
