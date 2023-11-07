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

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;

public class RoleMemberNotificationCommon {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberNotificationCommon.class);

    private final String userDomainPrefix;
    private final boolean consolidatedNotifications;
    private final NotificationCommon notificationCommon;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;

    public RoleMemberNotificationCommon(DBService dbService, String userDomainPrefix, boolean consolidatedNotifications) {
        this.userDomainPrefix = userDomainPrefix;
        this.consolidatedNotifications = consolidatedNotifications;
        this.domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
    }

    public List<Notification> getNotificationDetails(Map<String, DomainRoleMember> members,
            NotificationToEmailConverter principalNotificationToEmailConverter,
            NotificationToEmailConverter domainAdminNotificationToEmailConverter,
            RoleMemberDetailStringer roleMemberDetailStringer,
            NotificationToMetricConverter principalNotificationToMetricConverter,
            NotificationToMetricConverter domainAdminNotificationToMetricConverter,
            DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter) {

            if (consolidatedNotifications) {
                return getConsolidatedNotificationDetails(members, principalNotificationToEmailConverter,
                        domainAdminNotificationToEmailConverter, roleMemberDetailStringer,
                        principalNotificationToMetricConverter, domainAdminNotificationToMetricConverter,
                        disableRoleMemberNotificationFilter);
            } else {
                return getIndividualNotificationDetails(members, principalNotificationToEmailConverter,
                        domainAdminNotificationToEmailConverter, roleMemberDetailStringer,
                        principalNotificationToMetricConverter, domainAdminNotificationToMetricConverter,
                        disableRoleMemberNotificationFilter);
            }
    }

    public List<Notification> getConsolidatedNotificationDetails(Map<String, DomainRoleMember> members,
            NotificationToEmailConverter principalNotificationToEmailConverter,
            NotificationToEmailConverter domainAdminNotificationToEmailConverter,
            RoleMemberDetailStringer roleMemberDetailStringer,
            NotificationToMetricConverter principalNotificationToMetricConverter,
            NotificationToMetricConverter domainAdminNotificationToMetricConverter,
            DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter) {

        // our members map contains three types of entries:
        //  1. human user: user.john-doe -> { expiring-roles }
        //  2. service-identity: athenz.api -> { expiring-roles }
        //  3. group: athenz:group.dev-team -> { expiring-roles }
        // currently we're notifying human users and all service identity
        // admins. we skip group notifications because the group owner
        // is not the one requesting access and the domain admin notification
        // recipient should handle those.
        // So for service-identity accounts - we need to extract the list
        // of human domain admins and combine them with human users so the
        // human users gets only a single notification.

        Map<String, DomainRoleMember> consolidatedMembers = consolidateRoleMembers(members);

        // first we're going to send reminders to all the members indicating to
        // them that they're going to expiry (or nearing review date) and they should follow up with
        // domain admins to extend their membership.

        List<Notification> notificationList = new ArrayList<>();
        Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();

        for (String principal : consolidatedMembers.keySet()) {

            // we're going to process the role member, update
            // our domain admin map accordingly and return
            // the details object that we need to send to the
            // notification agent for processing

            Map<String, String> details = processRoleReminder(domainAdminMap, consolidatedMembers.get(principal),
                    roleMemberDetailStringer, disableRoleMemberNotificationFilter);
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

        Map<String, DomainRoleMember> consolidatedDomainAdmins = consolidateDomainAdmins(domainAdminMap);

        for (String principal : consolidatedDomainAdmins.keySet()) {

            Map<String, String> details = processMemberReminder(null,
                    consolidatedDomainAdmins.get(principal).getMemberRoles(), roleMemberDetailStringer);
            if (!details.isEmpty()) {
                Notification notification = notificationCommon.createNotification(
                        principal, details, domainAdminNotificationToEmailConverter,
                        domainAdminNotificationToMetricConverter);
                if (notification != null) {
                    notificationList.add(notification);
                }
            }
        }

        return notificationList;
    }

    Map<String, DomainRoleMember> consolidateRoleMembers(Map<String, DomainRoleMember> members) {

        Map<String, DomainRoleMember> consolidatedMembers = new HashMap<>();

        // iterate through each principal. if the principal is:
        // user -> as the roles to the list
        // service -> lookup domain admins for the service and add to the individual human users only
        // group -> skip

        for (String principal : members.keySet()) {

            if (principal.contains(AuthorityConsts.GROUP_SEP)) {
                continue;
            }
            final String domainName = AthenzUtils.extractPrincipalDomainName(principal);
            if (userDomainPrefix.equals(domainName + ".")) {
                addRoleMembers(principal, consolidatedMembers, members.get(principal).getMemberRoles());
            } else {

                // domain role fetcher only returns the human users

                Set<String> domainAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName,
                        ResourceUtils.roleResourceName(domainName, ADMIN_ROLE_NAME));
                if (ZMSUtils.isCollectionEmpty(domainAdminMembers)) {
                    continue;
                }
                for (String domainAdminMember : domainAdminMembers) {
                    addRoleMembers(domainAdminMember, consolidatedMembers, members.get(principal).getMemberRoles());
                }
            }
        }

        return consolidatedMembers;
    }

    Map<String, DomainRoleMember> consolidateDomainAdmins(Map<String, List<MemberRole>> domainRoleMembers) {

        Map<String, DomainRoleMember> consolidatedDomainAdmins = new HashMap<>();

        // iterate through each principal. if the principal is:
        // user -> as the roles to the list
        // service -> lookup domain admins for the service and add to the individual human users only
        // group -> skip

        for (String domainName : domainRoleMembers.keySet()) {

            // domain role fetcher only returns the human users

            Set<String> domainAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName,
                    ResourceUtils.roleResourceName(domainName, ADMIN_ROLE_NAME));
            if (ZMSUtils.isCollectionEmpty(domainAdminMembers)) {
                continue;
            }
            for (String domainAdminMember : domainAdminMembers) {
                addRoleMembers(domainAdminMember, consolidatedDomainAdmins, domainRoleMembers.get(domainName));
            }
        }

        return consolidatedDomainAdmins;
    }

    void addRoleMembers(final String consolidatedPrincipal, Map<String, DomainRoleMember> consolidatedMembers,
                        List<MemberRole> roleMemberList) {
        DomainRoleMember roleMembers = consolidatedMembers.computeIfAbsent(consolidatedPrincipal,
                k -> new DomainRoleMember().setMemberName(consolidatedPrincipal).setMemberRoles(new ArrayList<>()));
        if (!ZMSUtils.isCollectionEmpty(roleMemberList)) {
            roleMembers.getMemberRoles().addAll(roleMemberList);
        }
    }

    public List<Notification> getIndividualNotificationDetails(Map<String, DomainRoleMember> members,
            NotificationToEmailConverter principalNotificationToEmailConverter,
            NotificationToEmailConverter domainAdminNotificationToEmailConverter,
            RoleMemberDetailStringer roleMemberDetailStringer,
            NotificationToMetricConverter principalNotificationToMetricConverter,
            NotificationToMetricConverter domainAdminNotificationToMetricConverter,
            DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter) {

        // first we're going to send reminders to all the members indicating to
        // them that they're going to expiry (or nearing review date) and they should follow up with
        // domain admins to extend their membership.
        // if the principal is service then we're going to send the reminder
        // to the domain admins of that service
        // while doing this we're going to keep track of all domains that
        // have members that are about to expire (or pass their review date) and then send them a reminder
        // as well indicating that they have members with coming-up expiration

        List<Notification> notificationList = new ArrayList<>();
        Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();

        for (DomainRoleMember roleMember : members.values()) {

            // we're going to process the role member, update
            // our domain admin map accordingly and return
            // the details object that we need to send to the
            // notification agent for processing

            Map<String, String> details = processRoleReminder(domainAdminMap, roleMember, roleMemberDetailStringer,
                    disableRoleMemberNotificationFilter);
            if (!details.isEmpty()) {
                Notification notification = notificationCommon.createNotification(
                        roleMember.getMemberName(), details, principalNotificationToEmailConverter,
                        principalNotificationToMetricConverter);
                if (notification != null) {
                    notificationList.add(notification);
                }
            }
        }

        // now we're going to send reminders to all the domain administrators

        for (Map.Entry<String, List<MemberRole>> domainAdmin : domainAdminMap.entrySet()) {

            Map<String, String> details = processMemberReminder(domainAdmin.getKey(), domainAdmin.getValue(),
                    roleMemberDetailStringer);
            if (!details.isEmpty()) {
                Notification notification = notificationCommon.createNotification(
                        ResourceUtils.roleResourceName(domainAdmin.getKey(), ADMIN_ROLE_NAME),
                        details, domainAdminNotificationToEmailConverter, domainAdminNotificationToMetricConverter);
                if (notification != null) {
                    notificationList.add(notification);
                }
            }
        }

        return notificationList;
    }

    private Map<String, String> processRoleReminder(Map<String, List<MemberRole>> domainAdminMap,
            DomainRoleMember member, RoleMemberDetailStringer roleMemberDetailStringer,
            DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter) {

        Map<String, String> details = new HashMap<>();

        // each principal can have multiple roles in multiple domains that
        // it's part of thus multiple possible entries.
        // we're going to collect them into one string and separate
        // with | between those. The format will be:
        // memberRolesDetails := <role-entry>[|<role-entry]*
        // role-entry := <domain-name>;<role-name>;<expiration>

        final List<MemberRole> memberRoles = member.getMemberRoles();
        if (ZMSUtils.isCollectionEmpty(memberRoles)) {
            return details;
        }

        StringBuilder memberRolesDetails = new StringBuilder(256);
        for (MemberRole memberRole : memberRoles) {
            EnumSet<DisableNotificationEnum> disabledNotificationState =
                    disableRoleMemberNotificationFilter.getDisabledNotificationState(memberRole);
            if (disabledNotificationState.containsAll(Arrays.asList(DisableNotificationEnum.ADMIN, DisableNotificationEnum.USER))) {
                LOGGER.info("Notification disabled for role {}, domain {}", memberRole.getRoleName(), memberRole.getDomainName());
                continue;
            }

            // check to see if the administrator has configured to generate notifications
            // only for members that are expiring in less than a week

            if (disabledNotificationState.contains(DisableNotificationEnum.OVER_ONE_WEEK)) {
                Timestamp notificationTimestamp = roleMemberDetailStringer.getNotificationTimestamp(memberRole);
                if (notificationTimestamp == null || notificationTimestamp.millis() - System.currentTimeMillis() > NotificationUtils.WEEK_EXPIRY_CHECK) {
                    LOGGER.info("Notification skipped for role {}, domain {}, notification date is more than a week way",
                            memberRole.getRoleName(), memberRole.getDomainName());
                    continue;
                }
            }

            final String domainName = memberRole.getDomainName();

            // first we're going to update our expiry details string

            if (!disabledNotificationState.contains(DisableNotificationEnum.USER)) {
                if (memberRolesDetails.length() != 0) {
                    memberRolesDetails.append('|');
                }
                memberRolesDetails.append(roleMemberDetailStringer.getDetailString(memberRole));
            }

            // next we're going to update our domain admin map

            if (!disabledNotificationState.contains(DisableNotificationEnum.ADMIN)) {
                List<MemberRole> domainRoleMembers = domainAdminMap.computeIfAbsent(domainName, k -> new ArrayList<>());
                domainRoleMembers.add(memberRole);
            }
        }
        if (memberRolesDetails.length() > 0) {
            details.put(NOTIFICATION_DETAILS_ROLES_LIST, memberRolesDetails.toString());
            details.put(NOTIFICATION_DETAILS_MEMBER, member.getMemberName());
        }

        return details;
    }

    Map<String, String> processMemberReminder(final String domainName, List<MemberRole> memberRoles,
            RoleMemberDetailStringer roleMemberDetailStringer) {

        Map<String, String> details = new HashMap<>();

        // each domain can have multiple members that are about
        // to expire to we're going to collect them into one
        // string and separate with | between those. The format will be:
        // memberDetails := <member-entry>[|<member-entry]*
        // member-entry := <member-name>;<role-name>;<expiration>

        if (ZMSUtils.isCollectionEmpty(memberRoles)) {
            return details;
        }

        StringBuilder memberDetails = new StringBuilder(256);
        for (MemberRole memberRole : memberRoles) {

            // first we're going to update our expiry details string

            if (memberDetails.length() != 0) {
                memberDetails.append('|');
            }

            memberDetails.append(roleMemberDetailStringer.getDetailString(memberRole));
        }
        if (memberDetails.length() > 0) {
            details.put(NOTIFICATION_DETAILS_MEMBERS_LIST, memberDetails.toString());
            if (domainName != null) {
                details.put(NOTIFICATION_DETAILS_DOMAIN, domainName);
            }
        }
        return details;
    }

    List<Notification> printNotificationDetailsToLog(List<Notification> notificationDetails, String description, Logger logger) {
        return notificationCommon.printNotificationDetailsToLog(notificationDetails, description, logger);
    }

    /**
     * Extract attributes from memberRole and convert them to a detail string.
     */
    public interface RoleMemberDetailStringer {
        /**
         * Get the details extracted from the memberRole with a semicolon (;) between them
         * These details should fit in the notification template (for example, the html of an email body)
         * @param memberRole member role
         * @return StringBuilder object that contains details
         */
        StringBuilder getDetailString(MemberRole memberRole);

        /**
         * Returns the notification date (expiry or review date) for a given role
         * @param memberRole member role
         * @return notification date
         */
        Timestamp getNotificationTimestamp(MemberRole memberRole);
    }

    /**
     * Decide if notifications should be disabled for user / admin / both / none
     */
    public interface DisableRoleMemberNotificationFilter {
        /**
         * Gets disabled notifications state for memberRole
         * @param memberRole - principal / domain / role to check
         * @return DisableNotificationEnum enum set
         */
        EnumSet<DisableNotificationEnum> getDisabledNotificationState(MemberRole memberRole);
    }
}
