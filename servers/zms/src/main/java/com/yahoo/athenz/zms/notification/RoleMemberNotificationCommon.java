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
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;

public class RoleMemberNotificationCommon {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberNotificationCommon.class);

    private final DBService dbService;
    private final String userDomainPrefix;
    private final NotificationCommon notificationCommon;
    private final DomainRoleMembersFetcher domainRoleMembersFetcher;

    public RoleMemberNotificationCommon(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
        this.domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        DomainMetaFetcher domainMetaFetcher = new DomainMetaFetcher(dbService);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix, domainMetaFetcher);
    }

    public List<Notification> getNotificationDetails(Notification.Type type,
                                                     Map<String, DomainRoleMember> members,
                                                     NotificationToEmailConverter principalNotificationToEmailConverter,
                                                     NotificationToEmailConverter domainAdminNotificationToEmailConverter,
                                                     RoleMemberDetailStringer roleMemberDetailStringer,
                                                     NotificationToMetricConverter principalNotificationToMetricConverter,
                                                     NotificationToMetricConverter domainAdminNotificationToMetricConverter,
                                                     DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter) {

        return getNotificationDetails(type, Notification.ConsolidatedBy.PRINCIPAL, members,
                principalNotificationToEmailConverter, domainAdminNotificationToEmailConverter,
                roleMemberDetailStringer, principalNotificationToMetricConverter,
                domainAdminNotificationToMetricConverter, disableRoleMemberNotificationFilter,
                null, null);
    }

    public List<Notification> getNotificationDetails(Notification.Type type, Notification.ConsolidatedBy consolidatedBy,
                                                     Map<String, DomainRoleMember> members,
                                                     NotificationToEmailConverter principalNotificationToEmailConverter,
                                                     NotificationToEmailConverter domainAdminNotificationToEmailConverter,
                                                     RoleMemberDetailStringer roleMemberDetailStringer,
                                                     NotificationToMetricConverter principalNotificationToMetricConverter,
                                                     NotificationToMetricConverter domainAdminNotificationToMetricConverter,
                                                     DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter,
                                                     NotificationToSlackMessageConverter principalNotificationToSlackMessageConverter,
                                                     NotificationToSlackMessageConverter domainAdminNotificationToSlackMessageConverter) {

        // our members map contains three types of entries:
        //  1. human user: user.john-doe -> { expiring-roles }
        //  2. service-identity: athenz.api -> { expiring-roles }
        //  3. group: athenz:group.dev-team -> { expiring-roles }
        // currently we're notifying human users and all service identity
        // admins. for groups, we check if notify roles is configured and
        // if so we notify those roles members otherwise we notify the domain admins.
        // So for service-identity accounts - we need to extract the list
        // of human domain admins and combine them with human users so the
        // human users gets only a single notification.

        Map<String, DomainRoleMember> consolidatedMembers = new HashMap<>();

        if (Notification.ConsolidatedBy.DOMAIN.equals(consolidatedBy)) {
            consolidatedMembers = consolidateRoleMembersByDomain(members);
        } else if (Notification.ConsolidatedBy.PRINCIPAL.equals(consolidatedBy)) {
            consolidatedMembers = consolidateRoleMembers(members);
        }

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
                        type, consolidatedBy, principal, details, principalNotificationToEmailConverter,
                        principalNotificationToMetricConverter, principalNotificationToSlackMessageConverter);
                if (notification != null) {
                    notificationList.add(notification);
                }
            }
        }

        // now we're going to send reminders to all the domain/role administrators
        Map<String, DomainRoleMember> consolidatedDomainAdmins;

        if (Notification.ConsolidatedBy.DOMAIN.equals(consolidatedBy)) {
            consolidatedDomainAdmins = consolidateDomains(domainAdminMap);
        } else {
            consolidatedDomainAdmins = consolidateDomainAdmins(domainAdminMap);
        }

        for (String principal : consolidatedDomainAdmins.keySet()) {

            Map<String, String> details = processMemberReminder(consolidatedDomainAdmins.get(principal).getMemberRoles(),
                    roleMemberDetailStringer);
            if (!details.isEmpty()) {
                Notification notification = notificationCommon.createNotification(
                        type, consolidatedBy, principal, details, domainAdminNotificationToEmailConverter,
                        domainAdminNotificationToMetricConverter, domainAdminNotificationToSlackMessageConverter);
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
        // user -> add the roles to the list
        // service -> lookup domain admins for the service and add to the individual human users only
        // group -> lookup the configured notify roles users or domain admins (if no notify roles)
        //          and add to the individual human users only

        for (String principal : members.keySet()) {

            int idx = principal.indexOf(AuthorityConsts.GROUP_SEP);
            if (idx != -1) {
                final String domainName = principal.substring(0, idx);
                final String groupName = principal.substring(idx + AuthorityConsts.GROUP_SEP.length());
                Group group = dbService.getGroup(domainName, groupName, Boolean.FALSE, Boolean.FALSE);
                if (group == null) {
                    LOGGER.error("unable to retrieve group: {} in domain: {}", groupName, domainName);
                    continue;
                }
                Set<String> groupAdminMembers;
                if (!StringUtil.isEmpty(group.getNotifyRoles())) {
                    groupAdminMembers = NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                            domainName, group.getNotifyRoles());
                } else {
                    groupAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName, ADMIN_ROLE_NAME);
                }
                if (ZMSUtils.isCollectionEmpty(groupAdminMembers)) {
                    continue;
                }
                for (String groupAdminMember : groupAdminMembers) {
                    addRoleMembers(groupAdminMember, consolidatedMembers, members.get(principal).getMemberRoles());
                }
            } else {
                final String domainName = AthenzUtils.extractPrincipalDomainName(principal);
                if (userDomainPrefix.equals(domainName + ".")) {
                    addRoleMembers(principal, consolidatedMembers, members.get(principal).getMemberRoles());
                } else {

                    // domain role fetcher only returns the human users

                    Set<String> domainAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName, ADMIN_ROLE_NAME);
                    if (ZMSUtils.isCollectionEmpty(domainAdminMembers)) {
                        continue;
                    }
                    for (String domainAdminMember : domainAdminMembers) {
                        addRoleMembers(domainAdminMember, consolidatedMembers, members.get(principal).getMemberRoles());
                    }
                }
            }
        }

        return consolidatedMembers;
    }

    Map<String, DomainRoleMember> consolidateRoleMembersByDomain(Map<String, DomainRoleMember> members) {

        Map<String, DomainRoleMember> consolidatedMembers = new HashMap<>();

        // iterate through each principal. if the principal is:
        // user -> add the roles to the list
        // service -> add to domain name
        // group -> lookup the configured notify roles users, if no notify roles
        //          and add domain name

        for (String principal : members.keySet()) {

            int idx = principal.indexOf(AuthorityConsts.GROUP_SEP);
            if (idx != -1) {
                final String domainName = principal.substring(0, idx);
                final String groupName = principal.substring(idx + AuthorityConsts.GROUP_SEP.length());
                Group group = dbService.getGroup(domainName, groupName, Boolean.FALSE, Boolean.FALSE);
                if (group == null) {
                    LOGGER.error("unable to retrieve group: {} in domain: {}", groupName, domainName);
                    continue;
                }
                Set<String> groupRecipients;
                if (!StringUtil.isEmpty(group.getNotifyRoles())) {
                    groupRecipients = NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                            domainName, group.getNotifyRoles());
                } else {
                    groupRecipients = Collections.singleton(domainName);
                }
                if (ZMSUtils.isCollectionEmpty(groupRecipients)) {
                    continue;
                }
                for (String groupRecipient : groupRecipients) {
                    addRoleMembers(groupRecipient, consolidatedMembers, members.get(principal).getMemberRoles());
                }
            } else {
                final String domainName = AthenzUtils.extractPrincipalDomainName(principal);
                if (userDomainPrefix.equals(domainName + ".")) {
                    addRoleMembers(principal, consolidatedMembers, members.get(principal).getMemberRoles());
                } else {
                    // add domain of svc identity to the list
                    addRoleMembers(domainName, consolidatedMembers, members.get(principal).getMemberRoles());
                }
            }
        }

        return consolidatedMembers;
    }

    Map<String, DomainRoleMember> consolidateDomainAdmins(Map<String, List<MemberRole>> domainRoleMembers) {

        Map<String, DomainRoleMember> consolidatedDomainAdmins = new HashMap<>();

        // iterate through each domain and the roles within each domain.
        // if the role does not have the notify roles setup, then we'll
        // add the notifications to the domain admins otherwise we'll
        // add it to the configured notify roles members only

        for (String domainName : domainRoleMembers.keySet()) {

            List<MemberRole> roleMemberList = domainRoleMembers.get(domainName);
            if (ZMSUtils.isCollectionEmpty(roleMemberList)) {
                continue;
            }

            // domain role fetcher only returns the human users

            Set<String> domainAdminMembers = domainRoleMembersFetcher.getDomainRoleMembers(domainName, ADMIN_ROLE_NAME);

            for (MemberRole memberRole : roleMemberList) {

                // if we have a notify-roles configured then we're going to
                // extract the list of members from those roles, otherwise
                // we're going to use the domain admin members

                Set<String> roleAdminMembers;
                if (!StringUtil.isEmpty(memberRole.getNotifyRoles())) {
                    roleAdminMembers = NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                            memberRole.getDomainName(), memberRole.getNotifyRoles());
                } else {
                    roleAdminMembers = domainAdminMembers;
                }

                if (ZMSUtils.isCollectionEmpty(roleAdminMembers)) {
                    continue;
                }
                for (String roleAdminMember : roleAdminMembers) {
                    addRoleMembers(roleAdminMember, consolidatedDomainAdmins, Collections.singletonList(memberRole));
                }
            }
        }

        return consolidatedDomainAdmins;
    }

    Map<String, DomainRoleMember> consolidateDomains(Map<String, List<MemberRole>> domainRoleMembers) {

        Map<String, DomainRoleMember> consolidatedDomainAdmins = new HashMap<>();

        // iterate through each domain and the roles within each domain.
        // if the role does not have the notify roles setup, then we'll
        // add the notifications to the domain otherwise we'll
        // add it to the configured notify roles members only

        for (String domainName : domainRoleMembers.keySet()) {

            List<MemberRole> roleMemberList = domainRoleMembers.get(domainName);
            if (ZMSUtils.isCollectionEmpty(roleMemberList)) {
                continue;
            }

            for (MemberRole memberRole : roleMemberList) {

                // if we have a notify-roles configured then we're going to
                // extract the list of members from those roles, otherwise
                // we're going to use the domain name for consolidation

                Set<String> roleRecipient;
                if (!StringUtil.isEmpty(memberRole.getNotifyRoles())) {
                    roleRecipient = NotificationUtils.extractNotifyRoleMembers(domainRoleMembersFetcher,
                            memberRole.getDomainName(), memberRole.getNotifyRoles());
                } else {
                    roleRecipient = Collections.singleton(memberRole.getDomainName());
                }

                if (ZMSUtils.isCollectionEmpty(roleRecipient)) {
                    continue;
                }
                for (String recipient : roleRecipient) {
                    addRoleMembers(recipient, consolidatedDomainAdmins, Collections.singletonList(memberRole));
                }
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

    private Map<String, String> processRoleReminder(Map<String, List<MemberRole>> domainAdminMap,
                                                    DomainRoleMember member, RoleMemberDetailStringer roleMemberDetailStringer,
                                                    DisableRoleMemberNotificationFilter disableRoleMemberNotificationFilter) {

        Map<String, String> details = new HashMap<>();

        // each principal can have multiple roles in multiple domains that
        // it's part of thus multiple possible entries.
        // we're going to collect them into one string and separate
        // with | between those. The format will be:
        // memberRolesDetails := <role-entry>[|<role-entry]*
        // role-entry := <domain-name>;<role-name>;<member-name>;<expiration>

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

            // next we're going to update our domain/role admin map

            if (!disabledNotificationState.contains(DisableNotificationEnum.ADMIN)) {
                addDomainRoleMember(domainAdminMap, domainName, memberRole);
            }
        }
        if (memberRolesDetails.length() > 0) {
            details.put(NOTIFICATION_DETAILS_ROLES_LIST, memberRolesDetails.toString());
            details.put(NOTIFICATION_DETAILS_MEMBER, member.getMemberName());
        }

        return details;
    }

    private void addDomainRoleMember(Map<String, List<MemberRole>> domainAdminMap, final String domainName,
                                     MemberRole memberRole) {

        List<MemberRole> domainRoleMembers = domainAdminMap.computeIfAbsent(domainName, k -> new ArrayList<>());

        // make sure we don't have any duplicates

        for (MemberRole role : domainRoleMembers) {
            if (role.getRoleName().equals(memberRole.getRoleName())
                    && role.getMemberName().equals(memberRole.getMemberName())) {
                return;
            }
        }
        domainRoleMembers.add(memberRole);
    }

    Map<String, String> processMemberReminder(List<MemberRole> memberRoles, RoleMemberDetailStringer roleMemberDetailStringer) {

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
        }
        return details;
    }

    List<Notification> printNotificationDetailsToLog(List<Notification> notificationDetails, String description) {
        return notificationCommon.printNotificationDetailsToLog(notificationDetails, description);
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
