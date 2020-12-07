/*
 *  Copyright 2020 Verizon Media
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

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.athenz.zms.utils.ZMSUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.yahoo.athenz.common.ServerCommonConsts.ADMIN_ROLE_NAME;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;

public class RoleMemberNotificationCommon {
    private final NotificationCommon notificationCommon;

    public RoleMemberNotificationCommon(DBService dbService, String userDomainPrefix) {
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(domainRoleMembersFetcher, userDomainPrefix);
    }

    public List<Notification> getNotificationDetails(Map<String, DomainRoleMember> members,
                                                     NotificationToEmailConverter principalNotificationToEmailConverter,
                                                     NotificationToEmailConverter domainAdminNotificationToEmailConverter,
                                                     RoleMemberDetailStringer roleMemberDetailStringer,
                                                     NotificationToMetricConverter principalNotificationToMetricConverter,
                                                     NotificationToMetricConverter domainAdminNotificationToMetricConverter) {
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

            Map<String, String> details = processRoleReminder(domainAdminMap, roleMember, roleMemberDetailStringer);
            Notification notification = notificationCommon.createNotification(
                    roleMember.getMemberName(),
                    details,
                    principalNotificationToEmailConverter,
                    principalNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        // now we're going to send reminders to all the domain administrators

        for (Map.Entry<String, List<MemberRole>> domainAdmin : domainAdminMap.entrySet()) {

            Map<String, String> details = processMemberReminder(domainAdmin.getKey(), domainAdmin.getValue(), roleMemberDetailStringer);
            Notification notification = notificationCommon.createNotification(
                    ZMSUtils.roleResourceName(domainAdmin.getKey(), ADMIN_ROLE_NAME),
                    details,
                    domainAdminNotificationToEmailConverter,
                    domainAdminNotificationToMetricConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        return notificationList;
    }

    private Map<String, String> processRoleReminder(Map<String, List<MemberRole>> domainAdminMap,
                                                   DomainRoleMember member,
                                                   RoleMemberDetailStringer roleMemberDetailStringer) {

        Map<String, String> details = new HashMap<>();

        // each principal can have multiple roles in multiple domains that
        // it's part of thus multiple possible entries.
        // we're going to collect them into one string and separate
        // with | between those. The format will be:
        // memberRolesDetails := <role-entry>[|<role-entry]*
        // role-entry := <domain-name>;<role-name>;<expiration>

        final List<MemberRole> memberRoles = member.getMemberRoles();
        if (memberRoles == null || memberRoles.isEmpty()) {
            return details;
        }

        StringBuilder memberRolesDetails = new StringBuilder(256);
        for (MemberRole memberRole : memberRoles) {

            final String domainName = memberRole.getDomainName();

            // first we're going to update our expiry details string

            if (memberRolesDetails.length() != 0) {
                memberRolesDetails.append('|');
            }

            memberRolesDetails.append(domainName).append(';');
            memberRolesDetails.append(roleMemberDetailStringer.getDetailString(memberRole));

            // next we're going to update our domain admin map

            List<MemberRole> domainRoleMembers = domainAdminMap.computeIfAbsent(domainName, k -> new ArrayList<>());
            domainRoleMembers.add(memberRole);
        }
        details.put(NOTIFICATION_DETAILS_ROLES_LIST, memberRolesDetails.toString());
        details.put(NOTIFICATION_DETAILS_MEMBER, member.getMemberName());

        return details;
    }

    private Map<String, String> processMemberReminder(final String domainName,
                                                     List<MemberRole> memberRoles,
                                                     RoleMemberDetailStringer roleMemberDetailStringer) {

        Map<String, String> details = new HashMap<>();

        // each domain can have multiple members that are about
        // to expire to we're going to collect them into one
        // string and separate with | between those. The format will be:
        // memberDetails := <member-entry>[|<member-entry]*
        // member-entry := <member-name>;<role-name>;<expiration>

        if (memberRoles == null || memberRoles.isEmpty()) {
            return details;
        }

        StringBuilder memberDetails = new StringBuilder(256);
        for (MemberRole memberRole : memberRoles) {

            // first we're going to update our expiry details string

            if (memberDetails.length() != 0) {
                memberDetails.append('|');
            }

            memberDetails.append(memberRole.getMemberName()).append(';');
            memberDetails.append(roleMemberDetailStringer.getDetailString(memberRole));
        }
        details.put(NOTIFICATION_DETAILS_MEMBERS_LIST, memberDetails.toString());
        details.put(NOTIFICATION_DETAILS_DOMAIN, domainName);
        return details;
    }

    /**
     * Extract attributes from memberRole and convert them to a detail string.
     */
    public interface RoleMemberDetailStringer {
        /**
         *
         * @param memberRole member role
         * @return Details extracted from the memberRole with a semi-colon (;) between them
         * These details should fit in the notification template (for example, the html of an email body)
         */
        StringBuilder getDetailString(MemberRole memberRole);

    }
}
