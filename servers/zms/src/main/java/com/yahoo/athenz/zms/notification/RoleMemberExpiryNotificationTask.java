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
import com.yahoo.athenz.zms.DomainRoleMember;
import com.yahoo.athenz.zms.MemberRole;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_DETAILS_EXPIRY_MEMBERS;

public class RoleMemberExpiryNotificationTask implements NotificationTask {
    private final DBService dbService;
    private final NotificationCommon notificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberExpiryNotificationTask.class);
    private final static String DESCRIPTION = "membership expiration reminders";
    private final RoleExpiryDomainNotificationToEmailConverter roleExpiryDomainNotificationToEmailConverter;
    private final RoleExpiryPrincipalNotificationToEmailConverter roleExpiryPrincipalNotificationToEmailConverter;

    public RoleMemberExpiryNotificationTask(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        ZMSDomainRoleMembersFetcher zmsDomainRoleMembersFetcher = new ZMSDomainRoleMembersFetcher(dbService, userDomainPrefix);
        this.notificationCommon = new NotificationCommon(zmsDomainRoleMembersFetcher, userDomainPrefix);
        this.roleExpiryPrincipalNotificationToEmailConverter = new RoleExpiryPrincipalNotificationToEmailConverter();
        this.roleExpiryDomainNotificationToEmailConverter = new RoleExpiryDomainNotificationToEmailConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        // first we're going to send reminders to all the members indicating to
        // them that they're going to expiry and they should follow up with
        // domain admins to extend their membership.
        // if the principal is service then we're going to send the reminder
        // to the domain admins of that service
        // while doing this we're going to keep track of all domains that
        // have members that are about to expire and then send them a reminder
        // as well indicating that they have members with coming-up expiration

        List<Notification> notificationList = new ArrayList<>();
        Map<String, DomainRoleMember> expiryMembers = dbService.getRoleExpiryMembers();
        if (expiryMembers == null || expiryMembers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No expiry members available to send notifications");
            }
            return notificationList;
        }

        Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();

        for (DomainRoleMember roleMember : expiryMembers.values()) {

            // we're going to process the role member, update
            // our domain admin map accordingly and return
            // the details object that we need to send to the
            // notification agent for processing

            Map<String, String> details = processRoleExpiryReminder(domainAdminMap, roleMember);
            Notification notification = notificationCommon.createNotification(
                    roleMember.getMemberName(),
                    details,
                    roleExpiryPrincipalNotificationToEmailConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        // now we're going to send reminders to all the domain administrators
        // to make sure they're aware of upcoming principal expirations

        for (Map.Entry<String, List<MemberRole>> domainAdmin : domainAdminMap.entrySet()) {

            Map<String, String> details = processMemberExpiryReminder(domainAdmin.getKey(), domainAdmin.getValue());
            Notification notification = notificationCommon.createNotification(
                    ZMSUtils.roleResourceName(domainAdmin.getKey(), ZMSConsts.ADMIN_ROLE_NAME),
                    details,
                    roleExpiryDomainNotificationToEmailConverter);
            if (notification != null) {
                notificationList.add(notification);
            }
        }

        return notificationList;
    }

    Map<String, String> processRoleExpiryReminder(Map<String, List<MemberRole>> domainAdminMap, DomainRoleMember member) {

        Map<String, String> details = new HashMap<>();

        // each principal can have multiple roles in multiple domains that
        // it's part of thus multiple possible expiration entries.
        // we're going to collect them into one string and separate
        // with | between those. The format will be:
        // expiryRoles := <role-entry>[|<role-entry]*
        // role-entry := <domain-name>;<role-name>;<expiration>

        final List<MemberRole> memberRoles = member.getMemberRoles();
        if (memberRoles == null || memberRoles.isEmpty()) {
            return details;
        }

        StringBuilder expiryRoles = new StringBuilder(256);
        for (MemberRole memberRole : memberRoles) {

            final String domainName = memberRole.getDomainName();

            // first we're going to update our expiry details string

            if (expiryRoles.length() != 0) {
                expiryRoles.append('|');
            }
            expiryRoles.append(domainName).append(';')
                    .append(memberRole.getRoleName()).append(';')
                    .append(memberRole.getExpiration().toString());

            // next we're going to update our domain admin map

            List<MemberRole> domainRoleMembers = domainAdminMap.get(domainName);
            if (domainRoleMembers == null) {
                domainRoleMembers = new ArrayList<>();
                domainAdminMap.put(domainName, domainRoleMembers);
            }
            domainRoleMembers.add(memberRole);
        }
        details.put(NOTIFICATION_DETAILS_EXPIRY_ROLES, expiryRoles.toString());
        details.put(NOTIFICATION_DETAILS_MEMBER, member.getMemberName());

        return details;
    }

    Map<String, String> processMemberExpiryReminder(final String domainName, List<MemberRole> memberRoles) {

        Map<String, String> details = new HashMap<>();

        // each domain can have multiple members that are about
        // to expire to we're going to collect them into one
        // string and separate with | between those. The format will be:
        // expiryMembers := <member-entry>[|<member-entry]*
        // member-entry := <member-name>;<role-name>;<expiration>

        if (memberRoles == null || memberRoles.isEmpty()) {
            return details;
        }

        StringBuilder expiryMembers = new StringBuilder(256);
        for (MemberRole memberRole : memberRoles) {

            // first we're going to update our expiry details string

            if (expiryMembers.length() != 0) {
                expiryMembers.append('|');
            }
            expiryMembers.append(memberRole.getMemberName()).append(';')
                    .append(memberRole.getRoleName()).append(';')
                    .append(memberRole.getExpiration().toString());
        }
        details.put(NOTIFICATION_DETAILS_EXPIRY_MEMBERS, expiryMembers.toString());
        details.put(NOTIFICATION_DETAILS_DOMAIN, domainName);
        return details;
    }


    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class RoleExpiryPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_EXPIRY = "messages/principal-expiry.html";
        private static final String PRINCIPAL_EXPIRY_SUBJECT = "athenz.notification.email.principal.expiry.subject";
        private static final String PRINCIPAL_EXPIRY_BODY_ENTRY = "athenz.notification.email.principal.expiry.body.entry";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailPrincipalExpiryBody;

        public RoleExpiryPrincipalNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailPrincipalExpiryBody =  notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_PRINCIPAL_EXPIRY);
        }

        private String getPrincipalExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailPrincipalExpiryBody,
                    NOTIFICATION_DETAILS_MEMBER,
                    NOTIFICATION_DETAILS_EXPIRY_ROLES,
                    3,
                    PRINCIPAL_EXPIRY_BODY_ENTRY);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(PRINCIPAL_EXPIRY_SUBJECT);
            String body = getPrincipalExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleExpiryDomainNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/domain-member-expiry.html";
        private static final String DOMAIN_MEMBER_EXPIRY_SUBJECT = "athenz.notification.email.domain.member.expiry.subject";
        private static final String DOMAIN_MEMBER_EXPIRY_BODY_ENTRY = "athenz.notification.email.domain.member.expiry.body.entry";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailDomainMemberExpiryBody;

        public RoleExpiryDomainNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailDomainMemberExpiryBody = notificationToEmailConverterCommon.readContentFromFile(getClass().getClassLoader(), EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY);
        }

        private String getDomainMemberExpiryBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailDomainMemberExpiryBody,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_EXPIRY_MEMBERS,
                    3,
                    DOMAIN_MEMBER_EXPIRY_BODY_ENTRY);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(DOMAIN_MEMBER_EXPIRY_SUBJECT);
            String body = getDomainMemberExpiryBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }
}
