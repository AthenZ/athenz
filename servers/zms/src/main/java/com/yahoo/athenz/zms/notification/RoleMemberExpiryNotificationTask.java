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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_DETAILS_MEMBERS_LIST;

public class RoleMemberExpiryNotificationTask implements NotificationTask {
    private final DBService dbService;
    private final RoleMemberNotificationCommon roleMemberNotificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberExpiryNotificationTask.class);
    private final static String DESCRIPTION = "membership expiration reminders";
    private final RoleExpiryDomainNotificationToEmailConverter roleExpiryDomainNotificationToEmailConverter;
    private final RoleExpiryPrincipalNotificationToEmailConverter roleExpiryPrincipalNotificationToEmailConverter;

    public RoleMemberExpiryNotificationTask(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        this.roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbService, userDomainPrefix);
        this.roleExpiryPrincipalNotificationToEmailConverter = new RoleExpiryPrincipalNotificationToEmailConverter();
        this.roleExpiryDomainNotificationToEmailConverter = new RoleExpiryDomainNotificationToEmailConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        Map<String, DomainRoleMember> expiryMembers = dbService.getRoleExpiryMembers(1);
        if (expiryMembers == null || expiryMembers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No expiry members available to send notifications");
            }
            return new ArrayList<>();
        }

        return roleMemberNotificationCommon.getNotificationDetails(
                expiryMembers,
                roleExpiryPrincipalNotificationToEmailConverter,
                roleExpiryDomainNotificationToEmailConverter,
                new ExpiryRoleMemberDetailStringer());
    }

    static class ExpiryRoleMemberDetailStringer implements RoleMemberNotificationCommon.RoleMemberDetailStringer {

        @Override
        public StringBuilder getDetailString(MemberRole memberRole) {
            StringBuilder detailsRow = new StringBuilder(256);
            detailsRow.append(memberRole.getRoleName()).append(';');
            detailsRow.append(memberRole.getExpiration());
            return detailsRow;
        }
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class RoleExpiryPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_EXPIRY = "messages/role-member-expiry.html";
        private static final String PRINCIPAL_EXPIRY_SUBJECT = "athenz.notification.email.role_member.expiry.subject";

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
                    NOTIFICATION_DETAILS_ROLES_LIST,
                    3);
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
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_EXPIRY = "messages/domain-role-member-expiry.html";
        private static final String DOMAIN_MEMBER_EXPIRY_SUBJECT = "athenz.notification.email.domain.role_member.expiry.subject";

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
                    NOTIFICATION_DETAILS_MEMBERS_LIST,
                    3);
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
