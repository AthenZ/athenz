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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;

public class RoleMemberReviewNotificationTask implements NotificationTask {
    private final DBService dbService;
    private final RoleMemberNotificationCommon roleMemberNotificationCommon;
    private static final Logger LOGGER = LoggerFactory.getLogger(RoleMemberReviewNotificationTask.class);
    private final static String DESCRIPTION = "Review before expiration reminder";
    private final RoleReviewPrincipalNotificationToEmailConverter roleReviewPrincipalNotificationToEmailConverter;
    private final RoleReviewDomainNotificationToEmailConverter roleReviewDomainNotificationToEmailConverter;

    public RoleMemberReviewNotificationTask(DBService dbService, String userDomainPrefix) {
        this.dbService = dbService;
        this.roleMemberNotificationCommon = new RoleMemberNotificationCommon(dbService, userDomainPrefix);
        this.roleReviewDomainNotificationToEmailConverter = new RoleReviewDomainNotificationToEmailConverter();
        this.roleReviewPrincipalNotificationToEmailConverter = new RoleReviewPrincipalNotificationToEmailConverter();
    }

    @Override
    public List<Notification> getNotifications() {
        List<Notification> notificationList = new ArrayList<>();
        Map<String, DomainRoleMember> reviewMembers = dbService.getReviewMembers();
        if (reviewMembers == null || reviewMembers.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No members require review reminders");
            }
            return notificationList;
        }

        return roleMemberNotificationCommon.getNotificationDetails(
                notificationList,
                reviewMembers,
                roleReviewPrincipalNotificationToEmailConverter,
                roleReviewDomainNotificationToEmailConverter);
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    public static class RoleReviewPrincipalNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_PRINCIPAL_REVIEW = "messages/principal-review.html";
        private static final String PRINCIPAL_REVIEW_SUBJECT = "athenz.notification.email.principal.review.subject";
        private static final String PRINCIPAL_REVIEW_BODY_ENTRY = "athenz.notification.email.principal.review.body.entry";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailPrincipalReviewBody;

        public RoleReviewPrincipalNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailPrincipalReviewBody =  notificationToEmailConverterCommon.readContentFromFile(
                    getClass().getClassLoader(),
                    EMAIL_TEMPLATE_PRINCIPAL_REVIEW);
        }

        private String getPrincipalReviewBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailPrincipalReviewBody,
                    NOTIFICATION_DETAILS_MEMBER,
                    NOTIFICATION_DETAILS_EXPIRY_ROLES,
                    3,
                    PRINCIPAL_REVIEW_BODY_ENTRY);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(PRINCIPAL_REVIEW_SUBJECT);
            String body = getPrincipalReviewBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }

    public static class RoleReviewDomainNotificationToEmailConverter implements NotificationToEmailConverter {
        private static final String EMAIL_TEMPLATE_DOMAIN_MEMBER_REVIEW = "messages/domain-member-review.html";
        private static final String DOMAIN_MEMBER_REVIEW_SUBJECT = "athenz.notification.email.domain.member.review.subject";
        private static final String DOMAIN_MEMBER_REVIEW_BODY_ENTRY = "athenz.notification.email.domain.member.review.body.entry";

        private final NotificationToEmailConverterCommon notificationToEmailConverterCommon;
        private String emailDomainMemberReviewBody;

        public RoleReviewDomainNotificationToEmailConverter() {
            notificationToEmailConverterCommon = new NotificationToEmailConverterCommon();
            emailDomainMemberReviewBody = notificationToEmailConverterCommon.readContentFromFile(
                    getClass().getClassLoader(),
                    EMAIL_TEMPLATE_DOMAIN_MEMBER_REVIEW);
        }

        private String getDomainMemberReviewBody(Map<String, String> metaDetails) {
            if (metaDetails == null) {
                return null;
            }

            return notificationToEmailConverterCommon.generateBodyFromTemplate(
                    metaDetails,
                    emailDomainMemberReviewBody,
                    NOTIFICATION_DETAILS_DOMAIN,
                    NOTIFICATION_DETAILS_EXPIRY_MEMBERS,
                    3,
                    DOMAIN_MEMBER_REVIEW_BODY_ENTRY);
        }

        @Override
        public NotificationEmail getNotificationAsEmail(Notification notification) {
            String subject = notificationToEmailConverterCommon.getSubject(DOMAIN_MEMBER_REVIEW_SUBJECT);
            String body = getDomainMemberReviewBody(notification.getDetails());
            Set<String> fullyQualifiedEmailAddresses = notificationToEmailConverterCommon.getFullyQualifiedEmailAddresses(notification.getRecipients());
            return new NotificationEmail(subject, body, fullyQualifiedEmailAddresses);
        }
    }
}
