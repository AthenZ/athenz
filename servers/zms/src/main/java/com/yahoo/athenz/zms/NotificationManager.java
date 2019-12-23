/*
 * Copyright 2019 Oath Holdings Inc.
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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class NotificationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotificationManager.class);

    private NotificationService notificationService;
    private ScheduledExecutorService scheduledExecutor;
    private final DBService dbService;
    private final String userDomainPrefix;
    private int pendingRoleMemberLifespan;
    private String monitorIdentity;

    NotificationManager(final DBService dbService, final String userDomainPrefix) {
        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
        String notificationServiceFactoryClass = System.getProperty(ZMSConsts.ZMS_PROP_NOTIFICATION_SERVICE_FACTORY_CLASS);
        if (notificationServiceFactoryClass != null) {
            NotificationServiceFactory notificationServiceFactory;
            try {
                notificationServiceFactory = (NotificationServiceFactory) Class.forName(notificationServiceFactoryClass).newInstance();
                notificationService = notificationServiceFactory.create();
                init();
            } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
                LOGGER.error("Invalid NotificationServiceFactory class: " + notificationServiceFactoryClass + " error: " + e.getMessage());
            }
        }
    }

    private void init() {
        if (isNotificationFeatureAvailable()) {
            scheduledExecutor = Executors.newScheduledThreadPool(1);
            scheduledExecutor.scheduleAtFixedRate(new RoleMemberReminders(), 0, 1, TimeUnit.DAYS);
        }
        pendingRoleMemberLifespan = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_PENDING_ROLE_MEMBER_LIFESPAN, ZMSConsts.ZMS_PENDING_ROLE_MEMBER_LIFESPAN_DEFAULT));
        monitorIdentity = System.getProperty(ZMSConsts.ZMS_PROP_MONITOR_IDENTITY, ZMSConsts.SYS_AUTH_MONITOR);
    }

    NotificationManager(final DBService dbService, final NotificationServiceFactory notificationServiceFactory,
            final String userDomainPrefix) {
        this.dbService = dbService;
        this.userDomainPrefix = userDomainPrefix;
        notificationService = notificationServiceFactory.create();
        init();
    }

    void shutdown() {
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdownNow();
        }
    }

    void generateAndSendPostPutMembershipNotification(final String domain, final String org,
             Boolean auditEnabled, Boolean selfServe, Map<String, String> details) {

        if (!isNotificationFeatureAvailable()) {
            return;
        }

        Set<String> recipients = new HashSet<>();
        if (auditEnabled == Boolean.TRUE) {

            //get recipient role(s) from audit domain

            Role domainRole = dbService.getRole(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN,
                    domain, false, true, false);
            Role orgRole = dbService.getRole(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG,
                    org, false, true, false);
            if (domainRole != null) {
                recipients.addAll(domainRole.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                        .map(RoleMember::getMemberName).collect(Collectors.toSet()));
            }
            if (orgRole != null) {
                recipients.addAll(orgRole.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                        .map(RoleMember::getMemberName).collect(Collectors.toSet()));
            }
        } else if (selfServe == Boolean.TRUE) {
            // get admin role from the request domain
            Role adminRole = dbService.getRole(domain, "admin", false, true, false);
            recipients.addAll(adminRole.getRoleMembers().stream().filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                    .map(RoleMember::getMemberName).collect(Collectors.toSet()));
        }
        Notification notification = createNotification(NotificationService.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL,
                recipients, details);
        if (notification != null) {
            notificationService.notify(notification);
        }
    }

    void addDomainRoleRecipients(Notification notification, final String domainName, final String roleName) {
        AthenzDomain domain = dbService.getAthenzDomain(domainName, false);
        if (domain == null || domain.getRoles() == null) {
            return;
        }
        for (Role role : domain.getRoles()) {
            if (role.getName().equals(roleName)) {
                notification.getRecipients().addAll(role.getRoleMembers().stream()
                        .filter(m -> m.getMemberName().startsWith(userDomainPrefix))
                        .map(RoleMember::getMemberName).collect(Collectors.toSet()));
                return;
            }
        }
    }

    void addNotificationRecipient(Notification notification, final String recipient, boolean ignoreService) {

        int idx = recipient.indexOf(":role.");
        if (idx != -1) {
            addDomainRoleRecipients(notification, recipient.substring(0, idx), recipient);
        } else if (recipient.startsWith(userDomainPrefix)) {
            notification.addRecipient(recipient);
        } else if (!ignoreService) {
            final String domainName = AthenzUtils.extractPrincipalDomainName(recipient);
            if (domainName != null) {
                addDomainRoleRecipients(notification, domainName, ZMSUtils.roleResourceName(domainName, ZMSConsts.ADMIN_ROLE_NAME));
            }
        }
    }

    Notification createNotification(final String notificationType, Set<String> recipients, Map<String, String> details) {

        if (recipients == null || recipients.isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
            return null;
        }

        Notification notification = new Notification(notificationType);
        notification.setDetails(details);

        for (String recipient : recipients) {
            addNotificationRecipient(notification, recipient, true);
        }

        if (notification.getRecipients() == null || notification.getRecipients().isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
            return null;
        }

        return notification;
    }

    Notification createNotification(final String notificationType, final String recipient, Map<String, String> details) {

        if (recipient == null || recipient.isEmpty()) {
            LOGGER.error("Notification requires a valid recipient");
            return null;
        }

        Notification notification = new Notification(notificationType);
        notification.setDetails(details);

        // if the recipient is a service then we're going to send a notification
        // to the service's domain admin users

        addNotificationRecipient(notification, recipient, false);

        if (notification.getRecipients() == null || notification.getRecipients().isEmpty()) {
            LOGGER.error("Notification requires at least 1 recipient.");
            return null;
        }

        return notification;
    }

    void sendNotification(Notification notification) {
        if (isNotificationFeatureAvailable()) {
            notificationService.notify(notification);
        }
    }

    boolean isNotificationFeatureAvailable () {
        return notificationService != null;
    }

    class RoleMemberReminders implements Runnable {

        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("RoleMemberReminders: Starting role member reminder thread...");
            }
            try {
                // clean up expired pending members

                dbService.processExpiredPendingMembers(pendingRoleMemberLifespan, monitorIdentity);
                sendPendingMembershipApprovalReminders();

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("RoleMemberReminders: Sent reminders for pending membership approvals.");
                }

            } catch (Throwable t) {
                LOGGER.error("RoleMemberReminders: unable to send pending membership approval reminders: {}", t);
            }

            try {
                // send reminders for all about to be expired members

                sendRoleMemberExpiryReminders();

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("RoleMemberReminders: Sent reminders for membership expiration");
                }

            } catch (Throwable t) {
                LOGGER.error("RoleMemberReminders: unable to send membership expiration reminders: {}", t);
            }

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("RoleMemberReminders: Role member reminder thread completed");
            }
        }

        void sendPendingMembershipApprovalReminders() {
            Set<String> recipients = dbService.getPendingMembershipApproverRoles();
            Notification notification = createNotification(NotificationService.NOTIFICATION_TYPE_MEMBERSHIP_APPROVAL_REMINDER,
                    recipients, null);
            if (notification != null) {
                notificationService.notify(notification);
            }
        }

        void sendRoleMemberExpiryReminders() {

            // first we're going to send reminders to all the members indicating to
            // them that they're going to expiry and they should follow up with
            // domain admins to extend their membership.
            // if the principal is service then we're going to send the reminder
            // to the domain admins of that service
            // while doing this we're going to keep track of all domains that
            // have members that are about to expire and then send them a reminder
            // as well indicating that they have members with coming-up expiration

            Map<String, DomainRoleMember> expiryMembers = dbService.getRoleExpiryMembers();
            if (expiryMembers == null || expiryMembers.isEmpty()) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("No expiry members available to send notifications");
                }
                return;
            }

            Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();

            for (DomainRoleMember roleMember : expiryMembers.values()) {

                // we're going to process the role member, update
                // our domain admin map accordingly and return
                // the details object that we need to send to the
                // notification agent for processing

                Map<String, String> details = processRoleExpiryReminder(domainAdminMap, roleMember);
                Notification notification = createNotification(NotificationService.NOTIFICATION_TYPE_PRINCIPAL_EXPIRY_REMINDER,
                        roleMember.getMemberName(), details);
                if (notification != null) {
                    notificationService.notify(notification);
                }
            }

            // now we're going to send reminders to all the domain administrators
            // to make sure they're aware of upcoming principal expirations

            for (Map.Entry<String, List<MemberRole>> domainAdmin : domainAdminMap.entrySet()) {

                Map<String, String> details = processMemberExpiryReminder(domainAdmin.getKey(), domainAdmin.getValue());
                Notification notification = createNotification(NotificationService.NOTIFICATION_TYPE_DOMAIN_MEMBER_EXPIRY_REMINDER,
                        ZMSUtils.roleResourceName(domainAdmin.getKey(), ZMSConsts.ADMIN_ROLE_NAME), details);
                if (notification != null) {
                    notificationService.notify(notification);
                }
            }
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
            details.put(NotificationService.NOTIFICATION_DETAILS_EXPIRY_ROLES, expiryRoles.toString());
            details.put(NotificationService.NOTIFICATION_DETAILS_MEMBER, member.getMemberName());

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
            details.put(NotificationService.NOTIFICATION_DETAILS_EXPIRY_MEMBERS, expiryMembers.toString());
            details.put(NotificationService.NOTIFICATION_DETAILS_DOMAIN, domainName);
            return details;
        }
    }
}
