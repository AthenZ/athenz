/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationConverterCommon;
import com.yahoo.athenz.zms.notification.GroupMemberExpiryNotificationTask;
import com.yahoo.athenz.zms.notification.RoleMemberExpiryNotificationTask;
import com.yahoo.rdl.Timestamp;
import org.testng.annotations.*;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

public class ZMSNotificationsTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryMySQL();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryMySQL();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testRoleExpiryNotification() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "test-domain1-role-expiry-notify";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        try {
            long currentTimeMillis = System.currentTimeMillis();
            Timestamp currentTimestamp = Timestamp.fromMillis(currentTimeMillis);

            List<RoleMember> roleMembers = generateRoleMembers(currentTimeMillis);

            Role role1 = zmsTestInitializer.createRoleObject(domainName, "Role1", null, roleMembers);
            zmsImpl.putRole(ctx, domainName, "Role1", auditRef, false, null, role1);
            NotificationConverterCommon notificationConverterCommon =
                    new NotificationConverterCommon(zmsImpl.userAuthority);

            RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask =
                    new RoleMemberExpiryNotificationTask(zmsImpl.dbService, zmsImpl.userDomainPrefix,
                            notificationConverterCommon);
            List<Notification> notifications = roleMemberExpiryNotificationTask.getNotifications(null);

            // notifications should be sent 0,1,3,7,14,21,28 days
            // while metrics should be recorded every day
            Set<String> notificationMembers = new HashSet<>(Arrays.asList(
                    "user.expireddays0",
                    "user.expireddays1",
                    "user.expireddays3",
                    "user.expireddays7",
                    "user.expireddays14",
                    "user.expireddays21",
                    "user.expireddays28"));
            for (Notification notification : notifications) {
                if (Notification.ConsolidatedBy.PRINCIPAL.equals(notification.getConsolidatedBy())) {
                    String recipient = notification.getRecipients().stream().findFirst().get();
                    if (recipient.equals("user.testadminuser")) {
                        verifyAdminEmailNotifications(notificationMembers, notification);
                    } else {
                        if (notificationMembers.contains(recipient)) {
                            assertNotNull(notification.getNotificationAsEmail());
                        } else {
                            assertNull(notification.getNotificationAsEmail());
                        }
                        assertNotNull(notification.getNotificationAsMetrics(currentTimestamp));
                    }
                } else if (Notification.ConsolidatedBy.DOMAIN.equals(notification.getConsolidatedBy())) {
                    String recipient = notification.getRecipients().stream().findFirst().get();
                    if (recipient.equals("test-domain1-role-expiry-notify")) {
                        verifyAdminSlackNotifications(notificationMembers, notification);
                    } else {
                        if (notificationMembers.contains(recipient)) {
                            assertNotNull(notification.getNotificationAsSlackMessage());
                        } else {
                            assertNull(notification.getNotificationAsSlackMessage());
                        }
                        assertNotNull(notification.getNotificationAsMetrics(currentTimestamp));
                    }
                }
            }
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        }
    }

    private void verifyAdminEmailNotifications(Set<String> emailNotificationMembers, Notification notification) {
        String membersList = notification.getDetails().get("membersList");
        if (notification.getNotificationAsEmail() != null) {
            // Email and metric notification for admin
            for (String member : emailNotificationMembers) {
                assertTrue(membersList.contains(member + ";"), "memberList: " + membersList + " doesn't contain member: " + member);
            }
        } else {
            // Metric only notification for admin
            for (String member : emailNotificationMembers) {
                assertFalse(membersList.contains(member + ";"), "memberList: " + membersList + " contains member: " + member);
            }
        }
    }

    private void verifyAdminSlackNotifications(Set<String> notificationMembers, Notification notification) {
        String membersList = notification.getDetails().get("membersList");
        if (notification.getNotificationAsSlackMessage() != null) {
            // Slack and metric notification for admin
            for (String member : notificationMembers) {
                assertTrue(membersList.contains(member + ";"), "memberList: " + membersList + " doesn't contain member: " + member);
            }
        } else {
            // Metric only notification for admin
            for (String member : notificationMembers) {
                assertFalse(membersList.contains(member + ";"), "memberList: " + membersList + " contains member: " + member);
            }
        }
    }

    @Test
    public void testGroupExpiryNotification() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "test-domain1-group-expiry-notify";
        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        try {
            long currentTimeMillis = System.currentTimeMillis();
            Timestamp currentTimestamp = Timestamp.fromMillis(currentTimeMillis);

            List<GroupMember> groupMembers = generateGroupMembers(currentTimeMillis);

            Group group1 = zmsTestInitializer.createGroupObject(domainName, "Group1", groupMembers);
            zmsImpl.putGroup(ctx, domainName, "Group1", auditRef, false, null, group1);
            GroupMemberExpiryNotificationTask groupMemberExpiryNotificationTask =
                    new GroupMemberExpiryNotificationTask(zmsImpl.dbService, zmsImpl.userDomainPrefix,
                            zmsImpl.notificationConverterCommon);
            List<Notification> notifications = groupMemberExpiryNotificationTask.getNotifications(null);

            // Email notifications are generated based 0,1,3,7,14,21,28 days schedule
            Set<String> emailNotificationMembers = new HashSet<>(Arrays.asList(
                    "user.expireddays0",
                    "user.expireddays1",
                    "user.expireddays3",
                    "user.expireddays7",
                    "user.expireddays14",
                    "user.expireddays21",
                    "user.expireddays28"));
            assertEquals(notifications.size(), 16, "notificationRecipients: " + notificationsToRecipientString(notifications));
            for (Notification notification : notifications) {
                if (Notification.ConsolidatedBy.PRINCIPAL.equals(notification.getConsolidatedBy())) {
                    String recipient = notification.getRecipients().stream().findFirst().get();
                    if (recipient.equals("user.testadminuser")) {
                        verifyAdminEmailNotifications(emailNotificationMembers, notification);
                    } else {

                        if (emailNotificationMembers.contains(recipient)) {
                            assertNotNull(notification.getNotificationAsEmail());
                        } else {
                            assertNull(notification.getNotificationAsEmail());
                        }
                        assertNotNull(notification.getNotificationAsMetrics(currentTimestamp));
                    }
                } else if (Notification.ConsolidatedBy.DOMAIN.equals(notification.getConsolidatedBy())) {
                    String recipient = notification.getRecipients().stream().findFirst().get();
                    if (recipient.equals("test-domain1-group-expiry-notify")) {
                        verifyAdminSlackNotifications(emailNotificationMembers, notification);
                    } else {

                        if (emailNotificationMembers.contains(recipient)) {
                            assertNotNull(notification.getNotificationAsSlackMessage());
                        } else {
                            assertNull(notification.getNotificationAsSlackMessage());
                        }
                        assertNotNull(notification.getNotificationAsMetrics(currentTimestamp));
                    }
                }
            }
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        }
    }

    @Test
    public void testDisableUserGroupExpiryNotification() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "test-domain1-disable-expiry-notify";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        try {
            long currentTimeMillis = System.currentTimeMillis();

            List<GroupMember> groupMembers = generateGroupMembers(currentTimeMillis);

            Group group1 = zmsTestInitializer.createGroupObject(domainName, "Group1", groupMembers);
            // Now disable notification for users
            Map<String, TagValueList> disableUserTags = new HashMap<>();
            disableUserTags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("1")));
            group1.setTags(disableUserTags);

            zmsImpl.putGroup(ctx, domainName, "Group1", auditRef, false, null, group1);
            GroupMemberExpiryNotificationTask groupMemberExpiryNotificationTask =
                    new GroupMemberExpiryNotificationTask(zmsImpl.dbService, zmsImpl.userDomainPrefix,
                            zmsImpl.notificationConverterCommon);
            List<Notification> notifications = groupMemberExpiryNotificationTask.getNotifications(null);

            // Email notifications are generated based 0,1,3,7,14,21,28 days schedule
            Set<String> emailNotificationMembers = new HashSet<>(Arrays.asList(
                    "user.expireddays0",
                    "user.expireddays1",
                    "user.expireddays3",
                    "user.expireddays7",
                    "user.expireddays14",
                    "user.expireddays21",
                    "user.expireddays28"));
            assertEquals(notifications.size(), 2, "notificationRecipients: " + notificationsToRecipientString(notifications));
            Notification notification = notifications.get(0);
            assertEquals(notification.getConsolidatedBy(), Notification.ConsolidatedBy.PRINCIPAL);
            assertEquals(notifications.get(1).getConsolidatedBy(), Notification.ConsolidatedBy.DOMAIN);

            assertEquals(notification.getRecipients().size(), 1, "notificationRecipients: "
                    + notificationsToRecipientString(notifications));
            String recipient = notification.getRecipients().stream().findFirst().get();
            assertEquals(recipient, "user.testadminuser");
            verifyAdminEmailNotifications(emailNotificationMembers, notification);
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        }
    }

    private String notificationsToRecipientString(List<Notification> notifications) {
        return notifications.stream().map(notif -> notif.getRecipients().stream().findAny().get()).collect(Collectors.joining(", "));
    }

    @Test
    public void testDisableAdminGroupExpiryNotification() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "test-domain1-disable-admin-expiry-notify";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        try {
            long currentTimeMillis = System.currentTimeMillis();

            List<GroupMember> groupMembers = generateGroupMembers(currentTimeMillis);

            Group group1 = zmsTestInitializer.createGroupObject(domainName, "Group1", groupMembers);
            // Now disable notification for admins
            Map<String, TagValueList> disableUserTags = new HashMap<>();
            disableUserTags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("2")));
            group1.setTags(disableUserTags);

            zmsImpl.putGroup(ctx, domainName, "Group1", auditRef, false, null, group1);
            GroupMemberExpiryNotificationTask groupMemberExpiryNotificationTask =
                    new GroupMemberExpiryNotificationTask(zmsImpl.dbService, zmsImpl.userDomainPrefix,
                            zmsImpl.notificationConverterCommon);
            List<Notification> notifications = groupMemberExpiryNotificationTask.getNotifications(null);

            // Email notifications are generated based 0,1,3,7,14,21,28 days schedule
            Set<String> emailNotificationMembers = new HashSet<>(Arrays.asList(
                    "user.expireddays0",
                    "user.expireddays1",
                    "user.expireddays3",
                    "user.expireddays7",
                    "user.expireddays14",
                    "user.expireddays21",
                    "user.expireddays28"));
            assertEquals(notifications.size(), 14, "notificationRecipients: " + notificationsToRecipientString(notifications));
            for (Notification notification : notifications) {
                if (notification.getConsolidatedBy().equals(Notification.ConsolidatedBy.PRINCIPAL)) {
                    assertEquals(notification.getRecipients().size(), 1, "notificationRecipients: "
                            + notificationsToRecipientString(notifications));
                    String recipient = notification.getRecipients().stream().findFirst().get();
                    assertTrue(emailNotificationMembers.contains(recipient));
                    emailNotificationMembers.remove(recipient);
                }
            }
            assertTrue(emailNotificationMembers.isEmpty());
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        }
    }

    @Test
    public void testDisableAllGroupExpiryNotification() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "test-domain1-disable-all-expiry-notify";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        try {
            long currentTimeMillis = System.currentTimeMillis();
            List<GroupMember> groupMembers = generateGroupMembers(currentTimeMillis);

            Group group1 = zmsTestInitializer.createGroupObject(domainName, "Group1", groupMembers);
            // Now disable all notifications
            Map<String, TagValueList> disableUserTags = new HashMap<>();
            disableUserTags.put("zms.DisableReminderNotifications", new TagValueList().setList(List.of("3")));
            group1.setTags(disableUserTags);

            zmsImpl.putGroup(ctx, domainName, "Group1", auditRef, false, null, group1);
            GroupMemberExpiryNotificationTask groupMemberExpiryNotificationTask =
                    new GroupMemberExpiryNotificationTask(zmsImpl.dbService, zmsImpl.userDomainPrefix,
                            zmsImpl.notificationConverterCommon);
            List<Notification> notifications = groupMemberExpiryNotificationTask.getNotifications(null);
            assertEquals(notifications.size(), 0, "notificationRecipients: " + notificationsToRecipientString(notifications));
        } finally {
            zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        }
    }

    private List<GroupMember> generateGroupMembers(long currentTimeMillis) {
        List<GroupMember> groupMembers = new ArrayList<>();
        Timestamp timestamp = Timestamp.fromMillis(currentTimeMillis + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        groupMembers.add(new GroupMember().setMemberName("user.expireddays0").setExpiration(timestamp));
        for (int i = 1; i <= 28; ++i) {
            timestamp = Timestamp.fromMillis(currentTimeMillis + TimeUnit.MILLISECONDS.convert(i, TimeUnit.DAYS));
            groupMembers.add(new GroupMember().setMemberName("user.expireddays" + i).setExpiration(timestamp));
        }
        return groupMembers;
    }

    private List<RoleMember> generateRoleMembers(long currentTimeMillis) {
        // Create 29 members which will be expired in the next 29 days. Each day exactly one member will be expired.
        List<RoleMember> roleMembers = new ArrayList<>();
        Timestamp timestamp = Timestamp.fromMillis(currentTimeMillis + TimeUnit.MILLISECONDS.convert(1, TimeUnit.HOURS));
        roleMembers.add(new RoleMember().setMemberName("user.expireddays0").setExpiration(timestamp));
        for (int i = 1; i <= 28; ++i) {
            timestamp = Timestamp.fromMillis(currentTimeMillis + TimeUnit.MILLISECONDS.convert(i, TimeUnit.DAYS));
            roleMembers.add(new RoleMember().setMemberName("user.expireddays" + i).setExpiration(timestamp));
        }
        return roleMembers;
    }
}
