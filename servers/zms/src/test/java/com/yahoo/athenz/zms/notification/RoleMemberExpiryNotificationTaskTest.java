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

import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.notification.NotificationService;
import com.yahoo.athenz.common.server.notification.NotificationServiceFactory;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.NOTIFICATION_DETAILS_MEMBER;
import static com.yahoo.athenz.zms.notification.NotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.*;

public class RoleMemberExpiryNotificationTaskTest {
    @Test
    public void testProcessMemberExpiryReminderEmptySet() {

        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationManager notificationManager = getNotificationManager(dbsvc, null);
        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX);

        Map<String, String> details = roleMemberExpiryNotificationTask.processMemberExpiryReminder("athenz", null);
        assertTrue(details.isEmpty());

        details = roleMemberExpiryNotificationTask.processMemberExpiryReminder("athenz", Collections.emptyList());
        assertTrue(details.isEmpty());

        final String ts = Timestamp.fromMillis(100).toString();
        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));

        details = roleMemberExpiryNotificationTask.processMemberExpiryReminder("athenz", memberRoles);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_MEMBERS),
                "user.joe;role1;" + ts);
        assertEquals(details.get(NOTIFICATION_DETAILS_DOMAIN), "athenz");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz").setMemberName("user.jane")
                .setExpiration(Timestamp.fromMillis(100)));
        details = roleMemberExpiryNotificationTask.processMemberExpiryReminder("athenz", memberRoles);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_MEMBERS),
                "user.joe;role1;" + ts + "|user.jane;role1;" + ts);
        assertEquals(details.get(NOTIFICATION_DETAILS_DOMAIN), "athenz");

        notificationManager.shutdown();
    }

    @Test
    public void testProcessRoleExpiryReminder() {

        System.clearProperty(NOTIFICATION_PROP_SERVICE_FACTORY_CLASS);

        DBService dbsvc = Mockito.mock(DBService.class);
        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(Collections.emptySet());

        NotificationManager notificationManager = getNotificationManager(dbsvc, null);

        Map<String, List<MemberRole>> domainAdminMap = new HashMap<>();
        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberName("user.joe");

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX);

        Map<String, String> details = roleMemberExpiryNotificationTask.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertTrue(details.isEmpty());

        domainAdminMap.clear();
        roleMember.setMemberRoles(Collections.emptyList());
        details = roleMemberExpiryNotificationTask.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertTrue(details.isEmpty());

        final String ts = Timestamp.fromMillis(100).toString();
        domainAdminMap.clear();

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz1").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        roleMember.setMemberRoles(memberRoles);

        domainAdminMap.clear();
        details = roleMemberExpiryNotificationTask.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_ROLES),
                "athenz1;role1;" + ts);
        assertEquals(details.get(NOTIFICATION_DETAILS_MEMBER), "user.joe");

        assertEquals(domainAdminMap.size(), 1);
        List<MemberRole> domainRoleMembers = domainAdminMap.get("athenz1");
        assertEquals(domainRoleMembers.size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");

        memberRoles.add(new MemberRole().setRoleName("role1").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        memberRoles.add(new MemberRole().setRoleName("role2").setDomainName("athenz2").setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        domainAdminMap.clear();
        details = roleMemberExpiryNotificationTask.processRoleExpiryReminder(domainAdminMap, roleMember);
        assertEquals(details.size(), 2);
        assertEquals(details.get(NOTIFICATION_DETAILS_EXPIRY_ROLES),
                "athenz1;role1;" + ts + "|athenz2;role1;" + ts + "|athenz2;role2;" + ts);
        assertEquals(details.get(NOTIFICATION_DETAILS_MEMBER), "user.joe");
        assertEquals(domainAdminMap.size(), 2);
        domainRoleMembers = domainAdminMap.get("athenz1");
        assertEquals(domainRoleMembers.size(), 1);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");
        domainRoleMembers = domainAdminMap.get("athenz2");
        assertEquals(domainRoleMembers.size(), 2);
        assertEquals(domainRoleMembers.get(0).getMemberName(), "user.joe");
        assertEquals(domainRoleMembers.get(1).getMemberName(), "user.joe");

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersException() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        // we're going to throw an exception when called

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenThrow(new IllegalArgumentException());
        Mockito.when(dbsvc.getRoleExpiryMembers()).thenThrow(new IllegalArgumentException());
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX);
        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        try {
            roleMemberExpiryNotificationTask.getNotifications();
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }
        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersEmptySet() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;
        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        // we're going to return an empty set

        Mockito.when(dbsvc.getPendingMembershipApproverRoles()).thenReturn(null);

        // to make sure we're not creating any notifications, we're going
        // to configure our mock to throw an exception

        Mockito.when(mockNotificationService.notify(any())).thenThrow(new IllegalArgumentException());

        RoleMemberExpiryNotificationTask roleMemberExpiryNotificationTask = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX);
        assertEquals(roleMemberExpiryNotificationTask.getNotifications(), new ArrayList<>());

        notificationManager.shutdown();
    }
    @Test
    public void testSendRoleMemberExpiryReminders() {

        DBService dbsvc = Mockito.mock(DBService.class);
        NotificationService mockNotificationService =  Mockito.mock(NotificationService.class);
        NotificationServiceFactory testfact = () -> mockNotificationService;

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberName("user.joe")
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers())
                .thenReturn(null)
                .thenReturn(expiryMembers);

        NotificationManager notificationManager = getNotificationManager(dbsvc, testfact);

        ZMSTestUtils.sleep(1000);

        AthenzDomain domain = new AthenzDomain("athenz1");
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        Role adminRole = new Role()
                .setName("athenz1:role.admin")
                .setRoleMembers(roleMembers);
        List<Role> roles = new ArrayList<>();
        roles.add(adminRole);
        domain.setRoles(roles);

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(domain);

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX).getNotifications();


        // we should get 2 notifications - one for user and one for domain
        assertEquals(notifications.size(), 2);

        // Verify contents of notifications is as expected
        Notification expectedFirstNotification = new Notification(NOTIFICATION_TYPE_PRINCIPAL_EXPIRY_REMINDER);
        expectedFirstNotification.addRecipient("user.joe");
        expectedFirstNotification.addDetails("expiryRoles", "athenz1;role1;1970-01-01T00:00:00.100Z");
        expectedFirstNotification.addDetails("member", "user.joe");

        Notification expectedSecondNotification = new Notification(NOTIFICATION_TYPE_DOMAIN_MEMBER_EXPIRY_REMINDER);
        expectedSecondNotification.addRecipient("user.jane");
        expectedSecondNotification.addDetails("expiryMembers", "user.joe;role1;1970-01-01T00:00:00.100Z");
        expectedSecondNotification.addDetails("domain", "athenz1");

        assertEquals(notifications.get(0), expectedFirstNotification);
        assertEquals(notifications.get(1), expectedSecondNotification);

        notificationManager.shutdown();
    }

    @Test
    public void testSendRoleMemberExpiryRemindersNoValidDomain() {

        DBService dbsvc = Mockito.mock(DBService.class);

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(new MemberRole().setRoleName("role1")
                .setDomainName("athenz1")
                .setMemberName("user.joe")
                .setExpiration(Timestamp.fromMillis(100)));
        DomainRoleMember domainRoleMember = new DomainRoleMember()
                .setMemberRoles(memberRoles);
        Map<String, DomainRoleMember> expiryMembers = new HashMap<>();
        expiryMembers.put("user.joe", domainRoleMember);

        // we're going to return null for our first thread which will
        // run during init call and then the real data for the second
        // call

        Mockito.when(dbsvc.getRoleExpiryMembers())
                .thenReturn(null)
                .thenReturn(expiryMembers);

        ZMSTestUtils.sleep(1000);

        // we're going to return not found domain always

        Mockito.when(dbsvc.getAthenzDomain("athenz1", false)).thenReturn(null);

        List<Notification> notifications = new RoleMemberExpiryNotificationTask(dbsvc, USER_DOMAIN_PREFIX).getNotifications();

        // we should get 0 notifications
        assertEquals(notifications, new ArrayList<>());
    }
}
