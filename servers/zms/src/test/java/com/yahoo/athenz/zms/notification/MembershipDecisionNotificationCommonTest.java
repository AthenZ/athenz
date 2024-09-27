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

import com.yahoo.athenz.common.server.notification.*;
import com.yahoo.athenz.zms.DBService;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.rdl.Timestamp;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.USER_DOMAIN_PREFIX;
import static com.yahoo.athenz.common.server.notification.impl.MetricNotificationService.*;
import static com.yahoo.athenz.zms.notification.ZMSNotificationManagerTest.getNotificationManager;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.never;
import static org.testng.Assert.*;
import static org.testng.Assert.assertFalse;
import static org.testng.AssertJUnit.assertEquals;

public class MembershipDecisionNotificationCommonTest {

    @Test
    public void testGetRecipientsUser() {
        DBService dbsvc = Mockito.mock(DBService.class);

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        MembershipDecisionNotificationCommon membershipDecisionNotificationCommon = new MembershipDecisionNotificationCommon(dbsvc, domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        List<String> members = new ArrayList<>();
        members.add("user.joe");
        members.add("user.jane");
        Set<String> recipients = membershipDecisionNotificationCommon.getRecipients(members);

        assertEquals(2, recipients.size());
        assertTrue(recipients.contains("user.joe"));
        assertTrue(recipients.contains("user.jane"));
    }

    @Test
    public void testGetRecipientsService() {
        DBService dbsvc = Mockito.mock(DBService.class);

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        MembershipDecisionNotificationCommon membershipDecisionNotificationCommon = new MembershipDecisionNotificationCommon(dbsvc, domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        List<RoleMember>  roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.approver1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.approver2").setActive(true);
        roleMembers.add(rm);

        Role localRole = new Role().setName("dom2:role.admin").setRoleMembers(roleMembers);

        // get role call for the admin role of service getting added
        Mockito.when(dbsvc.getRole("dom2", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(localRole);

        List<String> members = new ArrayList<>();
        members.add("user.joe");
        members.add("dom2.svc1");
        Set<String> recipients = membershipDecisionNotificationCommon.getRecipients(members);

        assertEquals(3, recipients.size());
        assertTrue(recipients.contains("user.joe"));
        assertTrue(recipients.contains("user.approver1"));
        assertTrue(recipients.contains("user.approver2"));
    }

    @Test
    public void testGetRecipientsGroupAdmin() {
        DBService dbsvc = Mockito.mock(DBService.class);
        List<RoleMember>  roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.approver1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.approver2").setActive(true);
        roleMembers.add(rm);

        Role localRole = new Role().setName("dom1:role.admin").setRoleMembers(roleMembers);

        // get role call for the admin role of service getting added
        Mockito.when(dbsvc.getRole("dom1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(localRole);
        Group group = new Group();
        Mockito.when(dbsvc.getGroup("dom1", "group1", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(group);

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        MembershipDecisionNotificationCommon membershipDecisionNotificationCommon = new MembershipDecisionNotificationCommon(dbsvc, domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        List<String> members = new ArrayList<>();
        members.add("user.jane");
        members.add("dom1:group.group1");
        Set<String> recipients = membershipDecisionNotificationCommon.getRecipients(members);

        assertEquals(3, recipients.size());
        assertTrue(recipients.contains("user.jane"));
        assertTrue(recipients.contains("user.approver1"));
        assertTrue(recipients.contains("user.approver2"));
    }

    @Test
    public void testGetRecipientsGroupNotifyRoles() {
        DBService dbsvc = Mockito.mock(DBService.class);
        List<RoleMember>  roleMembers = new ArrayList<>();
        RoleMember rm = new RoleMember().setMemberName("user.notifier1").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.notifier2").setActive(true);
        roleMembers.add(rm);

        Role notifyRole1 = new Role().setName("dom2:role.notify1").setRoleMembers(roleMembers);

        roleMembers = new ArrayList<>();
        rm = new RoleMember().setMemberName("user.joe").setActive(true);
        roleMembers.add(rm);

        rm = new RoleMember().setMemberName("user.dom").setActive(true);
        roleMembers.add(rm);

        Role notifyRole2 = new Role().setName("dom2:role.notify2").setRoleMembers(roleMembers);

        Group group = new Group().setNotifyRoles("dom2:role.notify2,dom2:role.notify1");

        Mockito.when(dbsvc.getGroup("dom1", "group1", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(group);
        Mockito.when(dbsvc.getRole("dom2", "notify1", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(notifyRole1);
        Mockito.when(dbsvc.getRole("dom2", "notify2", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(notifyRole2);
        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        MembershipDecisionNotificationCommon membershipDecisionNotificationCommon = new MembershipDecisionNotificationCommon(dbsvc, domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        List<String> members = new ArrayList<>();
        members.add("user.jane");
        members.add("dom1:group.group1");
        Set<String> recipients = membershipDecisionNotificationCommon.getRecipients(members);

        assertEquals(5, recipients.size());
        assertTrue(recipients.contains("user.jane"));
        assertTrue(recipients.contains("user.notifier1"));
        assertTrue(recipients.contains("user.notifier2"));
        assertTrue(recipients.contains("user.joe"));
        assertTrue(recipients.contains("user.dom"));
    }

    @Test
    public void testGetRecipientsGroupEmptyAdmin() {
        DBService dbsvc = Mockito.mock(DBService.class);
        List<RoleMember>  roleMembers = new ArrayList<>();

        Role localRole = new Role().setName("dom1:role.admin").setRoleMembers(roleMembers);

        // get role call for the admin role of service getting added
        Mockito.when(dbsvc.getRole("dom1", "admin", Boolean.FALSE, Boolean.TRUE, Boolean.FALSE))
                .thenReturn(localRole);
        Group group = new Group();
        Mockito.when(dbsvc.getGroup("dom1", "group1", Boolean.FALSE, Boolean.FALSE))
                .thenReturn(group);

        DomainRoleMembersFetcher domainRoleMembersFetcher = new DomainRoleMembersFetcher(dbsvc, USER_DOMAIN_PREFIX);
        MembershipDecisionNotificationCommon membershipDecisionNotificationCommon = new MembershipDecisionNotificationCommon(dbsvc, domainRoleMembersFetcher, USER_DOMAIN_PREFIX);

        List<String> members = new ArrayList<>();
        members.add("user.jane");
        members.add("dom1:group.group1");
        Set<String> recipients = membershipDecisionNotificationCommon.getRecipients(members);

        assertEquals(1, recipients.size());
        assertTrue(recipients.contains("user.jane"));
    }

}
