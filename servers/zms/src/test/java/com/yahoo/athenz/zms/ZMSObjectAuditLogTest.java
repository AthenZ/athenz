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

package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import org.mockito.Mockito;
import org.testng.annotations.*;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class ZMSObjectAuditLogTest {

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

        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true);
        zmsTestInitializer.getZms().validateUserRoleMembers = dynamicConfigBoolean;
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testZMSAuditLogNoLimit() {

        // by default, we have no limit

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-log-no-limit";
        final String roleName = "role1";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName,
                "user.john", "user.jane");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        for (int i = 0; i < 25; i++) {
            final String memberName = "user.member" + i;
            Membership membership = new Membership().setMemberName(memberName);
            zmsImpl.putMembership(ctx, domainName, roleName, memberName, auditRef, false, null, membership);
            GroupMembership groupMembership = new GroupMembership().setMemberName(memberName);
            zmsImpl.putGroupMembership(ctx, domainName, groupName, memberName, auditRef, false, null, groupMembership);
        }

        Role resRole = zmsImpl.getRole(ctx, domainName, roleName, true, false, true);
        assertEquals(resRole.getRoleMembers().size(), 27);
        assertEquals(resRole.getAuditLog().size(), 27);

        Group resGroup = zmsImpl.getGroup(ctx, domainName, groupName, true, false);
        assertEquals(resGroup.getGroupMembers().size(), 27);
        assertEquals(resGroup.getAuditLog().size(), 27);

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testZMSRoleAuditLogLimit() throws InterruptedException {

        // set the role limit with max of 11 and then keep of 2
        // set the role limit with max of 10 and then keep of 3

        System.setProperty("athenz.zms.jdbc.audit_log_role_max_limit", "11");
        System.setProperty("athenz.zms.jdbc.audit_log_role_keep_count", "2");
        System.setProperty("athenz.zms.jdbc.audit_log_group_max_limit", "10");
        System.setProperty("athenz.zms.jdbc.audit_log_group_keep_count", "3");

        ZMSImpl zmsImpl = zmsTestInitializer.zmsInit();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        final String domainName = "audit-log-with-limit";
        final String roleName = "role1";
        final String groupName = "group1";

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName, "Test Domain1",
                "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName, null,
                "user.john", "user.jane");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role);

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName,
                "user.john", "user.jane");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group);

        // role-setup: when we get to i 9, then we'll hit our limit of 11
        // thus we're going to clean up and only keep last 2,
        // and then we'll be adding another one so we should
        // end up with 3 entries only
        // group-setup: when get to i 8, then 'll hit our limit of 10
        // thus we're going to clean up and only keep the last 3,
        // and then we'll be adding two more so we should end
        // up with 5 entries

        for (int i = 0; i < 10; i++) {
            final String memberName = "user.member" + i;
            Thread.sleep(1000);
            Membership membership = new Membership().setMemberName(memberName);
            zmsImpl.putMembership(ctx, domainName, roleName, memberName, auditRef, false, null, membership);
            GroupMembership groupMembership = new GroupMembership().setMemberName(memberName);
            zmsImpl.putGroupMembership(ctx, domainName, groupName, memberName, auditRef, false, null, groupMembership);
        }

        Role resRole = zmsImpl.getRole(ctx, domainName, roleName, true, false, true);
        assertEquals(resRole.getRoleMembers().size(), 12);

        assertEquals(resRole.getAuditLog().size(), 3);
        assertTrue(roleAuditLogEntryExists(resRole.getAuditLog(), "user.member9"));
        assertTrue(roleAuditLogEntryExists(resRole.getAuditLog(), "user.member8"));
        assertTrue(roleAuditLogEntryExists(resRole.getAuditLog(), "user.member7"));

        Group resGroup = zmsImpl.getGroup(ctx, domainName, groupName, true, false);
        assertEquals(resGroup.getGroupMembers().size(), 12);

        assertEquals(resGroup.getAuditLog().size(), 5);
        assertTrue(groupAuditLogEntryExists(resGroup.getAuditLog(), "user.member9"));
        assertTrue(groupAuditLogEntryExists(resGroup.getAuditLog(), "user.member8"));
        assertTrue(groupAuditLogEntryExists(resGroup.getAuditLog(), "user.member7"));
        assertTrue(groupAuditLogEntryExists(resGroup.getAuditLog(), "user.member6"));
        assertTrue(groupAuditLogEntryExists(resGroup.getAuditLog(), "user.member5"));

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);

        System.clearProperty("athenz.zms.jdbc.audit_log_role_max_limit");
        System.clearProperty("athenz.zms.jdbc.audit_log_role_keep_count");
        System.clearProperty("athenz.zms.jdbc.audit_log_group_max_limit");
        System.clearProperty("athenz.zms.jdbc.audit_log_group_keep_count");
    }

    boolean roleAuditLogEntryExists(List<RoleAuditLog> auditLogs, final String member) {
        for (RoleAuditLog auditLog : auditLogs) {
            if (auditLog.getMember().equals(member)) {
                return true;
            }
        }
        return false;
    }

    boolean groupAuditLogEntryExists(List<GroupAuditLog> auditLogs, final String member) {
        for (GroupAuditLog auditLog : auditLogs) {
            if (auditLog.getMember().equals(member)) {
                return true;
            }
        }
        return false;
    }
}
