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

import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.List;

import static com.yahoo.athenz.common.messaging.DomainChangeMessage.ObjectType.*;
import static org.testng.Assert.*;

public class ZMSDeleteUserTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();
    private  ZMSImpl zmsImpl;
    private  RsrcCtxWrapper ctx;
    private String auditRef;

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
        zmsImpl = zmsTestInitializer.getZms();
        ctx = zmsTestInitializer.getMockDomRsrcCtx();
        auditRef = zmsTestInitializer.getAuditRef();
    }

    @Test
    public void testDeleteUser() {

        final String domainName = "deleteuser1";

        ZMSTestUtils.cleanupNotAdminUsers(zmsImpl, zmsTestInitializer.getAdminUser(), ctx);

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject("deleteusersports",
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom2);

        ServiceIdentity service = new ServiceIdentity().setName(ResourceUtils.serviceResourceName("deleteusersports", "api"));
        zmsImpl.putServiceIdentity(ctx, "deleteusersports", "api", auditRef, false, null, service);

        SubDomain subDom1 = zmsTestInitializer.createSubDomainObject("jack", "user",
                "Test SubDomain2", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postSubDomain(ctx, "user", auditRef, null, subDom1);

        SubDomain subDom2 = zmsTestInitializer.createSubDomainObject("sub1", "user.jack",
                "Test SubDomain21", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postSubDomain(ctx, "user.jack", auditRef, null, subDom2);

        ServiceIdentity service2 = new ServiceIdentity().setName(ResourceUtils.serviceResourceName("user.jack.sub1", "api"));
        zmsImpl.putServiceIdentity(ctx, "user.jack.sub1", "api", auditRef, false, null, service2);

        ServiceIdentity service3 = new ServiceIdentity().setName(ResourceUtils.serviceResourceName("user.jack.sub1", "service"));
        zmsImpl.putServiceIdentity(ctx, "user.jack.sub1", "service", auditRef, false, null, service3);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", "user.jack.sub1.service");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        Role role2 = zmsTestInitializer.createRoleObject(domainName, "role2", null,
                "user.joe", "deleteusersports.api");
        zmsImpl.putRole(ctx, domainName, "role2", auditRef, false, null, role2);

        Role role3 = zmsTestInitializer.createRoleObject(domainName, "role3", null,
                "user.jack", "user.jack.sub1.api");
        zmsImpl.putRole(ctx, domainName, "role3", auditRef, false, null, role3);

        Group group1 = zmsTestInitializer.createGroupObject(domainName, "dev-team", "user.joe", "user.jack.sub1.api");
        zmsImpl.putGroup(ctx, domainName, "dev-team", auditRef, false, null, group1);

        Group group2 = zmsTestInitializer.createGroupObject(domainName, "ops-team", "user.joe", "deleteusersports.api");
        zmsImpl.putGroup(ctx, domainName, "ops-team", auditRef, false, null, group2);

        Group group3 = zmsTestInitializer.createGroupObject(domainName, "qa-team", "user.jack", "user.jack.sub1.api");
        zmsImpl.putGroup(ctx, domainName, "qa-team", auditRef, false, null, group3);

        // fetch the objects, so we can track of their modification timestamps

        role1 = zmsImpl.getRole(ctx, domainName, "role1", true, false, false);
        assertEquals(role1.getAuditLog().size(), 2);
        role2 = zmsImpl.getRole(ctx, domainName, "role2", true, false, false);
        assertEquals(role2.getAuditLog().size(), 2);
        role3 = zmsImpl.getRole(ctx, domainName, "role3", true, false, false);
        assertEquals(role3.getAuditLog().size(), 2);

        group1 = zmsImpl.getGroup(ctx, domainName, "dev-team", true, false);
        assertEquals(group1.getAuditLog().size(), 2);
        group2 = zmsImpl.getGroup(ctx, domainName, "ops-team", true, false);
        assertEquals(group2.getAuditLog().size(), 2);
        group3 = zmsImpl.getGroup(ctx, domainName, "qa-team", true, false);
        assertEquals(group3.getAuditLog().size(), 2);

        UserList userList = zmsImpl.getUserList(ctx, null);
        List<String> users = userList.getNames();
        int userSize = users.size();
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.jack"));
        assertTrue(users.contains("user.joe"));

        // sleep for a second, so we can track of last modification
        // timestamp changes for objects

        ZMSTestUtils.sleep(1000);

        RsrcCtxWrapper rsrcCtx = zmsTestInitializer.contextWithMockPrincipal("deleteUser");

        zmsImpl.deleteUser(rsrcCtx, "jack", auditRef);
        List<DomainChangeMessage> changeMsgs = rsrcCtx.getDomainChangeMessages();
        assertEquals(changeMsgs.size(), 4);
        ZMSTestUtils.assertChange(changeMsgs.get(0), DOMAIN, "user.jack", "user.jack", "deleteUser");
        ZMSTestUtils.assertChange(changeMsgs.get(1), DOMAIN, "user.jack.sub1", "user.jack.sub1", "deleteUser");
        ZMSTestUtils.assertChange(changeMsgs.get(2), ROLE, "deleteuser1", "role3", "deleteUser");
        ZMSTestUtils.assertChange(changeMsgs.get(3), GROUP, "deleteuser1", "qa-team", "deleteUser");

        Role role1Res = zmsImpl.getRole(ctx, domainName, "role1", true, false, false);
        assertTrue(role1Res.getModified().millis() > role1.getModified().millis());
        assertEquals(role1Res.getAuditLog().size(), 3);

        // role2 was not modified thus we must have the same value

        Role role2Res = zmsImpl.getRole(rsrcCtx, domainName, "role2", true, false, false);
        assertEquals(role2.getModified().millis(), role2Res.getModified().millis());
        assertEquals(role2Res.getAuditLog().size(), 2);

        Role role3Res = zmsImpl.getRole(rsrcCtx, domainName, "role3", true, false, false);
        assertTrue(role3Res.getModified().millis() > role3.getModified().millis());
        assertEquals(role3Res.getAuditLog().size(), 4);

        Group group1Res = zmsImpl.getGroup(rsrcCtx, domainName, "dev-team", true, false);
        assertTrue(group1Res.getModified().millis() > group1.getModified().millis());
        assertEquals(group1Res.getAuditLog().size(), 3);

        // group2 was not modified thus we must have the same value

        Group group2Res = zmsImpl.getGroup(rsrcCtx, domainName, "ops-team", true, false);
        assertEquals(group2.getModified().millis(), group2Res.getModified().millis());
        assertEquals(group2Res.getAuditLog().size(), 2);

        Group group3Res = zmsImpl.getGroup(rsrcCtx, domainName, "qa-team", true, false);
        assertTrue(group3Res.getModified().millis() > group3.getModified().millis());
        assertEquals(group3Res.getAuditLog().size(), 4);

        userList = zmsImpl.getUserList(rsrcCtx, null);
        users = userList.getNames();
        assertEquals(users.size(), userSize - 1);
        assertTrue(users.contains("user.testadminuser"));
        assertTrue(users.contains("user.joe"));
        assertFalse(users.contains("user.jack"));

        try {
            zmsImpl.getDomain(rsrcCtx, "user.jack");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        try {
            zmsImpl.getDomain(rsrcCtx, "user.jack.sub1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
        zmsImpl.deleteTopLevelDomain(ctx, "deleteusersports", auditRef, null);
    }

    @Test
    public void testDeleteUserWithGroups() {

        final String domainName = "delete-user-with-groups";

        ZMSTestUtils.cleanupNotAdminUsers(zmsImpl, zmsTestInitializer.getAdminUser(), ctx);

        // create a user domain with a group

        UserDomain userDomain1 = zmsTestInitializer.createUserDomainObject("john-doe", "Test Domain1", "testOrg");
        zmsImpl.postUserDomain(ctx, "john-doe", auditRef, null, userDomain1);

        Group group1 = zmsTestInitializer.createGroupObject("user.john-doe", "sys-team", "user.john-doe", "sys.auth.zms");
        zmsImpl.putGroup(ctx, "user.john-doe", "sys-team", auditRef, false, null, group1);

        // create a domain with role that has user group as a member

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        Role role1 = zmsTestInitializer.createRoleObject(domainName, "role1", null,
                "user.joe", "user.john-doe:group.sys-team");
        zmsImpl.putRole(ctx, domainName, "role1", auditRef, false, null, role1);

        // now delete the user

        RsrcCtxWrapper rsrcCtx = zmsTestInitializer.contextWithMockPrincipal("deleteUser");
        zmsImpl.deleteUser(rsrcCtx, "john-doe", auditRef);

        // verify the user and group are deleted

        Role role1Res = zmsImpl.getRole(ctx, domainName, "role1", true, false, false);
        assertEquals(role1Res.getRoleMembers().size(), 1);
        assertEquals(role1Res.getRoleMembers().get(0).getMemberName(), "user.joe");

        try {
            zmsImpl.getDomain(rsrcCtx, "user.john-doe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testDeleteAdminUserForbidden() {

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        // we should not be allowed to delete system admin users

        try {
            zmsImpl.deleteUser(ctx, "testadminuser", auditRef);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("system admin users cannot be deleted"));
        }
    }
}
