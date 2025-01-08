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

import com.yahoo.athenz.common.server.store.ResourceValidator;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.testng.Assert.*;

public class ResourceValidatorTest {

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
        MockitoAnnotations.openMocks(this);
        zmsTestInitializer.setUp();
    }

    @Test
    public void testRoleMemberValidation() {

        final String domainName = "role-member-validation";
        final String roleName = "role1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // set up our resource validator

        ResourceValidator savedResourceValidator = zmsImpl.resourceValidator;
        zmsImpl.resourceValidator = new TestResourceValidator();

        // let's add the role with 2 members

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, "user.joe", "user.doe");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        Role roleRes = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertEquals(roleRes.getRoleMembers().size(), 2);
        zmsTestInitializer.checkRoleMember(Arrays.asList("user.joe", "user.doe"), roleRes.getRoleMembers());

        // now let's add a member to the role that is not allowed

        Membership mbr = new Membership().setMemberName("user.jack");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName, "user.jack", auditRef, false, null, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.jack is not allowed by external resource validator"));
        }

        // now let's add a member to the role that is allowed

        mbr = new Membership().setMemberName("user.janie");
        zmsImpl.putMembership(ctx, domainName, roleName, "user.janie", auditRef, false, null, mbr);

        // now let's add a member to the role that is not allowed

        mbr = new Membership().setMemberName("user.janie");
        try {
            zmsImpl.putMembership(ctx, domainName, "admin", "user.janie", auditRef, false, null, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.janie is not allowed by external resource validator"));
        }

        // let's create a role with an invalid member

        role1 = zmsTestInitializer.createRoleObject(domainName, "role2", null, "user.jack", "user.janie");
        try {
            zmsImpl.putRole(ctx, domainName, "role2", auditRef, false, null, role1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.jack is not allowed by external resource validator"));
        }

        zmsImpl.resourceValidator = savedResourceValidator;
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    @Test
    public void testGroupMemberValidation() {

        final String domainName = "group-member-validation";
        final String groupName = "group1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // set up our resource validator

        ResourceValidator savedResourceValidator = zmsImpl.resourceValidator;
        zmsImpl.resourceValidator = new TestResourceValidator();

        // let's add the group with 2 members

        Group group1 = zmsTestInitializer.createGroupObject(domainName, groupName, "user.jack", "user.janie");
        zmsImpl.putGroup(ctx, domainName, groupName, auditRef, false, null, group1);

        Group groupRes = zmsImpl.getGroup(ctx, domainName, groupName, false, false);
        assertEquals(groupRes.getGroupMembers().size(), 2);
        zmsTestInitializer.checkGroupMember(Arrays.asList("user.jack", "user.janie"), groupRes.getGroupMembers());

        // now let's add a member to the group that is not allowed

        GroupMembership mbr = new GroupMembership().setMemberName("user.doe");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.doe", auditRef, false, null, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.doe is not allowed by external resource validator"));
        }

        // now let's add a member to the group that is allowed

        mbr = new GroupMembership().setMemberName("user.janie");
        zmsImpl.putGroupMembership(ctx, domainName, groupName, "user.janie", auditRef, false, null, mbr);

        // now let's add a member to the group that is not allowed

        Group group2 = zmsTestInitializer.createGroupObject(domainName, "readers", "user.jack", "user.janie");
        zmsImpl.putGroup(ctx, domainName, "readers", auditRef, false, null, group2);

        mbr = new GroupMembership().setMemberName("user.joe");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, "readers", "user.joe", auditRef, false, null, mbr);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.joe is not allowed by external resource validator"));
        }

        // let's create a role with an invalid member

        group1 = zmsTestInitializer.createGroupObject(domainName, "writers", "user.doe", "user.janie");
        try {
            zmsImpl.putGroup(ctx, domainName, "writers", auditRef, false, null, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Principal user.doe is not allowed by external resource validator"));
        }

        zmsImpl.resourceValidator = savedResourceValidator;
        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }

    static class TestResourceValidator implements ResourceValidator {

        @Override
        public boolean validateRoleMember(String domainName, String roleName, String memberName) {

            // our validator is going to reject user.jack from being added to any role
            // and user.janie from being added to the admin role

            if (memberName.equals("user.jack")) {
                return false;
            } else {
                return !roleName.equals("admin") || !memberName.equals("user.janie");
            }
        }

        @Override
        public boolean validateGroupMember(String domainName, String groupName, String memberName) {

            // our validator is going to reject user.doe from being added to any group
            // and user.joe from being added to the readers group

            if (memberName.equals("user.doe")) {
                return false;
            } else {
                return !groupName.equals("readers") || !memberName.equals("user.joe");
            }
        }
    }
}
