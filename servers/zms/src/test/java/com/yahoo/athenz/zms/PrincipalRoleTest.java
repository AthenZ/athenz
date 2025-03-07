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

import com.yahoo.athenz.common.server.store.PrincipalRole;
import com.yahoo.rdl.Timestamp;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.testng.Assert.assertEquals;

public class PrincipalRoleTest {

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
    public void testPrincipalRole() {
        PrincipalRole prRole = new PrincipalRole();
        prRole.setRoleName("role");
        prRole.setDomainName("domain");
        prRole.setDomainUserAuthorityFilter("authority");
        prRole.setDomainMemberExpiryDays(10);

        assertEquals(prRole.getRoleName(), "role");
        assertEquals(prRole.getDomainName(), "domain");
        assertEquals(prRole.getDomainUserAuthorityFilter(), "authority");
        assertEquals(prRole.getDomainMemberExpiryDays(), 10);
    }

    @Test
    public void testRoleMemberUpdateWithEmptyPendingState() {

        final String domainName = "role-member-update";
        final String roleName = "role1";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser());
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        // let's add the role with 2 members

        Role role1 = zmsTestInitializer.createRoleObject(domainName, roleName, null, "user.jack", "user.janie");
        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        Role roleRes = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertEquals(roleRes.getRoleMembers().size(), 2);
        zmsTestInitializer.checkRoleMember(Arrays.asList("user.jack", "user.janie"), roleRes.getRoleMembers());

        // now let's modify the same role without any changes

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        roleRes = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertEquals(roleRes.getRoleMembers().size(), 2);
        zmsTestInitializer.checkRoleMember(Arrays.asList("user.jack", "user.janie"), roleRes.getRoleMembers());

        // now let's set an expiry for jack, and we're also going to set the pending
        // state to empty string which is done by json deserializer

        Timestamp now = Timestamp.fromCurrentTime();
        for (RoleMember member : role1.getRoleMembers()) {
            if (member.getMemberName().equals("user.jack")) {
                member.setExpiration(now);
                member.setPendingState("");
            }
        }

        zmsImpl.putRole(ctx, domainName, roleName, auditRef, false, null, role1);

        roleRes = zmsImpl.getRole(ctx, domainName, roleName, false, false, false);
        assertEquals(roleRes.getRoleMembers().size(), 2);
        zmsTestInitializer.checkRoleMember(Arrays.asList("user.jack", "user.janie"), roleRes.getRoleMembers());

        for (RoleMember member : roleRes.getRoleMembers()) {
            if (member.getMemberName().equals("user.jack")) {
                assertEquals(member.getExpiration(), now);
            }
        }

        zmsImpl.deleteTopLevelDomain(ctx, domainName, auditRef, null);
    }
}
