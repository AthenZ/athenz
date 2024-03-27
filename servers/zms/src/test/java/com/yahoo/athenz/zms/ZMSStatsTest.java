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

import org.testng.annotations.*;

import static org.testng.Assert.*;

public class ZMSStatsTest {

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

    @Test
    public void testGetStats() {

        final String domainName1 = "stats-1";
        final String domainName2 = "stats-2";

        ZMSImpl zms = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        Stats systemStats = zms.getSystemStats(ctx);
        assertNotNull(systemStats);
        assertNull(systemStats.getName());

        // remember all the counts for our system stats

        int sysSubDomains = systemStats.getSubdomain();
        int sysRoles = systemStats.getRole();
        int sysGroups = systemStats.getGroup();
        int sysServices = systemStats.getService();
        int sysPolicies = systemStats.getPolicy();
        int sysEntity = systemStats.getEntity();
        int sysRoleMember = systemStats.getRoleMember();
        int sysGroupMember = systemStats.getGroupMember();
        int sysAssertions = systemStats.getAssertion();
        int sysServiceHosts = systemStats.getServiceHost();
        int sysServicePublicKeys = systemStats.getPublicKey();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName1,
                "Test Domain1", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom1);

        // verify the stats for the domain

        Stats domain1Stats = zms.getStats(ctx, domainName1);
        assertEquals(domain1Stats.getSubdomain(), 0);
        assertEquals(domain1Stats.getRole(), 1);
        assertEquals(domain1Stats.getGroup(), 0);
        assertEquals(domain1Stats.getService(), 0);
        assertEquals(domain1Stats.getPolicy(), 1);
        assertEquals(domain1Stats.getEntity(), 0);
        assertEquals(domain1Stats.getRoleMember(), 2);
        assertEquals(domain1Stats.getGroupMember(), 0);
        assertEquals(domain1Stats.getAssertion(), 1);
        assertEquals(domain1Stats.getServiceHost(), 0);
        assertEquals(domain1Stats.getPublicKey(), 0);
        assertEquals(domain1Stats.getName(), domainName1);

        // verify the system counts are updated accordingly

        systemStats = zms.getSystemStats(ctx);
        assertEquals(systemStats.getSubdomain(), sysSubDomains + 1);
        assertEquals(systemStats.getRole(), sysRoles + domain1Stats.getRole());
        assertEquals(systemStats.getGroup(), sysGroups + domain1Stats.getGroup());
        assertEquals(systemStats.getService(), sysServices + domain1Stats.getService());
        assertEquals(systemStats.getPolicy(), sysPolicies + domain1Stats.getPolicy());
        assertEquals(systemStats.getEntity(), sysEntity + domain1Stats.getEntity());
        assertEquals(systemStats.getRoleMember(), sysRoleMember + domain1Stats.getRoleMember());
        assertEquals(systemStats.getGroupMember(), sysGroupMember + domain1Stats.getGroupMember());
        assertEquals(systemStats.getAssertion(), sysAssertions + domain1Stats.getAssertion());
        assertEquals(systemStats.getServiceHost(), sysServiceHosts + domain1Stats.getServiceHost());
        assertEquals(systemStats.getPublicKey(), sysServicePublicKeys + domain1Stats.getPublicKey());

        // add a second domain all the objects

        TopLevelDomain dom2 = zmsTestInitializer.createTopLevelDomainObject(domainName2,
                "Test Domain2", "testOrg", zmsTestInitializer.getAdminUser(), ctx.principal().getFullName());
        zms.postTopLevelDomain(ctx, auditRef, null, dom2);

        Stats domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 0);
        assertEquals(domain2Stats.getRole(), 1);
        assertEquals(domain2Stats.getGroup(), 0);
        assertEquals(domain2Stats.getService(), 0);
        assertEquals(domain2Stats.getPolicy(), 1);
        assertEquals(domain2Stats.getEntity(), 0);
        assertEquals(domain2Stats.getRoleMember(), 2);
        assertEquals(domain2Stats.getGroupMember(), 0);
        assertEquals(domain2Stats.getAssertion(), 1);
        assertEquals(domain2Stats.getServiceHost(), 0);
        assertEquals(domain2Stats.getPublicKey(), 0);
        assertEquals(domain2Stats.getName(), domainName2);

        Entity entity1 = zmsTestInitializer.createEntityObject(domainName2, "test-entity1");
        zms.putEntity(ctx, domainName2, "test-entity1", auditRef, entity1);

        domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 0);
        assertEquals(domain2Stats.getRole(), 1);
        assertEquals(domain2Stats.getGroup(), 0);
        assertEquals(domain2Stats.getService(), 0);
        assertEquals(domain2Stats.getPolicy(), 1);
        assertEquals(domain2Stats.getEntity(), 1);
        assertEquals(domain2Stats.getRoleMember(), 2);
        assertEquals(domain2Stats.getGroupMember(), 0);
        assertEquals(domain2Stats.getAssertion(), 1);
        assertEquals(domain2Stats.getServiceHost(), 0);
        assertEquals(domain2Stats.getPublicKey(), 0);

        // this creates one service host + 2 public keys

        ServiceIdentity service = zmsTestInitializer.createServiceObject(domainName2,
                "Service1", "http://localhost", "/usr/bin/java", "root",
                "users", "host1");
        zms.putServiceIdentity(ctx, domainName2, "Service1", auditRef, false, null, service);

        domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 0);
        assertEquals(domain2Stats.getRole(), 1);
        assertEquals(domain2Stats.getGroup(), 0);
        assertEquals(domain2Stats.getService(), 1);
        assertEquals(domain2Stats.getPolicy(), 1);
        assertEquals(domain2Stats.getEntity(), 1);
        assertEquals(domain2Stats.getRoleMember(), 2);
        assertEquals(domain2Stats.getGroupMember(), 0);
        assertEquals(domain2Stats.getAssertion(), 1);
        assertEquals(domain2Stats.getServiceHost(), 1);
        assertEquals(domain2Stats.getPublicKey(), 2);

        Group group1 = zmsTestInitializer.createGroupObject(domainName2, "group1", "user.user1", "user.user2");
        zms.putGroup(ctx, domainName2, "group1", auditRef, false, null, group1);

        domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 0);
        assertEquals(domain2Stats.getRole(), 1);
        assertEquals(domain2Stats.getGroup(), 1);
        assertEquals(domain2Stats.getService(), 1);
        assertEquals(domain2Stats.getPolicy(), 1);
        assertEquals(domain2Stats.getEntity(), 1);
        assertEquals(domain2Stats.getRoleMember(), 2);
        assertEquals(domain2Stats.getGroupMember(), 2);
        assertEquals(domain2Stats.getAssertion(), 1);
        assertEquals(domain2Stats.getServiceHost(), 1);
        assertEquals(domain2Stats.getPublicKey(), 2);

        Role role = zmsTestInitializer.createRoleObject(domainName2, "role1", null, "user.john", "user.jane");
        zms.putRole(ctx, domainName2, "role1", auditRef, false, null, role);

        domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 0);
        assertEquals(domain2Stats.getRole(), 2);
        assertEquals(domain2Stats.getGroup(), 1);
        assertEquals(domain2Stats.getService(), 1);
        assertEquals(domain2Stats.getPolicy(), 1);
        assertEquals(domain2Stats.getEntity(), 1);
        assertEquals(domain2Stats.getRoleMember(), 4);
        assertEquals(domain2Stats.getGroupMember(), 2);
        assertEquals(domain2Stats.getAssertion(), 1);
        assertEquals(domain2Stats.getServiceHost(), 1);
        assertEquals(domain2Stats.getPublicKey(), 2);

        Policy pol = zmsTestInitializer.createPolicyObject(domainName2, "policy1", "role1",
                "action1", "*:resource1", AssertionEffect.ALLOW);
        zms.putPolicy(ctx, domainName2, "policy1", auditRef, false, null, pol);

        domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 0);
        assertEquals(domain2Stats.getRole(), 2);
        assertEquals(domain2Stats.getGroup(), 1);
        assertEquals(domain2Stats.getService(), 1);
        assertEquals(domain2Stats.getPolicy(), 2);
        assertEquals(domain2Stats.getEntity(), 1);
        assertEquals(domain2Stats.getRoleMember(), 4);
        assertEquals(domain2Stats.getGroupMember(), 2);
        assertEquals(domain2Stats.getAssertion(), 2);
        assertEquals(domain2Stats.getServiceHost(), 1);
        assertEquals(domain2Stats.getPublicKey(), 2);

        final String subDomainName2 = domainName2 + ".sub";
        SubDomain subDom = zmsTestInitializer.createSubDomainObject("sub", domainName2, null,
                null, zmsTestInitializer.getAdminUser());
        zms.postSubDomain(ctx, domainName2, auditRef, null, subDom);

        domain2Stats = zms.getStats(ctx, domainName2);
        assertEquals(domain2Stats.getSubdomain(), 1);
        assertEquals(domain2Stats.getRole(), 2);
        assertEquals(domain2Stats.getGroup(), 1);
        assertEquals(domain2Stats.getService(), 1);
        assertEquals(domain2Stats.getPolicy(), 2);
        assertEquals(domain2Stats.getEntity(), 1);
        assertEquals(domain2Stats.getRoleMember(), 4);
        assertEquals(domain2Stats.getGroupMember(), 2);
        assertEquals(domain2Stats.getAssertion(), 2);
        assertEquals(domain2Stats.getServiceHost(), 1);
        assertEquals(domain2Stats.getPublicKey(), 2);

        Stats domain2SubStats = zms.getStats(ctx, subDomainName2);
        assertEquals(domain2SubStats.getSubdomain(), 0);
        assertEquals(domain2SubStats.getRole(), 1);
        assertEquals(domain2SubStats.getGroup(), 0);
        assertEquals(domain2SubStats.getService(), 0);
        assertEquals(domain2SubStats.getPolicy(), 1);
        assertEquals(domain2SubStats.getEntity(), 0);
        assertEquals(domain2SubStats.getRoleMember(), 1);
        assertEquals(domain2SubStats.getGroupMember(), 0);
        assertEquals(domain2SubStats.getAssertion(), 1);
        assertEquals(domain2SubStats.getServiceHost(), 0);
        assertEquals(domain2SubStats.getPublicKey(), 0);
        assertEquals(domain2SubStats.getName(), subDomainName2);

        // verify the total system counts again

        systemStats = zms.getSystemStats(ctx);
        assertEquals(systemStats.getSubdomain(), sysSubDomains + 3);
        assertEquals(systemStats.getRole(), sysRoles + domain1Stats.getRole() + domain2Stats.getRole() + domain2SubStats.getRole());
        assertEquals(systemStats.getGroup(), sysGroups + domain1Stats.getGroup() + domain2Stats.getGroup() + domain2SubStats.getGroup());
        assertEquals(systemStats.getService(), sysServices + domain1Stats.getService() + domain2Stats.getService() + domain2SubStats.getService());
        assertEquals(systemStats.getPolicy(), sysPolicies + domain1Stats.getPolicy() + domain2Stats.getPolicy() + domain2SubStats.getPolicy());
        assertEquals(systemStats.getEntity(), sysEntity + domain1Stats.getEntity() + domain2Stats.getEntity() + domain2SubStats.getEntity());
        assertEquals(systemStats.getRoleMember(), sysRoleMember + domain1Stats.getRoleMember() + domain2Stats.getRoleMember() + domain2SubStats.getRoleMember());
        assertEquals(systemStats.getGroupMember(), sysGroupMember + domain1Stats.getGroupMember() + domain2Stats.getGroupMember() + domain2SubStats.getGroupMember());
        assertEquals(systemStats.getAssertion(), sysAssertions + domain1Stats.getAssertion() + domain2Stats.getAssertion() + domain2SubStats.getAssertion());
        assertEquals(systemStats.getServiceHost(), sysServiceHosts + domain1Stats.getServiceHost() + domain2Stats.getServiceHost() + domain2SubStats.getServiceHost());
        assertEquals(systemStats.getPublicKey(), sysServicePublicKeys + domain1Stats.getPublicKey() + domain2Stats.getPublicKey() + domain2SubStats.getPublicKey());

        // delete subdomain and verify system counts again

        zms.deleteSubDomain(ctx, domainName2, "sub", auditRef, null);

        // verify we can no longer get stats for the deleted domain

        try {
            zms.getStats(ctx, subDomainName2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        // verify system counts again

        systemStats = zms.getSystemStats(ctx);
        assertEquals(systemStats.getSubdomain(), sysSubDomains + 2);
        assertEquals(systemStats.getRole(), sysRoles + domain1Stats.getRole() + domain2Stats.getRole());
        assertEquals(systemStats.getGroup(), sysGroups + domain1Stats.getGroup() + domain2Stats.getGroup());
        assertEquals(systemStats.getService(), sysServices + domain1Stats.getService() + domain2Stats.getService());
        assertEquals(systemStats.getPolicy(), sysPolicies + domain1Stats.getPolicy() + domain2Stats.getPolicy());
        assertEquals(systemStats.getEntity(), sysEntity + domain1Stats.getEntity() + domain2Stats.getEntity());
        assertEquals(systemStats.getRoleMember(), sysRoleMember + domain1Stats.getRoleMember() + domain2Stats.getRoleMember());
        assertEquals(systemStats.getGroupMember(), sysGroupMember + domain1Stats.getGroupMember() + domain2Stats.getGroupMember());
        assertEquals(systemStats.getAssertion(), sysAssertions + domain1Stats.getAssertion() + domain2Stats.getAssertion());
        assertEquals(systemStats.getServiceHost(), sysServiceHosts + domain1Stats.getServiceHost() + domain2Stats.getServiceHost());
        assertEquals(systemStats.getPublicKey(), sysServicePublicKeys + domain1Stats.getPublicKey() + domain2Stats.getPublicKey());

        // now delete both domains

        zms.deleteTopLevelDomain(ctx, domainName2, auditRef, null);
        zms.deleteTopLevelDomain(ctx, domainName1, auditRef, null);

        // verify counts again

        systemStats = zms.getSystemStats(ctx);
        assertEquals(systemStats.getSubdomain(), sysSubDomains);
        assertEquals(systemStats.getRole(), sysRoles);
        assertEquals(systemStats.getGroup(), sysGroups);
        assertEquals(systemStats.getService(), sysServices);
        assertEquals(systemStats.getPolicy(), sysPolicies);
        assertEquals(systemStats.getEntity(), sysEntity);
        assertEquals(systemStats.getRoleMember(), sysRoleMember);
        assertEquals(systemStats.getGroupMember(), sysGroupMember);
        assertEquals(systemStats.getAssertion(), sysAssertions);
        assertEquals(systemStats.getServiceHost(), sysServiceHosts);
        assertEquals(systemStats.getPublicKey(), sysServicePublicKeys);
    }
}
