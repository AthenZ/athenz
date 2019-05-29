/*
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zms.utils;

import static org.testng.Assert.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.AuditLoggerFactory;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLoggerFactory;
import com.yahoo.athenz.zms.*;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequestWrapper;

public class ZMSUtilsTest {

    @Test
    public void testRemoveDomainPrefix() {
        assertEquals("role1", ZMSUtils.removeDomainPrefix("role1", "domain1", "role."));
        assertEquals("role1", ZMSUtils.removeDomainPrefix("domain1:role.role1", "domain1", "role."));
        assertEquals("domain1:role.role1", ZMSUtils.removeDomainPrefix("domain1:role.role1", "domain2", "role."));
        assertEquals("domain1:role.role1", ZMSUtils.removeDomainPrefix("domain1:role.role1", "domain1", "policy."));
        assertEquals("policy1", ZMSUtils.removeDomainPrefix("domain1:policy.policy1", "domain1", "policy."));
    }
    
    @Test
    public void testGetTenantResourceGroupRolePrefix() {
        
        assertEquals("storage.tenant.sports.api.",
                ZMSUtils.getTenantResourceGroupRolePrefix("storage", "sports.api", null));
        assertEquals("storage.tenant.sports.api.res_group.Group1.",
                ZMSUtils.getTenantResourceGroupRolePrefix("storage", "sports.api", "Group1"));
    }
    
    @Test
    public void testGetTrustedResourceGroupRolePrefix() {
        assertEquals("coretech:role.storage.tenant.sports.api.",
                ZMSUtils.getTrustedResourceGroupRolePrefix("coretech", "storage", "sports.api", null));
        assertEquals("coretech:role.storage.tenant.sports.api.res_group.group1.",
                ZMSUtils.getTrustedResourceGroupRolePrefix("coretech", "storage", "sports.api", "group1"));
    }
    
    @Test
    public void testGetProviderResourceGroupRolePrefix() {
        assertEquals("sports.hosted.res_group.hockey.",
                ZMSUtils.getProviderResourceGroupRolePrefix("sports", "hosted", "hockey"));
        assertEquals("sports.hosted.",
                ZMSUtils.getProviderResourceGroupRolePrefix("sports", "hosted", null));
    }
    
    @Test
    public void testAssumeRoleResourceMatchActionNoMatch() {
        Assertion assertion = new Assertion()
                .setAction("test")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:*");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role1")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:*");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_rol")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:*");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
    }
    
    @Test
    public void testAssumeRoleResourceMatchRoleNoMatch() {
        Assertion assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:role.role2");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain2:role.role1");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("domain1:role.reader*");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain1:role.role1")
                .setResource("*:role.role2");
        assertFalse(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
    }
    
    @Test
    public void testAssumeRoleResourceMatch() {
        Assertion assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("domain1:role.role1");
        assertTrue(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("domain1:role.*");
        assertTrue(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("domain1:*");
        assertTrue(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
        
        assertion = new Assertion()
                .setAction("assume_role")
                .setEffect(AssertionEffect.ALLOW)
                .setRole("domain2:role.role1")
                .setResource("*:role.role1");
        assertTrue(ZMSUtils.assumeRoleResourceMatch("domain1:role.role1", assertion));
    }
    
    @DataProvider(name = "roles")
    public static Object[][] getRoles() {
        String domainName = "test_domain";

        Role role1 = new Role();
        String memberName = "member";
        RoleMember roleMember = new RoleMember().setMemberName(memberName);
        
        Role role2 = new Role();
        role2.setMembers(Collections.singletonList(memberName));
        role2.setRoleMembers(Collections.singletonList(roleMember));
        
        Role role3 = new Role();
        role3.setRoleMembers(Collections.singletonList(roleMember));
        
        Role role4 = new Role();
        role4.setRoleMembers(Collections.singletonList(roleMember));
        role4.setTrust("trust");
        
        Role role5 = new Role();
        role5.setMembers(Collections.singletonList(memberName));
        role5.setTrust("trust");
        
        Role role6 = new Role();
        role6.setTrust("trust");
        
        return new Object[][] {
            {domainName, role1, false}, 
            {domainName, role2, true}, 
            {domainName, role3, false}, 
            {domainName, role4, true},
            {domainName, role5, true}, 
            {"trust", role6, true}, 
            {"test_domain", role6, false}, 
        };
    }

    @Test(dataProvider = "roles")
    public void testValidateRoleMembers(String domainName, Role role, boolean expectedFailure) {
        try {
            ZMSUtils.validateRoleMembers(role, null, domainName);
            if (expectedFailure) {
                fail();
            }
        } catch (ResourceException e) {
            if (expectedFailure) {
                assertEquals(e.getCode(), 400);
            } else {
                fail("should not have failed with ResourceException");
            }
        }
    }
    
    @DataProvider(name = "members")
    public static Object[][] getMembers() {
        return new Object[][] {
            {Collections.singletonList("member1"), null, 1},
            {Collections.singletonList("member1"), Collections.singletonList("member1"), 0},
            {Collections.singletonList("member1"), Collections.singletonList("member2"), 1},
            {Collections.singletonList("member1"), Arrays.asList("member2", "member1"), 0},
            {Arrays.asList("member1", "member2"), Arrays.asList("member2", "member1"), 0},
            {Arrays.asList("member1", "member2"), Collections.singletonList("member3"), 2}
        };
    }
    
    @Test(dataProvider = "members")
    public void testRemoveMembers(List<String> orginalRoleMembersList,
            List<String> removeRoleMembersList, int expectedSize) {
        
        List<RoleMember> orginalRoleMembers = ZMSUtils.convertMembersToRoleMembers(orginalRoleMembersList);
        List<RoleMember> removeRoleMembers = ZMSUtils.convertMembersToRoleMembers(removeRoleMembersList);
        
        ZMSUtils.removeMembers(orginalRoleMembers, removeRoleMembers);
        
        //remove case
        for (RoleMember orgMember: orginalRoleMembers) {
            for (RoleMember removeMember: removeRoleMembers) {
                if (orgMember.getMemberName().equalsIgnoreCase(removeMember.getMemberName())) {
                    fail("Should have removed " + removeMember);
                }
            }
        }
        
        assertEquals(orginalRoleMembers.size(), expectedSize);
    }
    
    @Test
    public void testRemoveMembersInvalidInput() {
        List<RoleMember> list = Collections.singletonList(new RoleMember().setMemberName("member1"));
        ZMSUtils.removeMembers(list, null);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getMemberName(), "member1");
        
        ZMSUtils.removeMembers(null, list);
        assertEquals(list.size(), 1);
        assertEquals(list.get(0).getMemberName(), "member1");
    }

    @Test
    public void testParseBoolean() {
        assertEquals(true, ZMSUtils.parseBoolean(null, true));
        assertEquals(false, ZMSUtils.parseBoolean(null, false));
        assertEquals(true, ZMSUtils.parseBoolean("", true));
        assertEquals(false, ZMSUtils.parseBoolean("", false));
        assertEquals(true, ZMSUtils.parseBoolean("true", false));
        assertEquals(false, ZMSUtils.parseBoolean("false", true));
        assertEquals(false, ZMSUtils.parseBoolean("unknown", false));
    }

    @Test
    public void testAddAssertion() {

        Policy policy = new Policy();
        ZMSUtils.addAssertion(policy, "service", "update", "writers", AssertionEffect.ALLOW);
        ZMSUtils.addAssertion(policy, "table", "delete", "writers", AssertionEffect.DENY);

        assertEquals(policy.getAssertions().size(), 2);
        Assertion assertion = policy.getAssertions().get(1);
        assertEquals(assertion.getResource(), "table");
        assertEquals(assertion.getRole(), "writers");
        assertEquals(assertion.getAction(), "delete");
        assertEquals(assertion.getEffect(), AssertionEffect.DENY);
    }

    @Test
    public void testRemoveDomainPrefixForService() {

        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.api", "athenz"), "api");
        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.dev.api", "athenz.dev"), "api");
        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.dev.api", "athenz"), "dev.api");
        assertEquals(ZMSUtils.removeDomainPrefixForService("athenz.api", "coretech"), "athenz.api");
    }

    @Test
    public void testGetAudtLogMsgBuilder() {

        List<String> roles = Arrays.asList("role1", "role2");
        Principal principal = SimplePrincipal.create("athenz", "creds", roles, null);
        RsrcCtxWrapper ctx = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(ctx.principal()).thenReturn(principal);
        HttpServletRequestWrapper request = Mockito.mock(HttpServletRequestWrapper.class);
        Mockito.when(ctx.request()).thenReturn(request);
        Mockito.when(request.getRemoteAddr()).thenReturn("10.11.12.13");

        AuditLoggerFactory factory = new DefaultAuditLoggerFactory();
        AuditLogger auditLogger = factory.create();

        AuditLogMsgBuilder msgBuilder = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger, "athenz",
                "audit-ref", "unit-test", "putRole");
        assertNotNull(msgBuilder);
        assertTrue(msgBuilder.who().contains("who-roles=[role1, role2]"), msgBuilder.who());
    }
}
