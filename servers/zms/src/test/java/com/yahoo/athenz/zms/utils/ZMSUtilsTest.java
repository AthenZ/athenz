/**
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
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.utils.ZMSUtils;

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
        role2.setMembers(Arrays.asList(memberName));
        role2.setRoleMembers(Arrays.asList(roleMember));
        
        Role role3 = new Role();
        role3.setRoleMembers(Arrays.asList(roleMember));
        
        Role role4 = new Role();
        role4.setRoleMembers(Arrays.asList(roleMember));
        role4.setTrust("trust");
        
        Role role5 = new Role();
        role5.setMembers(Arrays.asList(memberName));
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
    public void testValidateRoleMembers(String domainName, Role role, boolean expectedFailure)
            throws Exception {
        String caller = null;
        try {
            ZMSUtils.validateRoleMembers(role, caller, domainName);
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
            {Arrays.asList("member1"), null, 1}, 
            {Arrays.asList("member1"), Arrays.asList("member1"), 0}, 
            {Arrays.asList("member1"), Arrays.asList("member2"), 1},
            {Arrays.asList("member1"), Arrays.asList("member2", "member1"), 0},
            {Arrays.asList("member1", "member2"), Arrays.asList("member2", "member1"), 0},
            {Arrays.asList("member1", "member2"), Arrays.asList("member3"), 2}
        };
    }
    
    @Test(dataProvider = "members")
    public void testRemoveMembers(List<String> orginalRoleMembersList,
            List<String> removeRoleMembersList, int expectedSize) throws Exception {
        
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
}
