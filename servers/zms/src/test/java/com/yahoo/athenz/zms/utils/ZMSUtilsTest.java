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

import org.testng.annotations.Test;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
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
}
