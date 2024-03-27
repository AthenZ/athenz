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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.yahoo.athenz.zms.ZMSConsts.ZMS_PROP_QUOTA_ASSERTION_CONDITIONS;
import static org.testng.Assert.*;

import com.yahoo.athenz.zms.store.ObjectStoreConnection;

public class QuotaCheckerTest {

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
    public void testGetDomainQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13)
                .setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17)
                .setSubdomain(18);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        
        Quota quota = quotaCheck.getDomainQuota(con, "athenz");
        assertNotNull(quota);
        assertEquals(quota.getAssertion(), 10);
        assertEquals(quota.getRole(), 14);
        assertEquals(quota.getPolicy(), 12);
    }
    
    @Test
    public void testGetDomainQuotaDefault() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(null);
        
        // we should get back our default quota
        
        Quota quota = quotaCheck.getDomainQuota(con, "athenz");
        assertNotNull(quota);
        assertEquals(quota.getAssertion(), 100);
        assertEquals(quota.getRole(), 1000);
        assertEquals(quota.getPolicy(), 1000);
    }

    @Test
    public void testGetListSize() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        assertEquals(quotaCheck.getListSize(null), 0);
        
        ArrayList<String> list = new ArrayList<>();
        assertEquals(quotaCheck.getListSize(list), 0);
        
        list.add("test1");
        assertEquals(quotaCheck.getListSize(list), 1);

        list.add("test2");
        list.add("test3");
        assertEquals(quotaCheck.getListSize(list), 3);
    }

    @Test
    public void testCheckSubDomainQuotaTopLevel() {
        
        // top level domains have no check
        QuotaChecker quotaCheck = new QuotaChecker();
        quotaCheck.checkSubdomainQuota(null, "athenz", "caller");
    }
    
    @Test
    public void testCheckSubDomainQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setSubdomain(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        ArrayList<String> domains = new ArrayList<>();
        domains.add("athenz.one");
        Mockito.when(con.listDomains("athenz.", 0)).thenReturn(domains);
        
        // this should be successful - no exceptions
        
        quotaCheck.checkSubdomainQuota(con, "athenz.quota", "caller");
    }
    
    @Test
    public void testCheckSubDomainQuotaExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setSubdomain(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        ArrayList<String> domains = new ArrayList<>();
        domains.add("athenz.one");
        domains.add("athenz.two");
        Mockito.when(con.listDomains("athenz.", 0)).thenReturn(domains);
        
        // this should be successful - no exceptions
        
        try {
            quotaCheck.checkSubdomainQuota(con, "athenz.quota", "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkSubdomainQuota(con, "athenz.quota", "caller");
    }
    
    @Test
    public void testCheckRoleQuotaNull() {
        
        // null objects have no check
        QuotaChecker quotaCheck = new QuotaChecker();
        quotaCheck.checkRoleQuota(null, "athenz", null, "caller");
    }
    
    @Test
    public void testCheckRoleQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setRole(2).setRoleMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countRoles("athenz")).thenReturn(1);
        
        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        Role role = new Role().setRoleMembers(roleMembers);
        
        // this should be successful - no exceptions

        quotaCheck.checkRoleQuota(con, "athenz", role, "caller");
    }
    
    @Test
    public void testCheckRoleQuotaRoleMemberExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setRole(2).setRoleMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countRoles("athenz")).thenReturn(1);
        
        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("user.doe"));
        Role role = new Role().setRoleMembers(roleMembers);
        
        try {
            quotaCheck.checkRoleQuota(con, "athenz", role, "caller");
            fail();
       } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("role member quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkRoleQuota(con, "athenz", role, "caller");
    }
    
    @Test
    public void testCheckRoleQuotaRoleCountExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setRole(2).setRoleMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countRoles("athenz")).thenReturn(2);
        
        ArrayList<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        Role role = new Role().setRoleMembers(roleMembers);
        
        try {
            quotaCheck.checkRoleQuota(con, "athenz", role, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("role quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkRoleQuota(con, "athenz", role, "caller");
    }
    
    @Test
    public void testCheckRoleMembershipQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setRole(2).setRoleMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countRoleMembers("athenz", "readers")).thenReturn(1);
        Membership membership = new Membership().setIsMember(false);
        Mockito.when(con.getRoleMember("athenz", "readers", "user.joe", 0, false)).thenReturn(membership);

        // this should complete successfully
        
        quotaCheck.checkRoleMembershipQuota(con, "athenz", "readers", "user.joe", 0, "caller");
    }
    
    @Test
    public void testCheckRoleMembershipQuotaRoleCountExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setRole(2).setRoleMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countRoleMembers("athenz", "readers")).thenReturn(2);
        Membership membership = new Membership().setIsMember(false);
        Mockito.when(con.getRoleMember("athenz", "readers", "user.joe", 0, false)).thenReturn(membership);

        try {
            quotaCheck.checkRoleMembershipQuota(con, "athenz", "readers", "user.joe", 0, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("role member quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkRoleMembershipQuota(con, "athenz", "readers", "user.joe", 0, "caller");
    }

    @Test
    public void testCheckPolicyQuotaNull() {
        
        // null objects have no check
        QuotaChecker quotaCheck = new QuotaChecker();
        quotaCheck.checkPolicyQuota(null, "athenz", null, "caller");
    }
    
    @Test
    public void testCheckPolicyQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setPolicy(2).setAssertion(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countPolicies("athenz")).thenReturn(1);
        
        ArrayList<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setAction("*").setResource("*").setRole("admin"));
        
        Policy policy = new Policy();
        policy.setAssertions(assertions);
        
        // this should be successful - no exceptions

        quotaCheck.checkPolicyQuota(con, "athenz", policy, "caller");
    }
    
    @Test
    public void testCheckPolicyQuotaAssertionExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setPolicy(2).setAssertion(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countPolicies("athenz")).thenReturn(1);
        
        ArrayList<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setAction("*").setResource("*").setRole("admin"));
        assertions.add(new Assertion().setAction("*").setResource("*").setRole("admin"));
        assertions.add(new Assertion().setAction("*").setResource("*").setRole("admin"));
        
        Policy policy = new Policy();
        policy.setAssertions(assertions);
        
        try {
            quotaCheck.checkPolicyQuota(con, "athenz", policy, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("policy assertion quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkPolicyQuota(con, "athenz", policy, "caller");
    }
    
    @Test
    public void testCheckPolicyQuotaPolicyCountExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setPolicy(2).setAssertion(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countPolicies("athenz")).thenReturn(2);
        
        ArrayList<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setAction("*").setResource("*").setRole("admin"));
        assertions.add(new Assertion().setAction("*").setResource("*").setRole("admin"));
        
        Policy policy = new Policy();
        policy.setAssertions(assertions);
        
        try {
            quotaCheck.checkPolicyQuota(con, "athenz", policy, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("policy quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkPolicyQuota(con, "athenz", policy, "caller");
    }
    
    @Test
    public void testCheckPolicyAssertionQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setPolicy(2).setAssertion(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countAssertions("athenz", "readers", null)).thenReturn(1);

        // this should be successful - no exceptions

        quotaCheck.checkPolicyAssertionQuota(con, "athenz", "readers", null, "caller");
    }
    
    @Test
    public void testCheckPolicyAssertionQuotaAssertionExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setPolicy(2).setAssertion(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countAssertions("athenz", "readers", null)).thenReturn(3);
        
        try {
            quotaCheck.checkPolicyAssertionQuota(con, "athenz", "readers", null, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("policy assertion quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkPolicyAssertionQuota(con, "athenz", "readers", null, "caller");
    }

    @Test
    public void testCheckServiceQuotaNull() {
        
        // null objects have no check
        QuotaChecker quotaCheck = new QuotaChecker();
        quotaCheck.checkServiceIdentityQuota(null, "athenz", null, "caller");
    }
    
    @Test
    public void testCheckServiceQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setService(2).setServiceHost(2).setPublicKey(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countServiceIdentities("athenz")).thenReturn(1);
        
        ArrayList<String> hosts = new ArrayList<>();
        hosts.add("host1");
        
        ArrayList<PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(new PublicKeyEntry().setId("id1").setKey("key"));
        
        ServiceIdentity service = new ServiceIdentity();
        service.setHosts(hosts);
        service.setPublicKeys(publicKeys);
        
        // this should be successful - no exceptions

        quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
    }
    
    @Test
    public void testCheckServiceQuotaServiceCountExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setService(2).setServiceHost(2).setPublicKey(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countServiceIdentities("athenz")).thenReturn(2);
        
        ArrayList<String> hosts = new ArrayList<>();
        hosts.add("host1");
        
        ArrayList<PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(new PublicKeyEntry().setId("id1").setKey("key"));
        
        ServiceIdentity service = new ServiceIdentity();
        service.setHosts(hosts);
        service.setPublicKeys(publicKeys);
        
        // this should be successful - no exceptions
        
        try {
            quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("service quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
    }
    
    @Test
    public void testCheckServiceQuotaServiceHostExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setService(2).setServiceHost(2).setPublicKey(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countServiceIdentities("athenz")).thenReturn(1);
        
        ArrayList<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        hosts.add("host3");
        
        ArrayList<PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(new PublicKeyEntry().setId("id1").setKey("key"));
        
        ServiceIdentity service = new ServiceIdentity();
        service.setHosts(hosts);
        service.setPublicKeys(publicKeys);
        
        // this should be successful - no exceptions
        
        try {
            quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("service host quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
    }
    
    @Test
    public void testCheckServiceQuotaPublicKeyExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setService(2).setServiceHost(2).setPublicKey(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countServiceIdentities("athenz")).thenReturn(1);
        
        ArrayList<String> hosts = new ArrayList<>();
        hosts.add("host1");
        
        ArrayList<PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(new PublicKeyEntry().setId("id1").setKey("key"));
        publicKeys.add(new PublicKeyEntry().setId("id2").setKey("key"));
        publicKeys.add(new PublicKeyEntry().setId("id3").setKey("key"));
        
        ServiceIdentity service = new ServiceIdentity();
        service.setHosts(hosts);
        service.setPublicKeys(publicKeys);
        
        // this should be successful - no exceptions
        
        try {
            quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("service public key quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkServiceIdentityQuota(con, "athenz", service, "caller");
    }

    @Test
    public void testCheckServicePublicKeyQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setService(2).setServiceHost(2).setPublicKey(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countPublicKeys("athenz", "storage")).thenReturn(1);
        
        // this should be successful - no exceptions
        
        quotaCheck.checkServiceIdentityPublicKeyQuota(con, "athenz", "storage", "caller");
    }
    
    @Test
    public void testCheckServicePublicKeyQuotaExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setService(2).setServiceHost(2).setPublicKey(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countPublicKeys("athenz", "storage")).thenReturn(2);
        
        try {
            quotaCheck.checkServiceIdentityPublicKeyQuota(con, "athenz", "storage", "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("service public key quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkServiceIdentityPublicKeyQuota(con, "athenz", "storage", "caller");
    }

    @Test
    public void testCheckEntityQuotaNull() {
        
        // null objects have no check
        QuotaChecker quotaCheck = new QuotaChecker();
        quotaCheck.checkEntityQuota(null, "athenz", null, "caller");
    }
    
    @Test
    public void testCheckEntityQuota() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setEntity(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countEntities("athenz")).thenReturn(1);
        
        Entity entity = new Entity();
        
        // this should be successful - no exceptions

        quotaCheck.checkEntityQuota(con, "athenz", entity, "caller");
    }
    
    @Test
    public void testCheckEntityQuotaEntityCountExceeded() {
        
        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setEntity(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countEntities("athenz")).thenReturn(2);
        
        Entity entity = new Entity();
        
        try {
            quotaCheck.checkEntityQuota(con, "athenz", entity, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("entity quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkEntityQuota(con, "athenz", entity, "caller");
    }

    @Test
    public void testCheckGroupQuota() {

        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setGroup(2).setGroupMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countGroups("athenz")).thenReturn(1);

        ArrayList<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));
        Group group = new Group().setGroupMembers(groupMembers);

        // this should be successful - no exceptions

        quotaCheck.checkGroupQuota(con, "athenz", group, "caller");
    }

    @Test
    public void testCheckGroupQuotaGroupMemberExceeded() {

        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setGroup(2).setGroupMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countGroups("athenz")).thenReturn(1);

        ArrayList<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));
        groupMembers.add(new GroupMember().setMemberName("user.jane"));
        groupMembers.add(new GroupMember().setMemberName("user.doe"));
        Group group = new Group().setGroupMembers(groupMembers);

        try {
            quotaCheck.checkGroupQuota(con, "athenz", group, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("group member quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkGroupQuota(con, "athenz", group, "caller");
    }

    @Test
    public void testCheckGroupQuotaGroupCountExceeded() {

        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setGroup(2).setGroupMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countGroups("athenz")).thenReturn(2);

        ArrayList<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.joe"));
        Group group = new Group().setGroupMembers(groupMembers);

        try {
            quotaCheck.checkGroupQuota(con, "athenz", group, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("group quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkGroupQuota(con, "athenz", group, "caller");
    }

    @Test
    public void testCheckGroupMembershipQuota() {

        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setGroup(2).setGroupMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countGroupMembers("athenz", "readers")).thenReturn(1);
        GroupMembership membership = new GroupMembership().setIsMember(false);
        Mockito.when(con.getGroupMember("athenz", "readers", "user.joe", 0, false)).thenReturn(membership);

        // this should complete successfully

        quotaCheck.checkGroupMembershipQuota(con, "athenz", "readers", "user.joe", 0, "caller");
    }

    @Test
    public void testCheckGroupMembershipQuotaGroupCountExceeded() {

        QuotaChecker quotaCheck = new QuotaChecker();
        Quota mockQuota = new Quota().setName("athenz")
                .setGroup(2).setGroupMember(2);
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.getQuota("athenz")).thenReturn(mockQuota);
        Mockito.when(con.countGroupMembers("athenz", "readers")).thenReturn(2);
        GroupMembership membership = new GroupMembership().setIsMember(false);
        Mockito.when(con.getGroupMember("athenz", "readers", "user.joe", 0, false)).thenReturn(membership);

        try {
            quotaCheck.checkGroupMembershipQuota(con, "athenz", "readers", "user.joe", 0, "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
            assertTrue(ex.getMessage().contains("group member quota exceeded"));
        }

        // with quota check disabled - no exceptions

        quotaCheck.setQuotaCheckEnabled(false);
        quotaCheck.checkGroupMembershipQuota(con, "athenz", "readers", "user.joe", 0,  "caller");
    }

    @Test
    public void testCheckGroupQuotaNull() {

        // null objects have no check
        QuotaChecker quotaCheck = new QuotaChecker();
        quotaCheck.checkGroupQuota(null, "athenz", null, "caller");
    }

    @Test
    public void testCheckAssertionConditionsQuota() {
        QuotaChecker quotaCheck = new QuotaChecker();
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.countAssertionConditions(1)).thenReturn(8).thenReturn(8).thenReturn(10);
        AssertionConditions assertionConditions = new AssertionConditions();
        assertionConditions.setConditionsList(new ArrayList<>());
        AssertionCondition ac1 = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac1.setConditionsMap(m1);

        AssertionCondition ac2 = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m2 = new HashMap<>();
        m2.put("key2", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value2"));
        ac2.setConditionsMap(m2);
        assertionConditions.getConditionsList().add(ac1);
        assertionConditions.getConditionsList().add(ac2);
        try {
            // 8 conditions in DB
            quotaCheck.checkAssertionConditionsQuota(con, 1, assertionConditions, "test");
        } catch (ResourceException ignored) {
            fail();
        }
        // condition objects are still 2 but total num of conditions will be 3
        m2.put("key3", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value3"));
        try {
            // 8 conditions in DB
            quotaCheck.checkAssertionConditionsQuota(con, 1, assertionConditions, "test");
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        try {
            // 10 conditions in DB
            quotaCheck.checkAssertionConditionsQuota(con,1, assertionConditions, "test");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }
        quotaCheck.setQuotaCheckEnabled(false);
        try {
            quotaCheck.checkAssertionConditionsQuota(con, 1, assertionConditions, "test");
        } catch (ResourceException ignored) {
            fail();
        }
        quotaCheck.setQuotaCheckEnabled(true);
        try {
            quotaCheck.checkAssertionConditionsQuota(con, 1, null, "test");
        } catch (ResourceException ignored) {
            fail();
        }
        assertionConditions.setConditionsList(null);
        try {
            quotaCheck.checkAssertionConditionsQuota(con, 1, assertionConditions, "test");
        } catch (ResourceException ignored) {
            fail();
        }
        assertionConditions.setConditionsList(new ArrayList<>());
        try {
            quotaCheck.checkAssertionConditionsQuota(con, 1, assertionConditions, "test");
        } catch (ResourceException ignored) {
            fail();
        }
    }

    @Test
    public void testCheckAssertionConditionQuota() {
        QuotaChecker quotaCheck = new QuotaChecker();
        ObjectStoreConnection con = Mockito.mock(ObjectStoreConnection.class);
        Mockito.when(con.countAssertionConditions(1)).thenReturn(9).thenReturn(9).thenReturn(9).thenReturn(10).thenReturn(5);
        AssertionCondition ac1 = new AssertionCondition().setId(1);
        Map<String, AssertionConditionData> m1 = new HashMap<>();
        m1.put("key1", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value1"));
        ac1.setConditionsMap(m1);

        try {
            // 9 conditions in DB
            quotaCheck.checkAssertionConditionQuota(con, 1, ac1, "test");
        } catch (ResourceException ignored) {
            fail();
        }

        m1.put("key2", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value2"));
        try {
            // 9 conditions in DB
            quotaCheck.checkAssertionConditionQuota(con, 1, ac1, "test");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        m1.put("key3", new AssertionConditionData().setOperator(AssertionConditionOperator.EQUALS).setValue("value3"));
        try {
            // 9 conditions in DB
            quotaCheck.checkAssertionConditionQuota(con, 1, ac1, "test");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        try {
            // 10 conditions in DB
            quotaCheck.checkAssertionConditionQuota(con,  1, ac1, "test");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }
        quotaCheck.setQuotaCheckEnabled(false);
        try {
            quotaCheck.checkAssertionConditionQuota(con,  1, ac1, "test");
        } catch (ResourceException ignored) {
            fail();
        }
        quotaCheck.setQuotaCheckEnabled(true);
        try {
            quotaCheck.checkAssertionConditionQuota(con,  1, null, "test");
        } catch (ResourceException ignored) {
            fail();
        }
        System.setProperty(ZMS_PROP_QUOTA_ASSERTION_CONDITIONS, "5");
        QuotaChecker q2 = new QuotaChecker();
        try {
            // 5 conditions in DB but limit is set to 5
            q2.checkAssertionConditionQuota(con,  1, ac1, "test");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }
        System.clearProperty(ZMS_PROP_QUOTA_ASSERTION_CONDITIONS);
    }

    @Test
    public void testRoleWithMaxLimits() {

        final String domainName = "role-max-members";
        final String roleName1 = "role1";
        final String roleName2 = "role2";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.test1"));
        roleMembers.add(new RoleMember().setMemberName("user.test2"));

        // creating a role with the max members set to 1 should be
        // rejected

        Role role = zmsTestInitializer.createRoleObject(domainName, roleName1, null, roleMembers);
        role.setMaxMembers(1);

        try {
            zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // now we're going to increase the limit and make sure it works

        role.setMaxMembers(2);
        zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role);

        // now we're going to add a 3rd member and make sure it fails

        roleMembers.add(new RoleMember().setMemberName("user.test3"));
        role.setRoleMembers(roleMembers);
        try {
            zmsImpl.putRole(ctx, domainName, roleName1, auditRef, false, null, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // let's try to add a 3rd member directly which should also be rejected

        Membership membership = new Membership().setMemberName("user.test3");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName1, "user.test3", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // let's get our meta and verify the max members value

        Role roleRes = zmsImpl.getRole(ctx, domainName, roleName1, false, false, false);
        assertEquals(roleRes.getMaxMembers(), 2);

        // now let's update the max members through role meta

        RoleMeta roleMeta = new RoleMeta().setMaxMembers(3);
        zmsImpl.putRoleMeta(ctx, domainName, roleName1, auditRef, null, roleMeta);

        // now let's try our membership operation which should succeed

        zmsImpl.putMembership(ctx, domainName, roleName1, "user.test3", auditRef, false, null, membership);

        // if we try another one then it should fail

        Membership membership4 = new Membership().setMemberName("user.test4");
        try {
            zmsImpl.putMembership(ctx, domainName, roleName1, "user.test4", auditRef, false, null, membership4);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // let's remove the limit

        roleMeta = new RoleMeta().setMaxMembers(0);
        zmsImpl.putRoleMeta(ctx, domainName, roleName1, auditRef, null, roleMeta);

        roleRes = zmsImpl.getRole(ctx, domainName, roleName1, false, false, false);
        assertNull(roleRes.getMaxMembers());

        // now let's try our membership operation which should succeed

        zmsImpl.putMembership(ctx, domainName, roleName1, "user.test4", auditRef, false, null, membership4);

        // adding a role with the max member limit set to 0 is ok

        role = zmsTestInitializer.createRoleObject(domainName, roleName2, null, roleMembers);
        role.setMaxMembers(0);
        zmsImpl.putRole(ctx, domainName, roleName2, auditRef, false, null, role);

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }

    @Test
    public void testGroupWithMaxLimits() {

        final String domainName = "group-max-members";
        final String groupName1 = "group1";
        final String groupName2 = "group2";

        ZMSImpl zmsImpl = zmsTestInitializer.getZms();
        RsrcCtxWrapper ctx = zmsTestInitializer.getMockDomRsrcCtx();
        final String auditRef = zmsTestInitializer.getAuditRef();

        TopLevelDomain dom1 = zmsTestInitializer.createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", "user.user1");
        zmsImpl.postTopLevelDomain(ctx, auditRef, null, dom1);

        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user.test1"));
        groupMembers.add(new GroupMember().setMemberName("user.test2"));

        // creating a group with the max members set to 1 should be
        // rejected

        Group group = zmsTestInitializer.createGroupObject(domainName, groupName1, groupMembers);
        group.setMaxMembers(1);

        try {
            zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // now we're going to increase the limit and make sure it works

        group.setMaxMembers(2);
        zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group);

        // now we're going to add a 3rd member and make sure it fails

        groupMembers.add(new GroupMember().setMemberName("user.test3"));
        group.setGroupMembers(groupMembers);
        try {
            zmsImpl.putGroup(ctx, domainName, groupName1, auditRef, false, null, group);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // let's try to add a 3rd member directly which should also be rejected

        GroupMembership membership = new GroupMembership().setMemberName("user.test3");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.test3", auditRef, false, null, membership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // let's get our meta and verify the max members value

        Group groupRes = zmsImpl.getGroup(ctx, domainName, groupName1, false, false);
        assertEquals(groupRes.getMaxMembers(), 2);

        // now let's update the max members through group meta

        GroupMeta groupMeta = new GroupMeta().setMaxMembers(3);
        zmsImpl.putGroupMeta(ctx, domainName, groupName1, auditRef, null, groupMeta);

        // now let's try our membership operation which should succeed

        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.test3", auditRef, false, null, membership);

        // if we try another one then it should fail

        GroupMembership membership4 = new GroupMembership().setMemberName("user.test4");
        try {
            zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.test4", auditRef, false, null, membership4);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.TOO_MANY_REQUESTS);
        }

        // let's remove the limit

        groupMeta = new GroupMeta().setMaxMembers(0);
        zmsImpl.putGroupMeta(ctx, domainName, groupName1, auditRef, null, groupMeta);

        groupRes = zmsImpl.getGroup(ctx, domainName, groupName1, false, false);
        assertNull(groupRes.getMaxMembers());

        // now let's try our membership operation which should succeed

        zmsImpl.putGroupMembership(ctx, domainName, groupName1, "user.test4", auditRef, false, null, membership4);

        // adding a group with 0 as the limit is allowed

        group = zmsTestInitializer.createGroupObject(domainName, groupName2, groupMembers);
        group.setMaxMembers(0);
        zmsImpl.putGroup(ctx, domainName, groupName2, auditRef, false, null, group);

        zmsTestInitializer.deleteTopLevelDomain(domainName);
    }
}
