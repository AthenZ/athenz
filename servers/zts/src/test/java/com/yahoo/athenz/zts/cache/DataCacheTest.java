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
package com.yahoo.athenz.zts.cache;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.annotations.Test;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;

public class DataCacheTest {

    private static final String ZTS_Y64_CERT0 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84a"
            + "EtFVWZTU2dwWHIzQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbE"
            + "dVT0VnMmpzbWRha1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY"
            + "0cmJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT0 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1tGSVCA8wl5ew5Y76Wj2rJAUD\n"
            + "YanEJfKmAlx5cQ/8hKEUfSSgpXr3Czdh1a26dlb7mmK29qmXJXh6umW9AyfTOKVo\n"
            + "+6ASloVU3avvuflGUOEg2jsmdakR24KcLjAu6QrUe417lG3t8qSPIGjS5C+CsJUw\n"
            + "h04hHx5f+PEwxV4rbQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ZTS_Y64_CERT1 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FETUhWaFRNZldJQWdvTEdhbkx2QkNNRytRdAoySU9pcml2cGRLSFNPSkpsYX"
            + "VKRUNlWlY1MTVmWG91SjhRb09IczA4UGlsdXdjeHF5dmhJSlduNWFrVEhGSWh5CkdDNkdtUTUzbG9WSEtTVE1WO"
            + "DM1M0FjNkhydzYxbmJZMVQ2TnA2bjdxdXI4a1UwR2tmdk5hWFZrK09LNVBaankKbkxzZ251UjlCeFZndlM4ZjJR"
            + "SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT1 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMHVhTMfWIAgoLGanLvBCMG+Qt\n"
            + "2IOirivpdKHSOJJlauJECeZV515fXouJ8QoOHs08PiluwcxqyvhIJWn5akTHFIhy\n"
            + "GC6GmQ53loVHKSTMV8353Ac6Hrw61nbY1T6Np6n7qur8kU0GkfvNaXVk+OK5PZjy\n"
            + "nLsgnuR9BxVgvS8f2QIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ZTS_Y64_CERT2 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FEbmZsZVZ4d293aitRWStjQi8rbWs5YXZYZgpHUWVpTTdOMlMwby9LV3FWK2h"
            + "GVWtDZkExMWxEYVJoZUY0alFhSzVaM2pPUE9nbklOZE5hd3VXQ081NUxKdVJRCmI1R0ZSbzhPNjNJNzA3M3ZDZ0V"
            + "KdmNST09SdjJDYWhQbnBKbjc3bkhQdlV2Szl0M3JyRURhdi8vanA0UDN5REMKNEVNdHBScmduUXBXNmpJSWlRSUR"
            + "BUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT2 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnfleVxwowj+QY+cB/+mk9avXf\n"
            + "GQeiM7N2S0o/KWqV+hFUkCfA11lDaRheF4jQaK5Z3jOPOgnINdNawuWCO55LJuRQ\n"
            + "b5GFRo8O63I7073vCgEJvcROORv2CahPnpJn77nHPvUvK9t3rrEDav//jp4P3yDC\n"
            + "4EMtpRrgnQpW6jIIiQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ZTS_Y64_CERT3 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FETWRqSmUwY01wSGR4ZEJKTDcvR2poNTNVUAp5WTdVQ2VlYnZUa2M2S1ZmR0"
            + "RnVVlrMUhtaWJ5U21lbnZOYitkNkhXQ1YySGVicUptN1krL2VuaFNkcTR3QTJrCnFtdmFHY09rV1R2cUU2a2J1"
            + "MG5LemdUK21jck1sOVpqTHdBQXZPS1hTRi82MTJxQ0tlSElRd3ZtWlB1RkJJTjEKUnFteWgwT0k1aHN5VS9nYj"
            + "Z3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT3 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMdjJe0cMpHdxdBJL7/Gjh53UP\n"
            + "yY7UCeebvTkc6KVfGDgUYk1HmibySmenvNb+d6HWCV2HebqJm7Y+/enhSdq4wA2k\n"
            + "qmvaGcOkWTvqE6kbu0nKzgT+mcrMl9ZjLwAAvOKXSF/612qCKeHIQwvmZPuFBIN1\n"
            + "Rqmyh0OI5hsyU/gb6wIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    
    @Test
    public void testDomainSetGet() {
        
        DomainData domain = new DomainData();
        domain.setName("testDomain");
        
        DataCache cache = new DataCache();
        cache.setDomainData(domain);
        
        DomainData dom = cache.getDomainData();
        assertNotNull(dom);
        assertEquals(dom.getName(), "testDomain");
    }
    
    @Test
    public void testRoleNoMembers() {
        
        Role role = new Role();
        role.setName("dom.role1");
        
        DataCache cache = new DataCache();
        cache.processRole(role);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNull(set1);
    }
    
    @Test
    public void testSimpleRole() {
        
        Role role = new Role();
        role.setName("dom.role1");

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        members.add(new RoleMember().setMemberName("user_domain.user2"));
        role.setRoleMembers(members);
        
        DataCache cache = new DataCache();
        cache.processRole(role);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set2.size(), 1);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNull(set3);
        
        Map<String, Set<String>> map = cache.getTrustMap();
        assertNotNull(map);
        assertEquals(map.size(), 0);
    }
    
    @Test
    public void testSimpleRoleDuplicateMember() {
        
        Role role = new Role();
        role.setName("dom.role1");

        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        members.add(new RoleMember().setMemberName("user_domain.user2"));
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        role.setRoleMembers(members);
        
        DataCache cache = new DataCache();
        cache.processRole(role);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set2.size(), 1);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNull(set3);
        
        Map<String, Set<String>> map = cache.getTrustMap();
        assertNotNull(map);
        assertEquals(map.size(), 0);
    }
    
    @Test
    public void testMultipleRoles() {
        
        Role role1 = new Role();
        role1.setName("dom.role1");

        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        role1.setRoleMembers(members1);
        
        Role role2 = new Role();
        role2.setName("dom.role2");

        List<RoleMember> members2 = new ArrayList<>();
        members2.add(new RoleMember().setMemberName("user_domain.user2"));
        members2.add(new RoleMember().setMemberName("user_domain.user3"));
        role2.setRoleMembers(members2);
        
        DataCache cache = new DataCache();
        
        cache.processRole(role1);
        cache.processRole(role2);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("dom.role1", 0)));
        assertTrue(set2.contains(new MemberRole("dom.role2", 0)));
        assertEquals(set2.size(), 2);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("dom.role2", 0)));
        assertEquals(set3.size(), 1);
        
        Set<MemberRole> set4 = cache.getMemberRoleSet("user_domain.user4");
        assertNull(set4);
    }
    
    @Test
    public void testProcessRoleMembers() {
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        
        DataCache cache = new DataCache();
        cache.processRoleMembers("dom.role1", members1);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set2.size(), 1);
    }
    
    @Test
    public void testProcessRoleMembersWithWildcards() {
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        members1.add(new RoleMember().setMemberName("user_domain.*"));
        members1.add(new RoleMember().setMemberName("user_domain.user*"));
        members1.add(new RoleMember().setMemberName("*"));
        
        DataCache cache = new DataCache();
        cache.processRoleMembers("dom.role1", members1);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set2.size(), 1);
        
        Set<MemberRole> set3 = cache.getAllMemberRoleSet();
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set3.size(), 1);
        
        Map<String, Set<MemberRole>> setMap = cache.getPrefixMemberRoleSetMap();
        assertNotNull(setMap);
        assertEquals(setMap.size(), 2);
        
        Set<MemberRole> set4 = setMap.get("user_domain.");
        assertNotNull(set4);
        assertTrue(set4.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set4.size(), 1);
        
        Set<MemberRole> set5 = setMap.get("user_domain.user");
        assertNotNull(set5);
        assertTrue(set5.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set5.size(), 1);
    }
    
    @Test
    public void testProcessRoleMembersWithWildcardsMultipleRoles() {
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        members1.add(new RoleMember().setMemberName("user_domain.*"));
        members1.add(new RoleMember().setMemberName("user_domain.user*"));
        members1.add(new RoleMember().setMemberName("*"));
        
        List<RoleMember> members2 = new ArrayList<>();
        members2.add(new RoleMember().setMemberName("user_domain.user1"));
        members2.add(new RoleMember().setMemberName("user_domain.user3"));
        members2.add(new RoleMember().setMemberName("user_domain.*"));
        members2.add(new RoleMember().setMemberName("*"));
        
        DataCache cache = new DataCache();
        cache.processRoleMembers("dom.role1", members1);
        cache.processRoleMembers("dom.role2", members2);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("dom.role1", 0)));
        assertTrue(set1.contains(new MemberRole("dom.role2", 0)));
        assertEquals(set1.size(), 2);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set2.size(), 1);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("dom.role2", 0)));
        assertEquals(set3.size(), 1);
        
        Set<MemberRole> set4 = cache.getAllMemberRoleSet();
        assertNotNull(set4);
        assertTrue(set4.contains(new MemberRole("dom.role1", 0)));
        assertTrue(set4.contains(new MemberRole("dom.role2", 0)));
        assertEquals(set4.size(), 2);
        
        Map<String, Set<MemberRole>> setMap = cache.getPrefixMemberRoleSetMap();
        assertNotNull(setMap);
        assertEquals(setMap.size(), 2);
        
        Set<MemberRole> set5= setMap.get("user_domain.");
        assertNotNull(set5);
        assertTrue(set5.contains(new MemberRole("dom.role1", 0)));
        assertTrue(set5.contains(new MemberRole("dom.role2", 0)));
        assertEquals(set4.size(), 2);
        
        Set<MemberRole> set6 = setMap.get("user_domain.user");
        assertNotNull(set6);
        assertTrue(set6.contains(new MemberRole("dom.role1", 0)));
        assertEquals(set6.size(), 1);
    }
    
    @Test
    public void testRoleWithTrust() {
        
        Role role1 = new Role();
        role1.setName("dom.role1");
        role1.setTrust("dom2");
        
        DataCache cache = new DataCache();
        cache.processRole(role1);
       
        Map<String, Set<String>> map = cache.getTrustMap();
        assertNotNull(map);
        assertEquals(map.size(), 1);
        assertTrue(map.containsKey("dom2"));
        assertEquals(map.get("dom2").size(), 1);
        assertTrue(map.get("dom2").contains("dom.role1"));
    }

    @Test
    public void testProcessRoleTrustDomain() {
        
        DataCache cache = new DataCache();
        cache.processRoleTrustDomain("dom.role1", "trustD");
        
        Map<String, Set<String>> map = cache.getTrustMap();
        assertNotNull(map);
        assertEquals(map.size(), 1);
        assertTrue(map.containsKey("trustD"));
        assertEquals(map.get("trustD").size(), 1);
        assertTrue(map.get("trustD").contains("dom.role1"));
    }
    
    @Test
    public void testRolesWithTrust() {

        Role role1 = new Role();
        role1.setName("dom.role1");
        role1.setTrust("dom2");

        Role role2 = new Role();
        role2.setName("dom.role2");
        role2.setTrust("dom3");

        Role role3 = new Role();
        role3.setName("dom.role3");
        role3.setTrust("dom3");
        
        DataCache cache = new DataCache();
        cache.processRole(role1);
        cache.processRole(role2);
        cache.processRole(role3);
        
        Map<String, Set<String>> map = cache.getTrustMap();
        assertNotNull(map);
        assertEquals(map.size(), 2);
        
        assertTrue(map.containsKey("dom2"));
        assertEquals(map.get("dom2").size(), 1);
        assertTrue(map.get("dom2").contains("dom.role1"));
        
        assertTrue(map.containsKey("dom3"));
        assertEquals(map.get("dom3").size(), 2);
        assertTrue(map.get("dom3").contains("dom.role2"));
        assertTrue(map.get("dom3").contains("dom.role3"));
    }
    
    @Test
    public void testPolicyWithAssertions() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        Role role1 = new Role();
        role1.setName("testDomain.role.role1");
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        role1.setRoleMembers(members1);
        
        Role role2 = new Role();
        role2.setName("testDomain.role.role2");
        
        List<RoleMember> members2 = new ArrayList<>();
        members2.add(new RoleMember().setMemberName("user_domain.user2"));
        role2.setRoleMembers(members2);
        
        Role role3 = new Role();
        role3.setName("testDomain.role.role3");
        
        List<RoleMember> members3 = new ArrayList<>();
        members3.add(new RoleMember().setMemberName("user_domain.user3"));
        role3.setRoleMembers(members3);
        
        Policy policy = new Policy();
        policy.setName("testDomain.policy.policy1");

        Assertion assertion1 = new Assertion();
        assertion1.setAction("assume_role");
        assertion1.setEffect(AssertionEffect.ALLOW);
        assertion1.setResource("testDomain.roleA");
        assertion1.setRole("testDomain.role.role1");

        Assertion assertion2 = new Assertion();
        assertion2.setAction("read");
        assertion2.setEffect(AssertionEffect.ALLOW);
        assertion2.setResource("testDomain.data:*");
        assertion2.setRole("testDomain.role.role1");
        
        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion1);
        assertList.add(assertion2);
        
        policy.setAssertions(assertList);

        DataCache cache = new DataCache();
        cache.processRole(role1);
        cache.processRole(role2);
        cache.processRole(role3);
        HashMap<String, Role> roleList = new HashMap<>();
        roleList.put(role1.getName(), role1);
        roleList.put(role2.getName(), role2);
        roleList.put(role3.getName(), role3);
        cache.processPolicy(domain.getName(), policy, roleList);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("testDomain.role.role1", 0)));
        assertTrue(set1.contains(new MemberRole("testDomain.roleA", 0)));
        assertEquals(set1.size(), 2);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("testDomain.role.role1", 0)));
        assertTrue(set2.contains(new MemberRole("testDomain.role.role2", 0)));
        assertTrue(set2.contains(new MemberRole("testDomain.roleA", 0)));
        assertEquals(set2.size(), 3);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("testDomain.role.role3", 0)));
        assertEquals(set3.size(), 1);
    }
    
    @Test
    public void testPolicyNoRoleProcessed() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        Role role1 = new Role();
        role1.setName("testDomain.role.role1");
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        role1.setRoleMembers(members1);
        
        Policy policy = new Policy();
        policy.setName("testDomain.policy.policy1");

        Assertion assertion1 = new Assertion();
        assertion1.setAction("assume_role");
        assertion1.setEffect(AssertionEffect.ALLOW);
        assertion1.setResource("testDomain.roleA");
        assertion1.setRole("testDomain.role.role1");
        
        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion1);
        
        policy.setAssertions(assertList);

        DataCache cache = new DataCache();
        HashMap<String, Role> roleList = new HashMap<>();
        roleList.put(role1.getName(), role1);
        cache.processPolicy(domain.getName(), policy, roleList);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("testDomain.roleA", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNull(set2);
    }
    
    @Test
    public void testPolicyWithNoAssertions() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        Role role1 = new Role();
        role1.setName("testDomain.role.role1");
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        role1.setRoleMembers(members1);
        
        Role role2 = new Role();
        role2.setName("testDomain.role.role2");
        
        List<RoleMember> members2 = new ArrayList<>();
        members2.add(new RoleMember().setMemberName("user_domain.user2"));
        role2.setRoleMembers(members2);
        
        Role role3 = new Role();
        role3.setName("testDomain.role.role3");
        
        List<RoleMember> members3 = new ArrayList<>();
        members3.add(new RoleMember().setMemberName("user_domain.user3"));
        role3.setRoleMembers(members3);
        
        Policy policy = new Policy();
        policy.setName("testDomain.policy.policy1");
        
        HashMap<String, Role> roleList = new HashMap<>();
        roleList.put(role1.getName(), role1);
        roleList.put(role2.getName(), role2);
        roleList.put(role3.getName(), role3);

        DataCache cache = new DataCache();
        cache.processRole(role1);
        cache.processRole(role2);
        cache.processRole(role3);
        cache.processPolicy(domain.getName(), policy, roleList);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("testDomain.role.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("testDomain.role.role1", 0)));
        assertTrue(set2.contains(new MemberRole("testDomain.role.role2", 0)));
        assertEquals(set2.size(), 2);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("testDomain.role.role3", 0)));
        assertEquals(set3.size(), 1);
    }
    
    @Test
    public void testPolicyWithInvalidAssertionRole() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        Role role1 = new Role();
        role1.setName("testDomain.role.role1");
        
        List<RoleMember> members1 = new ArrayList<>();
        members1.add(new RoleMember().setMemberName("user_domain.user1"));
        members1.add(new RoleMember().setMemberName("user_domain.user2"));
        role1.setRoleMembers(members1);
        
        Role role2 = new Role();
        role2.setName("testDomain.role.role2");
        
        List<RoleMember> members2 = new ArrayList<>();
        members2.add(new RoleMember().setMemberName("user_domain.user2"));
        role2.setRoleMembers(members2);
        
        Role role3 = new Role();
        role3.setName("testDomain.role.role3");
        
        List<RoleMember> members3 = new ArrayList<>();
        members3.add(new RoleMember().setMemberName("user_domain.user3"));
        role3.setRoleMembers(members3);
        
        Policy policy = new Policy();
        policy.setName("testDomain.policy.policy1");

        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("testDomain.role");
        assertion.setRole("testDomain.role.Invalid");

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);
        
        policy.setAssertions(assertList);
        
        HashMap<String, Role> roleList = new HashMap<>();
        roleList.put(role1.getName(), role1);
        roleList.put(role2.getName(), role2);
        roleList.put(role3.getName(), role3);

        DataCache cache = new DataCache();
        cache.processRole(role1);
        cache.processRole(role2);
        cache.processRole(role3);
        cache.processPolicy(domain.getName(), policy, roleList);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNotNull(set1);
        assertTrue(set1.contains(new MemberRole("testDomain.role.role1", 0)));
        assertEquals(set1.size(), 1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("testDomain.role.role1", 0)));
        assertTrue(set2.contains(new MemberRole("testDomain.role.role2", 0)));
        assertEquals(set2.size(), 2);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("testDomain.role.role3", 0)));
        assertEquals(set3.size(), 1);
    }
    
    @Test
    public void testPolicyWithInvalidDomainNoRoles() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        Policy policy = new Policy();
        policy.setName("testDomain.policy.policy1");

        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("testDomain.role");
        assertion.setRole("testDomain.role.role1");

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);
        
        policy.setAssertions(assertList);
        
        HashMap<String, Role> roleList = new HashMap<>();

        DataCache cache = new DataCache();
        cache.processPolicy(domain.getName(), policy, roleList);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNull(set1);
    }
    
    @Test
    public void testPolicyWithAssertionRoleNoMember() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        Role role1 = new Role();
        role1.setName("testDomain.role.role1");
        
        Role role2 = new Role();
        role2.setName("testDomain.role.role2");
        
        List<RoleMember> members2 = new ArrayList<>();
        members2.add(new RoleMember().setMemberName("user_domain.user2"));
        role2.setRoleMembers(members2);
        
        Role role3 = new Role();
        role3.setName("testDomain.role.role3");
        
        List<RoleMember> members3 = new ArrayList<>();
        members3.add(new RoleMember().setMemberName("user_domain.user3"));
        role3.setRoleMembers(members3);
        
        Policy policy = new Policy();
        policy.setName("testDomain.policy.policy1");

        Assertion assertion = new Assertion();
        assertion.setAction("assume_role");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("testDomain.roleA");
        assertion.setRole("testDomain.role.role1");

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);
        
        policy.setAssertions(assertList);
        
        HashMap<String, Role> roleList = new HashMap<>();
        roleList.put(role1.getName(), role1);
        roleList.put(role2.getName(), role2);
        roleList.put(role3.getName(), role3);

        DataCache cache = new DataCache();
        cache.processRole(role1);
        cache.processRole(role2);
        cache.processRole(role3);
        cache.processPolicy(domain.getName(), policy, roleList);
        
        Set<MemberRole> set1 = cache.getMemberRoleSet("user_domain.user1");
        assertNull(set1);
        
        Set<MemberRole> set2 = cache.getMemberRoleSet("user_domain.user2");
        assertNotNull(set2);
        assertTrue(set2.contains(new MemberRole("testDomain.role.role2", 0)));
        assertEquals(set2.size(), 1);
        
        Set<MemberRole> set3 = cache.getMemberRoleSet("user_domain.user3");
        assertNotNull(set3);
        assertTrue(set3.contains(new MemberRole("testDomain.role.role3", 0)));
        assertEquals(set3.size(), 1);
    }
    
    @Test
    public void testSingleHostSingleService() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("testDomain.storage");
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);
        
        DataCache cache = new DataCache();
        cache.processServiceIdentity(service);
        
        Map<String, Set<String>> hostMap = cache.getHostMap();
        assertEquals(hostMap.size(), 1);
        assertTrue(hostMap.containsKey("host1"));
        
        Set<String> set = hostMap.get("host1");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage"));
    }
    
    @Test
    public void testMultipleHostsSingleService() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("testDomain.storage");
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        service.setHosts(hosts);
        
        DataCache cache = new DataCache();
        cache.processServiceIdentity(service);
        
        Map<String, Set<String>> hostMap = cache.getHostMap();
        assertEquals(hostMap.size(), 2);
        assertTrue(hostMap.containsKey("host1"));

        Set<String> set = hostMap.get("host1");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage"));
        
        assertTrue(hostMap.containsKey("host2"));
        
        set = hostMap.get("host2");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage"));
    }
    
    @Test
    public void testMultipleHostsSkipDuplicate() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("testDomain.storage");
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        hosts.add("host1");
        service.setHosts(hosts);
        
        DataCache cache = new DataCache();
        cache.processServiceIdentity(service);
        
        Map<String, Set<String>> hostMap = cache.getHostMap();
        assertEquals(hostMap.size(), 2);
        assertTrue(hostMap.containsKey("host1"));

        Set<String> set = hostMap.get("host1");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage"));
        
        assertTrue(hostMap.containsKey("host2"));
        
        set = hostMap.get("host2");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage"));
    }
    
    @Test
    public void testSingleHostMultipleServices() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        ServiceIdentity service1 = new ServiceIdentity();
        service1.setName("testDomain.storage1");
        List<String> hosts1 = new ArrayList<>();
        hosts1.add("host1");
        service1.setHosts(hosts1);
        
        ServiceIdentity service2 = new ServiceIdentity();
        service2.setName("testDomain.storage2");
        List<String> hosts2 = new ArrayList<>();
        hosts2.add("host1");
        service2.setHosts(hosts2);
        
        DataCache cache = new DataCache();
        cache.processServiceIdentity(service1);
        cache.processServiceIdentity(service2);
        
        Map<String, Set<String>> hostMap = cache.getHostMap();
        assertEquals(hostMap.size(), 1);
        assertTrue(hostMap.containsKey("host1"));

        Set<String> set = hostMap.get("host1");
        assertEquals(set.size(), 2);
        assertTrue(set.contains("testDomain.storage1"));
        assertTrue(set.contains("testDomain.storage2"));
    }
    
    @Test
    public void testMultipleHostsMultipleServices() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        ServiceIdentity service1 = new ServiceIdentity();
        service1.setName("testDomain.storage1");
        List<String> hosts1 = new ArrayList<>();
        hosts1.add("host1");
        hosts1.add("host2");
        service1.setHosts(hosts1);
        
        ServiceIdentity service2 = new ServiceIdentity();
        service2.setName("testDomain.storage2");
        List<String> hosts2 = new ArrayList<>();
        hosts2.add("host1");
        hosts2.add("host3");
        service2.setHosts(hosts2);
        
        DataCache cache = new DataCache();
        cache.processServiceIdentity(service1);
        cache.processServiceIdentity(service2);
        
        Map<String, Set<String>> hostMap = cache.getHostMap();
        assertEquals(hostMap.size(), 3);
        assertTrue(hostMap.containsKey("host1"));
        assertTrue(hostMap.containsKey("host2"));
        assertTrue(hostMap.containsKey("host3"));

        Set<String> set = hostMap.get("host1");
        assertEquals(set.size(), 2);
        assertTrue(set.contains("testDomain.storage1"));
        assertTrue(set.contains("testDomain.storage2"));
        
        set = hostMap.get("host2");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage1"));
        
        set = hostMap.get("host3");
        assertEquals(set.size(), 1);
        assertTrue(set.contains("testDomain.storage2"));
    }
    
    @Test
    public void testPublicKeysMultipleVersionFormat() {
        
        Domain domain = new Domain();
        domain.setName("testDomain");
        
        ServiceIdentity service1 = new ServiceIdentity();
        service1.setName("testDomain.storage1");
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry0 = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry0.setId("0");
        keyEntry0.setKey(ZTS_Y64_CERT0);
        List<com.yahoo.athenz.zms.PublicKeyEntry> listKeys1 = new ArrayList<>();
        listKeys1.add(keyEntry0);
        service1.setPublicKeys(listKeys1);
        
        ServiceIdentity service2 = new ServiceIdentity();
        service2.setName("testDomain.storage2");
        
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry1 = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry1.setId("0");
        keyEntry1.setKey(ZTS_Y64_CERT1);
        
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry3 = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry3.setId("3");
        keyEntry3.setKey(ZTS_Y64_CERT2);

        com.yahoo.athenz.zms.PublicKeyEntry keyEntry4 = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry4.setId("4");
        keyEntry4.setKey(ZTS_Y64_CERT3);
        
        List<com.yahoo.athenz.zms.PublicKeyEntry> listKeys = new ArrayList<>();
        listKeys.add(keyEntry1);
        listKeys.add(keyEntry3);
        listKeys.add(keyEntry4);
        
        service2.setPublicKeys(listKeys);
        
        ServiceIdentity service3 = new ServiceIdentity();
        service3.setName("testDomain.storage3");
        
        DataCache cache = new DataCache();
        cache.processServiceIdentity(service1);
        cache.processServiceIdentity(service2);
        cache.processServiceIdentity(service3);
        
        Map<String, String> publicKeyMap = cache.getPublicKeyMap();
        assertEquals(publicKeyMap.size(), 4);
        assertEquals(publicKeyMap.get("testDomain.storage1_0"), ZTS_PEM_CERT0);
        assertEquals(publicKeyMap.get("testDomain.storage2_0"), ZTS_PEM_CERT1);
        assertEquals(publicKeyMap.get("testDomain.storage2_3"), ZTS_PEM_CERT2);
        assertEquals(publicKeyMap.get("testDomain.storage2_4"), ZTS_PEM_CERT3);
    }

    @Test
    public void testProcessServiceIdentityPublicKey() {

        DataCache cache = new DataCache();

        // null key does not get processed

        cache.processServiceIdentityPublicKey("service1", "id1", null);
        assertNull(cache.getPublicKeyMap().get("service1_id1"));

        // invalid ybase64 encoded key does not get processed

        cache.processServiceIdentityPublicKey("service1", "id1", "invalid-data");
        assertNull(cache.getPublicKeyMap().get("service1_id1"));

        // now valid data

        cache.processServiceIdentityPublicKey("service1", "id1", ZTS_Y64_CERT0);
        assertEquals(cache.getPublicKeyMap().get("service1_id1"), ZTS_PEM_CERT0);
    }

    @Test
    public void testProcessAWSAssumeRoleAssertion() {

        DataCache cache = new DataCache();

        assertNull(cache.getAWSResourceRoleSet("role"));

        Assertion assertion = new Assertion();
        assertion.setAction("update");
        assertion.setResource("resource");
        assertion.setRole("role");

        cache.processAWSAssumeRoleAssertion(assertion);
        Set<String> set = cache.getAWSResourceRoleSet("role");
        assertEquals(1, set.size());

        // calling with same assertion - no changes

        cache.processAWSAssumeRoleAssertion(assertion);
        set = cache.getAWSResourceRoleSet("role");
        assertEquals(1, set.size());
    }
}

