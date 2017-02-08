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
package com.yahoo.athenz.zms;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.rdl.Array;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

import static org.testng.Assert.*;

import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class ZMSClientTest {

    private String systemAdminUser = null;
    private String systemAdminFullUser = null;
    private static String ZMS_CLIENT_PROP_ZMS_URL = "athenz.zms.client.zms_url";
    private static String ZMS_CLIENT_PROP_TEST_ADMIN = "athenz.zms.client.test_admin";
    
    private static final String PUB_KEY_ZONE1 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BM"
            + "EdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRA"
            + "pZYW5FSmZLbUFseDVjUS84aEtFVWZTU2dwWHIzQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF"
            + "5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbEdVT0VnMmpzbWRha1IyNEtjTGpBdTZRclVlNDE3bEczdDhx"
            + "U1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY0cmJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLR"
            + "VktLS0tLQo-";
    private static final String PUB_KEY_ZONE2 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRW"
            + "UpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBTDRnNlF1bGVRcG42bytpSmorK09nenNZM3hXekhHUw"
            + "p4ZW1xZzZhdkkvbHhvT3Jzd2h4YW93MjMrR3AxZXhOWEdzQlNsTkFQSXh5N3RHTXZaRnY0Q3ZrQ0F"
            + "3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    
    private boolean printURL = true;
    
    static final Struct TABLE_PROVIDER_ROLE_ACTIONS = new Struct()
        .with("admin", "*").with("writer", "WRITE").with("reader", "READ");

    private static String AUDIT_REF = "zmsjcltest";
 
    static final int BASE_PRODUCT_ID = 100000000; // these product id's will lie in 100 million range
    static java.util.Random domainProductId = new java.security.SecureRandom();

    static synchronized int getRandomProductId() {
        return BASE_PRODUCT_ID + domainProductId.nextInt(99999999);
    }
    
    @BeforeClass
    public void setup() {
        System.setProperty(ZMS_CLIENT_PROP_ZMS_URL, "http://localhost:10080/");

        systemAdminUser = System.getProperty(ZMS_CLIENT_PROP_TEST_ADMIN, "user_admin");
        systemAdminFullUser = "user." + systemAdminUser;
    }
    
    private Principal createPrincipal(String userName) {
        Authority authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        Principal p = SimplePrincipal.create("user", userName,
                "v=U1;d=user;n=" + userName + ";s=signature", 0, authority);
        return p;
    }
    
    private DomainMeta createDomainMetaObject(String description, String org, boolean auditEnabled) {

        DomainMeta meta = new DomainMeta();
        meta.setDescription(description);
        meta.setOrg(org);
        meta.setAuditEnabled(auditEnabled);

        return meta;
    }
    
    private ZMSClient createClient(String userName) {
        ZMSClient client = new ZMSClient(getZMSUrl());
        client.addCredentials(createPrincipal(userName));
        
        if (printURL) {
            System.out.println("ZMS Url set to: " + client.getZmsUrl());
            printURL = false;
        }
        
        return client;
    }
    
    private String getZMSUrl() {

        // if we're given a config setting then use that
        
        String zmsUrl = System.getProperty(ZMS_CLIENT_PROP_ZMS_URL);
        
        // if the value is not available then check the env setting
        
        if (zmsUrl == null) {
            zmsUrl = System.getenv("ZMS_URL");
        }
        
        return zmsUrl;
    }

    private TopLevelDomain createTopLevelDomainObject(String name,
            String description, String org, String admin) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setEnabled(true);
        dom.setYpmId(getRandomProductId());

        List<String> admins = new ArrayList<String>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }

    private SubDomain createSubDomainObject(String name, String parent,
            String description, String org, String admin) {
        
        SubDomain dom = new SubDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setParent(parent);
        dom.setEnabled(true);

        List<String> admins = new ArrayList<String>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }
    
    private Role createRoleObject(ZMSClient client, String domainName, String roleName, 
            String trust, String member1, String member2) {
        
        Role role = new Role();
        role.setName(client.generateRoleName(domainName, roleName));
        role.setTrust(trust);
        
        List<String> members = new ArrayList<String>();
        members.add(member1);
        if (member2 != null) {
            members.add(member2);
        }
        role.setMembers(members);
        return role;
    }
    
    private Policy createPolicyObject(ZMSClient client, String domainName, String policyName,
            String roleName, String action, String resource, AssertionEffect effect) {
        
        Policy policy = new Policy();
        policy.setName(client.generatePolicyName(domainName, policyName));
        
        Assertion assertion = new Assertion();
        assertion.setAction(action);
        assertion.setEffect(effect);
        assertion.setResource(resource);
        assertion.setRole(client.generateRoleName(domainName, roleName));
        
        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);
        
        policy.setAssertions(assertList);
        return policy;
    }
    
    private Policy createPolicyObject(ZMSClient client, String domainName, String policyName) {
        return createPolicyObject(client, domainName, policyName, "Role1", "*", domainName + ":*", AssertionEffect.ALLOW);
    }
    
    private ServiceIdentity createServiceObject(ZMSClient client, String domainName, 
            String serviceName, String endPoint, String executable, String user,
            String group, String host) {
        
        ServiceIdentity service = new ServiceIdentity();
        service.setExecutable(executable);
        service.setName(client.generateServiceIdentityName(domainName, serviceName));
        
        List<PublicKeyEntry> pubKeys = new ArrayList<>();
        pubKeys.add(new PublicKeyEntry().setId("0")
                .setKey("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTk"
                      + "FEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84aEtFVWZTU2dwWHI"
                      + "zQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbEdVT0VnMmpzbWRh"
                      + "a1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY0cmJRSURBUUFCC"
                      + "i0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-"));

        service.setPublicKeys(pubKeys);
        
        service.setUser(user);
        service.setGroup(group);

        service.setProviderEndpoint(endPoint);
        
        List<String> hosts = new ArrayList<String>();
        hosts.add(host);
        service.setHosts(hosts);
        
        return service;
    }

    private ServiceIdentity createServiceObjectWithZoneKeys(ZMSClient client, String domainName, 
            String serviceName, String endPoint, String executable, String user,
            String group, String host) {
        
        ServiceIdentity service = new ServiceIdentity();
        service.setExecutable(executable);
        service.setGroup(group);
        service.setName(client.generateServiceIdentityName(domainName, serviceName));
        service.setUser(user);

        List<PublicKeyEntry> pubKeys = new ArrayList<>();
        
        PublicKeyEntry key1 = new PublicKeyEntry();
        key1.setId("zone1");
        key1.setKey(PUB_KEY_ZONE1);
        
        PublicKeyEntry key2 = new PublicKeyEntry();
        key2.setId("zone2");
        key2.setKey(PUB_KEY_ZONE2);
        
        pubKeys.add(key1);
        pubKeys.add(key2);
        service.setPublicKeys(pubKeys);
        
        service.setProviderEndpoint(endPoint);
        
        List<String> hosts = new ArrayList<String>();
        hosts.add(host);
        service.setHosts(hosts);
        
        return service;
    }
    
    private Entity createEntityObject(ZMSClient client, String entityName) {
        
        Entity entity = new Entity();
        entity.setName(entityName);
        
        Struct value = new Struct();
        value.put("Key1", "Value1");
        entity.setValue(value);
        
        return entity;
    }
    
    private Tenancy createTenantObject(String domain, String service) {

        Tenancy tenant = new Tenancy();
        tenant.setDomain(domain);
        tenant.setService(service);

        return tenant;
    }
    
    private void testCreateTopLevelDomain(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddTopDom1",
                "Test Domain1", "testOrg", adminUser);
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, dom1);
        assertNotNull(resDom1);

        Domain resDom2 = client.getDomain("AddTopDom1");
        assertNotNull(resDom2);
        
        try {
            client.getDomain("AddTopDom3");
            fail();
        } catch(ResourceException ex) {
            assertTrue(true);
        }
        
        try {
            client.getDomain("AddTopDom3");
            fail();
        } catch(ResourceException ex) {
            assertTrue(true);
        }
        
        client.deleteTopLevelDomain("AddTopDom1", AUDIT_REF);
    }

    private void testCreateTopLevelDomainOnceOnly(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddOnceTopDom1",
                "Test Domain1", "testOrg", adminUser);
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, dom1);
        assertNotNull(resDom1);

        // we should get an exception for the second call
        
        try {
            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        
        client.deleteTopLevelDomain("AddOnceTopDom1", AUDIT_REF);
    }

    private void testCreateSubDomain(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("AddSubDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        SubDomain dom2 = createSubDomainObject("AddSubDom2", "AddSubDom1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom1 = client.postSubDomain("AddSubDom1", AUDIT_REF, dom2);
        assertNotNull(resDom1);
        try {
            client.postSubDomain("AddSubDom3", AUDIT_REF, dom2);
            fail();
        } catch(ResourceException ex) {
            assertTrue(true);
        }
        
        Domain resDom2 = client.getDomain("AddSubDom1.AddSubDom2");
        assertNotNull(resDom2);
        
        client.deleteSubDomain("AddSubDom1", "AddSubDom2", AUDIT_REF);
        
        client.deleteTopLevelDomain("AddSubDom1", AUDIT_REF);
    }

    private void testCreateSubdomainOnceOnly(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("AddOnceSubDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        SubDomain dom2 = createSubDomainObject("AddOnceSubDom2", "AddOnceSubDom1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom1 = client.postSubDomain("AddOnceSubDom1", AUDIT_REF, dom2);
        assertNotNull(resDom1);

        // we should get an exception for the second call
        
        try {
            client.postSubDomain("AddOnceSubDom1", AUDIT_REF, dom2);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        
        client.deleteSubDomain("AddOnceSubDom1", "AddOnceSubDom2", AUDIT_REF);
        client.deleteTopLevelDomain("AddOnceSubDom1", AUDIT_REF);
    }

    private void testCreateRole(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("CreateRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Role role1 = createRoleObject(client, "CreateRoleDom1", "Role1", null, "user.joe", "user.jane");
        client.putRole("CreateRoleDom1", "Role1", AUDIT_REF, role1);
        
        Role role3 = client.getRole("CreateRoleDom1", "Role1");
        assertNotNull(role3);
        assertEquals(role3.getName(), "CreateRoleDom1:role.Role1".toLowerCase());
        assertNull(role3.getTrust());
        
        try {
            client.putRole("CreateRoleDom1", "Role2", AUDIT_REF, role1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            client.putRole("CreateRoleDom1", "Role3", AUDIT_REF, role1);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        
        try {
            client.getRole("CreateRoleDom1", "Role2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            client.getRole("CreateRoleDom1", "Role3");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        
        client.deleteTopLevelDomain("CreateRoleDom1", AUDIT_REF);
    }

    private void testAddMembership(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Role role1 = createRoleObject(client, "MbrAddDom1", "Role1", null, "user.joe", "user.jane");
        client.putRole("MbrAddDom1", "Role1", AUDIT_REF, role1);
        client.putMembership("MbrAddDom1", "Role1", "user.doe", AUDIT_REF);
        
        client.putMembership("MbrAddDom1", "Role1", "user.temp",
                Timestamp.fromMillis(100000), AUDIT_REF);
        Role role = client.getRole("MbrAddDom1", "Role1");
        assertNotNull(role);
        
        List<RoleMember> members = role.getRoleMembers();
        assertNotNull(members);
        assertEquals(members.size(), 4);
        
        boolean userTempCheck = false;
        boolean userDoeCheck = false;
        for (RoleMember member: members) {
            if (member.getMemberName().equals("user.temp")) {
                userTempCheck = true;
            } else if (member.getMemberName().equals("user.doe")) {
                userDoeCheck = true;
            }
        }
        assertTrue(userTempCheck);
        assertTrue(userDoeCheck);
        
        client.deleteTopLevelDomain("MbrAddDom1", AUDIT_REF);
    }

    private void testDeleteMembership(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("MbrDelDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Role role1 = createRoleObject(client, "MbrDelDom1", "Role1", null, "user.joe", "user.jane");
        client.putRole("MbrDelDom1", "Role1", AUDIT_REF, role1);
        client.deleteMembership("MbrDelDom1", "Role1", "user.joe", AUDIT_REF);
        
        Role role = client.getRole("MbrDelDom1", "Role1");
        assertNotNull(role);
        
        List<String> members = role.getMembers();
        assertNotNull(members);
        assertEquals(members.size(), 1);
        
        assertFalse(members.contains("user.joe"));
        assertTrue(members.contains("user.jane"));
        
        client.deleteTopLevelDomain("MbrDelDom1", AUDIT_REF);
    }

    private void testCreatePolicy(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Policy policy1 = createPolicyObject(client, "PolicyAddDom1", "Policy1");
        client.putPolicy("PolicyAddDom1", "Policy1", AUDIT_REF, policy1);
        
        Policy policyRes2 = client.getPolicy("PolicyAddDom1", "Policy1");
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), "PolicyAddDom1:policy.Policy1".toLowerCase());
        
        client.deleteTopLevelDomain("PolicyAddDom1", AUDIT_REF);
    }

    private void testDeletePolicy(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyDelDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Policy policy1 = createPolicyObject(client, "PolicyDelDom1", "Policy1");
        client.putPolicy("PolicyDelDom1", "Policy1", AUDIT_REF, policy1);

        Policy policy2 = createPolicyObject(client, "PolicyDelDom1", "Policy2");
        client.putPolicy("PolicyDelDom1", "Policy2", AUDIT_REF, policy2);
        
        Policy policyRes1 = client.getPolicy("PolicyDelDom1", "Policy1");
        assertNotNull(policyRes1);

        Policy policyRes2 = client.getPolicy("PolicyDelDom1", "Policy2");
        assertNotNull(policyRes2);
        
        client.deletePolicy("PolicyDelDom1", "Policy1", AUDIT_REF);
        
        // we need to get an exception here 
        try {
            client.getPolicy("PolicyDelDom1", "Policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        policyRes2 = client.getPolicy("PolicyDelDom1", "Policy2");
        assertNotNull(policyRes2);

        client.deletePolicy("PolicyDelDom1", "Policy2", AUDIT_REF);

        // we need to get an exception here 
        try {
            client.getPolicy("PolicyDelDom1", "Policy1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        // we need to get an exception here 
        try {
            client.getPolicy("PolicyDelDom1", "Policy2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        
        client.deleteTopLevelDomain("PolicyDelDom1", AUDIT_REF);
    }

    private void testCreateServiceIdentity(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        ServiceIdentity service = createServiceObject(client, "ServiceAddDom1", "Service1", 
                "http://localhost", "/usr/bin/java", "root", "users", "host1");

        client.putServiceIdentity("ServiceAddDom1", "Service1", AUDIT_REF, service);
        
        ServiceIdentity serviceRes2 = client.getServiceIdentity("ServiceAddDom1", "Service1");
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), "ServiceAddDom1.Service1".toLowerCase());
        
        client.deleteTopLevelDomain("ServiceAddDom1", AUDIT_REF);
    }
 
    private void testDeletePublicKeyEntry(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("DelPublicKeyDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        ServiceIdentity service = createServiceObjectWithZoneKeys(client, "DelPublicKeyDom1", "Service1", 
                "http://localhost", "/usr/bin/java", "root", "users", "host1");

        client.putServiceIdentity("DelPublicKeyDom1", "Service1", AUDIT_REF, service);
        
        client.deletePublicKeyEntry("DelPublicKeyDom1", "Service1", "zone1", AUDIT_REF);
        
        try {
            client.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        PublicKeyEntry entry = client.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone2");
        assertNotNull(entry);
        assertEquals(entry.getKey(), PUB_KEY_ZONE2);

        // we are not allowed to delete the last public key
        
        try {
            client.deletePublicKeyEntry("DelPublicKeyDom1", "Service1", "zone2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        client.deleteTopLevelDomain("DelPublicKeyDom1", AUDIT_REF);
    }

    private void testCreateEntity(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("CreateEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Entity entity1 = createEntityObject(client, "Entity1");
        client.putEntity("CreateEntityDom1", "Entity1", AUDIT_REF, entity1);
        
        Entity entity2 = client.getEntity("CreateEntityDom1", "Entity1");
        assertNotNull(entity2);
        assertEquals(entity2.getName(), "Entity1".toLowerCase());
        
        client.deleteTopLevelDomain("CreateEntityDom1", AUDIT_REF);
    }

    private void testDeleteEntity(ZMSClient client, String adminUser) {
        
        TopLevelDomain dom1 = createTopLevelDomainObject("DelEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        
        Entity entity1 = createEntityObject(client, "Entity1");
        client.putEntity("DelEntityDom1", "Entity1", AUDIT_REF, entity1);
        
        Entity entity2 = createEntityObject(client, "Entity2");
        client.putEntity("DelEntityDom1", "Entity2", AUDIT_REF, entity2);
        
        Entity entityRes = client.getEntity("DelEntityDom1", "Entity1");
        assertNotNull(entityRes);

        entityRes = client.getEntity("DelEntityDom1", "Entity2");
        assertNotNull(entityRes);

        client.deleteEntity("DelEntityDom1", "Entity1", AUDIT_REF);

        try {
            entityRes = client.getEntity("DelEntityDom1", "Entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        entityRes = client.getEntity("DelEntityDom1", "Entity2");
        assertNotNull(entityRes);

        client.deleteEntity("DelEntityDom1", "Entity2", AUDIT_REF);

        try {
            entityRes = client.getEntity("DelEntityDom1", "Entity1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        try {
            entityRes = client.getEntity("DelEntityDom1", "Entity2");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        client.deleteTopLevelDomain("DelEntityDom1", AUDIT_REF);
    }
    
    // Unit Tests for ZMS Java Client
    
    @Test
    public void testClientNoAuth() {
        ZMSClient client = new ZMSClient("http://localhost:10080/zms/v1");
        assertNotNull(client);
    }

    @Test
    public void testClientOnlyUrl() {
        String zmsUrl = getZMSUrl();
        ZMSClient client = new ZMSClient(zmsUrl);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        assertNotNull(client);

        // verify we can get domain list
        DomainList domainListMock = Mockito.mock(DomainList.class);
        Mockito.when(client.getDomainList()).thenReturn(domainListMock).thenThrow(new ResourceException(400));
        DomainList domList = client.getDomainList();
        assertNotNull(domList);
        try {
            client.getDomainList();
            fail();
        } catch(ResourceException ex) {
            assertTrue(true);
        }

        // verify we can't add a domain

        TopLevelDomain dom1 = createTopLevelDomainObject("OnlyUrlDomain",
                "Test Domain1", "testOrg", systemAdminFullUser);
        try {
            Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1)).thenThrow(new ResourceException(400));
            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testClientInvalidPort() {
        String zmsUrl = "http://localhost:11080/zms/v1";
        ZMSClient client = new ZMSClient(zmsUrl);
        assertNotNull(client);
        
        // verify we can't get domain list and try some
        // other operations which should all return
        // zms client exceptions

        try {
            client.getDomainList();
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        
        try {
            TopLevelDomain dom1 = createTopLevelDomainObject("OnlyUrlDomain",
                    "Test Domain1", "testOrg", systemAdminFullUser);
            
            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        
        try {
            client.getAccess("UPDATE", "AccessDom1:resource1", "AccessDom1");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testClientUrlPrincipal() {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        assertNotNull(client);

        // verify we can get domain list
        DomainList domainListMock = Mockito.mock(DomainList.class);
        Mockito.when(client.getDomainList()).thenReturn(domainListMock);
        DomainList domList = client.getDomainList();
        assertNotNull(domList);

        // verify we can add a domain

        TopLevelDomain dom1 = createTopLevelDomainObject("UrlPrincipalDomain",
                "Test Domain1", "testOrg", systemAdminFullUser);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1)).thenReturn(domainMock);
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, dom1);
        assertNotNull(resDom1);

        client.deleteTopLevelDomain("UrlPrincipalDomain", AUDIT_REF);
    }
    
    @Test
    public void testClientClearPrincipal() {
        String zmsUrl = getZMSUrl();
        ZMSClient client = new ZMSClient(zmsUrl);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        assertNotNull(client);

        // add credentials

        Authority authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        Principal p = SimplePrincipal.create("user", systemAdminUser,
                "v=U1;d=user;n=" + systemAdminUser + ";s=signature", 0, authority);

        client.addCredentials(p);

        // add credentials again

        client.addCredentials(p);

        // verify we can add a domain

        TopLevelDomain dom1 = createTopLevelDomainObject("ClearPrincipalDomain",
                "Test Domain1", "testOrg", systemAdminFullUser);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1)).thenReturn(domainMock);
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, dom1);
        assertNotNull(resDom1);

        client.deleteTopLevelDomain("ClearPrincipalDomain", AUDIT_REF);

        // clear the credentials

        client.clearCredentials();

        // verify we can no longer add a new domain

        try {
            Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1)).thenThrow(new ResourceException(400));
            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }

        // but we should be able to read the domain list
        DomainList domainListMock = Mockito.mock(DomainList.class);
        Mockito.when(client.getDomainList()).thenReturn(domainListMock);
        DomainList domList = client.getDomainList();
        assertNotNull(domList);
    }
        
    @Test
    public void testClientWithoutEndingSlash() {
        String zmsUrl = getZMSUrl();
        if (zmsUrl == null) {
            zmsUrl = "http://localhost:10080";
        } else {
            if (zmsUrl.charAt(zmsUrl.length() - 1) == '/') {
                zmsUrl = zmsUrl.substring(0,  zmsUrl.length() - 1);
            }
        }

        ZMSClient client = new ZMSClient(zmsUrl);
        assertNotNull(client);

        // verify we should be able to read the domain list
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainListMock = Mockito.mock(DomainList.class);
        Mockito.when(c.getDomainList(null, null, null, null, null, null, null, null, null)).thenReturn(domainListMock);
        DomainList domList = client.getDomainList();
        assertNotNull(domList);
    }
    
    @Test
    public void testGetDomainList() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getDomainList(null, null, null, null, null, null, "MemberRole1", "RoleName1", null))
                    .thenThrow(new NullPointerException());
            client.getDomainList("MemberRole1", "RoleName1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getDomainList(null, null, null, null, null, null, "MemberRole2", "RoleName2", null))
                    .thenThrow(new ResourceException(400));
            client.getDomainList("MemberRole2", "RoleName2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteSubDomain() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteSubDomain("parent", "domain1", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteSubDomain("parent", "domain1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteSubDomain("parent", "domain2", AUDIT_REF)).thenThrow(new ResourceException(400));
            client.deleteSubDomain("parent", "domain2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutTenancyResourceGroup() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TenancyResourceGroup trg = new TenancyResourceGroup().setDomain("test.domain").setService("test-service")
                .setResourceGroup("test.group");
        try {
            Mockito.when(
                    c.putTenancyResourceGroup("TenantDom1", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF, trg))
                    .thenThrow(new NullPointerException());
            client.putTenancyResourceGroup("TenantDom1", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF, trg);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(
                    c.putTenancyResourceGroup("TenantDom2", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF, trg))
                    .thenThrow(new ResourceException(400));
            client.putTenancyResourceGroup("TenantDom2", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF, trg);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutTenantResourceGroupRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles();
        try {
            Mockito.when(c.putTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1", AUDIT_REF, tenantRoles)).thenThrow(new NullPointerException());
            client.putTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1", "ResourceGroup1",
                    AUDIT_REF, tenantRoles);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.putTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1", AUDIT_REF, tenantRoles)).thenThrow(new ResourceException(400));
            client.putTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1", "ResourceGroup1",
                    AUDIT_REF, tenantRoles);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetTenantResourceGroupRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1")).thenThrow(new NullPointerException());
            client.getTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1", "ResourceGroup1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1")).thenThrow(new ResourceException(400));
            client.getTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1", "ResourceGroup1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteTenancyResourceGroup() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteTenancyResourceGroup("TenantDom1", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF))
                    .thenThrow(new NullPointerException());
            client.deleteTenancyResourceGroup("TenantDom1", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteTenancyResourceGroup("TenantDom2", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF))
                    .thenThrow(new ResourceException(400));
            client.deleteTenancyResourceGroup("TenantDom2", "DelTenantRolesDom1", "ResourceGroup1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getRoles("domain1", true)).thenThrow(new NullPointerException());
            client.getRoles("domain1", true);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getRoles("domain2", true)).thenThrow(new ResourceException(400));
            client.getRoles("domain2", true);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetPolicies() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getPolicies("domain1", true)).thenThrow(new NullPointerException());
            client.getPolicies("domain1", true);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getPolicies("domain2", true)).thenThrow(new ResourceException(400));
            client.getPolicies("domain2", true);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteUserDomain() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteUserDomain("domain1", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteUserDomain("domain1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteUserDomain("domain2", AUDIT_REF)).thenThrow(new ResourceException(400));
            client.deleteUserDomain("domain2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutDomainMeta() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainMeta meta = createDomainMetaObject("Test2 Domain", "NewOrg", false);
        try {
            Mockito.when(c.putDomainMeta("domain1", AUDIT_REF, meta)).thenThrow(new NullPointerException());
            client.putDomainMeta("domain1", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.putDomainMeta("domain2", AUDIT_REF, meta)).thenThrow(new ResourceException(400));
            client.putDomainMeta("domain2", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutDomainTemplate() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        List<String> tempNames = new ArrayList<String>();
        DomainTemplate domTempl = new DomainTemplate().setTemplateNames(tempNames);
        try {
            Mockito.when(c.putDomainTemplate("name1", AUDIT_REF, domTempl)).thenThrow(new NullPointerException());
            client.putDomainTemplate("name1", AUDIT_REF, domTempl);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.putDomainTemplate("name2", AUDIT_REF, domTempl))
                    .thenThrow(new ResourceException(404, "Domain not found"));
            client.putDomainTemplate("name2", AUDIT_REF, domTempl);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetResourceAccessList() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getResourceAccessList("principal1", "action1")).thenThrow(new NullPointerException());
            client.getResourceAccessList("principal1", "action1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getResourceAccessList("principal2", "action2")).thenThrow(new ResourceException(400));
            client.getResourceAccessList("principal2", "action2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testAssertion() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Assertion assertion = new Assertion();
        Long assertionId = 18000305032230531L;
        try {
            Mockito.when(c.putAssertion("domain1", "policy1", AUDIT_REF, assertion))
                    .thenThrow(new NullPointerException());
            client.putAssertion("domain1", "policy1", AUDIT_REF, assertion);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getAssertion("principal2", "action2", assertionId)).thenThrow(new NullPointerException());
            client.getAssertion("principal2", "action2", assertionId);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteAssertion("principal2", "action2", assertionId, AUDIT_REF))
                    .thenThrow(new NullPointerException());
            client.deleteAssertion("principal2", "action2", assertionId, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetTemplate() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getTemplate("template")).thenThrow(new NullPointerException());
            client.getTemplate("template");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getTemplate("template2")).thenThrow(new ResourceException(400));
            client.getTemplate("template2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetProviderResourceGroupRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup")).thenThrow(new NullPointerException());
            client.getProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2")).thenThrow(new ResourceException(400));
            client.getProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteProviderResourceGroupRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF)).thenThrow(new ResourceException(400));
            client.deleteProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutProviderResourceGroupRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ProviderResourceGroupRoles provRoles = new ProviderResourceGroupRoles();
        try {
            Mockito.when(c.putProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup", AUDIT_REF, provRoles)).thenThrow(new NullPointerException());
            client.putProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup", AUDIT_REF, provRoles);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.putProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF, provRoles)).thenThrow(new ResourceException(400));
            client.putProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF, provRoles);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPostUserDomain() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        UserDomain ud = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testuser")
                .setTemplates(new DomainTemplateList().setTemplateNames(Arrays.asList("template")));
        try {
            Mockito.when(c.postUserDomain("domain1", AUDIT_REF, ud)).thenThrow(new NullPointerException());
            client.postUserDomain("domain1", AUDIT_REF, ud);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.postUserDomain("domain2", AUDIT_REF, ud)).thenThrow(new ResourceException(400));
            client.postUserDomain("domain2", AUDIT_REF, ud);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testUserTokenWithAuthority() {
        ZMSClient client = createClient(systemAdminUser);
        assertNotNull(client);
    }
    
    @Test
    public void testCreateTopLevelDomainUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1 = createTopLevelDomainObject("AddTopDom1",
                "Test Domain1", "testOrg", systemAdminFullUser);
        Domain domainMock = Mockito.mock(Domain.class);
        dom1.setAuditEnabled(true);
        Mockito.when(c.postTopLevelDomain(Mockito.anyString(), Mockito.any(TopLevelDomain.class))).thenReturn(domainMock);
        Mockito.when(c.getDomain("AddTopDom1")).thenReturn(domainMock);
        Mockito.when(c.getDomain("AddTopDom3")).thenThrow(new NullPointerException()).thenThrow(new ResourceException(204));;
        testCreateTopLevelDomain(client, systemAdminFullUser);
    }

    @Test
    public void testCreateTopLevelDomainOnceOnlyUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1 = createTopLevelDomainObject("AddTopDom1",
                "Test Domain1", "testOrg", systemAdminFullUser);
        Domain domainMock = Mockito.mock(Domain.class);
        dom1.setAuditEnabled(true);
        Mockito.when(c.postTopLevelDomain(Mockito.anyString(), Mockito.any(TopLevelDomain.class))).thenReturn(domainMock).thenThrow(new ResourceException(204));
        testCreateTopLevelDomainOnceOnly(client, systemAdminFullUser);
    }

    @Test
    public void testCreateSubDomainUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        SubDomain dom2 = createSubDomainObject("AddSubDom2", "AddSubDom1",
                "Test Domain2", "testOrg", systemAdminFullUser);
        Mockito.when(c.postSubDomain("AddSubDom1", AUDIT_REF, dom2)).thenReturn(domainMock);
        Mockito.when(c.getDomain("AddSubDom1.AddSubDom2")).thenReturn(domainMock);
        Mockito.when(c.postSubDomain("AddSubDom3", AUDIT_REF, dom2)).thenThrow(new NullPointerException());
        testCreateSubDomain(client, systemAdminFullUser);
    }

    @Test
    public void testCreateSubdomainOnceOnlyUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        SubDomain dom2 = createSubDomainObject("AddOnceSubDom2", "AddOnceSubDom1",
                "Test Domain2", "testOrg", systemAdminFullUser);
        Mockito.when(c.postSubDomain("AddOnceSubDom1", AUDIT_REF, dom2)).thenReturn(domainMock).thenThrow(new ResourceException(204));
        testCreateSubdomainOnceOnly(client, systemAdminFullUser);
    }

    @Test
    public void testCreateRoleUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Role role1Mock = Mockito.mock(Role.class);
        Role role1 = createRoleObject(client, "CreateRoleDom1", "Role1", null, "user.joe", "user.jane");
        Mockito.when(c.putRole("CreateRoleDom1", "Role1", AUDIT_REF, role1Mock)).thenReturn(role1Mock);
        Mockito.when(c.getRole("CreateRoleDom1", "Role1", false, false)).thenReturn(role1Mock);
        Mockito.when(role1Mock.getName()).thenReturn("CreateRoleDom1:role.Role1".toLowerCase());
        Mockito.when(role1Mock.getTrust()).thenReturn(null);
        Mockito.when(c.putRole("CreateRoleDom1", "Role2", AUDIT_REF, role1)).thenThrow(new NullPointerException());
        Mockito.when(c.putRole("CreateRoleDom1", "Role3", AUDIT_REF, role1)).thenThrow(new ResourceException(400));
        Mockito.when(c.getRole("CreateRoleDom1", "Role2", false, false)).thenThrow(new NullPointerException());
        Mockito.when(c.getRole("CreateRoleDom1", "Role3", false, false)).thenThrow(new ResourceException(400));
        testCreateRole(client, systemAdminFullUser);
    }

    @Test
    public void testGetRoleList() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        RoleList roleListMock = Mockito.mock(RoleList.class);
        Mockito.when(c.getRoleList("RoleListParamDom1", null, "Role1")).thenReturn(roleListMock);
        RoleList roleList = client.getRoleList("RoleListParamDom1", null, "Role1");
        assertNotNull(roleList);
        try {
            Mockito.when(c.getRoleList("RoleListParamDom1", null, "Role2")).thenThrow(new ResourceException(204));
            client.getRoleList("RoleListParamDom1", null, "Role2");
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getRoleList("RoleListParamDom2", null, "Role2")).thenThrow(new NullPointerException());
            client.getRoleList("RoleListParamDom2", null, "Role2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getRoleList("RoleListParamDom1", null, null)).thenThrow(new ResourceException(204));
            client.getRoleList("RoleListParamDom1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getRoleList("RoleListParamDom2", null, null)).thenThrow(new NullPointerException());
            client.getRoleList("RoleListParamDom2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testDeleteRole() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Role roleMock = Mockito.mock(Role.class);
        Mockito.when(c.deleteRole("DelRoleDom1", "Role1", AUDIT_REF)).thenReturn(roleMock);
        client.deleteRole("DelRoleDom1", "Role1", AUDIT_REF);
        try {
            Mockito.when(c.deleteRole("DelRoleDom1", "Role2", AUDIT_REF)).thenThrow(new ResourceException(204));
            client.deleteRole("DelRoleDom1", "Role2", AUDIT_REF);
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteRole("DelRoleDom2", "Role2", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteRole("DelRoleDom2", "Role2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetMembership() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Membership member1Mock = Mockito.mock(Membership.class);
        Mockito.when(c.getMembership("MbrGetRoleDom1", "Role1", "user.joe")).thenReturn(member1Mock);
        client.getMembership("MbrGetRoleDom1", "Role1", "user.doe");
        try {
            Mockito.when(c.getMembership("MbrGetRoleDom1", "Role2", "user.joe")).thenThrow(new ResourceException(204));
            client.getMembership("MbrGetRoleDom1", "Role2", "user.joe");
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }

        try {
            Mockito.when(c.getMembership("MbrGetRoleDom1", "Role3", "user.joe")).thenThrow(new NullPointerException());
            client.getMembership("MbrGetRoleDom1", "Role3", "user.joe");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetPolicyList() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        PolicyList policyListMock = Mockito.mock(PolicyList.class);
        Mockito.when(c.getPolicyList("PolicyListDom1", null, null)).thenReturn(policyListMock);
        client.getPolicyList("PolicyListDom1", null, null);
        try {
            Mockito.when(c.getPolicyList("PolicyListDom2", null, null)).thenThrow(new ResourceException(204));
            client.getPolicyList("PolicyListDom2", null, null);
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getPolicyList("PolicyListDom3", null, null)).thenThrow(new ResourceException(204));
            client.getPolicyList("PolicyListDom3");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }

        try {
            Mockito.when(c.getPolicyList("PolicyListDom4", null, null)).thenThrow(new NullPointerException());
            client.getPolicyList("PolicyListDom4");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getPolicyList("PolicyListDom5", null, null)).thenThrow(new NullPointerException());
            client.getPolicyList("PolicyListDom5", null, null);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteServiceIdentity() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);
        Mockito.when(c.deleteServiceIdentity("ServiceDelDom1", "Service1", AUDIT_REF)).thenReturn(serviceMock);
        client.deleteServiceIdentity("ServiceDelDom1", "Service1", AUDIT_REF);
        try {
            Mockito.when(c.deleteServiceIdentity("ServiceDelDom1", "Service2", AUDIT_REF)).thenThrow(new ResourceException(204));
            client.deleteServiceIdentity("ServiceDelDom1", "Service2", AUDIT_REF);
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteServiceIdentity("ServiceDelDom2", "Service2", AUDIT_REF))
                    .thenThrow(new NullPointerException());
            client.deleteServiceIdentity("ServiceDelDom2", "Service2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetServiceIdentityList() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServiceIdentityList serviceListMock = Mockito.mock(ServiceIdentityList.class);
        Mockito.when(c.getServiceIdentityList("ServiceListParamsDom1", null, "Service1")).thenReturn(serviceListMock);
        client.getServiceIdentityList("ServiceListParamsDom1", null, "Service1");
        try {
            Mockito.when(c.getServiceIdentityList("ServiceListParamsDom2", null, "Service1")).thenThrow(new ResourceException(204));
            client.getServiceIdentityList("ServiceListParamsDom2", null, "Service1");
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }

        Mockito.when(c.getServiceIdentityList("ServiceListParamsDom3", null, null)).thenReturn(serviceListMock);
        client.getServiceIdentityList("ServiceListParamsDom3");
        try {
            Mockito.when(c.getServiceIdentityList("ServiceListParamsDom4", null, null)).thenThrow(new ResourceException(204));
            client.getServiceIdentityList("ServiceListParamsDom4");
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutPublicKeyEntry() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        PublicKeyEntry keyEntry = new PublicKeyEntry();
        PublicKeyEntry keyEntryMock = Mockito.mock(PublicKeyEntry.class);
        Mockito.when(c.putPublicKeyEntry("PutPublicKeyDom2", "Service1", "zone2", AUDIT_REF, keyEntry)).thenReturn(keyEntryMock);
        client.putPublicKeyEntry("PutPublicKeyDom2", "Service1", "zone2", AUDIT_REF, keyEntry);

        try {
            Mockito.when(c.putPublicKeyEntry("PutPublicKeyDom3", "Service2", "zone2", AUDIT_REF, keyEntry)).thenThrow(new ResourceException(204));
            client.putPublicKeyEntry("PutPublicKeyDom3", "Service2", "zone2", AUDIT_REF, keyEntry);
            fail();
        } catch  (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testGetTenancy() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Tenancy tenancyMock = Mockito.mock(Tenancy.class);
        Mockito.when(c.getTenancy("tenantDom1", "providerService1")).thenReturn(tenancyMock).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.getTenancy("tenantDom1", "providerService1");
        try {
            client.getTenancy("tenantDom1", "providerService1");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getTenancy("tenantDom2", "providerService1")).thenThrow(new NullPointerException());
            client.getTenancy("tenantDom2", "providerService1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteTenancy() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Tenancy tenancyMock = Mockito.mock(Tenancy.class);
        Mockito.when(c.deleteTenancy("tenantDom1", "providerService1", AUDIT_REF)).thenReturn(tenancyMock).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.deleteTenancy("tenantDom1", "providerService1", AUDIT_REF);
        try {
            client.deleteTenancy("tenantDom1", "providerService1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.deleteTenancy("tenantDom2", "providerService1", AUDIT_REF))
                    .thenThrow(new NullPointerException());
            client.deleteTenancy("tenantDom2", "providerService1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutTenantRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TenantRoles tenantRoleMock = Mockito.mock(TenantRoles.class);
        List<TenantRoleAction> roleActions = new ArrayList<TenantRoleAction>();
        for (Struct.Field f : TABLE_PROVIDER_ROLE_ACTIONS) {
            roleActions.add(new TenantRoleAction().setRole(f.name())
                    .setAction((String) f.value()));
        }
        TenantRoles tenantRoles = new TenantRoles().setDomain("ProviderDomain1").setService("storage").setTenant("TenantDomain1").setRoles(roleActions);
        Mockito.when(c.putTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1", AUDIT_REF, tenantRoles)).thenReturn(tenantRoleMock).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.putTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1", AUDIT_REF, tenantRoles);
        try {
            client.putTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1", AUDIT_REF, tenantRoles);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(
                    c.putTenantRoles("ProviderDomain2", "ProviderService1", "TenantDomain1", AUDIT_REF, tenantRoles))
                    .thenThrow(new NullPointerException());
            client.putTenantRoles("ProviderDomain2", "ProviderService1", "TenantDomain1", AUDIT_REF, tenantRoles);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetTenantRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TenantRoles tenantRoleMock = Mockito.mock(TenantRoles.class);
        Mockito.when(c.getTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1")).thenReturn(tenantRoleMock).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.getTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1");
        try {
            client.getTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getTenantRoles("ProviderDomain2", "ProviderService1", "TenantDomain1"))
                    .thenThrow(new NullPointerException());
            client.getTenantRoles("ProviderDomain2", "ProviderService1", "TenantDomain1");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteTenantRoles() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TenantRoles tenantRoleMock = Mockito.mock(TenantRoles.class);
        Mockito.when(c.deleteTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1", AUDIT_REF)).thenReturn(tenantRoleMock).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.deleteTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1", AUDIT_REF);
        try {
            client.deleteTenantRoles("ProviderDomain1", "ProviderService1", "TenantDomain1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetSignedDomains() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Map<String, List<String>> respHdrs = new HashMap<String, List<String>>();
        SignedDomains signedDomain1 = Mockito.mock(SignedDomains.class);
        Mockito.when(c.getSignedDomains("dom1", "meta1", "tag1", respHdrs)).thenReturn(signedDomain1).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.getSignedDomains("dom1", "meta1", "tag1", respHdrs);
        try {
            client.getSignedDomains("dom1", "meta1", "tag1", respHdrs);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutDefaultAdmins() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DefaultAdmins adminsMock = Mockito.mock(DefaultAdmins.class);
        Mockito.when(c.putDefaultAdmins("sports", AUDIT_REF, adminsMock)).thenReturn(adminsMock);
        client.putDefaultAdmins("sports", AUDIT_REF, adminsMock);
        try {
            Mockito.when(c.putDefaultAdmins("media", AUDIT_REF, adminsMock)).thenThrow(new ZMSClientException(400,"Audit reference required"));
            client.putDefaultAdmins("media", AUDIT_REF, adminsMock);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetDomainDataCheck() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainDataCheck checkdom1 = Mockito.mock(DomainDataCheck.class);
        Mockito.when(c.getDomainDataCheck("domain1")).thenReturn(checkdom1).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.getDomainDataCheck("domain1");
        try {
            client.getDomainDataCheck("domain1");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.getDomainDataCheck("domain2")).thenThrow(new NullPointerException());
            client.getDomainDataCheck("domain2");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testPutTenancy() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Tenancy tenancyMock = Mockito.mock(Tenancy.class);
        Tenancy tenant = createTenantObject("tenantDom1", "providerDom1" + "." + "providerService1");
        Mockito.when(c.putTenancy("tenantDom1", "providerService1", AUDIT_REF, tenant)).thenReturn(tenancyMock).thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.putTenancy("tenantDom1", "providerService1", AUDIT_REF, tenant);
        try {
            client.putTenancy("tenantDom1", "providerService1", AUDIT_REF, tenant);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        try {
            Mockito.when(c.putTenancy("tenantDom2", "providerService1", AUDIT_REF, tenant))
                    .thenThrow(new NullPointerException());
            client.putTenancy("tenantDom2", "providerService1", AUDIT_REF, tenant);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testAddMembershipUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Role role1Mock = Mockito.mock(Role.class);
        Role roleMock = Mockito.mock(Role.class);
        Mockito.when(c.putRole("MbrAddDom1", "Role1", AUDIT_REF, role1Mock)).thenReturn(roleMock);
        Membership mbr = new Membership();
        mbr.setRoleName("Role1");
        mbr.setMemberName("user.doe");
        mbr.setIsMember(true);
        Membership mbrExp = new Membership();
        mbrExp.setRoleName("Role1");
        mbrExp.setMemberName("user.temp");
        mbrExp.setExpiration(Timestamp.fromMillis(100000));
        mbrExp.setIsMember(true);
        Membership membershipMock = Mockito.mock(Membership.class);
        Mockito.when(c.putMembership("MbrAddDom1", "Role1", "user.doe", AUDIT_REF, mbr)).thenReturn(membershipMock);
        Mockito.when(c.putMembership("MbrAddDom1", "Role1", "user.temp", AUDIT_REF, mbrExp)).thenReturn(membershipMock);
        Mockito.when(c.getRole("MbrAddDom1", "Role1", false, false)).thenReturn(roleMock);
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.joe"));
        roleMembers.add(new RoleMember().setMemberName("user.jane"));
        roleMembers.add(new RoleMember().setMemberName("user.doe"));
        roleMembers.add(new RoleMember().setMemberName("user.temp")
                .setExpiration(Timestamp.fromMillis(100000)));
        Mockito.when(roleMock.getRoleMembers()).thenReturn(roleMembers);
        testAddMembership(client, systemAdminFullUser);
        Mockito.when(c.deleteTopLevelDomain("MbrGetRoleDom1", AUDIT_REF)).thenReturn(dom1Mock);
    }

    @Test
    public void testDeleteMembershipUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Role role1Mock = Mockito.mock(Role.class);
        Mockito.when(c.putRole("MbrDelDom1", "Role1", AUDIT_REF, role1Mock)).thenReturn(role1Mock);
        Mockito.when(c.getRole("MbrDelDom1", "Role1", false, false)).thenReturn(role1Mock);
        @SuppressWarnings("unchecked")
        List<String> membersMock = Mockito.mock(List.class);
        Mockito.when(role1Mock.getMembers()).thenReturn(membersMock);
        Mockito.when(membersMock.size()).thenReturn(1);
        Mockito.when(membersMock.contains("user.joe")).thenReturn(false);
        Mockito.when(membersMock.contains("user.jane")).thenReturn(true);
        testDeleteMembership(client, systemAdminFullUser);
    }

    @Test
    public void testCreatePolicyUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Policy policy1Mock = Mockito.mock(Policy.class);
        Mockito.when(c.putPolicy("PolicyAddDom1", "Policy1", AUDIT_REF, policy1Mock)).thenReturn(policy1Mock);
        Mockito.when(c.getPolicy("PolicyAddDom1", "Policy1")).thenReturn(policy1Mock);
        Mockito.when(policy1Mock.getName()).thenReturn("PolicyAddDom1:policy.Policy1".toLowerCase());
        testCreatePolicy(client, systemAdminFullUser);
    }

    @Test
    public void testDeletePolicyUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Policy policy1Mock = Mockito.mock(Policy.class);
        Mockito.when(c.putPolicy("PolicyDelDom1", "Policy1", AUDIT_REF, policy1Mock)).thenReturn(policy1Mock);
        Mockito.when(c.putPolicy("PolicyDelDom1", "Policy2", AUDIT_REF, policy1Mock)).thenReturn(policy1Mock);
        Mockito.when(c.getPolicy("PolicyDelDom1", "Policy1")).thenReturn(policy1Mock).thenThrow(new ResourceException(204));
        Mockito.when(c.getPolicy("PolicyDelDom1", "Policy2")).thenReturn(policy1Mock,policy1Mock).thenThrow(new ResourceException(204));
        testDeletePolicy(client, systemAdminFullUser);
    }
    
    @Test
    public void testDeletePublicKeyEntryUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(Mockito.anyString(), Mockito.any(TopLevelDomain.class))).thenReturn(domainMock);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);
        Mockito.when(c.putServiceIdentity("DelPublicKeyDom1", "Service1", AUDIT_REF, serviceMock)).thenReturn(serviceMock);
        PublicKeyEntry entoryMock = Mockito.mock(PublicKeyEntry.class);
        Mockito.when(c.deletePublicKeyEntry("DelPublicKeyDom1", "Service1", "zone1", AUDIT_REF)).thenReturn(entoryMock);
        Mockito.when(c.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone1")).thenThrow(new ResourceException(404));
        Mockito.when(c.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone2")).thenReturn(entoryMock);
        Mockito.when(entoryMock.getKey()).thenReturn(PUB_KEY_ZONE2);
        Mockito.when(c.deletePublicKeyEntry("DelPublicKeyDom1", "Service1", "zone2", AUDIT_REF)).thenThrow(new ResourceException(400));
        testDeletePublicKeyEntry(client, systemAdminFullUser);
    }

    @Test
    public void testCreateServiceIdentityUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);
        Mockito.when(c.putServiceIdentity("ServiceAddDom1", "Service1", AUDIT_REF, serviceMock)).thenReturn(serviceMock);
        Mockito.when(c.getServiceIdentity("ServiceAddDom1", "Service1")).thenReturn(serviceMock);
        Mockito.when(serviceMock.getName()).thenReturn("ServiceAddDom1.Service1".toLowerCase());
        testCreateServiceIdentity(client, systemAdminFullUser);
    }

    @Test
    public void testCreateEntityUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Entity entityMock = Mockito.mock(Entity.class);
        Mockito.when(c.putEntity("CreateEntityDom1", "Entity1", AUDIT_REF, entityMock)).thenReturn(entityMock);
        Mockito.when(c.getEntity("CreateEntityDom1", "Entity1")).thenReturn(entityMock);
        Mockito.when(entityMock.getName()).thenReturn("Entity1".toLowerCase());
        testCreateEntity(client, systemAdminFullUser);
    }

    @Test
    public void testDeleteEntityUserToken() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1Mock)).thenReturn(domainMock);
        Entity entityMock = Mockito.mock(Entity.class);
        Mockito.when(c.getEntity("DelEntityDom1", "Entity1")).thenReturn(entityMock).thenThrow(new ResourceException(204));
        Mockito.when(c.getEntity("DelEntityDom1", "Entity2")).thenReturn(entityMock,entityMock).thenThrow(new ResourceException(204));
        testDeleteEntity(client, systemAdminFullUser);
    }
    
    @Test
    public void testGetPrincipalNull() {
        
        ZMSClient client = new ZMSClient(getZMSUrl());
        try {
            client.getPrincipal(null);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(ex.getCode() == 401);
        }
        client.close();
    }
    
    @Test
    public void testGetPrincipalInvalid() {
        
        ZMSClient client = new ZMSClient(getZMSUrl());
        try {
            client.getPrincipal("abcdefg");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(ex.getCode() == 401);
        }
        
        try {
            client.getPrincipal("v=U1;d=coretech;t=12345678;s=signature");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(ex.getCode() == 401);
        }
        
        try {
            client.getPrincipal("v=U1;n=storage;t=12345678;s=signature");
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(ex.getCode() == 401);
        }
        client.close();
    }
    
    Struct setupRespHdrsStruct() {
        
        Struct respHdrs = new Struct();
        Array values = new Array();
        values.add("Value1A");
        values.add("Value1B");
        respHdrs.put("tag1", values);
        
        values = new Array();
        values.add("Value2A");
        values.add("Value2B");
        respHdrs.put("tag2", values);
        
        return respHdrs;
    }
    
    @Test
    public void testLookupZMSUrl() {
        
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZMSClient client = new ZMSClient(getZMSUrl());
        assertEquals(client.lookupZMSUrl(), "https://server-zms.athenzcompany.com:4443/");
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }
    
    @Test
    public void testLookupZMSUrlInvalidFile() {
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz_invaild.conf");
        ZMSClient client = new ZMSClient(getZMSUrl());
        assertNull(client.lookupZMSUrl());
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }

    @Test
    public void testDeleteDomainTemplate() {
        ZMSClient client = createClient(systemAdminUser);
        String domName = "templesofold";
        String domName2 = "templesofold2";

        try {
            client.deleteTopLevelDomain(domName, AUDIT_REF);
        } catch (ZMSClientException ex) {
            // ignore cleanup errors - e.g. not found
        }

        TopLevelDomain dom1 = createTopLevelDomainObject(domName,
                "Test Domain", "testOrg", systemAdminFullUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, dom1)).thenReturn(domainMock);
        client.postTopLevelDomain(AUDIT_REF, dom1);
        ServerTemplateList svrTemplListMock = Mockito.mock(ServerTemplateList.class);
        @SuppressWarnings("unchecked")
        List<String> svrTemplNamesMock = Mockito.mock(List.class);
        Mockito.when(c.getServerTemplateList()).thenReturn(svrTemplListMock);
        ServerTemplateList svrTemplList = client.getServerTemplateList();
        Mockito.when(svrTemplListMock.getTemplateNames()).thenReturn(svrTemplNamesMock);
        List<String> svrTemplNames = svrTemplList.getTemplateNames();
        DomainTemplate domTempl = new DomainTemplate().setTemplateNames(svrTemplNames);
        client.putDomainTemplate(domName, AUDIT_REF, domTempl);
        DomainTemplateList domTemplListMock = Mockito.mock(DomainTemplateList.class);
        Mockito.when(c.getDomainTemplateList(domName)).thenReturn(domTemplListMock);
        DomainTemplateList domTemplList = client.getDomainTemplateList(domName);
        assertNotNull(domTemplList);
        try {
            Mockito.when(c.getDomainTemplateList(domName2)).thenThrow(new NullPointerException())
                    .thenThrow(new ResourceException(404));
            client.getDomainTemplateList(domName2);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            client.getDomainTemplateList(domName2);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        List<String> templNames = domTemplList.getTemplateNames();
        assertNotNull(templNames);
        assertTrue(templNames.size() == svrTemplNames.size());
        // HAVE: domain has all the templates

        // domain has multiple templates: deleting 1 at a time
        for (int cnt = 0; cnt < svrTemplNames.size(); ++cnt) {
            client.deleteDomainTemplate(domName, svrTemplNames.get(cnt), AUDIT_REF);
            domTemplList = client.getDomainTemplateList(domName);
            assertNotNull(domTemplList);
            templNames = domTemplList.getTemplateNames();
            assertNotNull(templNames);
            int templCnt = svrTemplNames.size() - (cnt + 1);
            assertTrue(templNames.size() == templCnt, "template should be count=" + templCnt);
            for (int cnt2 = cnt + 1; cnt2 < svrTemplNames.size(); ++cnt2) {
                assertTrue(templNames.contains(svrTemplNames.get(cnt2)), "should contain=" + svrTemplNames.get(cnt2));
            }
        }

        client.deleteTopLevelDomain(domName, AUDIT_REF);
    }

    @Test
    public void testDeleteDomainTemplateErrorCases() {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServerTemplateList svrTemplListMock = Mockito.mock(ServerTemplateList.class);
        Mockito.when(c.getServerTemplateList()).thenReturn(svrTemplListMock).thenThrow(new NullPointerException()).thenThrow(new ResourceException(404,"Domain not found"));
        ServerTemplateList svrTemplList = client.getServerTemplateList();
        try {
            client.getServerTemplateList();
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        try {
            client.getServerTemplateList();
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        @SuppressWarnings("unchecked")
        List<String> svrTemplNamesMock = Mockito.mock(List.class);
        Mockito.when(svrTemplListMock.getTemplateNames()).thenReturn(svrTemplNamesMock);
        List<String> svrTemplNames = svrTemplList.getTemplateNames();
        Mockito.when(c.deleteDomainTemplate("nonexistantdomain", svrTemplNames.get(1), AUDIT_REF)).thenThrow(new ResourceException(404, "Domain not found"));
        // test: no such domain
        try {
            client.deleteDomainTemplate("nonexistantdomain", svrTemplNames.get(1), AUDIT_REF);
            fail("requesterror not thrown by deleteDomainTemplate");
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("Domain not found"), ex.getMessage());
        }

        try {
            Mockito.when(c.deleteDomainTemplate("nonexistantdomain2", svrTemplNames.get(1), AUDIT_REF))
                    .thenThrow(new NullPointerException());
            client.deleteDomainTemplate("nonexistantdomain2", svrTemplNames.get(1), AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }

        // test: no such template
        String domName = "simontemplar";

        try {
            client.deleteTopLevelDomain(domName, AUDIT_REF);
        } catch (ZMSClientException ex) {
            // ignore cleanup errors - e.g. not found
        }

        TopLevelDomain dom1 = createTopLevelDomainObject(domName,
                "Test Domain", "testOrg", systemAdminFullUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        client.deleteDomainTemplate(domName, svrTemplNames.get(1), AUDIT_REF);
        client.deleteTopLevelDomain(domName, AUDIT_REF);
    }
}
