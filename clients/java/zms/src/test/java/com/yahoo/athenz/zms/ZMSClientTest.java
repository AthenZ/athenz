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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ZMSClientTest {

    private String systemAdminUser = null;
    private String systemAdminFullUser = null;
    private static final String ZMS_CLIENT_PROP_ZMS_URL = "athenz.zms.client.zms_url";
    private static final String ZMS_CLIENT_PROP_TEST_ADMIN = "athenz.zms.client.test_admin";

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

    private static final String AUDIT_REF = "zmsjcltest";
    private static final String HTTP_RFC1123_DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss zzz";

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
        return SimplePrincipal.create("user", userName,
                "v=U1;d=user;n=" + userName + ";s=signature", 0, authority);
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

        List<String> admins = new ArrayList<>();
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

        List<String> admins = new ArrayList<>();
        admins.add(admin);
        dom.setAdminUsers(admins);

        return dom;
    }

    private Role createRoleObject(ZMSClient client, String domainName, String roleName,
            String trust, String member1, String member2) {

        Role role = new Role();
        role.setName(client.generateRoleName(domainName, roleName));
        role.setTrust(trust);

        List<String> members = new ArrayList<>();
        members.add(member1);
        if (member2 != null) {
            members.add(member2);
        }
        role.setMembers(members);
        return role;
    }

    private Group createGroupObject(ZMSClient client, String domainName, String groupName, String... members) {

        Group group = new Group();
        group.setName(client.generateGroupName(domainName, groupName));

        List<GroupMember> groupMembers = new ArrayList<>();
        for (String member : members) {
            groupMembers.add(new GroupMember().setMemberName(member));
        }
        group.setGroupMembers(groupMembers);
        return group;
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

        List<Assertion> assertList = new ArrayList<>();
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
        service.setDescription("test");

        service.setProviderEndpoint(endPoint);

        List<String> hosts = new ArrayList<>();
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

        List<String> hosts = new ArrayList<>();
        hosts.add(host);
        service.setHosts(hosts);

        return service;
    }

    private Entity createEntityObject(ZMSClient client, String domainName, String entityName) {

        Entity entity = new Entity();
        entity.setName(client.generateEntityName(domainName, entityName));

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
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, null, dom1);
        assertNotNull(resDom1);

        Domain resDom2 = client.getDomain("AddTopDom1");
        assertNotNull(resDom2);

        try {
            client.getDomain("AddTopDom3");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        try {
            client.getDomain("AddTopDom3");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        client.deleteTopLevelDomain("AddOnceTopDom1", AUDIT_REF);
    }

    private void testCreateSubDomain(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("AddSubDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        SubDomain dom2 = createSubDomainObject("AddSubDom2", "AddSubDom1",
                "Test Domain2", "testOrg", adminUser);
        Domain resDom1 = client.postSubDomain("AddSubDom1", AUDIT_REF, null, dom2);
        assertNotNull(resDom1);
        try {
            client.postSubDomain("AddSubDom3", AUDIT_REF, dom2);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        client.deleteSubDomain("AddOnceSubDom1", "AddOnceSubDom2", AUDIT_REF);
        client.deleteTopLevelDomain("AddOnceSubDom1", AUDIT_REF);
    }

    private void testCreateRole(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateRoleDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Role role1 = createRoleObject(client, "CreateRoleDom1", "Role1", null, "user.joe", "user.jane");
        Role returnedRole = client.putRole("CreateRoleDom1", "Role1", AUDIT_REF, true, null, role1);

        Role role3 = client.getRole("CreateRoleDom1", "Role1");
        assertNotNull(role3);
        assertEquals(role3.getName(), "CreateRoleDom1:role.Role1".toLowerCase());
        assertNull(role3.getTrust());

        try {
            client.putRole("CreateRoleDom1", "Role2", AUDIT_REF, role1);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.putRole("CreateRoleDom1", "Role3", AUDIT_REF, role1);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        try {
            client.getRole("CreateRoleDom1", "Role2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getRole("CreateRoleDom1", "Role3");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        assertEquals(returnedRole, role1);
        client.deleteTopLevelDomain("CreateRoleDom1", AUDIT_REF);
    }

    private void testAddMembership(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("MbrAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Role role1 = createRoleObject(client, "MbrAddDom1", "Role1", null, "user.member1", "user.member2");
        client.putRole("MbrAddDom1", "Role1", AUDIT_REF, role1);
        Membership returnedMember = client.putMembership("MbrAddDom1", "Role1", "user.member3", AUDIT_REF, true);

        client.putMembership("MbrAddDom1", "Role1", "user.member4",
                Timestamp.fromMillis(100000), AUDIT_REF);

        client.putMembershipWithReview("MbrAddDom1", "Role1", "user.member5",
                Timestamp.fromMillis(100000), Timestamp.fromMillis(500000), AUDIT_REF);

        client.putMembershipWithReview("MbrAddDom1", "Role1", "user.member6",
                null, Timestamp.fromMillis(500000), AUDIT_REF);

        Role role = client.getRole("MbrAddDom1", "Role1");
        assertNotNull(role);

        List<RoleMember> members = role.getRoleMembers();
        assertEquals(members.size(), 6);
        RoleMember roleMember1 = new RoleMember().setMemberName("user.member1");
        RoleMember roleMember2 = new RoleMember().setMemberName("user.member2");
        RoleMember roleMember3 = new RoleMember().setMemberName("user.member3");
        RoleMember roleMember4 = new RoleMember().setMemberName("user.member4")
                .setExpiration(Timestamp.fromMillis(100000));
        RoleMember roleMember5 = new RoleMember().setMemberName("user.member5")
                .setExpiration(Timestamp.fromMillis(100000)).setReviewReminder(Timestamp.fromMillis(500000));
        RoleMember roleMember6 = new RoleMember().setMemberName("user.member6")
                .setReviewReminder(Timestamp.fromMillis(500000));

        assertEquals(members.get(0), roleMember1);
        assertEquals(members.get(1), roleMember2);
        assertEquals(members.get(2).getMemberName(), returnedMember.getMemberName());
        assertEquals(role.getName(), returnedMember.getRoleName());
        assertEquals(members.get(2).getMemberName(), returnedMember.getMemberName());
        assertEquals(members.get(3), roleMember4);
        assertEquals(members.get(4), roleMember5);
        assertEquals(members.get(5), roleMember6);

        client.deleteTopLevelDomain("MbrAddDom1", AUDIT_REF);
    }

    @Test
    public void testPutMembership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Membership member = new Membership().setRoleName("role1").setMemberName("joe")
                .setIsMember(true).setExpiration(null);

        Mockito.when(c.putMembership("domain", "role1", "joe", AUDIT_REF, true, null, member))
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException())
                .thenReturn(member);

        try {
            client.putMembership("domain", "role1", "joe", AUDIT_REF, true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putMembership("domain", "role1", "joe", AUDIT_REF, true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        Membership returnedMember = client.putMembership("domain", "role1", "joe", AUDIT_REF, true);
        assertNotNull(returnedMember);
        assertEquals(returnedMember.getMemberName(), "joe");

        Mockito.when(c.putMembership("domain", "role2", "joe", AUDIT_REF, false, null, member))
                .thenReturn(member);
        client.putMembership("domain", "role2", "joe", AUDIT_REF);

        Mockito.when(c.putMembership("domain", "role3", "joe", AUDIT_REF, false, null, member))
                .thenReturn(member);
        client.putMembership("domain", "role3", "joe", null, AUDIT_REF, false);
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

    @Test
    public void testDeleteMembership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteMembership("domain", "role1", "joe", AUDIT_REF, null)).thenThrow(new ResourceException(403));
        Mockito.when(c.deleteMembership("domain", "role2", "joe", AUDIT_REF, null)).thenThrow(new NullPointerException());

        try {
            client.deleteMembership("domain", "role1", "joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deleteMembership("domain", "role2", "joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeletePendingMembershipFailures() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deletePendingMembership("domain", "role1", "joe", AUDIT_REF)).thenThrow(new ResourceException(403));
        Mockito.when(c.deletePendingMembership("domain", "role2", "joe", AUDIT_REF)).thenThrow(new NullPointerException());

        try {
            client.deletePendingMembership("domain", "role1", "joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deletePendingMembership("domain", "role2", "joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeleteTopLevelDomain() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteTopLevelDomain("domain1", AUDIT_REF, null)).thenThrow(new ResourceException(403));
        Mockito.when(c.deleteTopLevelDomain("domain2", AUDIT_REF, null)).thenThrow(new NullPointerException());

        try {
            client.deleteTopLevelDomain("domain1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deleteTopLevelDomain("domain2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    private void testCreatePolicy(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Policy policy1 = createPolicyObject(client, "PolicyAddDom1", "Policy1");
        client.putPolicy("PolicyAddDom1", "Policy1", AUDIT_REF, null, policy1);

        Policy policyRes2 = client.getPolicy("PolicyAddDom1", "Policy1");
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), "PolicyAddDom1:policy.Policy1".toLowerCase());

        try {
            client.getPolicy("PolicyAddDom2", "Policy1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getPolicy("PolicyAddDom3", "Policy1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putPolicy("PolicyAddDom2", "Policy1", AUDIT_REF, new Policy());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putPolicy("PolicyAddDom3", "Policy1", AUDIT_REF, new Policy());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.deleteTopLevelDomain("PolicyAddDom1", AUDIT_REF);
    }

    private void testCreatePolicyVersion(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Policy policy1 = createPolicyObject(client, "PolicyAddDom1", "Policy1");
        client.putPolicy("PolicyAddDom1", "Policy1", AUDIT_REF, policy1);

        Policy policyRes2 = client.getPolicyVersion("PolicyAddDom1", "Policy1", "0");
        assertNotNull(policyRes2);
        assertEquals(policyRes2.getName(), "PolicyAddDom1:policy.Policy1".toLowerCase());

        try {
            client.getPolicyVersion("PolicyAddDom2", "Policy1", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getPolicyVersion("PolicyAddDom3", "Policy1", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putPolicyVersion("PolicyAddDom2", "Policy1", "new-version", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putPolicyVersion("PolicyAddDom3", "Policy1", "new-version", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putPolicyVersion("PolicyAddDom2", "Policy1", "new-version", "from-version", AUDIT_REF, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putPolicyVersion("PolicyAddDom3", "Policy1", "new-version", "from-version", AUDIT_REF, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.deleteTopLevelDomain("PolicyAddDom1", AUDIT_REF);
    }

    private void testSetActivePolicyVersion(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Policy policy1 = createPolicyObject(client, "PolicyAddDom1", "Policy1");
        Policy returnedPolicy = client.putPolicy("PolicyAddDom1", "Policy1", AUDIT_REF, true, policy1);
        assertEquals(returnedPolicy, policy1);
        client.putPolicyVersion("PolicyAddDom1", "Policy1", "new-version", AUDIT_REF);
        try {
            client.setActivePolicyVersion("PolicyAddDom2", "Policy1", "new-version", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.setActivePolicyVersion("PolicyAddDom2", "Policy1", "new-version2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        policyRes2 = client.getPolicy("PolicyDelDom1", "Policy2");
        assertNotNull(policyRes2);

        client.deletePolicy("PolicyDelDom1", "Policy2", AUDIT_REF);

        // we need to get an exception here
        try {
            client.getPolicy("PolicyDelDom1", "Policy1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        // we need to get an exception here
        try {
            client.getPolicy("PolicyDelDom1", "Policy2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            client.deletePolicy("PolicyDelDom2", "Policy1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deletePolicy("PolicyDelDom3", "Policy1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.deleteTopLevelDomain("PolicyDelDom1", AUDIT_REF);
    }

    private void testDeletePolicyVersion(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("PolicyDelDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Policy policy1 = createPolicyObject(client, "PolicyDelDom1", "Policy1");
        client.putPolicy("PolicyDelDom1", "Policy1", AUDIT_REF, policy1);

        Policy policy2 = createPolicyObject(client, "PolicyDelDom1", "Policy2");
        client.putPolicy("PolicyDelDom1", "Policy2", AUDIT_REF, policy2);

        Policy policyRes1 = client.getPolicyVersion("PolicyDelDom1", "Policy1", "0");
        assertNotNull(policyRes1);

        Policy policyRes2 = client.getPolicyVersion("PolicyDelDom1", "Policy2", "0");
        assertNotNull(policyRes2);

        client.deletePolicyVersion("PolicyDelDom1", "Policy1", "0", AUDIT_REF);

        // we need to get an exception here
        try {
            client.getPolicyVersion("PolicyDelDom1", "Policy1", "0");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        policyRes2 = client.getPolicyVersion("PolicyDelDom1", "Policy2", "0");
        assertNotNull(policyRes2);

        client.deletePolicyVersion("PolicyDelDom1", "Policy2", "0", AUDIT_REF);

        // we need to get an exception here
        try {
            client.getPolicyVersion("PolicyDelDom1", "Policy1", "0");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        // we need to get an exception here
        try {
            client.getPolicyVersion("PolicyDelDom1", "Policy2", "0");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            client.deletePolicyVersion("PolicyDelDom2", "Policy1", "0", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deletePolicyVersion("PolicyDelDom3", "Policy1", "0", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.deleteTopLevelDomain("PolicyDelDom1", AUDIT_REF);
    }

    private void testCreateServiceIdentity(ZMSClient client, String adminUser) {

        TopLevelDomain dom1 = createTopLevelDomainObject("ServiceAddDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        ServiceIdentity service = createServiceObject(client, "ServiceAddDom1", "Service1",
                "http://localhost", "/usr/bin/java", "root", "users", "host1");

        ServiceIdentity returnedServiceIdentity = client.putServiceIdentity("ServiceAddDom1", "Service1",
                AUDIT_REF, true, null, service);
        assertNotNull(returnedServiceIdentity);
        assertEquals(returnedServiceIdentity, service);

        ServiceIdentity serviceRes2 = client.getServiceIdentity("ServiceAddDom1", "Service1");
        assertNotNull(serviceRes2);
        assertEquals(serviceRes2.getName(), "ServiceAddDom1.Service1".toLowerCase());

        try {
            client.getServiceIdentity("ServiceAddDom2", "Service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.getServiceIdentity("ServiceAddDom3", "Service1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        client.deleteTopLevelDomain("ServiceAddDom1", AUDIT_REF);
    }

    private void testDeletePublicKeyEntry(ZMSClient client, String adminUser) throws URISyntaxException, IOException {

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

        try {
            client.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone3");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
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

        // exceptions are returned as 400 bad request

        try {
            Mockito.when(client.client.deletePublicKeyEntry("domain1", "Service1", "0", AUDIT_REF, null))
                    .thenThrow(new NullPointerException());
            client.deletePublicKeyEntry("domain1", "Service1", "0", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.deleteTopLevelDomain("DelPublicKeyDom1", AUDIT_REF);
    }

    private void testCreateEntity(ZMSClient client, String adminUser) throws URISyntaxException, IOException {

        TopLevelDomain dom1 = createTopLevelDomainObject("CreateEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Entity entity1 = createEntityObject(client, "CreateEntityDom1", "Entity1");
        client.putEntity("CreateEntityDom1", "Entity1", AUDIT_REF, entity1);

        Entity entity2 = client.getEntity("CreateEntityDom1", "Entity1");
        assertNotNull(entity2);
        assertEquals(entity2.getName(), "Entity1".toLowerCase());

        try {
            Mockito.when(client.client.getEntity("domain1", "ent1")).thenThrow(new NullPointerException());
            client.getEntity("domain1", "ent1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            Mockito.when(client.client.getEntity("domain2", "ent1")).thenThrow(new ResourceException(403));
            client.getEntity("domain2", "ent1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            Mockito.when(client.client.putEntity("domain1", "ent1", AUDIT_REF, entity1)).thenThrow(new NullPointerException());
            client.putEntity("domain1", "ent1", AUDIT_REF, entity1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            Mockito.when(client.client.putEntity("domain2", "ent1", AUDIT_REF, entity1)).thenThrow(new ResourceException(403));
            client.putEntity("domain2", "ent1", AUDIT_REF, entity1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        client.deleteTopLevelDomain("CreateEntityDom1", AUDIT_REF);
    }

    private void testDeleteEntity(ZMSClient client, String adminUser) throws URISyntaxException, IOException {

        TopLevelDomain dom1 = createTopLevelDomainObject("DelEntityDom1",
                "Test Domain1", "testOrg", adminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Entity entity1 = createEntityObject(client, "DelEntityDom1", "Entity1");
        client.putEntity("DelEntityDom1", "Entity1", AUDIT_REF, entity1);

        Entity entity2 = createEntityObject(client, "DelEntityDom1", "Entity2");
        client.putEntity("DelEntityDom1", "Entity2", AUDIT_REF, entity2);

        Entity entityRes = client.getEntity("DelEntityDom1", "Entity1");
        assertNotNull(entityRes);

        entityRes = client.getEntity("DelEntityDom1", "Entity2");
        assertNotNull(entityRes);

        client.deleteEntity("DelEntityDom1", "Entity1", AUDIT_REF);

        try {
            client.getEntity("DelEntityDom1", "Entity1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        entityRes = client.getEntity("DelEntityDom1", "Entity2");
        assertNotNull(entityRes);

        client.deleteEntity("DelEntityDom1", "Entity2", AUDIT_REF);

        try {
            client.getEntity("DelEntityDom1", "Entity1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            client.getEntity("DelEntityDom1", "Entity2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            Mockito.when(client.client.deleteEntity("domain1", "ent1", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteEntity("domain1", "ent1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            Mockito.when(client.client.deleteEntity("domain2", "ent1", AUDIT_REF)).thenThrow(new ResourceException(403));
            client.deleteEntity("domain2", "ent1", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        client.deleteTopLevelDomain("DelEntityDom1", AUDIT_REF);
    }

    // Unit Tests for ZMS Java Client

    @Test
    public void testClientConstructors() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {

        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");

        ZMSClient client = new ZMSClient("http://localhost:10080/zms/v1");
        assertNotNull(client);
        client.clearCredentials();
        client.close();

        client = new ZMSClient();
        assertNotNull(client);
        client.clearCredentials();
        client.close();

        Principal identity = SimplePrincipal.create("user", "johndoe", "cred", new PrincipalAuthority());

        client = new ZMSClient(identity);
        assertNotNull(client);
        client.clearCredentials();
        client.close();

        client = new ZMSClient("http://localhost:10080/zms/v1", identity);
        assertNotNull(client);
        client.clearCredentials();
        client.close();

        final SSLContext dummyContext = SSLContextBuilder.create()
            .setProtocol(null)
            .setSecureRandom(null)
            .loadTrustMaterial((KeyStore) null, null)
            .loadKeyMaterial((KeyStore) null, null, null)
            .build();

        client = new ZMSClient("http://localhost:10080/zms/v1", dummyContext);
        assertNotNull(client);
        client.clearCredentials();
        client.close();

        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF);
    }

    @Test
    public void testClientConstructorsInvalid() {

        try {
            new ZMSClient("http://localhost:10080/zms/v1", (Principal) null);
            fail();
        } catch (IllegalArgumentException ignored) {
        }

        try {
            new ZMSClient("http://localhost:10080/zms/v1", (SSLContext) null);
            fail();
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    public void testAddCredentialsInvalid() {
        ZMSClient client = new ZMSClient("http://localhost:10080/zms/v1");
        client.addCredentials("Header", "token");
        client.clearCredentials();

        try {
            client.addCredentials(null);
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        client.clearCredentials();

        Principal identity = SimplePrincipal.create("appid", "creds", (Authority) null);
        try {
            client.addCredentials(identity);
            fail();
        } catch (IllegalArgumentException ignored) {
        }
        client.clearCredentials();
    }

    @Test
    public void testClientOnlyUrl() throws URISyntaxException, IOException {
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        // verify we can't add a domain

        TopLevelDomain dom1 = createTopLevelDomainObject("OnlyUrlDomain",
                "Test Domain1", "testOrg", systemAdminFullUser);
        try {
            Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1)).thenThrow(new ResourceException(400));
            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
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
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        try {
            TopLevelDomain dom1 = createTopLevelDomainObject("OnlyUrlDomain",
                    "Test Domain1", "testOrg", systemAdminFullUser);

            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        try {
            client.getAccess("UPDATE", "AccessDom1:resource1", "AccessDom1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testClientUrlPrincipal() throws URISyntaxException, IOException {

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
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1)).thenReturn(domainMock);
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, dom1);
        assertNotNull(resDom1);

        client.deleteTopLevelDomain("UrlPrincipalDomain", AUDIT_REF);
    }

    @Test
    public void testClientClearPrincipal() throws URISyntaxException, IOException {
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
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1)).thenReturn(domainMock);
        Domain resDom1 = client.postTopLevelDomain(AUDIT_REF, dom1);
        assertNotNull(resDom1);

        client.deleteTopLevelDomain("ClearPrincipalDomain", AUDIT_REF);

        // clear the credentials

        client.clearCredentials();

        // verify we can no longer add a new domain

        try {
            Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1)).thenThrow(new ResourceException(400));
            client.postTopLevelDomain(AUDIT_REF, dom1);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }

        // but we should be able to read the domain list
        DomainList domainListMock = Mockito.mock(DomainList.class);
        Mockito.when(client.getDomainList()).thenReturn(domainListMock);
        DomainList domList = client.getDomainList();
        assertNotNull(domList);
    }

    @Test
    public void testClientWithoutEndingSlash() throws URISyntaxException, IOException {
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
        Mockito.when(
            c.getDomainList(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null))
            .thenReturn(domainListMock);
        DomainList domList = client.getDomainList();
        assertNotNull(domList);
    }

    @Test
    public void testGetDomainListByLimits() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        Date now = new Date();
        DateFormat df = new SimpleDateFormat(HTTP_RFC1123_DATE_FORMAT);
        final String modSinceStr = df.format(now);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(100, "skip", "prefix", 1, null, null, null, null,
                        null, null, null, null, null, null, modSinceStr)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainList(100, "skip", "prefix", 1, now));
        try {
            client.getDomainList(100, "skip", "prefix", 1, now);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainList(100, "skip", "prefix", 1, now);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, null, "MemberRole1", "RoleName1",
                        null, null, null, null, null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainList("MemberRole1", "RoleName1"));
        try {
            client.getDomainList("MemberRole1", "RoleName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainList("MemberRole1", "RoleName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListByRole() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, null, "MemberRole1", "RoleName1",
                null, null, null, null, null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByRole("MemberRole1", "RoleName1"));
        try {
            client.getDomainListByRole("MemberRole1", "RoleName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByRole("MemberRole1", "RoleName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListAwsAccount() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, "aws", null, null, null,
                        null, null, null, null, null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByAwsAccount("aws"));
        try {
            client.getDomainListByAwsAccount("aws");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByAwsAccount("aws");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListByAzureSubscription() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, null, null, null,
                        "azure", null, null, null, null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByAzureSubscription("azure"));
        try {
            client.getDomainListByAzureSubscription("azure");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByAzureSubscription("azure");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListByGcpProject() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, null, null, null,
                        null, "gcp", null, null, null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByGcpProject("gcp"));
        try {
            client.getDomainListByGcpProject("gcp");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByGcpProject("gcp");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListByBusinessService() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, null, null, null,
                        null, null, null, null, "business-service", null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByBusinessService("business-service"));
        try {
            client.getDomainListByBusinessService("business-service");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByBusinessService("business-service");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListByProductId() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, 101, null, null,
                        null, null, null, null, null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByProductId(101));
        try {
            client.getDomainListByProductId(101);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByProductId(101);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetDomainListByTags() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainList domainList = new DomainList().setNames(Collections.singletonList("domain"));
        Mockito.when(c.getDomainList(null, null, null, null, null, null, null, null,
                        null, null, "tag-key", "tag-value", null, null, null)).thenReturn(domainList)
                .thenThrow(new NullPointerException()).thenThrow(new ResourceException(400));
        assertNotNull(client.getDomainListByTags("tag-key", "tag-value"));
        try {
            client.getDomainListByTags("tag-key", "tag-value");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainListByTags("tag-key", "tag-value");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testDeleteSubDomain() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteSubDomain("parent", "domain1", AUDIT_REF, null)).thenThrow(new NullPointerException());
            client.deleteSubDomain("parent", "domain1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.deleteSubDomain("parent", "domain2", AUDIT_REF, null)).thenThrow(new ResourceException(400));
            client.deleteSubDomain("parent", "domain2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutTenantResourceGroupRoles() throws URISyntaxException, IOException {
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1", AUDIT_REF, tenantRoles)).thenThrow(new ResourceException(400));
            client.putTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1", "ResourceGroup1",
                    AUDIT_REF, tenantRoles);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetTenantResourceGroupRoles() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1")).thenThrow(new NullPointerException());
            client.getTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1", "ResourceGroup1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1")).thenThrow(new ResourceException(400));
            client.getTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1", "ResourceGroup1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testDeleteTenantResourceGroupRoles() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TenantResourceGroupRoles tenantRoles = new TenantResourceGroupRoles();
        Mockito.when(c.deleteTenantResourceGroupRoles("ProvidorDomain", "ProvidorService", "TenantDom",
                "ResourceGroup", AUDIT_REF)).thenReturn(tenantRoles);
        client.deleteTenantResourceGroupRoles("ProvidorDomain", "ProvidorService", "TenantDom",
                "ResourceGroup", AUDIT_REF);

        try {
            Mockito.when(c.deleteTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteTenantResourceGroupRoles("ProvidorDomain1", "ProvidorService1", "TenantDom1", "ResourceGroup1",
                    AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            Mockito.when(c.deleteTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1",
                    "ResourceGroup1", AUDIT_REF)).thenThrow(new ResourceException(401));
            client.deleteTenantResourceGroupRoles("ProvidorDomain2", "ProvidorService1", "TenantDom1", "ResourceGroup1",
                    AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testGetRoles() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getRoles("domain1", true, null, null)).thenThrow(new NullPointerException());
            client.getRoles("domain1", true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getRoles("domain2", true, null, null)).thenThrow(new ResourceException(400));
            client.getRoles("domain2", true, null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetPolicies() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getPolicies("domain1", true, false, null, null)).thenThrow(new NullPointerException());
            client.getPolicies("domain1", true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getPolicies("domain2", true, false, null, null)).thenThrow(new ResourceException(400));
            client.getPolicies("domain2", true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getPolicies("domain3", true, true, null, null)).thenThrow(new ResourceException(400));
            client.getPolicies("domain3", true, true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getPolicies("domain3", false, true, null, null)).thenThrow(new NullPointerException());
            client.getPolicies("domain3", false, true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testDeleteUserDomain() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteUserDomain("domain1", AUDIT_REF, null)).thenThrow(new NullPointerException());
            client.deleteUserDomain("domain1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.deleteUserDomain("domain2", AUDIT_REF, null)).thenThrow(new ResourceException(400));
            client.deleteUserDomain("domain2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutDomainMeta() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainMeta meta = createDomainMetaObject("Test2 Domain", "NewOrg", false);
        try {
            Mockito.when(c.putDomainMeta("domain1", AUDIT_REF, null, meta)).thenThrow(new NullPointerException());
            client.putDomainMeta("domain1", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            Mockito.when(c.putDomainMeta("domain2", AUDIT_REF, null, meta)).thenThrow(new ResourceException(403));
            client.putDomainMeta("domain2", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutDomainSystemMeta() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainMeta meta = new DomainMeta().setAccount("acct1");
        Domain metaDomain = new Domain().setName("domain");
        Mockito.when(c.putDomainSystemMeta("domain", "account", AUDIT_REF, meta)).thenReturn(metaDomain);
        client.putDomainSystemMeta("domain", "account", AUDIT_REF, meta);

        try {
            Mockito.when(c.putDomainSystemMeta("domain1", "account", AUDIT_REF, meta)).thenThrow(new NullPointerException());
            client.putDomainSystemMeta("domain1", "account", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            Mockito.when(c.putDomainSystemMeta("domain2", "account", AUDIT_REF, meta)).thenThrow(new ResourceException(403));
            client.putDomainSystemMeta("domain2", "account", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutDomainTemplate() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        List<String> tempNames = new ArrayList<>();
        DomainTemplate domTempl = new DomainTemplate().setTemplateNames(tempNames);
        try {
            Mockito.when(c.putDomainTemplate("name1", AUDIT_REF, domTempl)).thenThrow(new NullPointerException());
            client.putDomainTemplate("name1", AUDIT_REF, domTempl);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putDomainTemplate("name2", AUDIT_REF, domTempl))
                    .thenThrow(new ResourceException(404, "Domain not found"));
            client.putDomainTemplate("name2", AUDIT_REF, domTempl);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NOT_FOUND);
        }
    }

    @Test
    public void testPutDomainTemplateExt() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        List<String> tempNames = new ArrayList<>();
        DomainTemplate domTempl = new DomainTemplate().setTemplateNames(tempNames);
        try {
            Mockito.when(c.putDomainTemplateExt("name1", "template1", AUDIT_REF, domTempl)).thenThrow(new NullPointerException());
            client.putDomainTemplateExt("name1", "template1", AUDIT_REF, domTempl);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putDomainTemplateExt("name2", "template2", AUDIT_REF, domTempl))
                    .thenThrow(new ResourceException(404, "Domain not found"));
            client.putDomainTemplateExt("name2", "template2", AUDIT_REF, domTempl);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NOT_FOUND);
        }
    }

    @Test
    public void testGetResourceAccessList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getResourceAccessList("principal1", "action1")).thenThrow(new NullPointerException());
            client.getResourceAccessList("principal1", "action1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getResourceAccessList("principal2", "action2")).thenThrow(new ResourceException(400));
            client.getResourceAccessList("principal2", "action2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testAssertion() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Assertion assertion = new Assertion();
        Long assertionId = 18000305032230531L;
        try {
            Mockito.when(c.putAssertion("domain1", "policy1", AUDIT_REF, null, assertion))
                    .thenThrow(new NullPointerException());
            client.putAssertion("domain1", "policy1", AUDIT_REF, null, assertion);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putAssertionPolicyVersion("domain1", "policy1", "new-version", AUDIT_REF, null, assertion))
                    .thenThrow(new NullPointerException());
            client.putAssertionPolicyVersion("domain1", "policy1", "new-version", AUDIT_REF, null, assertion);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putAssertionPolicyVersion("domain1", "policy2", "new-version", AUDIT_REF, null, assertion))
                    .thenThrow(new NullPointerException());
            client.putAssertionPolicyVersion("domain1", "policy2", "new-version", AUDIT_REF, assertion);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getAssertion("principal2", "action2", assertionId)).thenThrow(new NullPointerException());
            client.getAssertion("principal2", "action2", assertionId);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.deleteAssertion("principal2", "action2", assertionId, AUDIT_REF, null))
                    .thenThrow(new NullPointerException());
            client.deleteAssertion("principal2", "action2", assertionId, AUDIT_REF, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.deleteAssertionPolicyVersion("principal2", "action2", "new-version",
                            assertionId, AUDIT_REF, null)).thenThrow(new NullPointerException());
            client.deleteAssertion("principal2", "action2", "new-version", assertionId, AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetTemplate() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getTemplate("template")).thenThrow(new NullPointerException());
            client.getTemplate("template");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getTemplate("template2")).thenThrow(new ResourceException(400));
            client.getTemplate("template2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetProviderResourceGroupRoles() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup")).thenThrow(new NullPointerException());
            client.getProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2")).thenThrow(new ResourceException(400));
            client.getProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testDeleteProviderResourceGroupRoles() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.deleteProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteProviderResourceGroupRoles("tenantDomain", "providerDomain", "providerServiceName",
                    "resourceGroup", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.deleteProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF)).thenThrow(new ResourceException(400));
            client.deleteProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutProviderResourceGroupRoles() throws URISyntaxException, IOException {
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF, provRoles)).thenThrow(new ResourceException(400));
            client.putProviderResourceGroupRoles("tenantDomain2", "providerDomain2", "providerServiceName2",
                    "resourceGroup2", AUDIT_REF, provRoles);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPostUserDomain() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        client.setDnsResolver(null);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        UserDomain ud = new UserDomain().setDescription("domain desc").setOrg("org:test").setEnabled(true)
                .setAuditEnabled(false).setAccount("user.test").setYpmId(10).setName("testuser")
                .setTemplates(new DomainTemplateList().setTemplateNames(Collections.singletonList("template")));
        try {
            Mockito.when(c.postUserDomain("domain1", AUDIT_REF, null, ud)).thenThrow(new NullPointerException());
            client.postUserDomain("domain1", AUDIT_REF, null, ud);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.postUserDomain("domain2", AUDIT_REF, null, ud)).thenThrow(new ResourceException(400));
            client.postUserDomain("domain2", AUDIT_REF, ud);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testUserTokenWithAuthority() {
        ZMSClient client = createClient(systemAdminUser);
        assertNotNull(client);
    }

    @Test
    public void testCreateTopLevelDomainUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1 = createTopLevelDomainObject("AddTopDom1",
                "Test Domain1", "testOrg", systemAdminFullUser);
        Domain domainMock = Mockito.mock(Domain.class);
        dom1.setAuditEnabled(true);
        Mockito.when(c.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock);
        Mockito.when(c.getDomain("AddTopDom1")).thenReturn(domainMock);
        Mockito.when(c.getDomain("AddTopDom3")).thenThrow(new NullPointerException()).thenThrow(new ResourceException(204));
        testCreateTopLevelDomain(client, systemAdminFullUser);
    }

    @Test
    public void testCreateTopLevelDomainOnceOnlyUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1 = createTopLevelDomainObject("AddTopDom1",
                "Test Domain1", "testOrg", systemAdminFullUser);
        Domain domainMock = Mockito.mock(Domain.class);
        dom1.setAuditEnabled(true);
        Mockito.when(c.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock).thenThrow(new ResourceException(204));
        testCreateTopLevelDomainOnceOnly(client, systemAdminFullUser);
    }

    @Test
    public void testCreateSubDomainUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        SubDomain dom2 = createSubDomainObject("AddSubDom2", "AddSubDom1",
                "Test Domain2", "testOrg", systemAdminFullUser);
        Mockito.when(c.postSubDomain("AddSubDom1", AUDIT_REF, null, dom2)).thenReturn(domainMock);
        Mockito.when(c.getDomain("AddSubDom1.AddSubDom2")).thenReturn(domainMock);
        Mockito.when(c.postSubDomain("AddSubDom3", AUDIT_REF, null, dom2)).thenThrow(new NullPointerException());
        testCreateSubDomain(client, systemAdminFullUser);
    }

    @Test
    public void testCreateSubdomainOnceOnlyUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        SubDomain dom2 = createSubDomainObject("AddOnceSubDom2", "AddOnceSubDom1",
                "Test Domain2", "testOrg", systemAdminFullUser);
        Mockito.when(c.postSubDomain("AddOnceSubDom1", AUDIT_REF, null, dom2)).thenReturn(domainMock)
                .thenThrow(new ResourceException(204));
        testCreateSubdomainOnceOnly(client, systemAdminFullUser);
    }

    @Test
    public void testCreateRoleUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        Role role1Mock = Mockito.mock(Role.class);
        Role role1 = createRoleObject(client, "CreateRoleDom1", "Role1", null, "user.joe", "user.jane");
        Mockito.when(c.putRole("CreateRoleDom1", "Role1", AUDIT_REF, true, null, role1)).thenReturn(role1);
        Mockito.when(c.getRole("CreateRoleDom1", "Role1", false, false, false)).thenReturn(role1Mock);
        Mockito.when(role1Mock.getName()).thenReturn("CreateRoleDom1:role.Role1".toLowerCase());
        Mockito.when(role1Mock.getTrust()).thenReturn(null);
        Mockito.when(c.putRole("CreateRoleDom1", "Role2", AUDIT_REF, false, null, role1)).thenThrow(new NullPointerException());
        Mockito.when(c.putRole("CreateRoleDom1", "Role3", AUDIT_REF, false, null, role1)).thenThrow(new ResourceException(400));
        Mockito.when(c.getRole("CreateRoleDom1", "Role2", false, false, false)).thenThrow(new NullPointerException());
        Mockito.when(c.getRole("CreateRoleDom1", "Role3", false, false, false)).thenThrow(new ResourceException(400));
        testCreateRole(client, systemAdminFullUser);
    }

    @Test
    public void testGetRoleList() throws URISyntaxException, IOException {
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }
        try {
            Mockito.when(c.getRoleList("RoleListParamDom2", null, "Role2")).thenThrow(new NullPointerException());
            client.getRoleList("RoleListParamDom2", null, "Role2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getRoleList("RoleListParamDom1", null, null)).thenThrow(new ResourceException(204));
            client.getRoleList("RoleListParamDom1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }
        try {
            Mockito.when(c.getRoleList("RoleListParamDom2", null, null)).thenThrow(new NullPointerException());
            client.getRoleList("RoleListParamDom2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testDeleteRole() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Role roleMock = Mockito.mock(Role.class);
        Mockito.when(c.deleteRole("DelRoleDom1", "Role1", AUDIT_REF, null)).thenReturn(roleMock);
        client.deleteRole("DelRoleDom1", "Role1", AUDIT_REF);
        try {
            Mockito.when(c.deleteRole("DelRoleDom1", "Role2", AUDIT_REF, null)).thenThrow(new ResourceException(204));
            client.deleteRole("DelRoleDom1", "Role2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }
        try {
            Mockito.when(c.deleteRole("DelRoleDom2", "Role2", AUDIT_REF, null)).thenThrow(new NullPointerException());
            client.deleteRole("DelRoleDom2", "Role2", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetMembership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Membership member1Mock = Mockito.mock(Membership.class);
        Mockito.when(c.getMembership("MbrGetRoleDom1", "Role1", "user.joe", null)).thenReturn(member1Mock);
        client.getMembership("MbrGetRoleDom1", "Role1", "user.doe");
        try {
            Mockito.when(c.getMembership("MbrGetRoleDom1", "Role2", "user.joe", null)).thenThrow(new ResourceException(204));
            client.getMembership("MbrGetRoleDom1", "Role2", "user.joe");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            Mockito.when(c.getMembership("MbrGetRoleDom1", "Role3", "user.joe", null)).thenThrow(new NullPointerException());
            client.getMembership("MbrGetRoleDom1", "Role3", "user.joe");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetOverdueReview() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainRoleMembers domainMembersMock1 = Mockito.mock(DomainRoleMembers.class);
        Mockito.when(c.getOverdueReview("testDomain1")).thenReturn(domainMembersMock1);

        // Make sure exception isn't thrown
        client.getOverdueReview("testDomain1");

        // Now make sure a resource exception is thrown
        try {
            Mockito.when(c.getOverdueReview("testDomain2")).thenThrow(new ResourceException(204));
            client.getOverdueReview("testDomain2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        // Now make sure a resource exception is thrown on NullPointerException
        try {
            Mockito.when(c.getOverdueReview("testDomain3")).thenThrow(new NullPointerException());
            client.getOverdueReview("testDomain3");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetPolicyList() throws URISyntaxException, IOException {
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }
        try {
            Mockito.when(c.getPolicyList("PolicyListDom3", null, null)).thenThrow(new ResourceException(204));
            client.getPolicyList("PolicyListDom3");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            Mockito.when(c.getPolicyList("PolicyListDom4", null, null)).thenThrow(new NullPointerException());
            client.getPolicyList("PolicyListDom4");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getPolicyList("PolicyListDom5", null, null)).thenThrow(new NullPointerException());
            client.getPolicyList("PolicyListDom5", null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetPolicyVersionList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        PolicyList policyListMock = Mockito.mock(PolicyList.class);
        Mockito.when(c.getPolicyVersionList("PolicyListDom1", "policyName1")).thenReturn(policyListMock);
        client.getPolicyVersionList("PolicyListDom1", "policyName1");
        try {
            Mockito.when(c.getPolicyVersionList("PolicyListDom2", "policyName1")).thenThrow(new ResourceException(204));
            client.getPolicyVersionList("PolicyListDom2", "policyName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }
        try {
            Mockito.when(c.getPolicyVersionList("PolicyListDom3", "policyName1")).thenThrow(new ResourceException(204));
            client.getPolicyVersionList("PolicyListDom3", "policyName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            Mockito.when(c.getPolicyVersionList("PolicyListDom4", "policyName1")).thenThrow(new NullPointerException());
            client.getPolicyVersionList("PolicyListDom4", "policyName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getPolicyVersionList("PolicyListDom5", "policyName1")).thenThrow(new NullPointerException());
            client.getPolicyVersionList("PolicyListDom5", "policyName1");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutServiceIdentity() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);

        ServiceIdentity serviceIdentity1 = new ServiceIdentity().setName("domain1.service.test");

        Mockito.when(c.putServiceIdentity("domain1", "service1", AUDIT_REF, true, null, serviceMock))
                .thenReturn(serviceIdentity1);
        ServiceIdentity returnedService = client.putServiceIdentity("domain1", "service1", AUDIT_REF, true, serviceMock);
        assertEquals(returnedService.getName(), "domain1.service.test");

        try {
            Mockito.when(c.putServiceIdentity("domain1", "service1", AUDIT_REF, false, null, serviceMock))
                    .thenThrow(new ResourceException(403));
            client.putServiceIdentity("domain1", "service1", AUDIT_REF, serviceMock);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        try {
            Mockito.when(c.putServiceIdentity("domain2", "service1", AUDIT_REF, false, null, serviceMock))
                    .thenThrow(new NullPointerException());
            client.putServiceIdentity("domain2", "service1", AUDIT_REF, serviceMock);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetServiceIdentityTags() {

        final String domainName = "get-service-identity-tags";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        try {
            Mockito.when(c.getServiceIdentities(domainName, false, false, "key", "value"))
                    .thenThrow(new ResourceException(401));
            client.getServiceIdentities(domainName, false, false, "key", "value");
            fail();
        } catch (URISyntaxException | IOException | ZMSClientException ex) {
            assertEquals(((ZMSClientException)ex).getCode(), 401);
        }
        try {
            Mockito.when(c.getServiceIdentities(domainName, false, true, "key", "value"))
                    .thenThrow(new IOException());
            client.getServiceIdentities(domainName, false, true, "key", "value");
            fail();
        } catch (IOException | URISyntaxException | ZMSClientException e){
            assertEquals(((ZMSClientException)e).getCode(), 400);
        }
    }

    @Test
    public void testPutServiceIdentityReturnObj() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);

        try {
            Mockito.when(c.putServiceIdentity("domain1", "service1", AUDIT_REF, false, null, serviceMock))
                    .thenThrow(new ResourceException(403));
            client.putServiceIdentity("domain1", "service1", AUDIT_REF, serviceMock);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        try {
            Mockito.when(c.putServiceIdentity("domain2", "service1", AUDIT_REF, false, null, serviceMock))
                    .thenThrow(new NullPointerException());
            client.putServiceIdentity("domain2", "service1", AUDIT_REF, serviceMock);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeleteServiceIdentity() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);
        Mockito.when(c.deleteServiceIdentity("ServiceDelDom1", "Service1", AUDIT_REF, null)).thenReturn(serviceMock);
        client.deleteServiceIdentity("ServiceDelDom1", "Service1", AUDIT_REF);
        try {
            Mockito.when(c.deleteServiceIdentity("ServiceDelDom1", "Service2", AUDIT_REF, null))
                    .thenThrow(new ResourceException(204));
            client.deleteServiceIdentity("ServiceDelDom1", "Service2", AUDIT_REF);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 204);
        }
        try {
            Mockito.when(c.deleteServiceIdentity("ServiceDelDom2", "Service2", AUDIT_REF, null))
                    .thenThrow(new NullPointerException());
            client.deleteServiceIdentity("ServiceDelDom2", "Service2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetServiceIdentities() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        ServiceIdentity service1 = createServiceObject(client,"dom1", "service1", "http://localhost",
                "/usr/bin/java", "someuser", "somegroup", "host");
        List<ServiceIdentity> serviceIdentitiesList = new LinkedList<>();
        serviceIdentitiesList.add(service1);
        ServiceIdentities serviceIdentities = new ServiceIdentities();
        serviceIdentities.setList(serviceIdentitiesList);

        Mockito.when(c.getServiceIdentities("dom1", false, true, null, null)).thenReturn(serviceIdentities);


        try {
            Mockito.when(c.getServiceIdentities("domain1", true, true, null, null)).thenThrow(new ResourceException(403));
            client.getServiceIdentities("domain1", true, true, null, null);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            Mockito.when(c.getServiceIdentities("domain2", true, true, null, null)).thenThrow(new NullPointerException());
            client.getServiceIdentities("domain2", true, true, null, null);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        // test that getServiceIdentities returns the description for services for athenz-ui
        ServiceIdentities serviceIdentities1 = client.getServiceIdentities("dom1", false, true, null, null);
        assertEquals(serviceIdentities1.getList().get(0).getDescription(), "test");
    }

    @Test
    public void testGetServiceIdentityList() throws URISyntaxException, IOException {
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
            assertEquals(ex.getCode(), 204);
        }

        Mockito.when(c.getServiceIdentityList("ServiceListParamsDom3", null, null)).thenReturn(serviceListMock);
        client.getServiceIdentityList("ServiceListParamsDom3");

        try {
            Mockito.when(c.getServiceIdentityList("ServiceListParamsDom4", null, null)).thenThrow(new ResourceException(204));
            client.getServiceIdentityList("ServiceListParamsDom4");
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 204);
        }

        try {
            Mockito.when(c.getServiceIdentityList("ServiceListParamsDom5", null, null)).thenThrow(new NullPointerException());
            client.getServiceIdentityList("ServiceListParamsDom5");
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPutPublicKeyEntry() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        PublicKeyEntry keyEntry = new PublicKeyEntry();
        PublicKeyEntry keyEntryMock = Mockito.mock(PublicKeyEntry.class);
        Mockito.when(c.putPublicKeyEntry("PutPublicKeyDom2", "Service1", "zone2", AUDIT_REF, null, keyEntry))
                .thenReturn(keyEntryMock);
        client.putPublicKeyEntry("PutPublicKeyDom2", "Service1", "zone2", AUDIT_REF, keyEntry);

        try {
            Mockito.when(c.putPublicKeyEntry("PutPublicKeyDom3", "Service2", "zone2", AUDIT_REF, null, keyEntry))
                    .thenThrow(new ResourceException(204));
            client.putPublicKeyEntry("PutPublicKeyDom3", "Service2", "zone2", AUDIT_REF, null, keyEntry);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NO_CONTENT);
        }

        try {
            Mockito.when(client.client.putPublicKeyEntry("domain1", "Service1", "0", AUDIT_REF, null, keyEntry))
                    .thenThrow(new NullPointerException());
            client.putPublicKeyEntry("domain1", "Service1", "0", AUDIT_REF, keyEntry);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeleteTenancy() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Tenancy tenancyMock = Mockito.mock(Tenancy.class);
        Mockito.when(c.deleteTenancy("tenantDom1", "providerService1", AUDIT_REF)).thenReturn(tenancyMock)
                .thenThrow(new ZMSClientException(400,"Audit reference required"));
        client.deleteTenancy("tenantDom1", "providerService1", AUDIT_REF);
        try {
            client.deleteTenancy("tenantDom1", "providerService1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.deleteTenancy("tenantDom2", "providerService1", AUDIT_REF))
                    .thenThrow(new NullPointerException());
            client.deleteTenancy("tenantDom2", "providerService1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testGetSignedDomains() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Map<String, List<String>> respHdrs = new HashMap<>();
        SignedDomains signedDomain1 = Mockito.mock(SignedDomains.class);
        Mockito.when(c.getSignedDomains("dom1", "meta1", null, true, false,"tag1", respHdrs))
                .thenReturn(signedDomain1)
                .thenReturn(signedDomain1)
                .thenReturn(signedDomain1)
                .thenThrow(new ZMSClientException(401, "Audit reference required"))
                .thenThrow(new NullPointerException());

        client.getSignedDomains("dom1", "meta1", "tag1", respHdrs);
        client.getSignedDomains("dom1", "meta1", null, "tag1", respHdrs);
        client.getSignedDomains("dom1", "meta1", null, true, "tag1", respHdrs);

        try {
            client.getSignedDomains("dom1", "meta1", "tag1", respHdrs);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 401);
        }
        try {
            client.getSignedDomains("dom1", "meta1", null, true, "tag1", respHdrs);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetDomainMetaStoreValidValuesList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainMetaStoreValidValuesList list = new DomainMetaStoreValidValuesList();
        Mockito.when(c.getDomainMetaStoreValidValuesList(null, null))
                .thenReturn(list)
                .thenThrow(new ResourceException(401))
                .thenThrow(new NullPointerException());

        DomainMetaStoreValidValuesList retList = client.getDomainMetaStoreValidValuesList(null, null);
        assertNotNull(retList);

        try {
            client.getDomainMetaStoreValidValuesList(null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getDomainMetaStoreValidValuesList(null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetAuthHistoryDependencies() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.getAuthHistoryDependencies(null))
                .thenThrow(new ResourceException(401))
                .thenThrow(new NullPointerException());

        try {
            client.getAuthHistoryDependencies(null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getAuthHistoryDependencies(null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        AuthHistoryDependencies dependencies = new AuthHistoryDependencies();
        Mockito.when(c.getAuthHistoryDependencies("good.domain")).thenReturn(dependencies);
        assertEquals(client.getAuthHistoryDependencies("good.domain"), dependencies);
    }

    @Test
    public void testGetDomainListException() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(
                    c.getDomainList(0, null, null, null, null, null, null, null, null, null, null, null, null, null, null))
                    .thenThrow(new RuntimeException());
            client.getDomainList(0, null, null, null, null, null, null, null, null, null, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getClass().toString(), "class com.yahoo.athenz.zms.ZMSClientException");
        }

        try {
            Mockito.when(
                    c.getDomainList(1, null, null, null, null, null, null, null, null, null, null, null, null, null, null))
                    .thenThrow(new InvalidParameterException("Bad parameter"));
            client.getDomainList(1, null, null, null, null, null, null, null, null, null, null);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), "ResourceException (400): Bad parameter");
        }

        try {
            Mockito.when(
                    c.getDomainList(2, null, null, null, null, null, null, null, null, null, null, null, null, null, null))
                    .thenThrow(new ResourceException(400));
            client.getDomainList(2, null, null, null, null, null, null, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPutDefaultAdmins() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DefaultAdmins adminsMock = Mockito.mock(DefaultAdmins.class);
        Mockito.when(c.putDefaultAdmins("sports", AUDIT_REF, adminsMock)).thenReturn(adminsMock);
        client.putDefaultAdmins("sports", AUDIT_REF, adminsMock);
        try {
            Mockito.when(c.putDefaultAdmins("media", AUDIT_REF, adminsMock))
                    .thenThrow(new ZMSClientException(403, "Forbidden"));
            client.putDefaultAdmins("media", AUDIT_REF, adminsMock);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }
        try {
            Mockito.when(c.putDefaultAdmins("weather", AUDIT_REF, adminsMock))
                    .thenThrow(new NullPointerException());
            client.putDefaultAdmins("weather", AUDIT_REF, adminsMock);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetDomainDataCheck() throws URISyntaxException, IOException {
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
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.getDomainDataCheck("domain2")).thenThrow(new NullPointerException());
            client.getDomainDataCheck("domain2");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutTenancy() throws URISyntaxException, IOException {
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
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            Mockito.when(c.putTenancy("tenantDom2", "providerService1", AUDIT_REF, tenant))
                    .thenThrow(new NullPointerException());
            client.putTenancy("tenantDom2", "providerService1", AUDIT_REF, tenant);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testAddMembershipUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        Role role1Mock = Mockito.mock(Role.class);
        Role roleMock = Mockito.mock(Role.class);
        when(roleMock.getName()).thenReturn("Role1");
        Mockito.when(c.putRole("MbrAddDom1", "Role1", AUDIT_REF, false, null, role1Mock)).thenReturn(roleMock);
        Membership mbr = new Membership();
        mbr.setRoleName("Role1");
        mbr.setMemberName("user.member3");
        mbr.setIsMember(true);
        Membership mbrExp = new Membership();
        mbrExp.setRoleName("Role1");
        mbrExp.setMemberName("user.member3");
        mbrExp.setExpiration(Timestamp.fromMillis(100000));
        mbrExp.setIsMember(true);
        Membership membershipMock = Mockito.mock(Membership.class);
        Mockito.when(c.putMembership("MbrAddDom1", "Role1", "user.member3", AUDIT_REF, true, null, mbr)).thenReturn(mbr);
        Mockito.when(c.putMembership("MbrAddDom1", "Role1", "user.member4", AUDIT_REF, false, null, mbrExp))
                .thenReturn(membershipMock);
        Mockito.when(c.getRole("MbrAddDom1", "Role1", false, false, false)).thenReturn(roleMock);
        List<RoleMember> roleMembers = new ArrayList<>();
        roleMembers.add(new RoleMember().setMemberName("user.member1"));
        roleMembers.add(new RoleMember().setMemberName("user.member2"));
        roleMembers.add(new RoleMember().setMemberName("user.member3"));
        roleMembers.add(new RoleMember().setMemberName("user.member4")
                .setExpiration(Timestamp.fromMillis(100000)));
        roleMembers.add(new RoleMember().setMemberName("user.member5")
                .setExpiration(Timestamp.fromMillis(100000)).setReviewReminder(Timestamp.fromMillis(500000)));
        roleMembers.add(new RoleMember().setMemberName("user.member6")
                .setReviewReminder(Timestamp.fromMillis(500000)));
        Mockito.when(roleMock.getRoleMembers()).thenReturn(roleMembers);
        testAddMembership(client, systemAdminFullUser);
        Mockito.when(c.deleteTopLevelDomain("MbrGetRoleDom1", AUDIT_REF, null)).thenReturn(dom1Mock);
    }

    @Test
    public void testDeleteMembershipUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        Role role1Mock = Mockito.mock(Role.class);
        Mockito.when(c.putRole("MbrDelDom1", "Role1", AUDIT_REF, false, null, role1Mock)).thenReturn(role1Mock);
        Mockito.when(c.getRole("MbrDelDom1", "Role1", false, false, false)).thenReturn(role1Mock);
        @SuppressWarnings("unchecked")
        List<String> membersMock = Mockito.mock(List.class);
        Mockito.when(role1Mock.getMembers()).thenReturn(membersMock);
        Mockito.when(membersMock.size()).thenReturn(1);
        Mockito.when(membersMock.contains("user.joe")).thenReturn(false);
        Mockito.when(membersMock.contains("user.jane")).thenReturn(true);
        testDeleteMembership(client, systemAdminFullUser);
    }

    @Test
    public void testDeleteUser() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        User userMock = Mockito.mock(User.class);
        Mockito.when(c.deleteUser("joe", AUDIT_REF)).thenReturn(userMock);
        Mockito.when(c.deleteUser("doe", AUDIT_REF)).thenThrow(new ResourceException(404));
        Mockito.when(c.deleteUser("jane", AUDIT_REF)).thenThrow(new NullPointerException());

        try {
            client.deleteUser("joe", AUDIT_REF);
        } catch (ZMSClientException ex) {
            fail();
        }

        try {
            client.deleteUser("doe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }

        try {
            client.deleteUser("jane", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetUserList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        UserList userListMock = Mockito
                .mock(UserList.class);
        Mockito.when(c.getUserList(null))
                .thenReturn(userListMock)
                .thenThrow(new ResourceException(401))
                .thenThrow(new NullPointerException());

        try {
            UserList userList = client.getUserList();
            assertNotNull(userList);
        } catch (ZMSClientException ex) {
            fail();
        }

        try {
            client.getUserList();
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getUserList();
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetUserListWithDomain() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        UserList userListMock = Mockito
                .mock(UserList.class);
        Mockito.when(c.getUserList("unix"))
                .thenReturn(userListMock)
                .thenThrow(new ResourceException(401))
                .thenThrow(new NullPointerException());

        try {
            UserList userList = client.getUserList("unix");
            assertNotNull(userList);
        } catch (ZMSClientException ex) {
            fail();
        }

        try {
            client.getUserList("unix");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getUserList("unix");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        UserToken token = new UserToken().setToken("token").setHeader("header");
        Mockito.when(c.getUserToken("user.johndoe", "service1", true))
                .thenReturn(token)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        UserToken tokenCheck = client.getUserToken("user.johndoe", "service1", true);
        assertNotNull(tokenCheck);
        assertEquals(tokenCheck.getToken(), "token");

        try {
            client.getUserToken("user.johndoe", "service1", true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getUserToken("user.johndoe", "service1", true);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testCreatePolicyUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        Policy policy1Mock = Mockito.mock(Policy.class);
        Policy policy1 = new Policy();
        Policy policy2 = createPolicyObject(client, "PolicyAddDom1", "Policy1");
        Mockito.when(c.putPolicy("PolicyAddDom1", "Policy1", AUDIT_REF, true, null, policy2)).thenReturn(policy2);
        Mockito.when(c.getPolicy("PolicyAddDom1", "Policy1")).thenReturn(policy1Mock);
        Mockito.when(c.putPolicy("PolicyAddDom2", "Policy1", AUDIT_REF, false, null, policy1))
                .thenThrow(new ResourceException(403));
        Mockito.when(c.getPolicy("PolicyAddDom2", "Policy1")).thenThrow(new ResourceException(403));
        Mockito.when(c.putPolicy("PolicyAddDom3", "Policy1", AUDIT_REF, false, null, policy1))
                .thenThrow(new NullPointerException());
        Mockito.when(c.getPolicy("PolicyAddDom3", "Policy1")).thenThrow(new NullPointerException());
        Mockito.when(policy1Mock.getName()).thenReturn("PolicyAddDom1:policy.Policy1".toLowerCase());
        testCreatePolicy(client, systemAdminFullUser);

        PolicyOptions policyOptions = new PolicyOptions();
        policyOptions.setVersion("new-version");
        Mockito.when(c.getPolicyVersion("PolicyAddDom1", "Policy1", "0")).thenReturn(policy1Mock);
        Mockito.when(c.putPolicyVersion(eq("PolicyAddDom2"), eq("Policy1"), eq(policyOptions),
                        eq(AUDIT_REF), eq(false), eq(null))).thenThrow(new ResourceException(403));
        Mockito.when(c.getPolicyVersion("PolicyAddDom2", "Policy1", "0")).thenThrow(new ResourceException(403));
        Mockito.when(c.putPolicyVersion(eq("PolicyAddDom3"), eq("Policy1"), eq(policyOptions),
                        eq(AUDIT_REF), eq(false), eq(null))).thenThrow(new NullPointerException());
        Mockito.when(c.getPolicyVersion("PolicyAddDom3", "Policy1", "0")).thenThrow(new NullPointerException());

        PolicyOptions policyOptionsFrom = new PolicyOptions();
        policyOptionsFrom.setVersion("new-version");
        policyOptionsFrom.setFromVersion("from-version");
        Mockito.when(c.putPolicyVersion(eq("PolicyAddDom2"), eq("Policy1"), eq(policyOptionsFrom),
                        eq(AUDIT_REF), eq(false), eq(null))).thenThrow(new ResourceException(403));
        Mockito.when(c.putPolicyVersion(eq("PolicyAddDom3"), eq("Policy1"), eq(policyOptionsFrom),
                        eq(AUDIT_REF), eq(false), eq(null))).thenThrow(new NullPointerException());
        testCreatePolicyVersion(client, systemAdminFullUser);

        Mockito.when(c.setActivePolicyVersion(eq("PolicyAddDom2"), eq("Policy1"), eq(policyOptions),
                        eq(AUDIT_REF), eq(null))).thenThrow(new ResourceException(403));
        PolicyOptions policyOptions2 = new PolicyOptions();
        policyOptions2.setVersion("new-version2");
        Mockito.when(c.setActivePolicyVersion(eq("PolicyAddDom2"), eq("Policy1"), eq(policyOptions2),
                        eq(AUDIT_REF), eq(null))).thenThrow(new NullPointerException());
        testSetActivePolicyVersion(client, systemAdminFullUser);
    }

    @Test
    public void testDeletePolicyUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        Policy policy1Mock = Mockito.mock(Policy.class);
        Mockito.when(c.putPolicy("PolicyDelDom1", "Policy1", AUDIT_REF, false, null, policy1Mock))
                .thenReturn(policy1Mock);
        Mockito.when(c.putPolicy("PolicyDelDom1", "Policy2", AUDIT_REF, false, null, policy1Mock))
                .thenReturn(policy1Mock);
        Mockito.when(c.getPolicy("PolicyDelDom1", "Policy1")).thenReturn(policy1Mock)
                .thenThrow(new ResourceException(204));
        Mockito.when(c.getPolicy("PolicyDelDom1", "Policy2")).thenReturn(policy1Mock,policy1Mock)
                .thenThrow(new ResourceException(204));
        Mockito.when(c.deletePolicy("PolicyDelDom2", "Policy1", AUDIT_REF, null))
                .thenThrow(new ResourceException(403));
        Mockito.when(c.deletePolicy("PolicyDelDom3", "Policy1", AUDIT_REF, null))
                .thenThrow(new NullPointerException());
        testDeletePolicy(client, systemAdminFullUser);

        Mockito.when(c.getPolicyVersion("PolicyDelDom1", "Policy1", "0")).thenReturn(policy1Mock)
                .thenThrow(new ResourceException(204));
        Mockito.when(c.getPolicyVersion("PolicyDelDom1", "Policy2", "0")).thenReturn(policy1Mock,policy1Mock)
                .thenThrow(new ResourceException(204));
        Mockito.when(c.deletePolicyVersion("PolicyDelDom2", "Policy1", "0", AUDIT_REF, null))
                .thenThrow(new ResourceException(403));
        Mockito.when(c.deletePolicyVersion("PolicyDelDom3", "Policy1", "0", AUDIT_REF, null))
                .thenThrow(new NullPointerException());
        testDeletePolicyVersion(client, systemAdminFullUser);
    }

    @Test
    public void testDeletePublicKeyEntryUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);
        Mockito.when(c.putServiceIdentity("DelPublicKeyDom1", "Service1", AUDIT_REF, false, null, serviceMock))
                .thenReturn(serviceMock);
        PublicKeyEntry entoryMock = Mockito.mock(PublicKeyEntry.class);
        Mockito.when(c.deletePublicKeyEntry("DelPublicKeyDom1", "Service1", "zone1", AUDIT_REF, null))
                .thenReturn(entoryMock);
        Mockito.when(c.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone1")).thenThrow(new ResourceException(404));
        Mockito.when(c.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone2")).thenReturn(entoryMock);
        Mockito.when(c.getPublicKeyEntry("DelPublicKeyDom1", "Service1", "zone3")).thenThrow(new NullPointerException());
        Mockito.when(entoryMock.getKey()).thenReturn(PUB_KEY_ZONE2);
        Mockito.when(c.deletePublicKeyEntry("DelPublicKeyDom1", "Service1", "zone2", AUDIT_REF, null))
                .thenThrow(new ResourceException(400));
        testDeletePublicKeyEntry(client, systemAdminFullUser);
    }

    @Test
    public void testCreateServiceIdentityUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        ServiceIdentity serviceMock = Mockito.mock(ServiceIdentity.class);
        ServiceIdentity service = createServiceObject(client, "ServiceAddDom1", "Service1",
                "http://localhost", "/usr/bin/java", "root", "users", "host1");
        Mockito.when(c.putServiceIdentity("ServiceAddDom1", "Service1", AUDIT_REF, true, null, service))
                .thenReturn(service);
        Mockito.when(c.getServiceIdentity("ServiceAddDom1", "Service1")).thenReturn(serviceMock);
        Mockito.when(c.getServiceIdentity("ServiceAddDom2", "Service1")).thenThrow(new NullPointerException());
        Mockito.when(c.getServiceIdentity("ServiceAddDom3", "Service1")).thenThrow(new ResourceException(403));
        Mockito.when(serviceMock.getName()).thenReturn("ServiceAddDom1.Service1".toLowerCase());
        testCreateServiceIdentity(client, systemAdminFullUser);
    }

    @Test
    public void testCreateEntityUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
        Entity entityMock = Mockito.mock(Entity.class);
        Mockito.when(c.putEntity("CreateEntityDom1", "Entity1", AUDIT_REF, entityMock)).thenReturn(entityMock);
        Mockito.when(c.getEntity("CreateEntityDom1", "Entity1")).thenReturn(entityMock);
        Mockito.when(entityMock.getName()).thenReturn("Entity1".toLowerCase());
        testCreateEntity(client, systemAdminFullUser);
    }

    @Test
    public void testDeleteEntityUserToken() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);
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
            assertEquals(401, ex.getCode());
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
            assertEquals(401, ex.getCode());
        }

        try {
            client.getPrincipal("v=U1;d=coretech;t=12345678;s=signature");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        try {
            client.getPrincipal("v=U1;n=storage;t=12345678;s=signature");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }
        client.close();
    }

    @Test
    public void testLookupZMSUrl() {

        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZMSClient client = new ZMSClient(getZMSUrl());
        assertEquals(client.lookupZMSUrl(), "https://server-zms.athenzcompany.com:4443/");
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF);
        client.close();

        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        client = new ZMSClient();
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
    public void testDeleteDomainTemplate() throws URISyntaxException, IOException {
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
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1)).thenReturn(domainMock);
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getDomainTemplateList(domName2);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NOT_FOUND);
        }
        List<String> templNames = domTemplList.getTemplateNames();
        assertNotNull(templNames);
        assertEquals(templNames.size(), svrTemplNames.size());
        // HAVE: domain has all the templates

        // domain has multiple templates: deleting 1 at a time
        for (int cnt = 0; cnt < svrTemplNames.size(); ++cnt) {
            client.deleteDomainTemplate(domName, svrTemplNames.get(cnt), AUDIT_REF);
            domTemplList = client.getDomainTemplateList(domName);
            assertNotNull(domTemplList);
            templNames = domTemplList.getTemplateNames();
            assertNotNull(templNames);
            int templCnt = svrTemplNames.size() - (cnt + 1);
            assertEquals(templNames.size(), templCnt, "template should be count=" + templCnt);
            for (int cnt2 = cnt + 1; cnt2 < svrTemplNames.size(); ++cnt2) {
                assertTrue(templNames.contains(svrTemplNames.get(cnt2)), "should contain=" + svrTemplNames.get(cnt2));
            }
        }

        client.deleteTopLevelDomain(domName, AUDIT_REF);
    }

    @Test
    public void testDeleteDomainTemplateErrorCases() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServerTemplateList svrTemplListMock = Mockito.mock(ServerTemplateList.class);
        Mockito.when(c.getServerTemplateList()).thenReturn(svrTemplListMock).thenThrow(new NullPointerException()).thenThrow(new ResourceException(404,"Domain not found"));
        ServerTemplateList svrTemplList = client.getServerTemplateList();
        try {
            client.getServerTemplateList();
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.getServerTemplateList();
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.NOT_FOUND);
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
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
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

    @Test
    public void testGetStats() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Stats stats = new Stats().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18);
        Mockito.when(c.getStats("athenz")).thenReturn(stats)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        Stats statsRes = client.getStats("athenz");
        assertNotNull(statsRes);
        assertEquals(statsRes.getPolicy(), 12);
        assertEquals(statsRes.getRole(), 14);

        // second time it fails

        try {
            client.getStats("athenz");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.getStats("athenz");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testGetInfo() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Info info = new Info().setBuildJdkSpec("17")
                .setImplementationTitle("title")
                .setImplementationVendor("vendor")
                .setImplementationVersion("version");
        Mockito.when(c.getInfo()).thenReturn(info)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        Info infoRes = client.getInfo();
        assertNotNull(infoRes);
        assertEquals(infoRes.getBuildJdkSpec(), "17");
        assertEquals(infoRes.getImplementationVersion(), "version");

        // second time it fails

        try {
            client.getInfo();
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.getInfo();
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testGetQuota() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Quota quota = new Quota().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18);
        Mockito.when(c.getQuota("athenz")).thenReturn(quota)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        Quota quotaRes = client.getQuota("athenz");
        assertNotNull(quotaRes);
        assertEquals(quotaRes.getPolicy(), 12);
        assertEquals(quotaRes.getRole(), 14);

        // second time it fails

        try {
            client.getQuota("athenz");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.getQuota("athenz");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testPutQuota() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Quota quota = new Quota().setName("athenz").setAssertion(10).setEntity(11)
                .setPolicy(12).setPublicKey(13).setRole(14).setRoleMember(15)
                .setService(16).setServiceHost(17).setSubdomain(18);
        Mockito.when(c.putQuota("athenz", AUDIT_REF, quota))
                .thenReturn(null)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));


        // first time it completes successfully

        client.putQuota("athenz", AUDIT_REF, quota);

        // second time it fails

        try {
            client.putQuota("athenz", AUDIT_REF, quota);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.putQuota("athenz", AUDIT_REF, quota);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testDeleteQuota() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteQuota("athenz", AUDIT_REF)).thenReturn(null)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        // first time it completes successfully

        client.deleteQuota("athenz", AUDIT_REF);

        // second time it fails

        try {
            client.deleteQuota("athenz", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // finally std exception

        try {
            client.deleteQuota("athenz", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testDeleteDomainRoleMember() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteDomainRoleMember("athenz", "athenz.api", AUDIT_REF))
                .thenReturn(null)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        // first time it completes successfully

        client.deleteDomainRoleMember("athenz", "athenz.api", AUDIT_REF);

        // second time it fails with zms client exception

        try {
            client.deleteDomainRoleMember("athenz", "athenz.api", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception - resulting in 400

        try {
            client.deleteDomainRoleMember("athenz", "athenz.api", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testGetDomainRoleMembers() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        MemberRole memberRole = new MemberRole();
        memberRole.setRoleName("readers");

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(memberRole);

        DomainRoleMember member = new DomainRoleMember();
        member.setMemberName("athenz.api");
        member.setMemberRoles(memberRoles);

        List<DomainRoleMember> members = new ArrayList<>();
        members.add(member);

        DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
        domainRoleMembers.setMembers(members);

        Mockito.when(c.getDomainRoleMembers("athenz"))
                .thenReturn(domainRoleMembers)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        DomainRoleMembers retMembers = client.getDomainRoleMembers("athenz");
        assertNotNull(retMembers);
        assertEquals(retMembers.getMembers().get(0).getMemberName(), "athenz.api");

        // second time it fails with zms client exception

        try {
            client.getDomainRoleMembers("athenz");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception - resulting in 400

        try {
            client.getDomainRoleMembers("athenz");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testGetPrincipalRoles() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        MemberRole memberRole1 = new MemberRole();
        memberRole1.setRoleName("role1");
        memberRole1.setDomainName("domain1");

        MemberRole memberRole2 = new MemberRole();
        memberRole2.setRoleName("role2");
        memberRole2.setDomainName("domain1");

        MemberRole memberRole3 = new MemberRole();
        memberRole3.setRoleName("role3");
        memberRole3.setDomainName("domain2");

        List<MemberRole> memberRoles = new ArrayList<>();
        memberRoles.add(memberRole1);
        memberRoles.add(memberRole2);
        memberRoles.add(memberRole3);

        DomainRoleMember domainRoleMember = new DomainRoleMember();
        domainRoleMember.setMemberName("currentPrincipalName");
        domainRoleMember.setMemberRoles(memberRoles);
        Mockito.when(c.getPrincipalRoles(null, null, null))
                .thenReturn(domainRoleMember)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));


        DomainRoleMember retMember = client.getPrincipalRoles(null, null);
        assertNotNull(retMember);
        assertEquals(retMember.getMemberName(), "currentPrincipalName");
        assertEquals(retMember.getMemberRoles().get(0).getDomainName(), "domain1");
        assertEquals(retMember.getMemberRoles().get(0).getRoleName(), "role1");

        assertEquals(retMember.getMemberRoles().get(1).getDomainName(), "domain1");
        assertEquals(retMember.getMemberRoles().get(1).getRoleName(), "role2");

        assertEquals(retMember.getMemberRoles().get(2).getDomainName(), "domain2");
        assertEquals(retMember.getMemberRoles().get(2).getRoleName(), "role3");

        // retry the same operation with expand option enabled

        Mockito.when(c.getPrincipalRoles(null, null, Boolean.TRUE))
                .thenReturn(domainRoleMember);

        retMember = client.getPrincipalRoles(null, null, Boolean.TRUE);
        assertNotNull(retMember);

        // second time it fails with zms client exception

        try {
            client.getPrincipalRoles(null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception - resulting in 400

        try {
            client.getPrincipalRoles(null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testPutTenant() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Tenancy tenancyMock = Mockito.mock(Tenancy.class);
        Tenancy tenant = createTenantObject("tenantDom1", "providerDom1" + "." + "providerService1");
        Mockito.when(c.putTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF, tenant))
                .thenReturn(tenancyMock)
                .thenThrow(new ZMSClientException(400, "Audit reference required"))
                .thenThrow(new NullPointerException());
        client.putTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF, tenant);
        try {
            client.putTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF, tenant);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.putTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF, tenant);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testDeleteTenant() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Tenancy tenancyMock = Mockito.mock(Tenancy.class);
        Mockito.when(c.deleteTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF))
                .thenReturn(tenancyMock)
                .thenThrow(new ZMSClientException(400, "Audit reference required"))
                .thenThrow(new NullPointerException());
        client.deleteTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF);
        try {
            client.deleteTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
        try {
            client.deleteTenant("providerDom1", "providerService1", "tenantDom1", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testCreateSSLContext() {

        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");

        ZMSClient client = new ZMSClient();

        // no keystore path returns null

        SSLContext sslContext = client.createSSLContext();
        assertNull(sslContext);

        // set our properties

        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_PATH, "src/test/resources/client.pkcs12");
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_TYPE, "pkcs12");
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_PASSWORD, "changeit");
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_KEY_MANAGER_PASSWORD, "test");

        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_PATH, "src/test/resources/ca.pkcs12");
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_TYPE, "pkcs12");
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_PASSWORD, "changeit");

        sslContext = client.createSSLContext();
        assertNotNull(sslContext);

        // no passwords

        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_TYPE);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_TYPE);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEY_MANAGER_PASSWORD);

        try {
            client.createSSLContext();
            fail();
        } catch (Exception ignored) {
        }

        client.close();

        // reset all properties

        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_PATH);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_TYPE);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_KEY_MANAGER_PASSWORD);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_PATH);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_TYPE);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_TRUSTSTORE_PASSWORD);
        System.clearProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF);
    }

    @Test
    public void testGetAccess() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Access access = new Access().setGranted(true);
        Mockito.when(c.getAccess("update", "service1", "athenz", "user.johndoe"))
                .thenReturn(access)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        Access accessCheck = client.getAccess("update", "service1", "athenz", "user.johndoe");
        assertNotNull(accessCheck);
        assertTrue(accessCheck.getGranted());

        // second time it fails

        try {
            client.getAccess("update", "service1", "athenz", "user.johndoe");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.getAccess("update", "service1", "athenz", "user.johndoe");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testGetAccessExt() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Access access = new Access().setGranted(true);
        Mockito.when(c.getAccessExt("update", "service1", "athenz", "user.johndoe"))
                .thenReturn(access)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        Access accessCheck = client.getAccessExt("update", "service1", "athenz", "user.johndoe");
        assertNotNull(accessCheck);
        assertTrue(accessCheck.getGranted());

        // second time it fails

        try {
            client.getAccessExt("update", "service1", "athenz", "user.johndoe");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.getAccessExt("update", "service1", "athenz", "user.johndoe");
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testGetEntityList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        EntityList entityList = new EntityList();
        Mockito.when(c.getEntityList("athenz"))
                .thenReturn(entityList)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        EntityList listCheck = client.getEntityList("athenz");
        assertNotNull(listCheck);

        try {
            client.getEntityList("athenz");
            fail();
        } catch  (ZMSClientException ex) {
            assertEquals(401, ex.getCode());
        }
        try {
            client.getEntityList("athenz");
            fail();
        } catch  (ZMSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testUpdatePrincipal() throws URISyntaxException, IOException {
        String zmsUrl = getZMSUrl();
        ZMSClient client = new ZMSClient(zmsUrl);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        Domain domain = new Domain().setName("domain");
        Mockito.when(c.getDomain("domain")).thenReturn(domain);
        UserToken userToken = new UserToken().setHeader("Header").setToken("Token");
        Mockito.when(c.getUserToken("joe", null, true)).thenReturn(userToken);
        client.setZMSRDLGeneratedClient(c);
        assertNotNull(client);

        // add credentials

        Authority authority = new com.yahoo.athenz.auth.impl.UserAuthority();
        Principal p = SimplePrincipal.create("user", "joe", "v=U1;d=user;n=joe;s=signature",
                0, authority);

        client.addCredentials(p);
        assertNotNull(client.getDomain("domain"));
        assertNotNull(client.getDomain("domain"));
    }

    @Test
    public void testGetPrincipal() throws URISyntaxException, IOException {
        String zmsUrl = getZMSUrl();
        ZMSClient client = new ZMSClient(zmsUrl);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        try {
            client.getPrincipal("serviceToken", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getPrincipal("v=S1;d=domain;s=signature", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }

        ServicePrincipal svcPrincipal = new ServicePrincipal().setDomain("domain").setService("service");

        Mockito.when(c.getServicePrincipal())
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException())
                .thenReturn(null)
                .thenReturn(svcPrincipal);

        //                .thenThrow(new ResourceException(403))
        try {
            client.getPrincipal("v=S1;d=domain;n=service;s=signature", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        //                .thenThrow(new NullPointerException())
        try {
            client.getPrincipal("v=S1;d=domain;n=service;s=signature", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        //                .thenReturn(null)
        try {
            client.getPrincipal("v=S1;d=domain;n=service;s=signature", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }

        //                .thenReturn(svcPrincipal);
        assertNotNull(client.getPrincipal("v=S1;d=domain;n=service;s=signature", null));

        try {
            client.getPrincipal("v=S1;d=domain1;n=service;s=signature", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getPrincipal("v=S1;d=domain;n=service1;s=signature", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testPutRoleSystemMeta() throws URISyntaxException, IOException {

        final String domainName = "role-meta";
        final String roleName = "role1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        RoleSystemMeta meta = new RoleSystemMeta().setAuditEnabled(true);

        Mockito.when(c.putRoleSystemMeta(domainName, roleName, "auditenabled", AUDIT_REF, meta))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putRoleSystemMeta(domainName, roleName, "auditenabled", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putRoleSystemMeta(domainName, roleName, "auditenabled", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetRole() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Mockito.when(c.getRole("domain1", "role1", true, false, false)).thenThrow(new ResourceException(400));
            client.getRole("domain1", "role1", true, false);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutRoleMeta() throws URISyntaxException, IOException {

        final String domainName = "role-meta";
        final String roleName = "role1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        RoleMeta meta = new RoleMeta().setSelfServe(true);

        Mockito.when(c.putRoleMeta(domainName, roleName, AUDIT_REF, null, meta))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putRoleMeta(domainName, roleName, AUDIT_REF, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putRoleMeta(domainName, roleName, AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutRoleMetaSuccess() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        RoleMeta meta = new RoleMeta().setSelfServe(true);
        Role r = new Role().setName("role1").setSelfServe(true);
        Mockito.when(c.putRoleMeta("domain1", "role1", AUDIT_REF, null, meta)).thenReturn(r);
        client.putRoleMeta("domain1", "role1", AUDIT_REF, meta);
    }

    @Test
    public void testPutMembershipDecision() throws URISyntaxException, IOException {

        final String domainName = "put-mbr-decision";
        final String roleName = "role1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.putMembershipDecision(anyString(), anyString(), anyString(), anyString(), any(Membership.class)))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putMembershipDecision(domainName, roleName, "user.jane", null, true, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putMembershipDecision(domainName, roleName, "user.jane", null, true, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutMembershipDecisionSuccess() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Membership mbr = new Membership().setActive(true).setMemberName("user.jane").setRoleName("role1");
        Mockito.when(c.putMembershipDecision(anyString(), anyString(), anyString(), anyString(), any(Membership.class))).thenReturn(mbr);
        client.putMembershipDecision("domain1", "role1", "user.jane", null, true, AUDIT_REF);
    }

    @Test
    public void testPutRoleReviewError() throws URISyntaxException, IOException {

        final String domainName = "put-role-review";
        final String roleName = "role1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.putRoleReview(anyString(), anyString(), anyString(), anyBoolean(), isNull(), any(Role.class)))
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        Role role = new Role();

        try {
            client.putRoleReview(domainName, roleName, AUDIT_REF, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putRoleReview(domainName, roleName, AUDIT_REF, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPutRoleReviewSuccess() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        try {
            Role role = createRoleObject(client,"Domain1", "role1", "no", "user.member1", "user.member2");
            Mockito.when(c.putRoleReview(anyString(), anyString(), anyString(), anyBoolean(), isNull(), any(Role.class)))
                    .thenReturn(role);
            Role returnedRole = client.putRoleReview("domain1", "role1", AUDIT_REF, true, role);
            verify(c, times(1)).putRoleReview("domain1", "role1", AUDIT_REF, true, null, role);
            assertEquals(returnedRole, role);

            client.putRoleReview("domain1", "role1", AUDIT_REF, null);
        } catch (ResourceException ex) {
            fail();
        }
    }

    @Test
    public void testPutServiceIdentitySystemMeta() throws URISyntaxException, IOException {

        final String domainName = "put-svc-meta";
        final String serviceName = "service1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ServiceIdentitySystemMeta meta = new ServiceIdentitySystemMeta().setProviderEndpoint("https://localhost");

        Mockito.when(c.putServiceIdentitySystemMeta(domainName, serviceName, "providerendpoint", AUDIT_REF, meta))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putServiceIdentitySystemMeta(domainName, serviceName, "providerendpoint", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putServiceIdentitySystemMeta(domainName, serviceName, "providerendpoint", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetJWSDomain() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Map<String, String> header = new HashMap<>();
        header.put("kid", "0");
        JWSDomain jwsDomain = new JWSDomain()
                .setPayload("payload").setSignature("signature")
                .setProtectedHeader("header").setHeader(header);
        Mockito.when(c.getJWSDomain("domain1", false, "tag", Collections.emptyMap())).thenReturn(jwsDomain);
        JWSDomain jwsDom = client.getJWSDomain("domain1", "tag", Collections.emptyMap());
        assertNotNull(jwsDom);
    }

    @Test
    public void testGetJWSDomainNoArguments() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Map<String, String> header = new HashMap<>();
        header.put("kid", "0");
        JWSDomain jwsDomain = new JWSDomain()
                .setPayload("payload").setSignature("signature")
                .setProtectedHeader("header").setHeader(header);
        Mockito.when(c.getJWSDomain("domain1", false, null, null)).thenReturn(jwsDomain);
        JWSDomain jwsDom = client.getJWSDomain("domain1");
        assertNotNull(jwsDom);
    }

    @Test
    public void testGetJWSDomainFailures() throws URISyntaxException, IOException {

        final String domainName = "jws-domain";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.getJWSDomain(domainName, false, null, null))
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        try {
            client.getJWSDomain(domainName);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getJWSDomain(domainName);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPutGroup() throws URISyntaxException, IOException {

        final String domainName = "put-group-test";
        final String groupName1 = "group1";
        final String groupName2 = "group2";
        final String groupName3 = "group3";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);

        Group group1 = createGroupObject(client, domainName, groupName1, "user.joe", "user.jane");
        Mockito.when(c.putGroup(domainName, groupName1, AUDIT_REF, true, null, group1)).thenReturn(group1);
        Mockito.when(c.getGroup(domainName, groupName1, false, false)).thenReturn(group1);
        Mockito.when(c.putGroup(domainName, groupName2, AUDIT_REF, false, null, group1))
                .thenThrow(new NullPointerException());
        Mockito.when(c.putGroup(domainName, groupName3, AUDIT_REF, false, null, group1))
                .thenThrow(new ResourceException(404));
        Mockito.when(c.getGroup(domainName, groupName2, false, false)).thenThrow(new NullPointerException());
        Mockito.when(c.getGroup(domainName, groupName3, false, false)).thenThrow(new ResourceException(404));

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", systemAdminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Group returnedGroup = client.putGroup(domainName, groupName1, AUDIT_REF, true, null, group1);
        assertNotNull(returnedGroup);
        assertEquals(returnedGroup.getName(), domainName + ":group." + groupName1);

        Group group1Res = client.getGroup(domainName, groupName1, false, false);
        assertNotNull(group1Res);
        assertEquals(group1Res.getName(), domainName + ":group." + groupName1);

        try {
            client.putGroup(domainName, groupName2, AUDIT_REF, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putGroup(domainName, groupName3, AUDIT_REF, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        try {
            client.getGroup(domainName, groupName2, false, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.getGroup(domainName, groupName3, false, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        client.deleteTopLevelDomain(domainName, AUDIT_REF);
    }

    @Test
    public void testPutGroupReturnObject() throws URISyntaxException, IOException {

        final String domainName = "put-group-test";
        final String groupName1 = "group1";
        final String groupName2 = "group2";
        final String groupName3 = "group3";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);

        Group group1 = createGroupObject(client, domainName, groupName1, "user.joe", "user.jane");
        Mockito.when(c.putGroup(domainName, groupName1, AUDIT_REF, true, null, group1)).thenReturn(group1);
        Mockito.when(c.getGroup(domainName, groupName1, false, false)).thenReturn(group1);
        Mockito.when(c.putGroup(domainName, groupName2, AUDIT_REF, false, null, group1))
                .thenThrow(new NullPointerException());
        Mockito.when(c.putGroup(domainName, groupName3, AUDIT_REF, false, null, group1))
                .thenThrow(new ResourceException(404));
        Mockito.when(c.getGroup(domainName, groupName2, false, false)).thenThrow(new NullPointerException());
        Mockito.when(c.getGroup(domainName, groupName3, false, false)).thenThrow(new ResourceException(404));

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName,
                "Test Domain1", "testOrg", systemAdminUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Group returnedGroup = client.putGroup(domainName, groupName1, AUDIT_REF, true, group1);

        assertEquals(returnedGroup.name, "put-group-test:group.group1");

        Group group1Res = client.getGroup(domainName, groupName1, false, false);
        assertNotNull(group1Res);
        assertEquals(group1Res.getName(), domainName + ":group." + groupName1);

        try {
            client.putGroup(domainName, groupName2, AUDIT_REF, false, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putGroup(domainName, groupName3, AUDIT_REF, false, group1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        try {
            client.getGroup(domainName, groupName2, false, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.getGroup(domainName, groupName3, false, false);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        client.deleteTopLevelDomain(domainName, AUDIT_REF);
    }

    @Test
    public void testPutGroupMembership() throws URISyntaxException, IOException {

        final String domainName = "put-group-mbr";
        final String groupName = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        GroupMembership member = new GroupMembership().setGroupName(groupName).setMemberName("user.joe")
                .setIsMember(true);
        GroupMembership membership1 = new GroupMembership().setMemberName("testMember").setGroupName("testGroup");

        Mockito.when(c.putGroupMembership(domainName, groupName, "user.joe", AUDIT_REF, false, null, member))
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException())
                .thenReturn(membership1);

        Mockito.when(c.putGroupMembership(domainName, groupName, "user.joe", AUDIT_REF, true, null, member))
                .thenReturn(membership1);

        GroupMembership groupMembership1 = client.putGroupMembership(domainName, groupName, "user.joe", AUDIT_REF, true);

        assertEquals(groupMembership1.groupName, "testGroup");
        assertEquals(groupMembership1.memberName, "testMember");

        try {
            client.putGroupMembership(domainName, groupName, "user.joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putGroupMembership(domainName, groupName, "user.joe", AUDIT_REF, false);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        GroupMembership returnedGroupMemberShip = client.putGroupMembership(domainName, groupName,
                "user.joe", AUDIT_REF, false);
        assertEquals(returnedGroupMemberShip, membership1);
        client.putGroupMembership(domainName, groupName, "user.joe", AUDIT_REF);
    }

    @Test
    public void testDeleteGroupMembership() throws URISyntaxException, IOException {

        final String domainName = "del-group-mbr-test";
        final String groupName1 = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        TopLevelDomain dom1Mock = Mockito.mock(TopLevelDomain.class);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(AUDIT_REF, null, dom1Mock)).thenReturn(domainMock);

        Group group1 = createGroupObject(client, domainName, groupName1, "user.joe", "user.jane");
        Mockito.when(c.putGroup(domainName, groupName1, AUDIT_REF, false, null, group1)).thenReturn(group1);

        TopLevelDomain dom1 = createTopLevelDomainObject(domainName, "Test Domain1", "testOrg", systemAdminFullUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        client.putGroup(domainName, groupName1, AUDIT_REF, group1);
        client.deleteGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF);

        client.deleteTopLevelDomain("MbrDelDom1", AUDIT_REF);
    }

    @Test
    public void testDeleteGroupMembershipFailures() throws URISyntaxException, IOException {

        final String domainName = "del-group-mbr-test";
        final String groupName1 = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF, null))
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        try {
            client.deleteGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deleteGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeletePendingGroupMembershipFailures() throws URISyntaxException, IOException {

        final String domainName = "del-pending-group-mbr-test";
        final String groupName1 = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deletePendingGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF))
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());
        try {
            client.deletePendingGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.deletePendingGroupMembership(domainName, groupName1, "user.joe", AUDIT_REF);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testDeleteGroup() throws URISyntaxException, IOException {

        final String domainName = "del-group";
        final String groupName1 = "group1";
        final String groupName2 = "group2";
        final String groupName3 = "group3";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Group groupMock = Mockito.mock(Group.class);
        Mockito.when(c.deleteGroup(domainName, groupName1, AUDIT_REF, null)).thenReturn(groupMock);

        client.deleteGroup(domainName, groupName1, AUDIT_REF);

        try {
            Mockito.when(c.deleteGroup(domainName, groupName2, AUDIT_REF, null)).thenThrow(new ResourceException(204));
            client.deleteGroup(domainName, groupName2, AUDIT_REF);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 204);
        }

        try {
            Mockito.when(c.deleteGroup(domainName, groupName3, AUDIT_REF, null)).thenThrow(new NullPointerException());
            client.deleteGroup(domainName, groupName3, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetPendingDomainRoleMembersList() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainRoleMembership domainRoleMembership = mock(DomainRoleMembership.class);

        Mockito.when(c.getPendingDomainRoleMembersList("user.joe", null))
                .thenReturn(domainRoleMembership)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        client.getPendingDomainRoleMembersList("user.joe");

        try {
            client.getPendingDomainRoleMembersList("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getPendingDomainRoleMembersList("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetPendingDomainRoleMembersListWithDomain() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainRoleMembership domainRoleMembership = mock(DomainRoleMembership.class);

        Mockito.when(c.getPendingDomainRoleMembersList("user.joe", "testdomain1"))
                .thenReturn(domainRoleMembership)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        client.getPendingDomainRoleMembersList("user.joe", "testdomain1");

        try {
            client.getPendingDomainRoleMembersList("user.joe", "testdomain1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getPendingDomainRoleMembersList("user.joe", "testdomain1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetGroupMembership() throws URISyntaxException, IOException {

        final String domainName = "get-group-mbr";
        final String groupName = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        GroupMembership member1Mock = Mockito.mock(GroupMembership.class);

        Mockito.when(c.getGroupMembership(domainName, groupName, "user.joe", null))
                .thenReturn(member1Mock)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        client.getGroupMembership(domainName, groupName, "user.joe", null);

        try {
            client.getGroupMembership(domainName, groupName, "user.joe", null);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getGroupMembership(domainName, groupName, "user.joe", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetPrincipalGroups() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        DomainGroupMember domainGroupMember = Mockito.mock(DomainGroupMember.class);
        Mockito.when(c.getPrincipalGroups(null, null))
                .thenReturn(domainGroupMember)
                .thenThrow(new ZMSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        DomainGroupMember retMember = client.getPrincipalGroups(null, null);
        assertNotNull(retMember);

        try {
            client.getPrincipalGroups(null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 401);
        }

        try {
            client.getPrincipalGroups(null, null);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPutGroupMeta() throws URISyntaxException, IOException {

        final String domainName = "group-meta";
        final String groupName = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        GroupMeta meta = new GroupMeta().setSelfServe(true);

        Mockito.when(c.putGroupMeta(domainName, groupName, AUDIT_REF, null, meta))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putGroupMeta(domainName, groupName, AUDIT_REF, null, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putGroupMeta(domainName, groupName, AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutGroupSystemMeta() throws URISyntaxException, IOException {

        final String domainName = "group-sys-meta";
        final String groupName = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        GroupSystemMeta meta = new GroupSystemMeta().setAuditEnabled(true);

        Mockito.when(c.putGroupSystemMeta(domainName, groupName, "auditenabled", AUDIT_REF, meta))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putGroupSystemMeta(domainName, groupName, "auditenabled", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putGroupSystemMeta(domainName, groupName, "auditenabled", AUDIT_REF, meta);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutGroupMembershipDecision() throws URISyntaxException, IOException {

        final String domainName = "put-group-mbr-decision";
        final String groupName = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.putGroupMembershipDecision(anyString(), anyString(), anyString(), anyString(), any(GroupMembership.class)))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        try {
            client.putGroupMembershipDecision(domainName, groupName, "user.jane", true, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.putGroupMembershipDecision(domainName, groupName, "user.jane", true, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutGroupReview() throws URISyntaxException, IOException {

        final String domainName = "put-group-review";
        final String groupName = "group1";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Group group1 = new Group().setName("TestGroup");

        Mockito.when(c.putGroupReview(anyString(), anyString(), anyString(), anyBoolean(), isNull(), any(Group.class)))
                .thenReturn(group1)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        Group role = new Group();

        Group returnedGroup = client.putGroupReview(domainName, groupName, AUDIT_REF, true, role);

        assertEquals(returnedGroup.name, "TestGroup");

        try {
            client.putGroupReview(domainName, groupName, AUDIT_REF, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.putGroupReview(domainName, groupName, AUDIT_REF, role);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetPendingDomainGroupMembersList() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainGroupMembership domainGroupMembership = mock(DomainGroupMembership.class);

        Mockito.when(c.getPendingDomainGroupMembersList("user.joe", null))
                .thenReturn(domainGroupMembership)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        DomainGroupMembership domainGroupMembership1 = client.getPendingDomainGroupMembersList("user.joe");
        assertEquals(domainGroupMembership1, domainGroupMembership);

        try {
            client.getPendingDomainGroupMembersList("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getPendingDomainGroupMembersList("user.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetPendingDomainGroupMembersListWithDomain() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        DomainGroupMembership domainGroupMembership = mock(DomainGroupMembership.class);

        Mockito.when(c.getPendingDomainGroupMembersList("user.joe", "testdomain1"))
                .thenReturn(domainGroupMembership)
                .thenThrow(new ResourceException(403))
                .thenThrow(new NullPointerException());

        DomainGroupMembership domainGroupMembership1 = client.getPendingDomainGroupMembersList("user.joe", "testdomain1");
        assertEquals(domainGroupMembership1, domainGroupMembership);

        try {
            client.getPendingDomainGroupMembersList("user.joe", "testdomain1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getPendingDomainGroupMembersList("user.joe", "testdomain1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetGroups() throws URISyntaxException, IOException {

        final String domainName = "get-groups";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.getGroups(domainName, true, null, null))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(401));

        try {
            client.getGroups(domainName, true);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.getGroups(domainName, true);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testGetGroupsTags() throws URISyntaxException, IOException {

        final String domainName = "get-groups-tags";

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        Mockito.when(c.getGroups(domainName, true, "key", "value"))
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(401));

        try {
            client.getGroups(domainName, true, "key", "value");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.getGroups(domainName, true, "key", "value");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testPutAssertionConditions() throws URISyntaxException, IOException {
        final String domainName = "put-assertion-conditions";
        final String policyName = "put-assertion-conditions.pol";
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        AssertionCondition ac = new AssertionCondition().setId(1);
        AssertionConditions ac1 = new AssertionConditions().setConditionsList(Collections.singletonList(ac));
        Mockito.when(c.putAssertionConditions(anyString(), anyString(), anyLong(), anyString(),
                        isNull(), any(AssertionConditions.class)))
                .thenReturn(ac1)
                .thenReturn(ac1)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(401));

        assertEquals(client.putAssertionConditions(domainName, policyName, 1L, AUDIT_REF, null, ac1), ac1);
        assertEquals(client.putAssertionConditions(domainName, policyName, 1L, AUDIT_REF, ac1), ac1);

        try {
            client.putAssertionConditions(domainName, policyName, 1L, AUDIT_REF, ac1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.putAssertionConditions(domainName, policyName, 1L, AUDIT_REF, ac1);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testPutAssertionCondition() throws URISyntaxException, IOException {
        final String domainName = "put-assertion-condition";
        final String policyName = "put-assertion-condition.pol";
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        AssertionCondition ac = new AssertionCondition().setId(1);
        Mockito.when(c.putAssertionCondition(anyString(), anyString(), anyLong(), anyString(), isNull(),
                        any(AssertionCondition.class)))
                .thenReturn(ac)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(401));

        assertEquals(client.putAssertionCondition(domainName, policyName, 1L, AUDIT_REF, ac), ac);

        try {
            client.putAssertionCondition(domainName, policyName, 1L, AUDIT_REF, ac);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.putAssertionCondition(domainName, policyName, 1L, AUDIT_REF, ac);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testDeleteAssertionConditions() throws URISyntaxException, IOException {
        final String domainName = "delete-assertion-conditions";
        final String policyName = "delete-assertion-conditions.pol";
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteAssertionConditions(anyString(), anyString(), anyLong(), anyString(), isNull()))
                .thenReturn(null)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(401));

        try {
            client.deleteAssertionConditions(domainName, policyName, 1L, AUDIT_REF);
        } catch(ResourceException re){
            fail();
        }
        try {
            client.deleteAssertionConditions(domainName, policyName, 1L, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.deleteAssertionConditions(domainName, policyName, 1L, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testDeleteAssertionCondition() throws URISyntaxException, IOException {
        final String domainName = "delete-assertion-condition";
        final String policyName = "delete-assertion-condition.pol";
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Mockito.when(c.deleteAssertionCondition(anyString(), anyString(), anyLong(), anyInt(), anyString(), isNull()))
                .thenReturn(null)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(401));

        try {
            client.deleteAssertionCondition(domainName, policyName, 1L, 1, AUDIT_REF);
        } catch(ResourceException re){
            fail();
        }
        try {
            client.deleteAssertionCondition(domainName, policyName, 1L, 1, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        try {
            client.deleteAssertionCondition(domainName, policyName, 1L, 1, AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
        }
    }

    @Test
    public void testPutDomainDependency() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        String domainName = "put-domain-dependency";
        try {
            DependentService dependentService = new DependentService().setService(domainName + ".service1");
            Mockito.when(c.putDomainDependency(domainName, AUDIT_REF, dependentService)).thenThrow(new ResourceException(403));
            client.putDomainDependency(domainName, AUDIT_REF, dependentService);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        try {
            DependentService dependentService = new DependentService().setService(domainName + ".service2");
            Mockito.when(c.putDomainDependency(domainName, AUDIT_REF, dependentService)).thenThrow(new NullPointerException());
            client.putDomainDependency(domainName, AUDIT_REF, dependentService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // Should succeed
        DependentService dependentService = new DependentService().setService(domainName + ".service3");
        Mockito.when(c.putDomainDependency(domainName, AUDIT_REF, dependentService)).thenReturn(dependentService);
        client.putDomainDependency(domainName, AUDIT_REF, dependentService);
    }

    @Test
    public void testDeleteDomainDependency() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        String domainName = "delete-domain-dependency";
        try {
            Mockito.when(c.deleteDomainDependency(domainName, domainName + ".service1", AUDIT_REF)).thenThrow(new ResourceException(403));
            client.deleteDomainDependency(domainName, domainName + ".service1", AUDIT_REF);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        try {
            Mockito.when(c.deleteDomainDependency(domainName, domainName + ".service2", AUDIT_REF)).thenThrow(new NullPointerException());
            client.deleteDomainDependency(domainName, domainName + ".service2", AUDIT_REF);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // Should succeed
        Mockito.when(c.deleteDomainDependency(domainName, domainName + ".service3", AUDIT_REF)).thenReturn("");
        client.deleteDomainDependency(domainName, domainName + ".service3", AUDIT_REF);
    }

    @Test
    public void testGetDependentServiceList() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        String domainName = "get-dependent-service-list";
        try {
            Mockito.when(c.getDependentServiceList(domainName)).thenThrow(new ResourceException(404));
            client.getDependentServiceList(domainName);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        try {
            Mockito.when(c.getDependentServiceList(domainName + "1")).thenThrow(new NullPointerException());
            client.getDependentServiceList(domainName + "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // Should succeed
        Mockito.when(c.getDependentServiceList(domainName + "2")).thenReturn(new ServiceIdentityList());
        client.getDependentServiceList(domainName + "2");
    }

    @Test
    public void testGetDependentDomainList() throws URISyntaxException, IOException {

        final String baseUrl = "https://zms.athenz.yahoo.com:4443/zms/v1";
        final String name = "athens";
        URIBuilder uriBuilder = new URIBuilder(baseUrl + "/domain/").setFragment("{name}");
        uriBuilder.setPathSegments(name);

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);

        String service = "get-dependent-domain-list";
        try {
            Mockito.when(c.getDependentDomainList(service)).thenThrow(new ResourceException(404));
            client.getDependentDomainList(service);
            fail();
        } catch  (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
        try {
            Mockito.when(c.getDependentDomainList(service + "1")).thenThrow(new NullPointerException());
            client.getDependentDomainList(service + "1");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // Should succeed
        Mockito.when(c.getDependentDomainList(service + "2")).thenReturn(new DomainList());
        client.getDependentDomainList(service + "2");
    }

    @Test
    public void testDeleteExpiredMembers() throws URISyntaxException, IOException {

        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ExpiredMembers expiredMembers = Mockito.mock(ExpiredMembers.class);

        Mockito.when(c.deleteExpiredMembers(null, AUDIT_REF, false)).thenReturn(expiredMembers);
        client.deleteExpiredMembers(null, AUDIT_REF, false);

        Mockito.when(c.deleteExpiredMembers(3, AUDIT_REF, false))
                .thenReturn(expiredMembers)
                .thenThrow(new ResourceException(401))
                .thenThrow(new NullPointerException());

        client.deleteExpiredMembers(3, AUDIT_REF, false);
        try {
            client.deleteExpiredMembers(3, AUDIT_REF, false);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.UNAUTHORIZED);
        }
        try {
            client.deleteExpiredMembers(3, AUDIT_REF, false);
            fail();
        } catch (ZMSClientException ex) {
            assertEquals(ex.getCode(), ZMSClientException.BAD_REQUEST);
        }
    }

    @Test
    public void testPutResourceRoleOwnership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ResourceRoleOwnership resourceOwnership = new ResourceRoleOwnership().setObjectOwner("TF");
        Mockito.when(c.putResourceRoleOwnership("domain1", "role1", AUDIT_REF, resourceOwnership))
                .thenReturn(resourceOwnership)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        // first request is completed successfully

        client.putResourceRoleOwnership("domain1", "role1", AUDIT_REF, resourceOwnership);

        // next call we're getting an invalid request 400 error
        try {
            client.putResourceRoleOwnership("domain1", "role1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // last call we're getting back forbidden 403 error
        try {
            client.putResourceRoleOwnership("domain1", "role1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutResourcePolicyOwnership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ResourcePolicyOwnership resourceOwnership = new ResourcePolicyOwnership().setObjectOwner("TF");
        Mockito.when(c.putResourcePolicyOwnership("domain1", "policy1", AUDIT_REF, resourceOwnership))
                .thenReturn(resourceOwnership)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        // first request is completed successfully

        client.putResourcePolicyOwnership("domain1", "policy1", AUDIT_REF, resourceOwnership);

        // next call we're getting an invalid request 400 error
        try {
            client.putResourcePolicyOwnership("domain1", "policy1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // last call we're getting back forbidden 403 error
        try {
            client.putResourcePolicyOwnership("domain1", "policy1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutResourceServiceIdentityOwnership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ResourceServiceIdentityOwnership resourceOwnership = new ResourceServiceIdentityOwnership().setObjectOwner("TF");
        Mockito.when(c.putResourceServiceIdentityOwnership("domain1", "service1", AUDIT_REF, resourceOwnership))
                .thenReturn(resourceOwnership)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        // first request is completed successfully

        client.putResourceServiceIdentityOwnership("domain1", "service1", AUDIT_REF, resourceOwnership);

        // next call we're getting an invalid request 400 error
        try {
            client.putResourceServiceIdentityOwnership("domain1", "service1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // last call we're getting back forbidden 403 error
        try {
            client.putResourceServiceIdentityOwnership("domain1", "service1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPutResourceDomainOwnership() throws URISyntaxException, IOException {
        ZMSClient client = createClient(systemAdminUser);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        ResourceDomainOwnership resourceOwnership = new ResourceDomainOwnership().setObjectOwner("TF");
        Mockito.when(c.putResourceDomainOwnership("domain1", AUDIT_REF, resourceOwnership))
                .thenReturn(resourceOwnership)
                .thenThrow(new NullPointerException())
                .thenThrow(new ResourceException(403));

        // first request is completed successfully

        client.putResourceDomainOwnership("domain1", AUDIT_REF, resourceOwnership);

        // next call we're getting an invalid request 400 error
        try {
            client.putResourceDomainOwnership("domain1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // last call we're getting back forbidden 403 error
        try {
            client.putResourceDomainOwnership("domain1", AUDIT_REF, resourceOwnership);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
}
