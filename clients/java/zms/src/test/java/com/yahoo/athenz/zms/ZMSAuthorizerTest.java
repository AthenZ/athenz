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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;

import static org.testng.Assert.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.mockito.Mockito;

public class ZMSAuthorizerTest {

    private static final String ZMS_CLIENT_PROP_TEST_ADMIN = "athenz.zms.client.test_admin";
    private static final String AUDIT_REF = "zmsjcltauthtest";

    private String systemAdminUser = null;
    private String systemAdminFullUser = null;
    private final String zmsUrl = "http://localhost:10080/";
    
    @BeforeClass
    public void setup() {
        systemAdminUser = System.getProperty(ZMS_CLIENT_PROP_TEST_ADMIN, "user_admin");
        systemAdminFullUser = "user." + systemAdminUser;
        System.setProperty(ZMSClient.ZMS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
    }

    @Test
    public void testAuthorizer() throws URISyntaxException, IOException {

        ZMSClient client = getClient(systemAdminUser);
        String domain = "authorizerdom1";
        ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, domain);
        assertNotNull(authorizer);

        // create 3 user client objects

        Principal p1 = createPrincipal("user1");
        Principal p2 = createPrincipal("user2");
        Principal p3 = createPrincipal("user3");

        ZMSRDLGeneratedClient zmsRdlClient = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(zmsRdlClient);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(zmsRdlClient.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock);

        setupAccess(client, domain);

        // only user1 and user3 have access to UPDATE/resource1
        ZMSClient mockZMSClient = Mockito.mock(ZMSClient.class);
        authorizer.setZMSClient(mockZMSClient);
        Access accessMock = Mockito.mock(Access.class);
        Mockito.when(mockZMSClient.getAccess("UPDATE", "authorizerdom1:resource1", "authorizerdom1"))
            .thenReturn(accessMock);
        Mockito.when(mockZMSClient.getAccess("UPDATE", "authorizerdom1:resource1", null))
            .thenReturn(accessMock);
        Mockito.when(accessMock.getGranted()).thenReturn(true, true, true, false, false, false, true, true);
        Mockito.when(zmsRdlClient.getAccess("UPDATE", "authorizerdom1:resource1", "authorizerdom1", null))
                .thenReturn(accessMock);

        boolean access = authorizer.access("UPDATE", "resource1", p1, domain);
        assertTrue(access);

        // we're going to use a principal token as well to test this access
        
        String principalToken1 = "v=U1;d=user;n=user1;s=signature";
        access = authorizer.access("UPDATE", "resource1", principalToken1, domain);
        assertTrue(access);
        
        // finally testing with role token as well
        
        String roleToken1 = "v=Z1;d=authorizerdom1;r=role1;s=signature";
        access = authorizer.access("UPDATE", "resource1", roleToken1, null);
        assertTrue(access);

        // now try with other users
        
        access = authorizer.access("UPDATE", "resource1", p2, domain);
        assertFalse(access);

        String principalToken2 = "v=U1;d=user;n=user2;s=signature";
        access = authorizer.access("UPDATE", "resource1", principalToken2, domain);
        assertFalse(access);

        String roleToken2 = "v=Z1;d=authorizerdom1;r=role2;s=signature";
        access = authorizer.access("UPDATE", "resource1", roleToken2, null);
        assertFalse(access);

        access = authorizer.access("UPDATE", "resource1", p3, domain);
        assertTrue(access);

        String principalToken3 = "v=U1;d=user;n=user3;s=signature";
        access = authorizer.access("UPDATE", "resource1", principalToken3, domain);
        assertTrue(access);

        // we should get exception with no principal
        try {
            authorizer.access("UPDATE", "resource2", (Principal) null, domain);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        
        // we should get exception with no principal token

        try {
            authorizer.access("UPDATE", "resource2", (String) null, domain);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
        
        TopLevelDomain topLevelDomainMock = Mockito.mock(TopLevelDomain.class);
        Mockito.when(zmsRdlClient.deleteTopLevelDomain(domain, null, AUDIT_REF)).thenReturn(topLevelDomainMock);
        cleanUpAccess(domain);
    }

    @Test
    public void testAuthorizerNoEndpoint() {
        String domain = "AuthorizerDom2";
        ZMSAuthorizer authorizer = new ZMSAuthorizer(domain);
        assertNotNull(authorizer);

        // closing with no client should cause no exceptions

        authorizer.client = null;
        authorizer.close();
    }

    @Test
    public void testAddCredentials() throws URISyntaxException, IOException {
        ZMSClient client = getClient(systemAdminUser);
        String domain = "AuthorizerDom5";
        ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, null);

        Principal p1 = createPrincipal("user1");
        Principal p2 = createPrincipal("user2");
        Principal p3 = createPrincipal("user3");
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock);

        setupAccess(client, domain);
        ZMSClient mockZMSClient = Mockito.mock(ZMSClient.class);
        authorizer.setZMSClient(mockZMSClient);

        Access accessMock = Mockito.mock(Access.class);
        Mockito.when(mockZMSClient.getAccess("UPDATE", "AuthorizerDom3:resource1", "AuthorizerDom3"))
                .thenReturn(accessMock);
        Mockito.when(accessMock.getGranted()).thenReturn(true, false, true);
        Mockito.when(c.getAccess("UPDATE", "AuthorizerDom3:resource1", "AuthorizerDom3", null)).thenReturn(accessMock);
        try {
            Mockito.when(mockZMSClient.addCredentials(p1)).thenThrow(new ResourceException(204));
            authorizer.access("UPDATE", domain + ":resource1", p1, domain);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }

        try {
            Mockito.when(mockZMSClient.addCredentials(p2)).thenThrow(new ZMSClientException(204, "No Content"));
            authorizer.access("UPDATE", domain + ":resource1", p2, domain);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        
        try {
            Mockito.when(mockZMSClient.addCredentials(p3)).thenThrow(new ZMSClientException(404, "Not Found"));
            authorizer.access("UPDATE", domain + ":resource1", p3, domain);
            fail();
        } catch (ZMSClientException ex) {
            assertTrue(true);
        }
        authorizer.close();
    }

    @Test
    public void testAuthorizerNoDomain() throws URISyntaxException, IOException {
        ZMSClient client = getClient(systemAdminUser);
        String domain = "AuthorizerDom3";
        ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, null);
        assertNotNull(authorizer);

        // create 3 user client objects

        Principal p1 = createPrincipal("user1");
        Principal p2 = createPrincipal("user2");
        Principal p3 = createPrincipal("user3");

        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock);

        setupAccess(client, domain);
        ZMSClient mockZMSClient = Mockito.mock(ZMSClient.class);
        authorizer.setZMSClient(mockZMSClient);

        // only user1 and user3 have access to UPDATE/resource1
        Access accessMock = Mockito.mock(Access.class);
        Mockito.when(mockZMSClient.getAccess("UPDATE", "AuthorizerDom3:resource1", "AuthorizerDom3"))
                .thenReturn(accessMock);
        Mockito.when(accessMock.getGranted()).thenReturn(true, false, true);
        Mockito.when(c.getAccess("UPDATE", "AuthorizerDom3:resource1", "AuthorizerDom3", null)).thenReturn(accessMock);
        boolean access = authorizer.access("UPDATE", domain + ":resource1", p1, domain);
        assertTrue(access);

        access = authorizer.access("UPDATE", domain + ":resource1", p2, domain);
        assertFalse(access);

        access = authorizer.access("UPDATE", domain + ":resource1", p3, domain);
        assertTrue(access);
        TopLevelDomain topLevelDomainMock = Mockito.mock(TopLevelDomain.class);
        Mockito.when(c.deleteTopLevelDomain(domain, null, AUDIT_REF)).thenReturn(topLevelDomainMock);
        authorizer.close();
        cleanUpAccess(domain);
    }

    @Test
    public void testAuthorizerResourceWithDomain() throws URISyntaxException, IOException {
        ZMSClient client = getClient(systemAdminUser);
        String domain = "AuthorizerDom4";
        ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, domain);
        assertNotNull(authorizer);

        // create 3 user client objects

        Principal p1 = createPrincipal("user1");
        Principal p2 = createPrincipal("user2");
        Principal p3 = createPrincipal("user3");

        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        Domain domainMock = Mockito.mock(Domain.class);
        Mockito.when(c.postTopLevelDomain(Mockito.any(), Mockito.isNull(), Mockito.any(TopLevelDomain.class)))
                .thenReturn(domainMock);
        setupAccess(client, domain);

        // only user1 and user3 have access to UPDATE/resource1
        ZMSClient mockZMSClient = Mockito.mock(ZMSClient.class);
        authorizer.setZMSClient(mockZMSClient);
        Access accessMock = Mockito.mock(Access.class);
        Mockito.when(mockZMSClient.getAccess("UPDATE", "AuthorizerDom4:resource1", "AuthorizerDom4"))
                .thenReturn(accessMock);
        Mockito.when(accessMock.getGranted()).thenReturn(true, false, true);
        Mockito.when(c.getAccess("UPDATE", "AuthorizerDom4:resource1", "AuthorizerDom4", null)).thenReturn(accessMock);
        boolean access = authorizer.access("UPDATE", domain + ":resource1", p1, domain);
        assertTrue(access);

        access = authorizer.access("UPDATE", domain + ":resource1", p2, domain);
        assertFalse(access);

        access = authorizer.access("UPDATE", domain + ":resource1", p3, domain);
        assertTrue(access);

        TopLevelDomain topLevelDomainMock = Mockito.mock(TopLevelDomain.class);
        Mockito.when(c.deleteTopLevelDomain(domain, null, AUDIT_REF)).thenReturn(topLevelDomainMock);
        cleanUpAccess(domain);
    }

    @Test
    public void testIsRoleToken() {
        String domain = "AuthorizerRoleToken";
        ZMSAuthorizer authorizer = new ZMSAuthorizer(zmsUrl, domain);
        
        assertTrue(authorizer.isRoleToken("v=Z1;d=domain;r=roles;s=signature"));
        assertTrue(authorizer.isRoleToken("d=domain;r=roles;v=Z1;s=signature"));
        assertFalse(authorizer.isRoleToken("v=S1;d=domain;n=server;s=signature"));
        assertFalse(authorizer.isRoleToken("d=domain;r=roles;s=signature"));
        assertFalse(authorizer.isRoleToken("vZ1"));
        authorizer.close();
    }
    
    private Role createRoleObject(ZMSClient client, String domainName, String roleName, String trust, String member1,
            String member2) {

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

    private Policy createPolicyObject(ZMSClient client, String domainName, String policyName, String roleName,
            String action, String resource, AssertionEffect effect) {

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

    private TopLevelDomain createTopLevelDomainObject(String name, String description, String org, String admin) {

        TopLevelDomain dom = new TopLevelDomain();
        dom.setName(name);
        dom.setDescription(description);
        dom.setOrg(org);
        dom.setEnabled(true);
        dom.setYpmId(2000);

        List<String> admins = new ArrayList<>();
        admins.add(admin);
        dom.setAdminUsers(admins);
        return dom;
    }

    private Principal createPrincipal(String userName) {
        Authority authority = new com.yahoo.athenz.auth.impl.PrincipalAuthority();
        return SimplePrincipal.create("user", userName, "v=U1;d=user;n=" + userName + ";s=signature", 0,
                authority);
    }

    private ZMSClient getClient(String userName) {
        ZMSClient client = new ZMSClient(zmsUrl);
        ZMSRDLGeneratedClient c = Mockito.mock(ZMSRDLGeneratedClient.class);
        client.setZMSRDLGeneratedClient(c);
        client.addCredentials(createPrincipal(userName));
        return client;
    }

    private void setupAccess(ZMSClient client, String domain) {
        TopLevelDomain dom1 = createTopLevelDomainObject(domain, "Test Domain1", "testOrg", systemAdminFullUser);
        client.postTopLevelDomain(AUDIT_REF, dom1);

        Role role1 = createRoleObject(client, domain, "Role1", null, "user.user1", "user.user3");
        client.putRole(domain, "Role1", AUDIT_REF, role1);

        Policy policy1 = createPolicyObject(client, domain, "Policy1", "Role1", "UPDATE", domain + ":resource1",
                AssertionEffect.ALLOW);
        client.putPolicy(domain, "Policy1", AUDIT_REF, policy1);
    }

    private void cleanUpAccess(String domain) {
        ZMSClient client = getClient(systemAdminUser);
        client.deleteTopLevelDomain(domain, AUDIT_REF);
    }
}
