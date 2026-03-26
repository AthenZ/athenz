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
package com.yahoo.athenz.auth.impl;

import static org.testng.Assert.*;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

public class SimplePrincipalTest {

    String fakeUnsignedCreds = "v=U1;d=user;n=jdoe";
    String fakeCreds = fakeUnsignedCreds + ";s=signature";
    
    @Test
    public void testSimplePrincipal() {
        String testApplicationId = "test_app_id";
        SimplePrincipal p = (SimplePrincipal) SimplePrincipal.create("user", "jdoe", fakeCreds, null);
        assertNotNull(p);

        assertTrue(p.equals(p));
        assertFalse(p.equals(null));
        assertFalse(p.equals(testApplicationId));

        p.setUnsignedCreds(fakeUnsignedCreds);
        p.setApplicationId(testApplicationId);
        assertEquals(p.getName(), "jdoe");
        assertEquals(p.getDomain(), "user");
        assertEquals(p.getCredentials(), fakeCreds);
        assertEquals(p.getUnsignedCredentials(), fakeUnsignedCreds);
        assertEquals(p.getApplicationId(), testApplicationId);
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();
        
        p = (SimplePrincipal) SimplePrincipal.create("user", "jdoe", fakeCreds,
                userAuthority);
        assertNotNull(p);
    }
    
    @Test
    public void testSimplePrincipalNullUnsignedCred() {
        Principal p = SimplePrincipal.create("user", "jdoe", fakeCreds, null);
       
        assertNotNull(p);
        assertEquals(p.getName(), "jdoe");
        assertEquals(p.getDomain(), "user");
        assertEquals(p.getCredentials(), fakeCreds);
        assertNull(p.getUnsignedCredentials());
    }
    
    @Test
    public void testFullName() {
        
        Principal p = SimplePrincipal.create("user", "jdoe", fakeCreds, null);
        assertEquals(p.getFullName(), "user.jdoe");
        assertEquals(p.getFullName(), "user.jdoe");
        
        assertNotNull(SimplePrincipal.create(null, "jdoe", fakeCreds));
        assertNotNull(SimplePrincipal.create("user", null, fakeCreds));
        
        List<String> roles = new ArrayList<>();
        roles.add("role1");
        
        p = SimplePrincipal.create("user", fakeCreds, roles, null);
        assertNotNull(p);
        assertEquals(p.getFullName(), "user");
        
        p = SimplePrincipal.create("appid", fakeCreds, (Authority) null);
        assertEquals(p.getFullName(), "appid");
        
        assertNull(SimplePrincipal.create(null, null, (Authority) null));
    }
    
    @Test
    public void testSimplePrincipalNullRole() {
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        assertNull(SimplePrincipal.create("user", fakeCreds, (List<String>) null,
                userAuthority));
    }
    
    @Test
    public void testSimplePrincipalEmptyRole() {
        
        List<String> roles = new ArrayList<>();
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        assertNull(SimplePrincipal.create("user", fakeCreds, roles, userAuthority));
        
        roles.add("newrole");
        SimplePrincipal p = (SimplePrincipal) SimplePrincipal.create("user", fakeCreds,
                roles, userAuthority);
        assertNotNull(p);

        assertEquals(p.getRoles().size(), 1);
        assertTrue(p.getRoles().contains("newrole"));
        assertNull(p.getRolePrincipalName());
    }

    @Test
    public void testSimplePrincipalRolePrincipal() {

        List<String> roles = new ArrayList<>();

        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        assertNull(SimplePrincipal.create("user", fakeCreds, roles, "user.athenz", userAuthority));

        roles.add("newrole");
        SimplePrincipal p = (SimplePrincipal) SimplePrincipal.create("user", fakeCreds, roles, "user.athenz", userAuthority);
        assertNotNull(p);

        assertEquals(p.getRoles().size(), 1);
        assertTrue(p.getRoles().contains("newrole"));
        assertEquals(p.getRolePrincipalName(), "user.athenz");

        p.setRolePrincipalName("home.athenz");
        assertEquals(p.getRolePrincipalName(), "home.athenz");
    }

    @Test
    public void testSimplePrincipalNullDomainAuthorityDomainNotNull() {

        Principal p = SimplePrincipal.create("user", "jdoe", fakeCreds, 0, null);
        assertNotNull(p);
    }
    
    @Test
    public void testSimplePrincipalDomainNoMatch() {
        
        // we output warning but still create a principal
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        Principal p = SimplePrincipal.create("coretech", "jdoe", fakeCreds, 0, userAuthority);
        assertNull(p);
    }
    
    @Test
    public void testSimplePrincipalIssueTime() {
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        Principal p = SimplePrincipal.create("user", "jdoe", fakeCreds, 101, userAuthority);
        assertNotNull(p);
        assertEquals(p.getIssueTime(), 101);
    }
    
    @Test
    public void testSimplePrincipalToStringZToken() {
        
        List<String> roles = new ArrayList<>();
        roles.add("updater");
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        Principal p = SimplePrincipal.create("user", fakeCreds, roles, userAuthority);
        assertNotNull(p);

        assertEquals(p.toString(), "ZToken_user~updater");
    }
    
    @Test
    public void testSimplePrincipalToStringUser() {
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        Principal p = SimplePrincipal.create("user", "jdoe", fakeCreds, 101, userAuthority);
        assertNotNull(p);
        assertEquals(p.toString(), "user.jdoe");
    }
    
    @Test
    public void testSimplePrincipalExtraFields() {
        
        UserAuthority userAuthority = new UserAuthority();
        userAuthority.initialize();

        Principal p = SimplePrincipal.create("user", "jdoe", fakeCreds, 101, userAuthority);
        assertNotNull(p);

        ((SimplePrincipal) p).setOriginalRequestor("athenz.ci");
        ((SimplePrincipal) p).setKeyService("zts");
        ((SimplePrincipal) p).setKeyId("v1");
        X509Certificate cert = Mockito.mock(X509Certificate.class);
        ((SimplePrincipal) p).setX509Certificate(cert);
        ((SimplePrincipal) p).setState(Principal.State.ACTIVE);
        ((SimplePrincipal) p).setIssuerIdentity("partner1");

        assertEquals(p.toString(), "user.jdoe");
        assertEquals(p.getOriginalRequestor(), "athenz.ci");
        assertEquals(p.getKeyService(), "zts");
        assertEquals(p.getKeyId(), "v1");
        assertEquals(p.getX509Certificate(), cert);
        assertEquals(p.getState(), Principal.State.ACTIVE);
        assertEquals(p.getIssuerIdentity(), "partner1");

        Principal p2 = SimplePrincipal.create("user", "jdoe", fakeCreds, 101, userAuthority);
        assertTrue(p.equals(p2));
        assertEquals(p2.getState(), Principal.State.ACTIVE);
        assertEquals(p.hashCode(), p2.hashCode());

        Principal p3 = SimplePrincipal.create("user", "jdoe1", fakeCreds, 101, userAuthority);
        assertFalse(p.equals(p3));
        assertNotEquals(p.hashCode(), p3.hashCode());
    }

    @Test
    public void testSimplePrincipalIP() {
        SimplePrincipal check = (SimplePrincipal) SimplePrincipal.create("user", "jdoe", "hoge");
        
        check.setIP("10.10.10.10");
        assertEquals(check.getIP(),"10.10.10.10");
    }

    @Test
    public void testSimplePrincipalExternalMember() {

        Principal p = SimplePrincipal.create("external", "external:member1");
        assertNotNull(p);

        assertEquals(p.getFullName(), "external:member1");
        assertEquals(p.getDomain(), "external");
        assertNull(p.getName());
        assertNull(p.getCredentials());
        assertNull(p.getUnsignedCredentials());
        assertNull(p.getAuthority());
        assertNull(p.getRoles());
        assertNull(p.getApplicationId());
        assertNull(p.getAuthorizedService());
        assertNull(p.getX509Certificate());
        assertNull(p.getIP());
        assertNull(p.getOriginalRequestor());
        assertNull(p.getKeyService());
        assertNull(p.getKeyId());
        assertNull(p.getRolePrincipalName());
        assertNull(p.getIssuerIdentity());
        assertFalse(p.getMtlsRestricted());
        assertEquals(p.getState(), Principal.State.ACTIVE);
        assertEquals(p.getIssueTime(), 0);
    }

    @Test
    public void testSimplePrincipalExternalMemberEquals() {

        Principal p1 = SimplePrincipal.create("external", "external:member1");
        Principal p2 = SimplePrincipal.create("external", "external:member1");
        Principal p3 = SimplePrincipal.create("external", "external:member2");

        assertTrue(p1.equals(p1));
        assertTrue(p1.equals(p2));
        assertFalse(p1.equals(p3));
        assertFalse(p1.equals(null));

        assertEquals(p1.hashCode(), p2.hashCode());
        assertNotEquals(p1.hashCode(), p3.hashCode());
    }

    @Test
    public void testSimplePrincipalExternalMemberEqualsRegularPrincipal() {

        Principal extPrincipal = SimplePrincipal.create("user", "user.jdoe");
        Principal regPrincipal = SimplePrincipal.create("user", "jdoe", fakeCreds, null);

        assertEquals(extPrincipal.getFullName(), regPrincipal.getFullName());
        assertTrue(extPrincipal.equals(regPrincipal));
    }

    @Test
    public void testSimplePrincipalAuthorityCreate() {
        Authority hoge = Mockito.mock(Authority.class);
        
        SimplePrincipal check = (SimplePrincipal) SimplePrincipal.create("user", "jdoe", hoge);
        assertNotNull(check);

        Mockito.when(hoge.getDomain()).thenReturn(null);
        check = (SimplePrincipal) SimplePrincipal.create("user", "jdoe", "hoge", 0, hoge);
        assertNotNull(check);
    }
}
