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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.DomainPolicies;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.SignedPolicies;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class ZTSAuthorizerTest {

    @Test
    public void testAccessAuthoritySupport() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.allowAuthorization()).thenReturn(false);

        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getAuthority()).thenReturn(authority);

        assertFalse(authz.access("op", "resource", principal, null));
    }

    @Test
    public void testAccessInvalidResourceDomain() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.allowAuthorization()).thenReturn(true);

        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getAuthority()).thenReturn(authority);

        try {
            authz.access("op", "invalid-resource", principal, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testValidateRoleBasedAccessCheckTrustDomain() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertFalse(authz.validateRoleBasedAccessCheck(Collections.emptyList(), "trustdomain",
                "domain1", "domain1"));
    }

    @Test
    public void testValidateRoleBasedAccessCheckMismatchNames() {

        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        List<String> roles = new ArrayList<>();
        roles.add("readers");
        assertFalse(authz.validateRoleBasedAccessCheck(roles, null, "domain1", "domain2"));

        roles = new ArrayList<>();
        roles.add("domain1:role.readers");
        roles.add("domain2:role.readers");
        assertFalse(authz.validateRoleBasedAccessCheck(roles, null, "domain1", "domain1"));
    }

    @Test
    public void testValidateRoleBasedAccessCheckValid() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);

        assertTrue(authz.validateRoleBasedAccessCheck(Collections.emptyList(), null, "domain1", "domain1"));

        List<String> roles = new ArrayList<>();
        roles.add("readers");
        assertTrue(authz.validateRoleBasedAccessCheck(roles, null, "domain1", "domain1"));

        roles = new ArrayList<>();
        roles.add("domain1:role.readers");
        roles.add("domain1:role.writers");
        assertTrue(authz.validateRoleBasedAccessCheck(roles, null, "domain1", "domain1"));
        assertTrue(authz.validateRoleBasedAccessCheck(roles, null, "domain1", "domain2"));
    }

    @Test
    public void testMatchRoleNoRoles() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertFalse(authz.matchRole("domain", new ArrayList<>(), "role", null));
    }

    @Test
    public void testMatchRoleNoRoleMatch() {
        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertFalse(authz.matchRole("domain", new ArrayList<>(), "domain:role\\.role2.*", null));
    }

    @Test
    public void testMatchRoleAuthRoleNoMatchShortName() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);

        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("role3");

        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertFalse(authz.matchRole("domain", roles, "domain:role\\.role1.*", authRoles));
    }

    @Test
    public void testMatchRoleAuthRoleNoMatchFullName() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);

        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("domain:role.role3");

        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertFalse(authz.matchRole("domain", roles, "domain:role\\.role1.*", authRoles));
    }

    @Test
    public void testMatchRoleNoMatchPattern() {
        Role role = new Role().setName("domain:role.role2");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);

        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("role3");

        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertFalse(authz.matchRole("domain", roles, "domain:role\\.role1.*", authRoles));
    }

    @Test
    public void testMatchRoleShortName() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);

        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("role1");

        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertTrue(authz.matchRole("domain", roles, "domain:role\\.role.*", authRoles));
    }

    @Test
    public void testMatchRoleFullName() {
        Role role = new Role().setName("domain:role.role1");
        ArrayList<Role> roles = new ArrayList<>();
        roles.add(role);

        ArrayList<String> authRoles = new ArrayList<>();
        authRoles.add("domain:role.role1");

        ZTSAuthorizer authz = new ZTSAuthorizer(null);
        assertTrue(authz.matchRole("domain", roles, "domain:role\\.role.*", authRoles));
    }

    @Test
    public void testAccessRoleBasedFailure() {
        DataStore dataStore = Mockito.mock(DataStore.class);
        DataCache domain = Mockito.mock(DataCache.class);
        DomainData domainData = Mockito.mock(DomainData.class);
        Mockito.when(domain.getDomainData()).thenReturn(domainData);
        Mockito.when(domainData.getName()).thenReturn("athenz");
        Mockito.when(dataStore.getDataCache("athenz")).thenReturn(domain);
        ZTSAuthorizer authz = new ZTSAuthorizer(dataStore);
        Principal principal = Mockito.mock(Principal.class);
        // with role based principal, the full name is the domain name
        // for the failure case we're going to return a different value
        Mockito.when(principal.getFullName()).thenReturn("sports");
        Mockito.when(principal.getRoles()).thenReturn(List.of("readers"));
        assertFalse(authz.access("introspect", "athenz:token", principal, null));
    }

    @Test
    public void testAccessRoleBased() {
        DataStore dataStore = Mockito.mock(DataStore.class);
        DataCache domain = Mockito.mock(DataCache.class);

        DomainData domainData = Mockito.mock(DomainData.class);
        Mockito.when(domain.getDomainData()).thenReturn(domainData);
        Mockito.when(domainData.getName()).thenReturn("athenz");
        SignedPolicies signedPolicies = Mockito.mock(SignedPolicies.class);
        DomainPolicies domainPolicies = Mockito.mock(DomainPolicies.class);
        Policy policy = new Policy().setName("policy1").setActive(true)
                .setAssertions(List.of(new Assertion().setRole("athenz:role.introspect").setResource("athenz:token").setAction("introspect")));
        Mockito.when(domainPolicies.getPolicies()).thenReturn(List.of(policy));
        Mockito.when(signedPolicies.getContents()).thenReturn(domainPolicies);
        Mockito.when(domainData.getPolicies()).thenReturn(signedPolicies);

        Role role = new Role().setName("athenz:role.introspect");
        Mockito.when(domainData.getRoles()).thenReturn(List.of(role));

        Mockito.when(dataStore.getDataCache("athenz")).thenReturn(domain);
        ZTSAuthorizer authz = new ZTSAuthorizer(dataStore);

        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getFullName()).thenReturn("athenz");
        Mockito.when(principal.getRoles()).thenReturn(List.of("introspect"));
        assertTrue(authz.access("introspect", "athenz:token", principal, null));
        assertFalse(authz.access("introspect", "athenz:resource", principal, null));
        assertFalse(authz.access("update", "athenz:token", principal, null));
    }
}
