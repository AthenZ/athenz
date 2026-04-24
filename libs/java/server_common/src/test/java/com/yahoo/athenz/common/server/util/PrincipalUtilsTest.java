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
package com.yahoo.athenz.common.server.util;

import com.yahoo.athenz.auth.Principal;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;

public class PrincipalUtilsTest {

    @Test
    public void testPrincipalType() {
        // Set different strings between user and home domain
        String userDomain = "user";
        String userDomain2 = "user2";
        String homeDomain = "home";
        String headlessDomain = "headless";
        String topLevelDomain = "athenz";
        String groupSep = ":group";
        List<String> addlUserCheckDomainPrefixList = Arrays.asList(userDomain2);

        // ALL
        assertEquals(PrincipalUtils.principalType("*", userDomain, addlUserCheckDomainPrefixList,
            headlessDomain), Principal.Type.ALL);
        // GROUP
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(PrincipalUtils.principalType(topLevelDomain + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ":group.test:ext.test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        // USER
        assertEquals(PrincipalUtils.principalType(userDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        assertEquals(PrincipalUtils.principalType(userDomain2 + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        // USER_HEADLESS
        assertEquals(PrincipalUtils.principalType(headlessDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER_HEADLESS);
        // SERVICE
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        // EXTERNAL
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ":ext.oidc-user", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.EXTERNAL);
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe:ext.github-identity", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.EXTERNAL);
        assertEquals(PrincipalUtils.principalType("sports:ext.test:group.entry", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.EXTERNAL);

        // Set same strings between user and home domain.
        userDomain = "personal";
        homeDomain = userDomain;

        // ALL
        assertEquals(PrincipalUtils.principalType("*", userDomain, addlUserCheckDomainPrefixList,
            headlessDomain), Principal.Type.ALL);
        // GROUP
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        assertEquals(PrincipalUtils.principalType(topLevelDomain + groupSep + ".test-group", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.GROUP);
        // USER
        assertEquals(PrincipalUtils.principalType(userDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        assertEquals(PrincipalUtils.principalType(userDomain2 + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER);
        // USER_HEADLESS
        assertEquals(PrincipalUtils.principalType(headlessDomain + ".joe", userDomain, addlUserCheckDomainPrefixList,
                headlessDomain), Principal.Type.USER_HEADLESS);
        // SERVICE
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe" + ".test-service", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.SERVICE);
        // EXTERNAL
        assertEquals(PrincipalUtils.principalType(topLevelDomain + ":ext.oidc-user", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.EXTERNAL);
        assertEquals(PrincipalUtils.principalType(homeDomain + ".joe:ext.github-identity", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.EXTERNAL);
        assertEquals(PrincipalUtils.principalType("sports:ext.test:group.entry", userDomain,
                addlUserCheckDomainPrefixList, headlessDomain), Principal.Type.EXTERNAL);
    }

    @Test
    public void testCreatePrincipalForNameGroupPrincipal() {
        assertNull(PrincipalUtils.createPrincipalForName("athenz:group.dev-team", "user", null));
        assertNull(PrincipalUtils.createPrincipalForName("home.joe:group.readers", "user", "home"));
        assertNull(PrincipalUtils.createPrincipalForName("sports:group.writers", "user", "alias"));
    }

    @Test
    public void testCreatePrincipalForNameExternalPrincipal() {
        Principal principal = PrincipalUtils.createPrincipalForName("athenz:ext.oidc-user", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getFullName(), "athenz:ext.oidc-user");

        principal = PrincipalUtils.createPrincipalForName("home.joe:ext.github-identity", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "home.joe");
        assertEquals(principal.getFullName(), "home.joe:ext.github-identity");
    }

    @Test
    public void testCreatePrincipalForNameExternalWithGroupInName() {
        Principal principal = PrincipalUtils.createPrincipalForName("sports:ext.test:group.entry", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "sports");
        assertEquals(principal.getFullName(), "sports:ext.test:group.entry");
    }

    @Test
    public void testCreatePrincipalForNameSimpleUser() {
        Principal principal = PrincipalUtils.createPrincipalForName("joe", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "joe");
        assertEquals(principal.getFullName(), "user.joe");
    }

    @Test
    public void testCreatePrincipalForNameUserWithDomain() {
        Principal principal = PrincipalUtils.createPrincipalForName("user.joe", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "joe");
        assertEquals(principal.getFullName(), "user.joe");
    }

    @Test
    public void testCreatePrincipalForNameServicePrincipal() {
        Principal principal = PrincipalUtils.createPrincipalForName("athenz.api", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getName(), "api");
        assertEquals(principal.getFullName(), "athenz.api");
    }

    @Test
    public void testCreatePrincipalForNameSubdomainService() {
        Principal principal = PrincipalUtils.createPrincipalForName("home.joe.storage", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "home.joe");
        assertEquals(principal.getName(), "storage");
        assertEquals(principal.getFullName(), "home.joe.storage");
    }

    @Test
    public void testCreatePrincipalForNameUserDomainAlias() {
        Principal principal = PrincipalUtils.createPrincipalForName("alias.joe", "user", "alias");
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "joe");
        assertEquals(principal.getFullName(), "user.joe");
    }

    @Test
    public void testCreatePrincipalForNameUserDomainAliasNoMatch() {
        Principal principal = PrincipalUtils.createPrincipalForName("other.joe", "user", "alias");
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "other");
        assertEquals(principal.getName(), "joe");
        assertEquals(principal.getFullName(), "other.joe");
    }

    @Test
    public void testCreatePrincipalForNameNullAlias() {
        Principal principal = PrincipalUtils.createPrincipalForName("home.joe", "user", null);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "home");
        assertEquals(principal.getName(), "joe");
        assertEquals(principal.getFullName(), "home.joe");
    }
}
