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
package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigCsv;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSTestUtils;
import org.testng.annotations.Test;

import java.util.Set;

import static org.testng.Assert.*;

public class OAuthTokenScopeTest {

    @Test
    public void testOauthTokenInvalidScope() {

        try {
            new OAuthTokenScope("scope", 0, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid value specified for max domains"));
        }
    }

    @Test
    public void testOauthTokenScopeMaxDomains() {

        try {
            new OAuthTokenScope("openid sports:domain weather:domain finance:domain", 2, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Domain limit: 2 has been reached"));
        }

        try {
            new OAuthTokenScope("openid sports:domain weather:domain introspect", 2, null, "finance");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Domain limit: 2 has been reached"));
        }

        OAuthTokenScope request = new OAuthTokenScope("openid sports:domain weather:domain finance:domain", 3, null, null);
        assertNotNull(request);
        Set<String> domains = request.getDomainNames();
        assertEquals(domains.size(), 3);
        assertTrue(domains.contains("sports"));
        assertTrue(domains.contains("weather"));
        assertTrue(domains.contains("finance"));

        request = new OAuthTokenScope("openid sports:domain weather:domain introspect", 3, null, "finance");
        assertNotNull(request);
        domains = request.getDomainNames();
        assertEquals(domains.size(), 3);
        assertTrue(domains.contains("sports"));
        assertTrue(domains.contains("weather"));
        assertTrue(domains.contains("finance"));
    }

    @Test
    public void testOauthTokenGetDomainName() {
        OAuthTokenScope request = new OAuthTokenScope("openid", 1, null, null);
        assertNull(request.getDomainName());

        request = new OAuthTokenScope("openid sports:domain weather:domain", 2, null, null);
        assertNull(request.getDomainName());

        request = new OAuthTokenScope("openid sports:domain", 2, null, null);
        assertNull(request.getDomainName());

        request = new OAuthTokenScope("openid sports:domain", 1, null, null);
        assertEquals(request.getDomainName(), "sports");

        request = new OAuthTokenScope("openid connect-id", 1, null, "sports");
        assertEquals(request.getDomainName(), "sports");
    }

    @Test
    public void testOauthTokenGetRoleNames() {
        OAuthTokenScope request = new OAuthTokenScope("openid", 1, null, null);
        assertNull(request.getRoleNames("sports"));

        request = new OAuthTokenScope("openid weather:role.test", 1, null, null);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getRoleNames("weather").length, 1);
        assertEquals(request.getRoleNames("weather")[0], "test");

        request = new OAuthTokenScope("openid weather:role.test weather:role.admin", 2, null, null);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getRoleNames("weather").length, 2);
        assertTrue(ZTSTestUtils.validArrayMember(request.getRoleNames("weather"), "test"));
        assertTrue(ZTSTestUtils.validArrayMember(request.getRoleNames("weather"), "admin"));

        request = new OAuthTokenScope("connect-id", 1, null, "sports");
        assertEquals(request.getDomainName(), "sports");
        assertEquals(request.getRoleNames("sports").length, 1);
        assertEquals(request.getRoleNames("sports")[0], "connect-id");

        request = new OAuthTokenScope("connect-id introspect", 1, null, "sports");
        assertEquals(request.getDomainName(), "sports");
        assertEquals(request.getRoleNames("sports").length, 2);
        assertTrue(ZTSTestUtils.validArrayMember(request.getRoleNames("sports"), "connect-id"));
        assertTrue(ZTSTestUtils.validArrayMember(request.getRoleNames("sports"), "introspect"));

        request = new OAuthTokenScope("openid connect-id introspect", 1, null, "sports");
        assertTrue(request.isOpenIdScope());
        assertEquals(request.getDomainName(), "sports");
        assertEquals(request.getRoleNames("sports").length, 2);
        assertTrue(ZTSTestUtils.validArrayMember(request.getRoleNames("sports"), "connect-id"));
        assertTrue(ZTSTestUtils.validArrayMember(request.getRoleNames("sports"), "introspect"));
    }

    @Test
    public void testOauthTokenMultipleIdenticalServiceNames() {
        OAuthTokenScope request = new OAuthTokenScope("openid sports:service.api sports:service.api", 1, null, null);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getServiceName(), "api");
        assertEquals(request.getDomainName(), "sports");
    }

    @Test
    public void testOauthTokenScopeMaxDomainsWithAuthorizedRoles() {

        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.reader,system:role.writer");

        // without authorized roles we'll have failure

        try {
            new OAuthTokenScope("openid system:role.reader sports:service.api", 1, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Multiple domains in scope"));
        }

        // with authorized list, we're good

        OAuthTokenScope request = new OAuthTokenScope("openid system:role.reader sports:service.api",
                1, systemAllowedRoles, null);
        Set<String> domains = request.getDomainNames();
        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("sports"));
        assertTrue(domains.contains("system"));
        assertEquals(request.getRoleNames("system")[0], "reader");

        // with 2 authorized roles - not allowed

        try {
            new OAuthTokenScope("openid system:role.reader sports:service.api system:role.writer", 1, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Multiple domains in scope"));
        }

        // standard single role without any system should work fine

        request = new OAuthTokenScope("openid sports:service.api", 1, systemAllowedRoles, null);
        domains = request.getDomainNames();
        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("sports"));
    }

    @Test
    public void testIsSystemAllowedRolesNullConfig() {
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);
        assertFalse(scope.isSystemAllowedRoles(null, "system:role.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesExactMatch() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.reader,system:role.writer");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.admin"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesWildcardPrefix() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.*");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.admin"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.any-role-name"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:group.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesWildcardSuffix() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("*.role.reader");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "weather:role.reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:group.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesWildcardMiddle() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:*.reader");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:group.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:service.reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesMultipleWildcards() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("*:role.*");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.admin"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "weather:role.any"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:group.reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:service.api"));
    }

    @Test
    public void testIsSystemAllowedRolesMixedExactAndWildcard() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.reader,system:role.writer,*:role.admin");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        // Exact matches
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));

        // Wildcard matches
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.admin"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.admin"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "weather:role.admin"));

        // Non-matches
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.other"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesEmptyConfig() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "any:role.any"));
    }

    @Test
    public void testIsSystemAllowedRolesWhitespaceHandling() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv(" system:role.reader , system:role.writer ");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        // DynamicConfigCsv trims whitespace, so these should match
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
    }

    @Test
    public void testIsSystemAllowedRolesSpecialCharacters() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.test-role,system:role.test_role,*:role.test.role");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.test-role"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.test_role"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.test.role"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.test.role"));
    }

    @Test
    public void testIsSystemAllowedRolesWildcardOnly() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("*");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        // Wildcard * should match everything
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.writer"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "any:any.anything"));
    }

    @Test
    public void testIsSystemAllowedRolesWildcardAtStart() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("*reader");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
    }

    @Test
    public void testIsSystemAllowedRolesWildcardAtEnd() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:*");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:group.writer"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:service.api"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:anything"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
    }

    @Test
    public void testIsSystemAllowedRolesMultipleWildcardPatterns() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.*,*:role.reader,*:*.admin");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        // Matches first pattern
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));

        // Matches second pattern
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.reader"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "weather:role.reader"));

        // Matches third pattern
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.admin"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:group.admin"));
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "weather:service.admin"));

        // No match
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "sports:role.writer"));
    }

    @Test
    public void testIsSystemAllowedRolesExactMatchTakesPrecedence() {
        // Even if there's a wildcard pattern, exact match should work
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.reader,system:role.*");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        // Exact match should be found first (via hasItem)
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
        // Wildcard should also match
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.writer"));
    }

    @Test
    public void testIsSystemAllowedRolesCaseSensitive() {
        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.Reader");
        OAuthTokenScope scope = new OAuthTokenScope("openid", 1, null, null);

        // Should be case-sensitive
        assertTrue(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.Reader"));
        assertFalse(scope.isSystemAllowedRoles(systemAllowedRoles, "system:role.reader"));
    }
}
