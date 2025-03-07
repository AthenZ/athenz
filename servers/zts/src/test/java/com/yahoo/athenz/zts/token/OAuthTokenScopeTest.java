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
import org.testng.annotations.Test;

import java.util.Set;

import static org.testng.Assert.*;

public class OAuthTokenScopeTest {

    @Test
    public void testOauthTokenInvalidScope() {

        try {
            new OAuthTokenScope("scope", 0, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid value specified for max domains"));
        }
    }

    @Test
    public void testOauthTokenScopeMaxDomains() {

        try {
            new OAuthTokenScope("openid sports:domain weather:domain finance:domain", 2, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Domain limit: 2 has been reached"));
        }

        OAuthTokenScope request = new OAuthTokenScope("openid sports:domain weather:domain finance:domain", 3, null);
        assertNotNull(request);
        Set<String> domains = request.getDomainNames();
        assertEquals(domains.size(), 3);
        assertTrue(domains.contains("sports"));
        assertTrue(domains.contains("weather"));
        assertTrue(domains.contains("finance"));
    }

    @Test
    public void testOauthTokenGetDomainName() {
        OAuthTokenScope request = new OAuthTokenScope("openid", 1, null);
        assertNull(request.getDomainName());

        request = new OAuthTokenScope("openid sports:domain weather:domain", 2, null);
        assertNull(request.getDomainName());

        request = new OAuthTokenScope("openid sports:domain", 2, null);
        assertNull(request.getDomainName());

        request = new OAuthTokenScope("openid sports:domain", 1, null);
        assertEquals(request.getDomainName(), "sports");
    }

    @Test
    public void testOauthTokenGetRoleNames() {
        OAuthTokenScope request = new OAuthTokenScope("openid", 1, null);
        assertNull(request.getRoleNames("sports"));

        request = new OAuthTokenScope("openid weather:role.test", 1, null);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getRoleNames("weather").length, 1);
        assertEquals(request.getRoleNames("weather")[0], "test");

        request = new OAuthTokenScope("openid weather:role.test weather:role.admin", 2, null);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getRoleNames("weather").length, 2);
        assertEquals(request.getRoleNames("weather")[0], "test");
        assertEquals(request.getRoleNames("weather")[1], "admin");
    }

    @Test
    public void testOauthTokenMultipleIdenticalServiceNames() {
        OAuthTokenScope request = new OAuthTokenScope("openid sports:service.api sports:service.api", 1, null);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getServiceName(), "api");
        assertEquals(request.getDomainName(), "sports");
    }

    @Test
    public void testOauthTokenScopeMaxDomainsWithAuthorizedRoles() {

        DynamicConfigCsv systemAllowedRoles = new DynamicConfigCsv("system:role.reader,system:role.writer");

        // without authorized roles we'll have failure

        try {
            new OAuthTokenScope("openid system:role.reader sports:service.api", 1, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Multiple domains in scope"));
        }

        // with authorized list, we're good

        OAuthTokenScope request = new OAuthTokenScope("openid system:role.reader sports:service.api",
                1, systemAllowedRoles);
        Set<String> domains = request.getDomainNames();
        assertEquals(domains.size(), 2);
        assertTrue(domains.contains("sports"));
        assertTrue(domains.contains("system"));
        assertEquals(request.getRoleNames("system")[0], "reader");

        // with 2 authorized roles - not allowed

        try {
            new OAuthTokenScope("openid system:role.reader sports:service.api system:role.writer", 1, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Multiple domains in scope"));
        }

        // standard single role without any system should work fine

        request = new OAuthTokenScope("openid sports:service.api", 1, systemAllowedRoles);
        domains = request.getDomainNames();
        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("sports"));
    }
}
