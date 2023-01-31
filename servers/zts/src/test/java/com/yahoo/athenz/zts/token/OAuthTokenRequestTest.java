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

import com.yahoo.athenz.zts.ResourceException;
import org.testng.annotations.Test;

import java.util.Set;

import static org.testng.Assert.*;

public class OAuthTokenRequestTest {

    @Test
    public void testOauthTokenInvalidRequest() {

        try {
            new OAuthTokenRequest("scope", 0);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid value specified for max domains"));
        }
    }

    @Test
    public void testOauthTokenRequestMaxDomains() {

        try {
            new OAuthTokenRequest("openid sports:domain weather:domain finance:domain", 2);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Domain limit: 2 has been reached"));
        }

        OAuthTokenRequest request = new OAuthTokenRequest("openid sports:domain weather:domain finance:domain", 3);
        assertNotNull(request);
        Set<String> domains = request.getDomainNames();
        assertEquals(domains.size(), 3);
        assertTrue(domains.contains("sports"));
        assertTrue(domains.contains("weather"));
        assertTrue(domains.contains("finance"));
    }

    @Test
    public void testOauthTokenGetDomainName() {
        OAuthTokenRequest request = new OAuthTokenRequest("openid", 1);
        assertNull(request.getDomainName());

        request = new OAuthTokenRequest("openid sports:domain weather:domain", 2);
        assertNull(request.getDomainName());

        request = new OAuthTokenRequest("openid sports:domain", 2);
        assertNull(request.getDomainName());

        request = new OAuthTokenRequest("openid sports:domain", 1);
        assertEquals(request.getDomainName(), "sports");
    }

    @Test
    public void testOauthTokenGetRoleNames() {
        OAuthTokenRequest request = new OAuthTokenRequest("openid", 1);
        assertNull(request.getRoleNames("sports"));

        request = new OAuthTokenRequest("openid weather:role.test", 1);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getRoleNames("weather").length, 1);
        assertEquals(request.getRoleNames("weather")[0], "test");

        request = new OAuthTokenRequest("openid weather:role.test weather:role.admin", 2);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getRoleNames("weather").length, 2);
        assertEquals(request.getRoleNames("weather")[0], "test");
        assertEquals(request.getRoleNames("weather")[1], "admin");
    }

    @Test
    public void testOauthTokenMultipleIdenticalServiceNames() {
        OAuthTokenRequest request = new OAuthTokenRequest("openid sports:service.api sports:service.api", 1);
        assertNull(request.getRoleNames("sports"));
        assertEquals(request.getServiceName(), "api");
        assertEquals(request.getDomainName(), "sports");
    }
}
