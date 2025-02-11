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

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AccessTokenBodyTest {

    @Test
    public void testAccessTokenBody() {

        AccessTokenBody body = new AccessTokenBody("grant_type=client_credentials&scope=coretech:role.writers"
                + "&authorization_details=details&expires_in=100&proxy_principal_spiffe_uris=");
        assertNotNull(body);
        assertEquals(body.getGrantType(), "client_credentials");
        assertEquals(body.getScope(), "coretech:role.writers");
        assertEquals(body.getAuthzDetails(), "details");
        assertEquals(body.getExpiryTime(), 100);
        assertNull(body.getProxyPrincipalsSpiffeUris());
    }

    @Test
    public void testAccessTokenBodyInvalidGrant() {

        try {
            new AccessTokenBody("grant_type=unknown&scope=coretech:role.writers"
                    + "&authorization_details=details");
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid grant request: unknown");
        }
    }

    @Test
    public void testAccessTokenBodyEmptyScope() {

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=&expiry_time=100");
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid request: no scope provided");
        }
    }

    @Test
    public void testAccessTokenBodyValidSpiffeUri() {

        // first valid uri test

        AccessTokenBody body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service");
        assertNotNull(body);
        assertEquals(body.getGrantType(), "client_credentials");
        assertEquals(body.getScope(), "test");
        assertEquals(body.getProxyPrincipalsSpiffeUris().size(), 1);
        assertEquals(body.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with leading space

        body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris= spiffe://data/sa/service");
        assertNotNull(body);
        assertEquals(body.getProxyPrincipalsSpiffeUris().get(0), "spiffe://data/sa/service");

        // uri with multiple values

        body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service,spiffe://sports/sa/api");
        assertNotNull(body);
        assertEquals(body.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));

        // uri with spaces around the separator

        body = new AccessTokenBody("grant_type=client_credentials&scope=test"
                + "&proxy_principal_spiffe_uris=spiffe://data/sa/service , spiffe://sports/sa/api");
        assertNotNull(body);
        assertEquals(body.getProxyPrincipalsSpiffeUris().size(), 2);
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://data/sa/service"));
        assertTrue(body.getProxyPrincipalsSpiffeUris().contains("spiffe://sports/sa/api"));
    }

    @Test
    public void testAccessTokenBodyInvalidSpiffeUri() {
        try {
            new AccessTokenBody("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=https://athenz.io");
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://athenz/sa/service,https://athenz.io");
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: https://athenz.io");
        }

        try {
            new AccessTokenBody("grant_type=client_credentials&scope=test&proxy_principal_spiffe_uris=spiffe://a .io");
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid spiffe uri specified: spiffe://a .io");
        }
    }
}
