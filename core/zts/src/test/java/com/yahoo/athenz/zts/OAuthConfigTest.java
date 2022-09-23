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

import org.testng.annotations.Test;

import java.util.Collections;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class OAuthConfigTest {

    @Test
    public void testOAuthConfig() {

        OAuthConfig cfg1 = new OAuthConfig();
        OAuthConfig cfg2 = new OAuthConfig();

        cfg1.setAuthorization_endpoint("authz-endpoint");
        cfg1.setToken_endpoint("token-endpoint");
        cfg1.setIssuer("issuer");
        cfg1.setJwks_uri("jwks-uri");
        cfg1.setGrant_types_supported(Collections.singletonList("grant"));
        cfg1.setToken_endpoint_auth_signing_alg_values_supported(Collections.singletonList("RS256"));
        cfg1.setResponse_types_supported(Collections.singletonList("token"));

        cfg2.setAuthorization_endpoint("authz-endpoint");
        cfg2.setToken_endpoint("token-endpoint");
        cfg2.setIssuer("issuer");
        cfg2.setJwks_uri("jwks-uri");
        cfg2.setGrant_types_supported(Collections.singletonList("grant"));
        cfg2.setToken_endpoint_auth_signing_alg_values_supported(Collections.singletonList("RS256"));
        cfg2.setResponse_types_supported(Collections.singletonList("token"));

        assertEquals(cfg1, cfg2);
        assertEquals(cfg1, cfg1);
        assertNotEquals(null, cfg1);
        assertNotEquals("OAuthconfig", cfg1);

        assertEquals("authz-endpoint", cfg1.getAuthorization_endpoint());
        assertEquals("token-endpoint", cfg1.getToken_endpoint());
        assertEquals("issuer", cfg1.getIssuer());
        assertEquals("jwks-uri", cfg1.getJwks_uri());
        assertEquals(Collections.singletonList("grant"), cfg1.getGrant_types_supported());
        assertEquals(Collections.singletonList("RS256"), cfg1.getToken_endpoint_auth_signing_alg_values_supported());
        assertEquals(Collections.singletonList("token"), cfg1.getResponse_types_supported());

        cfg2.setToken_endpoint("token-endpoint2");
        assertNotEquals(cfg1, cfg2);
        cfg2.setToken_endpoint(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setToken_endpoint("token-endpoint");

        cfg2.setAuthorization_endpoint("authz-endpoint2");
        assertNotEquals(cfg1, cfg2);
        cfg2.setAuthorization_endpoint(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setAuthorization_endpoint("authz-endpoint");

        cfg2.setIssuer("issuer2");
        assertNotEquals(cfg1, cfg2);
        cfg2.setIssuer(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setIssuer("issuer");

        cfg2.setJwks_uri("jwks-uri2");
        assertNotEquals(cfg1, cfg2);
        cfg2.setJwks_uri(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setJwks_uri("jwks-uri");

        cfg2.setGrant_types_supported(Collections.singletonList("grant2"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setGrant_types_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setGrant_types_supported(Collections.singletonList("grant"));

        cfg2.setToken_endpoint_auth_signing_alg_values_supported(Collections.singletonList("ES256"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setToken_endpoint_auth_signing_alg_values_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setToken_endpoint_auth_signing_alg_values_supported(Collections.singletonList("RS256"));

        cfg2.setResponse_types_supported(Collections.singletonList("code"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setResponse_types_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setResponse_types_supported(Collections.singletonList("token"));
    }
}
