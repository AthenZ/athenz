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

public class OpenIDConfigTest {

    @Test
    public void testOpenIDConfig() {

        OpenIDConfig cfg1 = new OpenIDConfig();
        OpenIDConfig cfg2 = new OpenIDConfig();

        cfg1.setAuthorization_endpoint("authz-endpoint");
        cfg1.setIssuer("issuer");
        cfg1.setJwks_uri("jwks-uri");
        cfg1.setClaims_supported(Collections.singletonList("openid"));
        cfg1.setId_token_signing_alg_values_supported(Collections.singletonList("RS256"));
        cfg1.setResponse_types_supported(Collections.singletonList("token"));
        cfg1.setSubject_types_supported(Collections.singletonList("public"));

        cfg2.setAuthorization_endpoint("authz-endpoint");
        cfg2.setIssuer("issuer");
        cfg2.setJwks_uri("jwks-uri");
        cfg2.setClaims_supported(Collections.singletonList("openid"));
        cfg2.setId_token_signing_alg_values_supported(Collections.singletonList("RS256"));
        cfg2.setResponse_types_supported(Collections.singletonList("token"));
        cfg2.setSubject_types_supported(Collections.singletonList("public"));

        assertEquals(cfg1, cfg2);
        assertEquals(cfg1, cfg1);
        assertNotEquals(null, cfg1);
        assertNotEquals("openidconfig", cfg1);

        assertEquals("authz-endpoint", cfg1.getAuthorization_endpoint());
        assertEquals("issuer", cfg1.getIssuer());
        assertEquals("jwks-uri", cfg1.getJwks_uri());
        assertEquals(Collections.singletonList("openid"), cfg1.getClaims_supported());
        assertEquals(Collections.singletonList("RS256"), cfg1.getId_token_signing_alg_values_supported());
        assertEquals(Collections.singletonList("token"), cfg1.getResponse_types_supported());
        assertEquals(Collections.singletonList("public"), cfg1.getSubject_types_supported());

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

        cfg2.setClaims_supported(Collections.singletonList("openid2"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setClaims_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setClaims_supported(Collections.singletonList("openid"));

        cfg2.setId_token_signing_alg_values_supported(Collections.singletonList("ES256"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setId_token_signing_alg_values_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setId_token_signing_alg_values_supported(Collections.singletonList("RS256"));

        cfg2.setResponse_types_supported(Collections.singletonList("code"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setResponse_types_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setResponse_types_supported(Collections.singletonList("token"));

        cfg2.setSubject_types_supported(Collections.singletonList("pairwise"));
        assertNotEquals(cfg1, cfg2);
        cfg2.setSubject_types_supported(null);
        assertNotEquals(cfg1, cfg2);
        cfg2.setSubject_types_supported(Collections.singletonList("public"));
    }
}
