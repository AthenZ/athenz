/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.pdp;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.common.server.pdp.authzen.Resource;
import com.yahoo.athenz.common.server.pdp.authzen.Subject;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.*;

public class AuthZenRequestBuilderTest {

    private final AuthZenRequestBuilder builder = new AuthZenRequestBuilder("user");

    @Test
    public void testSubjectFromPrincipal() {
        Authority authority = Mockito.mock(Authority.class);
        Mockito.when(authority.getID()).thenReturn("Auth-X509");
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("sports", "api", "creds", 0, authority);
        principal.setX509Certificate(Mockito.mock(X509Certificate.class));
        principal.setAuthorizedService("sports.backend");

        Subject subject = builder.subject(principal);
        assertEquals(subject.getType(), AuthZenRequestBuilder.SUBJECT_SERVICE);
        assertEquals(subject.getId(), "sports.api");
        Map<String, Object> props = subject.getProperties();
        assertEquals(props.get("domain"), "sports");
        assertEquals(props.get("name"), "api");
        assertEquals(props.get("authority"), "Auth-X509");
        assertEquals(props.get("authorized_service"), "sports.backend");
        assertEquals(props.get("role_identity"), false);
        assertEquals(props.get("mtls"), true);

        Principal user = SimplePrincipal.create("user", "joe", "creds", 0, null);
        subject = builder.subject(user);
        assertEquals(subject.getType(), AuthZenRequestBuilder.SUBJECT_USER);
        assertFalse(subject.getProperties().containsKey("authority"));
        assertEquals(subject.getProperties().get("mtls"), false);

        Principal rolePrincipal = SimplePrincipal.create("sports", "creds", List.of("readers"), null);
        assertEquals(builder.subject(rolePrincipal).getProperties().get("role_identity"), true);
    }

    @Test
    public void testSubjectFromName() {
        Subject subject = builder.subject("user.joe");
        assertEquals(subject.getType(), AuthZenRequestBuilder.SUBJECT_USER);
        assertEquals(subject.getProperties().get("domain"), "user");
        assertEquals(subject.getProperties().get("name"), "joe");

        subject = builder.subject("nodomain");
        assertEquals(subject.getType(), AuthZenRequestBuilder.SUBJECT_SERVICE);
        assertEquals(subject.getProperties().get("domain"), "");
        assertEquals(subject.getProperties().get("name"), "nodomain");
    }

    @Test
    public void testResources() {
        Resource token = AuthZenRequestBuilder.tokenResource("sports", List.of("weather", "sports"));
        assertEquals(token.getType(), AuthZenRequestBuilder.RESOURCE_TOKEN);
        assertEquals(token.getId(), "sports");
        assertEquals(token.getProperties().get("token_type"), "access_token");
        assertEquals(token.getProperties().get("scope_domains"), List.of("sports", "weather"));

        Resource role = AuthZenRequestBuilder.roleResource("sports", "readers", false, null);
        assertEquals(role.getId(), "sports:role.readers");
        assertEquals(role.getProperties().get("defined"), false);
        assertFalse(role.getProperties().containsKey("rbac_granted"));

        Resource resource = AuthZenRequestBuilder.athenzResource("a:b");
        assertEquals(resource.getType(), AuthZenRequestBuilder.RESOURCE_ATHENZ);
        assertNull(resource.getProperties());

        assertEquals(AuthZenRequestBuilder.action("x").getName(), "x");
    }

    @Test
    public void testTokenClaims() {
        OAuth2Token token = Mockito.mock(OAuth2Token.class);
        Mockito.when(token.getIssuer()).thenReturn("https://athenz.io");
        Mockito.when(token.getSubject()).thenReturn("user.joe");
        Mockito.when(token.getAudience()).thenReturn("sports");
        Mockito.when(token.getClaim("scope")).thenReturn("sports:role.readers");
        Mockito.when(token.getClaim("client_id")).thenReturn("sports.api");
        Mockito.when(token.getJwtId()).thenReturn("jti-1");
        Mockito.when(token.getExpiryTime()).thenReturn(100L);
        Map<String, Object> claims = AuthZenRequestBuilder.tokenClaims(token);
        assertEquals(claims, Map.of("iss", "https://athenz.io", "sub", "user.joe", "aud", "sports",
                "scope", "sports:role.readers", "client_id", "sports.api", "jti", "jti-1", "exp", 100L));

        OAuth2Token empty = Mockito.mock(OAuth2Token.class);
        assertTrue(AuthZenRequestBuilder.tokenClaims(empty).isEmpty());
    }
}
