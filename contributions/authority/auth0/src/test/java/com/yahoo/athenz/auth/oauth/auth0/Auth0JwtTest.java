/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.auth.oauth.auth0;

import static org.testng.Assert.*;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.LinkedHashMap;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;

public class Auth0JwtTest {

    private final Key secretKey = Keys.hmacShaKeyFor("secret_key_secret_key_secret_key".getBytes(StandardCharsets.UTF_8));
    private final JwtParser parser = Jwts.parserBuilder().setSigningKey(secretKey).build();

    @Test
    public void testAuth0Jwt() {
        assertThrows(NullPointerException.class, () -> new Auth0Jwt(null));
        assertNotNull(new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().setSubject("subject").signWith(secretKey).compact())));
    }

    @Test
    public void testGetSubject() {
        Auth0Jwt jwt;

        jwt  = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().claim("null", "null").signWith(secretKey).compact()));
        assertNull(jwt.getSubject());
        jwt = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().setSubject("github|1234567").signWith(secretKey).compact()));
        assertEquals(jwt.getSubject(), "user.github-1234567");
        jwt = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().setSubject("GITHUB|1234567").signWith(secretKey).compact()));
        assertEquals(jwt.getSubject(), "user.github-1234567");
    }

    @Test
    public void testGetClientId() {
        Auth0Jwt jwt;

        jwt  = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().setSubject("subject").signWith(secretKey).compact()));
        assertNull(jwt.getClientId());
        jwt = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().claim("https://myapp.example.com/client_id", "client_id").signWith(secretKey).compact()));
        assertEquals(jwt.getClientId(), "client_id");
    }

    @Test
    public void testGetCertificateThumbprint() {
        Auth0Jwt jwt;

        jwt  = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().setSubject("subject").signWith(secretKey).compact()));
        assertNull(jwt.getCertificateThumbprint());
        jwt = new Auth0Jwt(parser.parseClaimsJws(Jwts.builder().claim("https://myapp.example.com/cnf", "string").signWith(secretKey).compact()));
        assertNull(jwt.getCertificateThumbprint());

        // { "https://myapp.example.com/cnf": {} }
        jwt = new Auth0Jwt(parser.parseClaimsJws("eyJhbGciOiJIUzI1NiJ9.eyJodHRwczovL215YXBwLmV4YW1wbGUuY29tL2NuZiI6e319.E9C0TQFvCKFdxWpJ-Q4HzXLX6ySLt2XymbdMdebjcXU"));
        assertNull(jwt.getCertificateThumbprint());
        // { "https://myapp.example.com/cnf": { "x5t#S256": "cert_hash" } }
        jwt = new Auth0Jwt(parser.parseClaimsJws("eyJhbGciOiJIUzI1NiJ9.eyJodHRwczovL215YXBwLmV4YW1wbGUuY29tL2NuZiI6eyJ4NXQjUzI1NiI6ImNlcnRfaGFzaCJ9fQ.wGIpUNocgVjGUVSXgsO22dFzaG06NxB9aPIAz2FbC94"));
        assertEquals(jwt.getCertificateThumbprint(), "cert_hash");
    }

    @Test
    public void testStaticGetterSetter() {
        // getters
        assertEquals(Auth0Jwt.getClaimClientId(), "https://myapp.example.com/client_id");
        assertEquals(Auth0Jwt.getClaimConfirm(), "https://myapp.example.com/cnf");
        assertEquals(Auth0Jwt.getUserDomain(), "user");

        // setters
        Auth0Jwt.setClaimClientId("claim_client_id");
        assertEquals(Auth0Jwt.getClaimClientId(), "claim_client_id");
        Auth0Jwt.setClaimConfirm("claim_confirm");
        assertEquals(Auth0Jwt.getClaimConfirm(), "claim_confirm");
        Auth0Jwt.setUserDomain("user_domain");
        assertEquals(Auth0Jwt.getUserDomain(), "user_domain");
    }

}
