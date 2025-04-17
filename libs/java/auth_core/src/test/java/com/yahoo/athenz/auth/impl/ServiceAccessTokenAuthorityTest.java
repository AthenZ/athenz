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

package com.yahoo.athenz.auth.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.util.Crypto;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.testng.Assert.*;

public class ServiceAccessTokenAuthorityTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    @Test
    public void testServiceAccessTokenAuthority() {
        ServiceAccessTokenAuthority serviceAccessTokenAuthority = new ServiceAccessTokenAuthority();
        assertNotNull(serviceAccessTokenAuthority);
        serviceAccessTokenAuthority.initialize();
        assertEquals(serviceAccessTokenAuthority.getID(), "Auth-SvcAccessToken");
        assertNull(serviceAccessTokenAuthority.getDomain());
        assertEquals(serviceAccessTokenAuthority.getHeader(), "Authorization");
        assertEquals(serviceAccessTokenAuthority.getAuthenticateChallenge(), "Basic realm=\"athenz\"");
    }

    @Test
    public void testServiceAccessTokenAuthenticateFailures() {
        ServiceAccessTokenAuthority serviceAccessTokenAuthority = new ServiceAccessTokenAuthority();
        StringBuilder errMsg = new StringBuilder(512);
        assertNull(serviceAccessTokenAuthority.authenticate(null, null, null, errMsg));
        assertNotNull(errMsg);
        assertTrue(errMsg.toString().contains("No credentials provided"));
        errMsg.setLength(0);
        assertNull(serviceAccessTokenAuthority.authenticate("", null, null, errMsg));
        assertNotNull(errMsg);
        assertTrue(errMsg.toString().contains("No credentials provided"));
        errMsg.setLength(0);
        assertNull(serviceAccessTokenAuthority.authenticate("Token", null, null, errMsg));
        assertTrue(errMsg.toString().contains("No Bearer prefix"));
        errMsg.setLength(0);
        assertNull(serviceAccessTokenAuthority.authenticate("BearerToken", null, null, errMsg));
        assertNotNull(errMsg);
        assertTrue(errMsg.toString().contains("No Bearer prefix"));
        errMsg.setLength(0);
        assertNull(serviceAccessTokenAuthority.authenticate("Bearer Invalid-Token", null, null, errMsg));
        assertNotNull(errMsg);
        assertTrue(errMsg.toString().contains("Invalid token: exc=Unable to parse token"));
    }

    @Test
    public void testServiceAccessTokenAuthenticate() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("athenz.api")
                .audience("https://athenz.io")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        ServiceAccessTokenAuthority serviceAccessTokenAuthority = getServiceAccessTokenAuthority();
        StringBuilder errMsg = new StringBuilder(512);
        Principal principal = serviceAccessTokenAuthority.authenticate("Bearer " + token, null, null, errMsg);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getName(), "api");
        assertEquals(principal.getCredentials(), "Bearer " + token);
        assertEquals(principal.getIssueTime(), now);
    }

    @Test
    public void testServiceAccessTokenAuthenticateAthenzIssuer() throws JOSEException {

        long now = System.currentTimeMillis() / 1000;
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) privateKey);
        List<String> roles = List.of("read", "write");
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("athenz.api")
                .jwtID("id001")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .notBeforeTime(Date.from(Instant.ofEpochSecond(now)))
                .issuer("https://athenz.io")
                .audience("athenz")
                .claim(OAuth2Token.CLAIM_AUTH_TIME, now)
                .claim(OAuth2Token.CLAIM_VERSION, 1)
                .claim(AccessToken.CLAIM_SCOPE, roles)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("eckey1").build(), claimsSet);
        signedJWT.sign(signer);
        final String token = signedJWT.serialize();

        ServiceAccessTokenAuthority serviceAccessTokenAuthority = getServiceAccessTokenAuthority();
        StringBuilder errMsg = new StringBuilder(512);
        Principal principal = serviceAccessTokenAuthority.authenticate("Bearer " + token, null, null, errMsg);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getRolePrincipalName(), "athenz.api");
        assertEquals(principal.getCredentials(), "Bearer " + token);
        assertEquals(principal.getRoles(), roles);
    }

    private ServiceAccessTokenAuthority getServiceAccessTokenAuthority() {
        ServiceAccessTokenAuthority serviceAccessTokenAuthority = new ServiceAccessTokenAuthority();
        serviceAccessTokenAuthority.setKeyStore(new KeyStore() {
            @Override
            public String getPublicKey(String domain, String service, String keyId) {
                return null;
            }

            @Override
            public PublicKey getServicePublicKey(String domain, String service, String keyId) {
                if ((("athenz".equals(domain) && "api".equals(service)) ||
                        ("sys.auth".equals(domain) && "zts".equals(service))) && "eckey1".equals(keyId)) {
                    return Crypto.loadPublicKey(ecPublicKey);
                } else {
                    return null;
                }
            }
        });
        serviceAccessTokenAuthority.initialize();
        return serviceAccessTokenAuthority;
    }
}
