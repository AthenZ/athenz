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
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;

import static org.testng.Assert.*;

public class ServiceIdentityJWTSecretProviderTest {

    private static final String OAUTH_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String TEST_CLIENT_ID = "test.client.id";
    private static final String TEST_AUDIENCE = "https://test.audience.com";
    private static final int TEST_EXPIRY_TIME_SECS = 3600;
    private byte[] testSecret;

    @BeforeMethod
    public void setUp() {
        testSecret = "test-secret-key-for-jwt-signing-unit-tests".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    public void testConstructor() {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        assertNotNull(provider);
        assertEquals(provider.clientId, TEST_CLIENT_ID);
        assertEquals(provider.audience, TEST_AUDIENCE);
        assertEquals(provider.expiryTimeSecs, TEST_EXPIRY_TIME_SECS);
        assertEquals(provider.secret, testSecret);
        assertEquals(provider.jwsAlgorithm, JWSAlgorithm.HS256);
    }

    @Test
    public void testGetClientAssertionType() {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionType = provider.getClientAssertionType();
        assertEquals(assertionType, OAUTH_ASSERTION_TYPE_JWT_BEARER);
    }

    @Test
    public void testGetIdentity() {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        Principal identity = provider.getIdentity("domain", "service");
        assertNull(identity);
    }

    @Test
    public void testGetClientAssertionValueSuccess() throws ParseException, JOSEException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);
        assertFalse(assertionValue.isEmpty());

        // Parse and verify the JWT
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        assertNotNull(signedJWT);

        // Verify the signature
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(testSecret);
        assertTrue(signedJWT.verify(verifier));

        // Verify the claims
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);
        assertEquals(claimsSet.getSubject(), TEST_CLIENT_ID);
        assertEquals(claimsSet.getIssuer(), TEST_CLIENT_ID);
        assertTrue(claimsSet.getAudience().contains(TEST_AUDIENCE));

        // Verify timestamps
        long now = System.currentTimeMillis() / 1000;
        Date issueTime = claimsSet.getIssueTime();
        Date expirationTime = claimsSet.getExpirationTime();
        assertNotNull(issueTime);
        assertNotNull(expirationTime);

        long issueTimeSecs = issueTime.getTime() / 1000;
        long expirationTimeSecs = expirationTime.getTime() / 1000;

        // Allow 5 seconds tolerance for timing
        assertTrue(Math.abs(issueTimeSecs - now) < 5);
        assertEquals(expirationTimeSecs, issueTimeSecs + TEST_EXPIRY_TIME_SECS);
    }

    @Test
    public void testGetClientAssertionValueWithDifferentExpiryTime() throws ParseException {
        int customExpiryTime = 7200; // 2 hours
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, customExpiryTime, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        Date issueTime = claimsSet.getIssueTime();
        Date expirationTime = claimsSet.getExpirationTime();
        long issueTimeSecs = issueTime.getTime() / 1000;
        long expirationTimeSecs = expirationTime.getTime() / 1000;

        assertEquals(expirationTimeSecs - issueTimeSecs, customExpiryTime);
    }

    @Test
    public void testGetClientAssertionValueWithDifferentClientId() throws ParseException {
        String customClientId = "custom.client.id";
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                customClientId, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertEquals(claimsSet.getSubject(), customClientId);
        assertEquals(claimsSet.getIssuer(), customClientId);
    }

    @Test
    public void testGetClientAssertionValueWithDifferentAudience() throws ParseException {
        String customAudience = "https://custom.audience.com";
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, customAudience, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertTrue(claimsSet.getAudience().contains(customAudience));
    }

    @Test
    public void testSetKeyAlgorithmHS256() throws ParseException, JOSEException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        provider.setKeyAlgorithm("HS256");
        assertEquals(provider.jwsAlgorithm, JWSAlgorithm.HS256);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();
        assertEquals(header.getAlgorithm(), JWSAlgorithm.HS256);

        // Verify signature still works
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(testSecret);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testSetKeyAlgorithmHS384() throws ParseException, JOSEException {

        byte[] secret = "test-secret-key-for-jwt-signing-unit-tests-to-be-used-with-hs384-tests".getBytes(StandardCharsets.UTF_8);

        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, secret);

        provider.setKeyAlgorithm("HS384");
        assertEquals(provider.jwsAlgorithm, JWSAlgorithm.HS384);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();
        assertEquals(header.getAlgorithm(), JWSAlgorithm.HS384);

        // Verify signature with HS384
        MACVerifier verifier = new MACVerifier(secret);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testGetClientAssertionValueMultipleCalls() throws ParseException, JOSEException, InterruptedException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue1 = provider.getClientAssertionValue();
        Thread.sleep(1000);
        String assertionValue2 = provider.getClientAssertionValue();

        // Each call should generate a new token (different issue time)
        assertNotEquals(assertionValue1, assertionValue2);

        // Both should be valid
        SignedJWT signedJWT1 = SignedJWT.parse(assertionValue1);
        SignedJWT signedJWT2 = SignedJWT.parse(assertionValue2);

        JWSVerifier verifier = JwtsHelper.getJWSVerifier(testSecret);
        assertTrue(signedJWT1.verify(verifier));
        assertTrue(signedJWT2.verify(verifier));
    }

    @Test
    public void testGetClientAssertionValueWithZeroExpiryTime() throws ParseException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, 0, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        Date issueTime = claimsSet.getIssueTime();
        Date expirationTime = claimsSet.getExpirationTime();
        long issueTimeSecs = issueTime.getTime() / 1000;
        long expirationTimeSecs = expirationTime.getTime() / 1000;

        assertEquals(expirationTimeSecs, issueTimeSecs);
    }

    @Test
    public void testGetClientAssertionValueWithNegativeExpiryTime() throws ParseException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, -100, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        Date issueTime = claimsSet.getIssueTime();
        Date expirationTime = claimsSet.getExpirationTime();
        long issueTimeSecs = issueTime.getTime() / 1000;
        long expirationTimeSecs = expirationTime.getTime() / 1000;

        // Expiration time should be less than issue time
        assertTrue(expirationTimeSecs < issueTimeSecs);
    }

    @Test
    public void testGetClientAssertionValueWithEmptySecret() {
        byte[] emptySecret = new byte[0];
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, emptySecret);

        // Should handle empty secret gracefully (may return null or throw exception)
        provider.getClientAssertionValue();
        // The implementation may return null on error, or it may still generate a token
        // depending on MACSigner behavior with empty secret
    }

    @Test
    public void testGetClientAssertionValueWithNullSecret() {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, null);

        // Should handle null secret gracefully
        String assertionValue = provider.getClientAssertionValue();
        // The implementation may return null on error
        assertNull(assertionValue);
    }

    @Test
    public void testJWTHeaderAlgorithm() throws ParseException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getAlgorithm(), JWSAlgorithm.HS256);
    }

    @Test
    public void testJWTClaimsSetStructure() throws ParseException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        // Verify all required claims are present
        assertNotNull(claimsSet.getSubject());
        assertNotNull(claimsSet.getIssuer());
        assertNotNull(claimsSet.getAudience());
        assertNotNull(claimsSet.getIssueTime());
        assertNotNull(claimsSet.getExpirationTime());

        // Verify no unexpected claims
        assertNull(claimsSet.getJWTID());
        assertNull(claimsSet.getNotBeforeTime());
    }

    @Test
    public void testJWTVerificationWithWrongSecret() throws ParseException, JOSEException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);

        // Try to verify with wrong secret
        byte[] wrongSecret = "wrong-secret-that-is-not-going-to-work".getBytes(StandardCharsets.UTF_8);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(wrongSecret);
        assertFalse(signedJWT.verify(verifier));
    }

    @Test
    public void testJWTVerificationWithCorrectSecret() throws ParseException, JOSEException {
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);

        // Verify with correct secret
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(testSecret);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testGetClientAssertionValueWithLongSecret() throws ParseException, JOSEException {
        // Test with a very long secret
        byte[] longSecret = "a".repeat(1000).getBytes(StandardCharsets.UTF_8);

        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, longSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(longSecret);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testGetClientAssertionValueWithSpecialCharactersInClientId() throws ParseException {
        String specialClientId = "test.client-id_with+special@chars";
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                specialClientId, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertEquals(claimsSet.getSubject(), specialClientId);
        assertEquals(claimsSet.getIssuer(), specialClientId);
    }

    @Test
    public void testGetClientAssertionValueWithSpecialCharactersInAudience() throws ParseException {
        String specialAudience = "https://test.audience.com/path?query=value&other=test";
        ServiceIdentityJWTSecretProvider provider = new ServiceIdentityJWTSecretProvider(
                TEST_CLIENT_ID, specialAudience, TEST_EXPIRY_TIME_SECS, testSecret);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertTrue(claimsSet.getAudience().contains(specialAudience));
    }
}

