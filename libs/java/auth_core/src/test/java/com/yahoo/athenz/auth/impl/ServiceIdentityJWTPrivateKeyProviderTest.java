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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.text.ParseException;

import static org.testng.Assert.*;

public class ServiceIdentityJWTPrivateKeyProviderTest {

    private static final String OAUTH_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String TEST_CLIENT_ID = "test.client.id";
    private static final String TEST_AUDIENCE = "https://test.audience.com";
    private static final int TEST_EXPIRY_TIME_SECS = 3600;
    private static final String TEST_KEY_ID = "key-id-1";

    private final String rsaPrivateKeyPemFile = "./src/test/resources/unit_test_jwt_private.key";
    private final String ecPrivateKeyPemFile = "./src/test/resources/unit_test_ec_private.key";
    private File rsaPublicKeyFile;
    private File ecPublicKeyFile;

    @BeforeMethod
    public void setUp() throws IOException {
        rsaPublicKeyFile = new File("./src/test/resources/unit_test_jwt_public.key");
        ecPublicKeyFile = new File("./src/test/resources/ec_public.key");
    }

    @Test
    public void testConstructor() {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        assertNotNull(provider);
        assertEquals(provider.clientId, TEST_CLIENT_ID);
        assertEquals(provider.audience, TEST_AUDIENCE);
        assertEquals(provider.expiryTimeSecs, TEST_EXPIRY_TIME_SECS);
        assertEquals(provider.privateKeyPemFile, rsaPrivateKeyPemFile);
        assertEquals(provider.privateKeyId, TEST_KEY_ID);
        assertNull(provider.jwsAlgorithm); // Should be null initially
    }

    @Test
    public void testGetClientAssertionType() {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionType = provider.getClientAssertionType();
        assertEquals(assertionType, OAUTH_ASSERTION_TYPE_JWT_BEARER);
    }

    @Test
    public void testGetIdentity() {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        Principal identity = provider.getIdentity("domain", "service");
        assertNull(identity);
    }

    @Test
    public void testGetClientAssertionValueWithRSAKey() throws ParseException, JOSEException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);
        assertFalse(assertionValue.isEmpty());

        // Parse and verify the JWT
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        assertNotNull(signedJWT);

        // Verify the header contains the key ID
        JWSHeader header = signedJWT.getHeader();
        assertEquals(header.getKeyID(), TEST_KEY_ID);
        assertEquals(header.getAlgorithm(), JWSAlgorithm.RS256); // Default for RSA

        // Verify the signature using public key
        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));

        // Verify the claims
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);
        assertEquals(claimsSet.getSubject(), TEST_CLIENT_ID);
        assertEquals(claimsSet.getIssuer(), TEST_CLIENT_ID);
        assertTrue(claimsSet.getAudience().contains(TEST_AUDIENCE));

        // Verify timestamps
        long now = System.currentTimeMillis() / 1000;
        long issueTimeSecs = claimsSet.getIssueTime().getTime() / 1000;
        long expirationTimeSecs = claimsSet.getExpirationTime().getTime() / 1000;

        // Allow 5 seconds tolerance for timing
        assertTrue(Math.abs(issueTimeSecs - now) < 5);
        assertEquals(expirationTimeSecs, issueTimeSecs + TEST_EXPIRY_TIME_SECS);
    }

    @Test
    public void testGetClientAssertionValueWithECKey() throws ParseException, JOSEException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, ecPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);
        assertFalse(assertionValue.isEmpty());

        // Parse and verify the JWT
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        assertNotNull(signedJWT);

        // Verify the header contains the key ID
        JWSHeader header = signedJWT.getHeader();
        assertEquals(header.getKeyID(), TEST_KEY_ID);
        assertEquals(header.getAlgorithm(), JWSAlgorithm.ES256); // Default for EC

        // Verify the signature using public key
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));

        // Verify the claims
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);
        assertEquals(claimsSet.getSubject(), TEST_CLIENT_ID);
        assertEquals(claimsSet.getIssuer(), TEST_CLIENT_ID);
        assertTrue(claimsSet.getAudience().contains(TEST_AUDIENCE));
    }

    @Test
    public void testSetKeyAlgorithmRS256() throws ParseException, JOSEException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        provider.setKeyAlgorithm("RS256");
        assertEquals(provider.jwsAlgorithm, JWSAlgorithm.RS256);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();
        assertEquals(header.getAlgorithm(), JWSAlgorithm.RS256);
        assertEquals(header.getKeyID(), TEST_KEY_ID);

        // Verify signature still works
        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testSetKeyAlgorithmES256() throws ParseException, JOSEException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, ecPrivateKeyPemFile, TEST_KEY_ID);

        provider.setKeyAlgorithm("ES256");
        assertEquals(provider.jwsAlgorithm, JWSAlgorithm.ES256);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();
        assertEquals(header.getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(header.getKeyID(), TEST_KEY_ID);

        // Verify signature still works
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testSetKeyAlgorithmOverridesDefault() {
        // Test that setting algorithm overrides the default RSA->RS256 mapping
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        // Set to ES256 even though key is RSA (should use specified algorithm)
        provider.setKeyAlgorithm("ES256");
        assertEquals(provider.jwsAlgorithm, JWSAlgorithm.ES256);

        // This should fail because RSA key can't sign with ES256
        provider.getClientAssertionValue();
        // The implementation may return null or throw exception
        // depending on how it handles the mismatch
    }

    @Test
    public void testGetClientAssertionValueWithDifferentExpiryTime() throws ParseException, CryptoException {
        int customExpiryTime = 7200; // 2 hours
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, customExpiryTime, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        long issueTimeSecs = claimsSet.getIssueTime().getTime() / 1000;
        long expirationTimeSecs = claimsSet.getExpirationTime().getTime() / 1000;

        assertEquals(expirationTimeSecs - issueTimeSecs, customExpiryTime);
    }

    @Test
    public void testGetClientAssertionValueWithDifferentClientId() throws ParseException, CryptoException {
        String customClientId = "custom.client.id";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                customClientId, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertEquals(claimsSet.getSubject(), customClientId);
        assertEquals(claimsSet.getIssuer(), customClientId);
    }

    @Test
    public void testGetClientAssertionValueWithDifferentAudience() throws ParseException, CryptoException {
        String customAudience = "https://custom.audience.com";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, customAudience, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertTrue(claimsSet.getAudience().contains(customAudience));
    }

    @Test
    public void testGetClientAssertionValueWithDifferentKeyId() throws ParseException, CryptoException {
        String customKeyId = "custom-key-id-123";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, customKeyId);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getKeyID(), customKeyId);
    }

    @Test
    public void testGetClientAssertionValueMultipleCalls() throws ParseException, JOSEException,
            CryptoException, InterruptedException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue1 = provider.getClientAssertionValue();
        Thread.sleep(1000);
        String assertionValue2 = provider.getClientAssertionValue();

        // Each call should generate a new token (different issue time)
        assertNotEquals(assertionValue1, assertionValue2);

        // Both should be valid
        SignedJWT signedJWT1 = SignedJWT.parse(assertionValue1);
        SignedJWT signedJWT2 = SignedJWT.parse(assertionValue2);

        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
        assertTrue(signedJWT1.verify(verifier));
        assertTrue(signedJWT2.verify(verifier));
    }

    @Test
    public void testGetClientAssertionValueWithZeroExpiryTime() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, 0, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        long issueTimeSecs = claimsSet.getIssueTime().getTime() / 1000;
        long expirationTimeSecs = claimsSet.getExpirationTime().getTime() / 1000;

        assertEquals(expirationTimeSecs, issueTimeSecs);
    }

    @Test
    public void testGetClientAssertionValueWithNegativeExpiryTime() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, -100, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        long issueTimeSecs = claimsSet.getIssueTime().getTime() / 1000;
        long expirationTimeSecs = claimsSet.getExpirationTime().getTime() / 1000;

        // Expiration time should be less than issue time
        assertTrue(expirationTimeSecs < issueTimeSecs);
    }

    @Test
    public void testGetClientAssertionValueWithInvalidPrivateKey() {
        String invalidPrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nInvalidKey\n-----END PRIVATE KEY-----";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, invalidPrivateKeyPem, TEST_KEY_ID);

        // Should handle invalid key gracefully
        String assertionValue = provider.getClientAssertionValue();
        assertNull(assertionValue);
    }

    @Test
    public void testGetClientAssertionValueWithNullPrivateKey() {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, null, TEST_KEY_ID);

        // Should handle null key gracefully
        String assertionValue = provider.getClientAssertionValue();
        assertNull(assertionValue);
    }

    @Test
    public void testGetClientAssertionValueWithEmptyPrivateKey() {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, "", TEST_KEY_ID);

        // Should handle empty key gracefully
        String assertionValue = provider.getClientAssertionValue();
        assertNull(assertionValue);
    }

    @Test
    public void testJWTHeaderAlgorithmRSA() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getAlgorithm(), JWSAlgorithm.RS256);
        assertEquals(header.getKeyID(), TEST_KEY_ID);
    }

    @Test
    public void testJWTHeaderAlgorithmEC() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, ecPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(header.getKeyID(), TEST_KEY_ID);
    }

    @Test
    public void testJWTClaimsSetStructure() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

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
    public void testJWTVerificationWithWrongPublicKey() throws ParseException, JOSEException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);

        File publicKeyFile = new File("./src/test/resources/zts_public_k0.key");
        PublicKey wrongPublicKey = Crypto.loadPublicKey(publicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(wrongPublicKey);
        assertFalse(signedJWT.verify(verifier));
    }

    @Test
    public void testJWTVerificationWithCorrectPublicKey() throws ParseException, JOSEException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        SignedJWT signedJWT = SignedJWT.parse(assertionValue);

        // Verify with correct public key
        PublicKey publicKey = Crypto.loadPublicKey(rsaPublicKeyFile);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(publicKey);
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    public void testGetClientAssertionValueWithSpecialCharactersInClientId() throws ParseException, CryptoException {
        String specialClientId = "test.client-id_with+special@chars";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                specialClientId, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertEquals(claimsSet.getSubject(), specialClientId);
        assertEquals(claimsSet.getIssuer(), specialClientId);
    }

    @Test
    public void testGetClientAssertionValueWithSpecialCharactersInAudience() throws ParseException, CryptoException {
        String specialAudience = "https://test.audience.com/path?query=value&other=test";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, specialAudience, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertTrue(claimsSet.getAudience().contains(specialAudience));
    }

    @Test
    public void testGetClientAssertionValueWithSpecialCharactersInKeyId() throws ParseException, CryptoException {
        String specialKeyId = "key-id_with-special.chars@123";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, specialKeyId);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getKeyID(), specialKeyId);
    }

    @Test
    public void testDefaultAlgorithmSelectionRSA() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, TEST_KEY_ID);

        // Don't set algorithm explicitly - should default to RS256 for RSA key
        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getAlgorithm(), JWSAlgorithm.RS256);
    }

    @Test
    public void testDefaultAlgorithmSelectionEC() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, ecPrivateKeyPemFile, TEST_KEY_ID);

        // Don't set algorithm explicitly - should default to ES256 for EC key
        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        assertEquals(header.getAlgorithm(), JWSAlgorithm.ES256);
    }

    @Test
    public void testKeyIdInJWTHeader() throws ParseException, CryptoException {
        String keyId = "my-custom-key-id-12345";
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, keyId);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        // Verify key ID is present in header
        assertNotNull(header.getKeyID());
        assertEquals(header.getKeyID(), keyId);
    }

    @Test
    public void testGetClientAssertionValueWithNullKeyId() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, null);

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        // Key ID should be null in header if null was provided
        assertNull(header.getKeyID());
    }

    @Test
    public void testGetClientAssertionValueWithEmptyKeyId() throws ParseException, CryptoException {
        ServiceIdentityJWTPrivateKeyProvider provider = new ServiceIdentityJWTPrivateKeyProvider(
                TEST_CLIENT_ID, TEST_AUDIENCE, TEST_EXPIRY_TIME_SECS, rsaPrivateKeyPemFile, "");

        String assertionValue = provider.getClientAssertionValue();
        assertNotNull(assertionValue);

        SignedJWT signedJWT = SignedJWT.parse(assertionValue);
        JWSHeader header = signedJWT.getHeader();

        // Empty string key ID should be set in header
        assertEquals(header.getKeyID(), "");
    }
}

