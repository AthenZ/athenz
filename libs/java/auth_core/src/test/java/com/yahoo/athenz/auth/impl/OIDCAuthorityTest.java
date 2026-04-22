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
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yahoo.athenz.auth.Principal;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static org.testng.Assert.*;

public class OIDCAuthorityTest {

    private static final String ISSUER = "https://oauth.id.jumpcloud.com/";
    private static final String AUDIENCE = "test-client-id";
    private static final String EMAIL_DOMAIN = "@example.com";
    private static final String PROPERTY_PREFIX = "athenz.auth.oidc";

    private RSAKey rsaKey;
    private JWSSigner signer;
    private OIDCAuthority authority;

    @BeforeMethod
    public void setUp() throws JOSEException {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key-1").generate();
        signer = new RSASSASigner(rsaKey);

        authority = new OIDCAuthority();
        authority.setJwtProcessor(buildTestProcessor());
        authority.setIssuer(ISSUER);
        authority.setAudience(AUDIENCE);
        authority.setEmailDomain(EMAIL_DOMAIN);
        authority.setClaimMapping(OIDCAuthority.DEFAULT_CLAIM_MAPPING);
        authority.setPrincipalDomain(OIDCAuthority.DEFAULT_DOMAIN);
        authority.setAuthorityId("Auth-OIDC-jumpcloud");
        authority.setValidUsernamePattern(Pattern.compile(OIDCAuthority.DEFAULT_USERNAME_PATTERN));
    }

    /**
     * Build a JWT processor that verifies signatures against {@link #rsaKey}.
     * Used by {@link #setUp} and by tests that construct a second authority
     * instance (for example those exercising {@code initialize()}).
     */
    private ConfigurableJWTProcessor<SecurityContext> buildTestProcessor() {
        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(
                Set.of(JWSAlgorithm.RS256),
                new ImmutableJWKSet<>(new JWKSet(rsaKey.toPublicJWK()))));
        return processor;
    }

    private void clearSystemProperties() {
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_ISSUER);
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_AUDIENCE);
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_EMAIL_DOMAIN);
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_CLAIM_MAPPING);
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_DOMAIN);
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_NAME);
        System.clearProperty(PROPERTY_PREFIX + "." + OIDCAuthority.PROP_USERNAME_PATTERN);
    }

    // ---------------------------------------------------------------
    // Basic accessors
    // ---------------------------------------------------------------

    @Test
    public void testGetters() {
        assertEquals(authority.getID(), "Auth-OIDC-jumpcloud");
        assertEquals(authority.getDomain(), "user");
        assertEquals(authority.getHeader(), "Authorization");
        assertEquals(authority.getAuthenticateChallenge(), "Bearer realm=\"athenz\"");
        assertTrue(authority.allowAuthorization());
    }

    @Test
    public void testPropertyPrefixDefault() {
        OIDCAuthority instance = new OIDCAuthority();
        assertEquals(instance.propertyPrefix(), "athenz.auth.oidc");
    }

    // ---------------------------------------------------------------
    // Successful authentication scenarios
    // ---------------------------------------------------------------

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        Date now = new Date();
        String token = createToken(ISSUER, AUDIENCE, "gv@example.com", now,
                new Date(now.getTime() + 3600_000));

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + token, "10.0.0.1", "GET", errMsg);

        assertNotNull(principal, "Expected non-null principal, error: " + errMsg);
        assertEquals(principal.getDomain(), "user");
        assertEquals(principal.getName(), "gv");
        assertEquals(principal.getFullName(), "user.gv");
        assertEquals(principal.getIssueTime(), now.getTime() / 1000);
        assertSame(principal.getAuthority(), authority);
    }

    @Test
    public void testMixedCaseUsername() throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("GV@example.com"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "gv");
    }

    @Test
    public void testMixedCaseDomain() throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("gv@Example.COM"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "gv");
    }

    @Test
    public void testAudienceAsListIncludesExpected() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(List.of("other-client", AUDIENCE))
                .claim("email", "gv@example.com")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "gv");
    }

    @Test
    public void testValidUsernameWithDigit() throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("gv2@example.com"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "gv2");
    }

    @Test
    public void testCustomPrincipalDomain() throws Exception {
        authority.setPrincipalDomain("myusers");
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("gv@example.com"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getDomain(), "myusers");
        assertEquals(principal.getFullName(), "myusers.gv");
    }

    // ---------------------------------------------------------------
    // Bearer header handling
    // ---------------------------------------------------------------

    @Test
    public void testNonBearerCredentials() {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Basic dXNlcjpwYXNz", "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("do not start with 'Bearer '"));
    }

    @Test
    public void testNullCredentials() {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(null, "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("do not start with 'Bearer '"));
    }

    @Test
    public void testEmptyBearerToken() {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer ", "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("no token after 'Bearer '"));
    }

    @Test
    public void testNullErrMsgDoesNotThrow() {
        assertNull(authority.authenticate("Basic foo", "10.0.0.1", "GET", null));
    }

    // ---------------------------------------------------------------
    // Token validation failures
    // ---------------------------------------------------------------

    @Test
    public void testInvalidJwt() {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer not-a-valid-jwt", "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("failed to parse JWT"));
    }

    @Test
    public void testWrongIssuerBailsOutEarly() throws Exception {
        String token = createToken("https://evil.example.com/", AUDIENCE, "gv@example.com",
                new Date(), new Date(System.currentTimeMillis() + 3600_000));
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + token, "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("issuer mismatch"));
    }

    @Test
    public void testWrongAudience() throws Exception {
        String token = createToken(ISSUER, "wrong-client-id", "gv@example.com",
                new Date(), new Date(System.currentTimeMillis() + 3600_000));
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + token, "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("does not contain expected"));
    }

    @Test
    public void testMissingAudience() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .claim("email", "gv@example.com")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("does not contain expected"));
    }

    @Test
    public void testExpiredToken() throws Exception {
        Date past = new Date(System.currentTimeMillis() - 7200_000);
        Date expired = new Date(System.currentTimeMillis() - 3600_000);
        String token = createToken(ISSUER, AUDIENCE, "gv@example.com", past, expired);
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + token, "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("JWT validation failed"));
    }

    @Test
    public void testTokenSignedWithWrongKey() throws Exception {
        RSAKey wrongKey = new RSAKeyGenerator(2048).keyID("wrong-key").generate();
        JWSSigner wrongSigner = new RSASSASigner(wrongKey);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("email", "gv@example.com")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("wrong-key").build(), claims);
        jwt.sign(wrongSigner);

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + jwt.serialize(), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("JWT validation failed"));
    }

    // ---------------------------------------------------------------
    // Claim extraction (email mapping)
    // ---------------------------------------------------------------

    @Test
    public void testMissingEmailClaim() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject("user-id-123")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("missing claim 'email'"));
    }

    @Test
    public void testWrongEmailDomain() throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("gv@evil.com"), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("does not end with"));
    }

    @Test
    public void testEmailNotVerified() throws Exception {
        String token = createTokenWithEmailVerified("gv@example.com", false);
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + token, "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("email not verified"));
    }

    @Test
    public void testEmailVerifiedTrue() throws Exception {
        String token = createTokenWithEmailVerified("gv@example.com", true);
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + token, "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "gv");
    }

    @Test
    public void testEmailVerifiedAbsent() throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("gv@example.com"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
    }

    @Test
    public void testEmailEmptyUsername() throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("@example.com"), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("invalid username"));
    }

    @Test
    public void testEmailClaimIsNotString() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("email", 42)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("failed to parse claim 'email'"));
    }

    @Test
    public void testEmailVerifiedClaimIsNotBoolean() throws Exception {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("email", "gv@example.com")
                .claim("email_verified", "not-a-boolean")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("failed to parse email_verified"));
    }

    // ---------------------------------------------------------------
    // Claim mapping to a non-email claim
    // ---------------------------------------------------------------

    @Test
    public void testAlternateClaimMapping() throws Exception {
        authority.setClaimMapping("preferred_username");
        authority.setEmailDomain(null);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("preferred_username", "alice")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "alice");
    }

    @Test
    public void testAlternateClaimMappingIsLowercased() throws Exception {
        authority.setClaimMapping("preferred_username");
        authority.setEmailDomain(null);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("preferred_username", "ALICE")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "alice");
    }

    @Test
    public void testAlternateClaimMappingMissingClaim() throws Exception {
        authority.setClaimMapping("preferred_username");
        authority.setEmailDomain(null);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("missing claim 'preferred_username'"));
    }

    @Test
    public void testAlternateClaimMappingSkipsEmailVerified() throws Exception {
        authority.setClaimMapping("preferred_username");
        authority.setEmailDomain(null);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("preferred_username", "alice")
                .claim("email_verified", false)
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "alice");
    }

    // ---------------------------------------------------------------
    // Username pattern validation
    // ---------------------------------------------------------------

    @Test
    public void testUsernameWithDotsRejected() throws Exception {
        assertInvalidUsername("first.last@example.com");
    }

    @Test
    public void testUsernameWithPlusRejected() throws Exception {
        assertInvalidUsername("user+tag@example.com");
    }

    @Test
    public void testUsernameWithHyphenRejected() throws Exception {
        assertInvalidUsername("my-user@example.com");
    }

    @Test
    public void testUsernameWithUnderscoreRejected() throws Exception {
        assertInvalidUsername("my_user@example.com");
    }

    @Test
    public void testUsernameStartingWithDigitRejected() throws Exception {
        assertInvalidUsername("1user@example.com");
    }

    private void assertInvalidUsername(String email) throws Exception {
        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken(email), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("invalid username"));
    }

    // ---------------------------------------------------------------
    // Configurable username pattern
    // ---------------------------------------------------------------

    @Test
    public void testCustomPatternAcceptsDottedUsername() throws Exception {
        authority.setValidUsernamePattern(Pattern.compile("[a-z0-9][a-z0-9._-]*"));

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("first.last@example.com"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "first.last");
    }

    @Test
    public void testCustomPatternAcceptsUnderscoreAndHyphen() throws Exception {
        authority.setValidUsernamePattern(Pattern.compile("[a-z0-9][a-z0-9._-]*"));

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + createValidToken("my_user-name@example.com"), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "my_user-name");
    }

    @Test
    public void testCustomPatternStillRejectsMismatch() throws Exception {
        // Permissive pattern still excludes '@' so an unstripped email fails.
        authority.setValidUsernamePattern(Pattern.compile("[a-z0-9][a-z0-9._-]*"));
        authority.setClaimMapping("preferred_username");
        authority.setEmailDomain(null);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("preferred_username", "bad@value")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("invalid username"));
    }

    @Test
    public void testInitializeLoadsUsernamePatternFromProperty() throws Exception {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        System.setProperty(PROPERTY_PREFIX + ".username_pattern", "[a-z0-9][a-z0-9._-]*");
        try {
            OIDCAuthority instance = newInstanceWithTestKey();
            instance.initialize();

            StringBuilder errMsg = new StringBuilder();
            Principal principal = instance.authenticate(
                    "Bearer " + createValidToken("first.last@example.com"), "10.0.0.1", "GET", errMsg);
            assertNotNull(principal, errMsg.toString());
            assertEquals(principal.getName(), "first.last");
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeUsesDefaultPatternWhenPropertyAbsent() throws Exception {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        try {
            OIDCAuthority instance = newInstanceWithTestKey();
            instance.initialize();

            // The default pattern rejects dotted usernames.
            StringBuilder errMsg = new StringBuilder();
            Principal principal = instance.authenticate(
                    "Bearer " + createValidToken("first.last@example.com"), "10.0.0.1", "GET", errMsg);
            assertNull(principal);
            assertTrue(errMsg.toString().contains("invalid username"));
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeRejectsInvalidRegex() {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        System.setProperty(PROPERTY_PREFIX + ".username_pattern", "[invalid(");
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.setJwtProcessor(new DefaultJWTProcessor<>());
            instance.initialize();
            fail("Expected IllegalStateException for invalid regex");
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("username_pattern"));
            assertTrue(ex.getMessage().contains("[invalid("));
            assertTrue(ex.getCause() instanceof java.util.regex.PatternSyntaxException,
                    "Expected PatternSyntaxException cause, got: " + ex.getCause());
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeTreatsEmptyPatternAsDefault() throws Exception {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        System.setProperty(PROPERTY_PREFIX + ".username_pattern", "");
        try {
            OIDCAuthority instance = newInstanceWithTestKey();
            instance.initialize();

            // Default pattern accepts a simple username, proving empty didn't
            // leak through as Pattern.compile("").
            StringBuilder errMsg = new StringBuilder();
            Principal principal = instance.authenticate(
                    "Bearer " + createValidToken("gv@example.com"), "10.0.0.1", "GET", errMsg);
            assertNotNull(principal, errMsg.toString());
            assertEquals(principal.getName(), "gv");
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testDefaultPatternRejectsDottedNonEmailClaim() throws Exception {
        authority.setClaimMapping("preferred_username");
        authority.setEmailDomain(null);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("preferred_username", "first.last")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate("Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNull(principal);
        assertTrue(errMsg.toString().contains("invalid username"));
    }

    /**
     * Build an OIDCAuthority instance wired with the test JWT processor, so
     * tests that call initialize() can still authenticate tokens produced by
     * the test helpers.
     */
    private OIDCAuthority newInstanceWithTestKey() {
        OIDCAuthority instance = new OIDCAuthority();
        instance.setJwtProcessor(buildTestProcessor());
        return instance;
    }

    // ---------------------------------------------------------------
    // initialize() — system property loading & validation
    // ---------------------------------------------------------------

    @Test
    public void testInitializeRequiresIssuer() {
        clearSystemProperties();
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.initialize();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("issuer"));
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeRequiresAudience() {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.initialize();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("audience"));
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeRequiresEmailDomainWhenMappingIsEmail() {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.setJwtProcessor(new DefaultJWTProcessor<>()); // bypass JWKS discovery
            instance.initialize();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("email_domain"));
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeAllowsMissingEmailDomainForOtherClaim() {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".claim_mapping", "preferred_username");
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.setJwtProcessor(new DefaultJWTProcessor<>()); // bypass JWKS discovery
            instance.initialize();
            assertEquals(instance.getID(), "Auth-OIDC-jumpcloud");
            assertEquals(instance.getDomain(), "user");
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeAcceptsIssuerWithoutTrailingSlash() {
        // The iss claim must match the configured issuer byte-for-byte; Google
        // and Okta issuer URLs omit the trailing slash, JumpCloud and Auth0
        // include it. initialize() must preserve the configured form.
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", "https://accounts.google.com");
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.setJwtProcessor(new DefaultJWTProcessor<>()); // bypass JWKS discovery
            instance.initialize();
            assertEquals(instance.getID(), "Auth-OIDC-google");
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testIssuerWithoutTrailingSlashMatchesTokenIss() throws Exception {
        // Operator configures Google-style issuer (no trailing slash); tokens
        // must authenticate even though the iss claim also lacks a slash.
        final String noSlashIssuer = "https://accounts.google.com";
        authority.setIssuer(noSlashIssuer);

        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(noSlashIssuer)
                .audience(AUDIENCE)
                .claim("email", "gv@example.com")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = authority.authenticate(
                "Bearer " + sign(claims), "10.0.0.1", "GET", errMsg);
        assertNotNull(principal, errMsg.toString());
        assertEquals(principal.getName(), "gv");
    }

    @Test
    public void testInitializeRejectsNonHttpsIssuer() {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", "http://insecure.example.com/");
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.setJwtProcessor(new DefaultJWTProcessor<>());
            instance.initialize();
            fail("Expected IllegalStateException for non-HTTPS issuer");
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("must use https"));
            assertTrue(ex.getMessage().contains("http://insecure.example.com/"));
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeUsesConfiguredName() {
        clearSystemProperties();
        System.setProperty(PROPERTY_PREFIX + ".issuer", ISSUER);
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        System.setProperty(PROPERTY_PREFIX + ".name", "my-idp");
        try {
            OIDCAuthority instance = new OIDCAuthority();
            instance.setJwtProcessor(new DefaultJWTProcessor<>());
            instance.initialize();
            assertEquals(instance.getID(), "Auth-OIDC-my-idp");
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testInitializeDiscoversJwksUriFailure() {
        clearSystemProperties();
        // Use an unreachable URL so OIDC discovery fails deterministically.
        // Port 1 is closed, so the connection fails regardless of scheme.
        System.setProperty(PROPERTY_PREFIX + ".issuer", "https://127.0.0.1:1/");
        System.setProperty(PROPERTY_PREFIX + ".audience", AUDIENCE);
        System.setProperty(PROPERTY_PREFIX + ".email_domain", EMAIL_DOMAIN);
        try {
            new OIDCAuthority().initialize();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException ex) {
            assertTrue(ex.getMessage().contains("Failed to discover JWKS URI"));
        } finally {
            clearSystemProperties();
        }
    }

    @Test
    public void testSubclassOverridesPropertyPrefix() {
        final String customPrefix = "athenz.auth.oidc.okta";
        System.setProperty(customPrefix + ".issuer", ISSUER);
        System.setProperty(customPrefix + ".audience", AUDIENCE);
        System.setProperty(customPrefix + ".email_domain", EMAIL_DOMAIN);
        System.setProperty(customPrefix + ".name", "okta");
        try {
            OIDCAuthority instance = new OIDCAuthority() {
                @Override protected String propertyPrefix() { return customPrefix; }
            };
            instance.setJwtProcessor(new DefaultJWTProcessor<>());
            instance.initialize();
            assertEquals(instance.getID(), "Auth-OIDC-okta");
        } finally {
            System.clearProperty(customPrefix + ".issuer");
            System.clearProperty(customPrefix + ".audience");
            System.clearProperty(customPrefix + ".email_domain");
            System.clearProperty(customPrefix + ".name");
        }
    }

    // ---------------------------------------------------------------
    // Authority name derivation from issuer host
    // ---------------------------------------------------------------

    @Test
    public void testDeriveNameFromIssuerStandardHosts() {
        assertEquals(OIDCAuthority.deriveNameFromIssuer("https://oauth.id.jumpcloud.com/"), "jumpcloud");
        assertEquals(OIDCAuthority.deriveNameFromIssuer("https://accounts.google.com/"), "google");
        assertEquals(OIDCAuthority.deriveNameFromIssuer("https://login.microsoftonline.com/"), "microsoftonline");
        assertEquals(OIDCAuthority.deriveNameFromIssuer("https://dev-123.okta.com/"), "okta");
    }

    @Test
    public void testDeriveNameFromIssuerShortHost() {
        assertEquals(OIDCAuthority.deriveNameFromIssuer("https://localhost/"), "localhost");
    }

    @Test
    public void testDeriveNameFromIssuerLowercasesResult() {
        assertEquals(OIDCAuthority.deriveNameFromIssuer("https://LOGIN.EXAMPLE.COM/"), "example");
    }

    @Test
    public void testDeriveNameFromIssuerInvalidUrl() {
        // Malformed URL (bad authority); falls back to "default".
        assertEquals(OIDCAuthority.deriveNameFromIssuer("ht!tp://[bad"), "default");
    }

    @Test
    public void testDeriveNameFromIssuerNoHost() {
        // URI with no host component.
        assertEquals(OIDCAuthority.deriveNameFromIssuer("file:///tmp/config"), "default");
    }

    // ---------------------------------------------------------------
    // JWT helpers
    // ---------------------------------------------------------------

    private String createValidToken(String email) throws JOSEException {
        Date now = new Date();
        return createToken(ISSUER, AUDIENCE, email, now, new Date(now.getTime() + 3600_000));
    }

    private String createTokenWithEmailVerified(String email, boolean emailVerified) throws JOSEException {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .claim("email", email)
                .claim("email_verified", emailVerified)
                .subject("user-id-123")
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 3600_000))
                .build();
        return sign(claims);
    }

    private String createToken(String issuer, String audience, String email,
                               Date issueTime, Date expirationTime) throws JOSEException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .claim("email", email)
                .subject("user-id-123")
                .issueTime(issueTime)
                .expirationTime(expirationTime)
                .build();
        return sign(claims);
    }

    private String sign(JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                claims);
        jwt.sign(signer);
        return jwt.serialize();
    }
}
