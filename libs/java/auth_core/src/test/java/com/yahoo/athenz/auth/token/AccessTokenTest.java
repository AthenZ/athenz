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
package com.yahoo.athenz.auth.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

import static org.testng.Assert.*;

public class AccessTokenTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    void setAccessCommonFields(AccessToken accessToken, long now) {
        accessToken.setAuthTime(now);
        accessToken.setJwtId("jwt-id001");
        accessToken.setSubject("subject");
        accessToken.setUserId("userid");
        accessToken.setExpiryTime(now + 3600);
        accessToken.setIssueTime(now);
        accessToken.setClientId("mtls");
        accessToken.setAudience("coretech");
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");
        accessToken.setProxyPrincipal("proxy.user");
        accessToken.setConfirmEntry("x5t#uri", "spiffe://athenz/sa/api");
        accessToken.setAuthorizationDetails("[{\"type\":\"message_access\",\"data\":\"resource\"}]");

        try {
            Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            accessToken.setConfirmX509CertHash(cert);
        } catch (IOException ignored) {
            fail();
        }
    }

    AccessToken createAccessToken(long now) {

        AccessToken accessToken = new AccessToken();
        setAccessCommonFields(accessToken, now);
        accessToken.setScope(Collections.singletonList("readers"));

        return accessToken;
    }

    AccessToken createAccessTokenMultipleRoles(long now) {

        AccessToken accessToken = new AccessToken();
        setAccessCommonFields(accessToken, now);
        accessToken.setScope(Arrays.asList("readers", "writers"));

        return accessToken;
    }

    void validateAccessTokenCommon(AccessToken accessToken, long now) {
        assertEquals(now, accessToken.getAuthTime());
        assertEquals(accessToken.getSubject(), "subject");
        assertEquals(accessToken.getUserId(), "userid");
        assertEquals(accessToken.getExpiryTime(), now + 3600);
        assertEquals(accessToken.getIssueTime(), now);
        assertEquals(accessToken.getClientId(), "mtls");
        assertEquals(accessToken.getAudience(), "coretech");
        assertEquals(accessToken.getVersion(), 1);
        assertEquals(accessToken.getIssuer(), "athenz");
        assertEquals(accessToken.getProxyPrincipal(), "proxy.user");
        LinkedHashMap<String, Object> confirm = accessToken.getConfirm();
        assertNotNull(confirm);
        assertEquals(confirm.get("x5t#S256"), "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0");
        assertEquals(accessToken.getConfirmEntry("x5t#S256"), "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0");
        assertEquals(confirm.get("x5t#uri"), "spiffe://athenz/sa/api");
        assertEquals(accessToken.getConfirmEntry("x5t#uri"), "spiffe://athenz/sa/api");
        assertNull(accessToken.getConfirmEntry("unknown"));
        assertEquals(accessToken.getAuthorizationDetails(), "[{\"type\":\"message_access\",\"data\":\"resource\"}]");

        try {
            Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            final String cnfHash = (String) accessToken.getConfirmEntry(AccessToken.CLAIM_CONFIRM_X509_HASH);
            assertTrue(accessToken.confirmX509CertHash(cert, cnfHash));
        } catch (IOException ignored) {
            fail();
        }
    }

    void validateAccessToken(AccessToken accessToken, long now) {
        validateAccessTokenCommon(accessToken, now);
        assertEquals(accessToken.getScope().size(), 1);
        assertTrue(accessToken.getScope().contains("readers"));
        assertEquals(accessToken.getScopeStd(), "readers");
    }

    void validateAccessTokenMultipleRoles(AccessToken accessToken, long now) {
        validateAccessTokenCommon(accessToken, now);
        assertEquals(accessToken.getScope().size(), 2);
        assertTrue(accessToken.getScope().contains("readers"));
        assertTrue(accessToken.getScope().contains("writers"));
        assertEquals(accessToken.getScopeStd(), "readers writers");
        assertEquals(accessToken.getJwtId(), "jwt-id001");
    }

    private void resetConfProperty(final String oldConf) {
        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
    }

    @BeforeMethod
    public void setup() {
        AccessToken.setAccessTokenCertOffset(3600);
    }

    @Test
    public void testAccessToken() throws JOSEException, ParseException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // verify the getters

        validateAccessToken(accessToken, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        SignedJWT signedJWT = SignedJWT.parse(accessJws);
        assertTrue(signedJWT.verify(verifier));
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);

        assertEquals(claimsSet.getSubject(), "subject");
        assertEquals(JwtsHelper.getAudience(claimsSet), "coretech");
        assertEquals(claimsSet.getIssuer(), "athenz");
        assertEquals(claimsSet.getJWTID(), "jwt-id001");
        assertEquals(claimsSet.getStringClaim("scope"), "readers");
        List<String> scopes = claimsSet.getStringListClaim("scp");
        assertNotNull(scopes);
        assertEquals(scopes.size(), 1);
        assertEquals(scopes.get(0), "readers");
    }

    @Test
    public void testAccessTokenMultipleRoles() throws JOSEException, ParseException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessTokenMultipleRoles(now);

        // verify the getters

        validateAccessTokenMultipleRoles(accessToken, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        JWSVerifier verifier = new ECDSAVerifier((ECPublicKey) publicKey);
        SignedJWT signedJWT = SignedJWT.parse(accessJws);
        assertTrue(signedJWT.verify(verifier));
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        assertNotNull(claimsSet);

        assertEquals(claimsSet.getSubject(), "subject");
        assertEquals(JwtsHelper.getAudience(claimsSet), "coretech");
        assertEquals(claimsSet.getIssuer(), "athenz");
        assertEquals(claimsSet.getJWTID(), "jwt-id001");
        assertEquals(claimsSet.getStringClaim("scope"), "readers writers");
        List<String> scopes = claimsSet.getStringListClaim("scp");
        assertNotNull(scopes);
        assertEquals(scopes.size(), 2);
        assertEquals(scopes.get(0), "readers");
        assertEquals(scopes.get(1), "writers");
    }

    @Test
    public void testAccessTokenWithX509Cert() throws IOException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessToken checkToken = new AccessToken(accessJws, resolver, cert);
        validateAccessToken(checkToken, now);
    }

    @Test
    public void testAccessTokenWithMismatchX509Cert() throws IOException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        // use a different cert than one used for signing

        Path path = Paths.get("src/test/resources/rsa_public_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        try {
            new AccessToken(accessJws, resolver, cert);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("X.509 Certificate Confirmation failure"));
        }
    }

    @Test
    public void testAccessTokenSignedToken() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);
    }

    @Test
    public void testAccessTokenWithoutSignedToken() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        // remove the signature part from the token

        int idx = accessJws.lastIndexOf('.');
        final String unsignedJws = accessJws.substring(0, idx + 1);

        try {
            new AccessToken(unsignedJws, resolver);
            fail();
        } catch (CryptoException ignored) {
        }
    }

    @Test
    public void testAccessTokenWithNoneAlgorithm() {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        // now get the unsigned token with none algorithm

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(accessToken.subject)
                .jwtID(accessToken.jwtId)
                .issueTime(Date.from(Instant.ofEpochSecond(accessToken.issueTime)))
                .expirationTime(Date.from(Instant.ofEpochSecond(accessToken.expiryTime)))
                .issuer(accessToken.issuer)
                .audience(accessToken.audience)
                .claim(AccessToken.CLAIM_AUTH_TIME, accessToken.authTime)
                .claim(AccessToken.CLAIM_VERSION, accessToken.version)
                .claim(AccessToken.CLAIM_SCOPE, accessToken.getScope())
                .claim(AccessToken.CLAIM_SCOPE_STD, accessToken.getScopeStd())
                .claim(AccessToken.CLAIM_UID, accessToken.getUserId())
                .claim(AccessToken.CLAIM_CLIENT_ID, accessToken.getClientId())
                .claim(AccessToken.CLAIM_CONFIRM, accessToken.getConfirm())
                .claim(AccessToken.CLAIM_PROXY, accessToken.getProxyPrincipal())
                .claim(AccessToken.CLAIM_AUTHZ_DETAILS, accessToken.getAuthorizationDetails())
                .build();

        PlainJWT signedJWT = new PlainJWT(claimsSet);
        final String accessJws = signedJWT.serialize();

        // without a key resolver we should be able to parse the token

        AccessToken checkToken = new AccessToken(accessJws, (JwtsSigningKeyResolver) null);
        assertNotNull(checkToken);

        // with a key resolver we must get a failure

        try {
            final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
            JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

            new AccessToken(accessJws, resolver);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Unsecured (plain) JWTs are rejected"));
        }
    }

    @Test
    public void testAccessTokenSignedTokenPublicKey() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        AccessToken checkToken = new AccessToken(accessJws, Crypto.loadPublicKey(ecPublicKey));
        validateAccessToken(checkToken, now);
    }

    @Test
    public void testAccessTokenSignedTokenConfigFile() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);
    }

    @Test
    public void testAccessTokenSignedTokenOldConfigFile() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        final String confPath = "src/test/resources/athenz.conf";
        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, confPath);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("athenz-no-keys_jwk.conf")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);

        // without backup config we won't be able to parse it

        resolver = new JwtsSigningKeyResolver(jwksUri, null, null, true);
        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("no matching key(s) found"));
        }
        resetConfProperty(oldConf);
    }

    @Test
    public void testAccessTokenSignedTokenConfigFileUnknownKey() {
        testAccessTokenSignedTokenConfigFileNoKeys("athenz_jwks.conf");
        testAccessTokenSignedTokenConfigFileNoKeys("athenz-no-keys_jwk.conf");
        testAccessTokenSignedTokenConfigFileNoKeys("athenz-no-valid-keys_jwk.conf");
        testAccessTokenSignedTokenConfigFileNoKeys("");
        // passing invalid file that will generate parse exception
        testAccessTokenSignedTokenConfigFileNoKeys("arg_file");
    }

    void testAccessTokenSignedTokenConfigFileNoKeys(final String keyPath) {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey99", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource(keyPath)).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testAccessTokenSignedTokenServerKeys() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        String jwksUri = Objects.requireNonNull(classLoader.getResource("athenz_jwks.conf")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);

        // with the no keys jwk file we should get a failure

        jwksUri = Objects.requireNonNull(classLoader.getResource("athenz-no-keys_jwk.conf")).toString();
        resolver = new JwtsSigningKeyResolver(jwksUri, null);
        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("no matching key(s) found"));
        }

        // now verify with sia config file we should get success

        System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_JWK_ATHENZ_CONF,
                new File("src/test/resources/athenz_sia_jwks.conf").getCanonicalPath());
        resolver = new JwtsSigningKeyResolver(jwksUri, null);

        checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);

        System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_JWK_ATHENZ_CONF);
    }

    @Test
    public void testAccessTokenSignedTokenServerKeysFailure() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        SSLContext sslContext = Mockito.mock(SSLContext.class);
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("athenz-no-keys_jwk.conf")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, sslContext);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("no matching key(s) found"));
        }
    }

    @Test
    public void testAccessTokenExpired() {

        long now = System.currentTimeMillis() / 1000;

        // we allow clock skew of 60 seconds so we'll go
        // back 3600 + 61 to make our token expired
        AccessToken accessToken = createAccessToken(now - 3661);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Expired"));
        }

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        try {
            new AccessToken(accessJws, publicKey);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Expired"));
        }
    }

    @Test
    public void testAccessTokenNullConfirm() {
        AccessToken accessToken = new AccessToken();
        assertNull(accessToken.getConfirm());
        assertNull(accessToken.getConfirmEntry("key"));
    }

    @Test
    public void testGetX509CertificateHash() throws CertificateEncodingException {

        X509Certificate mockCert = Mockito.mock(X509Certificate.class);
        Mockito.when(mockCert.getEncoded()).thenThrow(new CryptoException());

        AccessToken accessToken = new AccessToken();
        assertNull(accessToken.getX509CertificateHash(mockCert));
    }

    @Test
    public void testConfirmX509CertHashFailure() {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        try {
            Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            final String cnfHash = (String) accessToken.getConfirmEntry(AccessToken.CLAIM_CONFIRM_X509_HASH);
            assertFalse(accessToken.confirmX509CertHash(cert, cnfHash));
        } catch (IOException ignored) {
            fail();
        }
    }

    @Test
    public void testConfirmMTLSBoundTokenNullX509Cert() {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        assertFalse(accessToken.confirmMTLSBoundToken(null, "cnf-hash"));
    }

    @Test
    public void testConfirmMTLSBoundTokenNoHash() {

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");
        accessToken.setConfirmEntry("x5t#uri", "spiffe://athenz/sa/api");

        try {
            Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            assertFalse(accessToken.confirmMTLSBoundToken(cert, "cnf-hash"));
        } catch (IOException ignored) {
            fail();
        }
    }

    @Test
    public void testConfirmMTLSBoundTokenWithProxyNotAllowed() throws IOException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessToken.setAccessTokenProxyPrincipals(new HashSet<>());
        assertFalse(accessToken.confirmMTLSBoundToken(cert, "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0"));
        AccessToken.setAccessTokenProxyPrincipals(null);
    }

    @Test
    public void testConfirmMTLSBoundTokenWithProxyAllowed() throws IOException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessToken.setAccessTokenProxyPrincipals(new HashSet<>(Collections.singletonList("athenz.syncer")));
        assertTrue(accessToken.confirmMTLSBoundToken(cert, "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0"));
        AccessToken.setAccessTokenProxyPrincipals(null);
    }

    @Test
    public void testConfirmMTLSBoundTokenCertPrincipalAllowed() throws IOException {

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 - 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 - 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        assertTrue(accessToken.confirmMTLSBoundToken(cert, null));
    }

    @Test
    public void testConfirmMTLSBoundTokenNoCN() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/no_cn_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmMTLSBoundToken(cert, "cnf-hash"));
    }

    @Test
    public void testConfirmX509CertPrincipalNullCert() {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        assertFalse(accessToken.confirmX509CertPrincipal(null, "athenz.proxy", new StringBuilder()));
    }

    @Test
    public void testConfirmX509CertPrincipalCertNoCN() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/no_cn_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "athenz.proxy", new StringBuilder()));
    }

    @Test
    public void testConfirmX509CertPrincipalCertCNMismatch() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/rsa_public_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "athenz.proxy", new StringBuilder()));
    }

    @Test
    public void testConfirmX509CertProxyPrincipal() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setConfirmProxyPrincipalSpiffeUris(Collections.singletonList("spiffe://athenz/domain1/service1"));

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessToken checkToken = new AccessToken(accessJws, resolver, cert);
        assertNotNull(checkToken);
        List<String> spiffeUris = checkToken.getConfirmProxyPrincpalSpiffeUris();
        assertEquals(spiffeUris.size(), 1);
        assertEquals(spiffeUris.get(0), "spiffe://athenz/domain1/service1");
    }

    @Test
    public void testConfirmX509CertMultipleProxyPrincipal() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        List<String> proxyPrincipalUris = new ArrayList<>();
        proxyPrincipalUris.add("spiffe://athenz/domain1/service2");
        proxyPrincipalUris.add("spiffe://athenz/domain1/service1");
        accessToken.setConfirmProxyPrincipalSpiffeUris(proxyPrincipalUris);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessToken checkToken = new AccessToken(accessJws, resolver, cert);
        assertNotNull(checkToken);
    }

    @Test
    public void testConfirmX509CertMismatchProxyPrincipal() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setConfirmProxyPrincipalSpiffeUris(Collections.singletonList("spiffe://athenz/sports/service1"));

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        try {
            new AccessToken(accessJws, resolver, cert);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Confirmation failure"));
        }
    }

    @Test
    public void testConfirmX509CertInvalidProxyPrincipal() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setConfirmProxyPrincipalSpiffeUris(Collections.singletonList("spiffe://athenz/sports/service1"));

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        try {
            new AccessToken(accessJws, resolver, cert);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Confirmation failure"));
        }
    }

    @Test
    public void testConfirmX509CertInvalidEmptyProxyPrincipal() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setConfirmProxyPrincipalSpiffeUris(Collections.emptyList());

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        try {
            new AccessToken(accessJws, resolver, cert);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Confirmation failure"));
        }
    }

    @Test
    public void testConfirmX509CertInvalidProxyPrincipalDetails() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setConfirmEntry("proxy-principals#spiffe", "spiffe://athenz/sports/service1");

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        try {
            new AccessToken(accessJws, resolver, cert);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Confirmation failure"));
        }
    }

    @Test
    public void testConfirmX509CertNoAuthzDetails() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setAuthorizationDetails(null);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", "ES256");
        assertNotNull(accessJws);

        // now verify our signed token

        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null);

        Path path = Paths.get("src/test/resources/x509_altnames_singleuri.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        try {
            new AccessToken(accessJws, resolver, cert);
            fail();
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Confirmation failure"));
        }
    }

    @Test
    public void testConfirmX509CertPrincipalCertStartTime() throws IOException {

        AccessToken.setAccessTokenCertOffset(3600);

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 + 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 + 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "mtls", new StringBuilder()));
    }

    @Test
    public void testConfirmX509CertPrincipalCertStartTimeCheckDisabled() throws IOException {

        AccessToken.setAccessTokenCertOffset(-1);

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 + 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 + 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertTrue(accessToken.confirmX509CertPrincipal(cert, "mtls", new StringBuilder()));

        AccessToken.setAccessTokenCertOffset(3600);
    }

    @Test
    public void testConfirmX509CertPrincipalCertStartTimePassOffset() throws IOException {

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 - ACCESS_TOKEN_CERT_OFFSET - 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 - 3600 - 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "mtls", new StringBuilder()));
    }

    @Test
    public void testConfirmX509CertPrincipal() throws IOException {

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 - 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 - 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertTrue(accessToken.confirmX509CertPrincipal(cert, "mtls", new StringBuilder()));
    }

    @Test
    public void testConfirmX509CertPrincipalDisable() throws IOException {

        AccessToken.setAccessTokenCertOffset(0);

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 - 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 - 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "mtls", new StringBuilder()));

        AccessToken.setAccessTokenCertOffset(3600);
    }

    @Test
    public void testInvalidConfirmEntry() {
        AccessToken accessToken = new AccessToken();
        LinkedHashMap<String, Object> confirm = new LinkedHashMap<>();
        confirm.put("proxy-principals#spiffe", "value");
        accessToken.setConfirm(confirm);
        assertNull(accessToken.getConfirmProxyPrincpalSpiffeUris());
    }

    @Test
    public void testGetSignedTokenFailure() {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        assertNull(accessToken.getSignedToken(privateKey, "eckey1", "RS256"));
    }
}
