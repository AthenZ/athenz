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

import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.token.jwts.MockJwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import io.jsonwebtoken.*;
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
import java.time.Instant;
import java.util.*;

import static org.testng.Assert.*;

public class AccessTokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    private final String JWT_KEYS = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"0\",\"alg\":\"RS256\","
        + "\"use\":\"sig\",\"n\":\"AMV3cnZXxYJL-A0TYY8Fy245HKSOBCYt9atNAUQVtbEwx9QaZGj8moYIe4nXgx"
        + "72Ktwg0Gruh8sS7GQLBizCXg7fCk62sDV_MZINnwON9gsKbxxgn9mLFeYSaatUzk-VRphDoHNIBC-qeDtYnZhs"
        + "HYcV9Jp0GPkLNquhN1TXA7gT\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"eckey1\",\"alg\":"
        + "\"ES256\",\"use\":\"sig\",\"crv\":\"prime256v1\",\"x\":\"AI0x6wEUk5T0hslaT83DNVy5r98Xn"
        + "G7HAjQynjCrcdCe\",\"y\":\"ATdV2ebpefqBli_SXZwvL3-7OiD3MTryGbR-zRSFZ_s=\"},"
        + "{\"kty\":\"ATHENZ\",\"alg\":\"ES256\"}]}";

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
        assertEquals("subject", accessToken.getSubject());
        assertEquals("userid", accessToken.getUserId());
        assertEquals(now + 3600, accessToken.getExpiryTime());
        assertEquals(now, accessToken.getIssueTime());
        assertEquals("mtls", accessToken.getClientId());
        assertEquals("coretech", accessToken.getAudience());
        assertEquals(1, accessToken.getVersion());
        assertEquals("athenz", accessToken.getIssuer());
        assertEquals("proxy.user", accessToken.getProxyPrincipal());
        LinkedHashMap<String, Object> confirm = accessToken.getConfirm();
        assertNotNull(confirm);
        assertEquals("A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0", confirm.get("x5t#S256"));
        assertEquals("A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0", accessToken.getConfirmEntry("x5t#S256"));
        assertEquals("spiffe://athenz/sa/api", confirm.get("x5t#uri"));
        assertEquals("spiffe://athenz/sa/api", accessToken.getConfirmEntry("x5t#uri"));
        assertNull(accessToken.getConfirmEntry("unknown"));
        assertEquals("[{\"type\":\"message_access\",\"data\":\"resource\"}]", accessToken.getAuthorizationDetails());

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
        assertEquals(1, accessToken.getScope().size());
        assertTrue(accessToken.getScope().contains("readers"));
        assertEquals(accessToken.getScopeStd(), "readers");
    }

    void validateAccessTokenMultipleRoles(AccessToken accessToken, long now) {
        validateAccessTokenCommon(accessToken, now);
        assertEquals(2, accessToken.getScope().size());
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
    public void testAccessToken() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // verify the getters

        validateAccessToken(accessToken, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(accessJws);
        assertNotNull(claims);

        assertEquals("subject", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals("athenz", claims.getBody().getIssuer());
        assertEquals("jwt-id001", claims.getBody().getId());
        assertEquals("readers", claims.getBody().get("scope"));
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("readers", scopes.get(0));
    }

    @Test
    public void testAccessTokenMultipleRoles() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessTokenMultipleRoles(now);

        // verify the getters

        validateAccessTokenMultipleRoles(accessToken, now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(accessJws);
        assertNotNull(claims);

        assertEquals("subject", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals("athenz", claims.getBody().getIssuer());
        assertEquals("jwt-id001", claims.getBody().getId());
        assertEquals("readers writers", claims.getBody().get("scope"));
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(2, scopes.size());
        assertEquals("readers", scopes.get(0));
        assertEquals("writers", scopes.get(1));
    }

    @Test
    public void testAccessTokenWithX509Cert() throws IOException {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);
    }

    @Test
    public void testAccessTokenWithoutSignedToken() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

        // remove the signature part from the token

        int idx = accessJws.lastIndexOf('.');
        final String unsignedJws = accessJws.substring(0, idx + 1);

        try {
            new AccessToken(unsignedJws, resolver);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof UnsupportedJwtException);
        }
    }

    @Test
    public void testAccessTokenWithNoneAlgorithm() {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        // now get the unsigned token with none algorithm

        final String accessJws = Jwts.builder().setSubject(accessToken.subject)
                .setId(accessToken.jwtId)
                .setIssuedAt(Date.from(Instant.ofEpochSecond(accessToken.issueTime)))
                .setExpiration(Date.from(Instant.ofEpochSecond(accessToken.expiryTime)))
                .setIssuer(accessToken.issuer)
                .setAudience(accessToken.audience)
                .claim(AccessToken.CLAIM_AUTH_TIME, accessToken.authTime)
                .claim(AccessToken.CLAIM_VERSION, accessToken.version)
                .claim(AccessToken.CLAIM_SCOPE, accessToken.getScope())
                .claim(AccessToken.CLAIM_SCOPE_STD, accessToken.getScopeStd())
                .claim(AccessToken.CLAIM_UID, accessToken.getUserId())
                .claim(AccessToken.CLAIM_CLIENT_ID, accessToken.getClientId())
                .claim(AccessToken.CLAIM_CONFIRM, accessToken.getConfirm())
                .claim(AccessToken.CLAIM_PROXY, accessToken.getProxyPrincipal())
                .claim(AccessToken.CLAIM_AUTHZ_DETAILS, accessToken.getAuthorizationDetails())
                .setHeaderParam(AccessToken.HDR_TOKEN_TYPE, AccessToken.HDR_TOKEN_JWT)
                .compact();
        assertNotNull(accessJws);

        try {
            new AccessToken(accessJws, new JwtsSigningKeyResolver(null, null));
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof UnsupportedJwtException);
        }
    }

    @Test
    public void testAccessTokenSignedTokenPublicKey() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);

        resetConfProperty(oldConf);
    }

    @Test
    public void testAccessTokenSignedTokenConfigFileUnknownKey() {
        testAccessTokenSignedTokenConfigFileNoKeys("src/test/resources/athenz.conf");
        testAccessTokenSignedTokenConfigFileNoKeys("src/test/resources/athenz-no-keys.conf");
        testAccessTokenSignedTokenConfigFileNoKeys("src/test/resources/athenz-no-valid-keys.conf");
        testAccessTokenSignedTokenConfigFileNoKeys("");
        // passing invalid file that will generate parse exception
        testAccessTokenSignedTokenConfigFileNoKeys("arg_file");
    }

    void testAccessTokenSignedTokenConfigFileNoKeys(final String confPath) {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey99", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                confPath);
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (Exception ignored) {
        }

        resetConfProperty(oldConf);
    }

    @Test
    public void testAccessTokenSignedTokenServerKeys() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz-no-keys.conf");
        MockJwtsSigningKeyResolver.setResponseBody(JWT_KEYS);
        MockJwtsSigningKeyResolver resolver = new MockJwtsSigningKeyResolver("https://localhost:4443", null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);

        resetConfProperty(oldConf);
    }

    @Test
    public void testAccessTokenSignedTokenServerKeysFailure() {

        long now = System.currentTimeMillis() / 1000;

        AccessToken accessToken = createAccessToken(now);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz-no-keys.conf");
        MockJwtsSigningKeyResolver.setResponseBody("");
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        MockJwtsSigningKeyResolver resolver = new MockJwtsSigningKeyResolver("https://localhost:4443", sslContext);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }

        resetConfProperty(oldConf);
    }

    @Test
    public void testAccessTokenExpired() {

        long now = System.currentTimeMillis() / 1000;

        // we allow clock skew of 60 seconds so we'll go
        // back 3600 + 61 to make our token expired
        AccessToken accessToken = createAccessToken(now - 3661);

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        final String oldConf = System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF,
                "src/test/resources/athenz.conf");
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("expired"));
        }

        resetConfProperty(oldConf);
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
        assertFalse(accessToken.confirmX509CertPrincipal(null, "athenz.proxy"));
    }

    @Test
    public void testConfirmX509CertPrincipalCertNoCN() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/no_cn_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "athenz.proxy"));
    }

    @Test
    public void testConfirmX509CertPrincipalCertCNMismatch() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);

        Path path = Paths.get("src/test/resources/rsa_public_x509.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "athenz.proxy"));
    }

    @Test
    public void testConfirmX509CertProxyPrincipal() throws IOException {

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = createAccessToken(now);
        accessToken.setConfirmProxyPrincipalSpiffeUris(Collections.singletonList("spiffe://athenz/domain1/service1"));

        // now get the signed token

        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        // now verify our signed token

        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        resolver.addPublicKey("eckey1", Crypto.loadPublicKey(ecPublicKey));

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
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "mtls"));
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
        assertTrue(accessToken.confirmX509CertPrincipal(cert, "mtls"));

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
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "mtls"));
    }

    @Test
    public void testConfirmX509CertPrincipal() throws IOException {

        // our cert issue time is 1565245568
        // so we're going to set token issue time to cert time + 3600 - 100

        AccessToken accessToken = createAccessToken(1565245568 + 3600 - 100);

        Path path = Paths.get("src/test/resources/mtls_token2_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        assertTrue(accessToken.confirmX509CertPrincipal(cert, "mtls"));
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
        assertFalse(accessToken.confirmX509CertPrincipal(cert, "mtls"));

        AccessToken.setAccessTokenCertOffset(3600);
    }
}
