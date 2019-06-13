/*
 * Copyright 2019 Oath Holdings Inc.
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

import ch.qos.logback.core.net.ssl.SSL;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.token.jwts.MockJwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import io.jsonwebtoken.*;
import org.mockito.Mockito;
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
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import static org.testng.Assert.*;

public class AccessTokenTest {

    private final File ecPrivateKey = new File("./src/test/resources/ec_private.key");
    private final File ecPublicKey = new File("./src/test/resources/ec_public.key");

    private final String JWT_KEYS = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"0\",\"alg\":\"RS256\","
        + "\"use\":\"sig\",\"n\":\"AMV3cnZXxYJL-A0TYY8Fy245HKSOBCYt9atNAUQVtbEwx9QaZGj8moYIe4nXgx"
        + "72Ktwg0Gruh8sS7GQLBizCXg7fCk62sDV_MZINnwON9gsKbxxgn9mLFeYSaatUzk-VRphDoHNIBC-qeDtYnZhs"
        + "HYcV9Jp0GPkLNquhN1TXA7gT\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"eckey1\",\"alg\":"
        + "\"ES256\",\"use\":\"sig\",\"crv\":\"prime256v1\",\"x\":\"AI0x6wEUk5T0hslaT83DNVy5r98Xn"
        + "G7HAjQynjCrcdCe\",\"y\":\"ATdV2ebpefqBli_SXZwvL3-7OiD3MTryGbR-zRSFZ_s=\"},"
        + "{\"kty\":\"ATHENZ\",\"alg\":\"ES256\"}]}";

    AccessToken createAccessToken(long now) {

        AccessToken accessToken = new AccessToken();
        accessToken.setAuthTime(now);
        accessToken.setScope(Collections.singletonList("readers"));
        accessToken.setSubject("subject");
        accessToken.setUserId("userid");
        accessToken.setExpiryTime(now + 3600);
        accessToken.setIssueTime(now);
        accessToken.setClientId("clientid");
        accessToken.setAudience("coretech");
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");
        accessToken.setConfirmEntry("x5t#uri", "spiffe://athenz/sa/api");

        try {
            Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            accessToken.setConfirmX509CertHash(cert);
        } catch (IOException ignored) {
            fail();
        }

        return accessToken;
    }

    void validateAccessToken(AccessToken accessToken, long now) {
        assertEquals(now, accessToken.getAuthTime());
        assertEquals(1, accessToken.getScope().size());
        assertTrue(accessToken.getScope().contains("readers"));
        assertEquals("subject", accessToken.getSubject());
        assertEquals("userid", accessToken.getUserId());
        assertEquals(now + 3600, accessToken.getExpiryTime());
        assertEquals(now, accessToken.getIssueTime());
        assertEquals("clientid", accessToken.getClientId());
        assertEquals("coretech", accessToken.getAudience());
        assertEquals(1, accessToken.getVersion());
        assertEquals("athenz", accessToken.getIssuer());
        LinkedHashMap<String, Object> confirm = accessToken.getConfirm();
        assertNotNull(confirm);
        assertEquals("A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0", confirm.get("x5t#S256"));
        assertEquals("A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0", accessToken.getConfirmEntry("x5t#S256"));
        assertEquals("spiffe://athenz/sa/api", confirm.get("x5t#uri"));
        assertEquals("spiffe://athenz/sa/api", accessToken.getConfirmEntry("x5t#uri"));
        assertNull(accessToken.getConfirmEntry("unknown"));

        try {
            Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            assertTrue(accessToken.confirmX509CertHash(cert));
        } catch (IOException ignored) {
            fail();
        }
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
        Jws<Claims> claims = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(accessJws);
        assertNotNull(claims);

        assertEquals("subject", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals("athenz", claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("readers", scopes.get(0));
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

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
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
        } catch (Exception ex) {
        }

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
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
        MockJwtsSigningKeyResolver.setResponseCode(200);
        MockJwtsSigningKeyResolver.setResponseBody(JWT_KEYS);
        MockJwtsSigningKeyResolver resolver = new MockJwtsSigningKeyResolver("https://localhost:4443", null);

        AccessToken checkToken = new AccessToken(accessJws, resolver);
        validateAccessToken(checkToken, now);

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
        }
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
        MockJwtsSigningKeyResolver.setResponseCode(401);
        MockJwtsSigningKeyResolver.setResponseBody("");
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        MockJwtsSigningKeyResolver resolver = new MockJwtsSigningKeyResolver("https://localhost:4443", sslContext);

        try {
            new AccessToken(accessJws, resolver);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
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

        if (oldConf == null) {
            System.clearProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF);
        } else {
            System.setProperty(JwtsSigningKeyResolver.ZTS_PROP_ATHENZ_CONF, oldConf);
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
            assertFalse(accessToken.confirmX509CertHash(cert));
        } catch (IOException ignored) {
            fail();
        }
    }

    @Test
    public void testConfirmX509CertHashNoHash() {

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");
        accessToken.setConfirmEntry("x5t#uri", "spiffe://athenz/sa/api");

        try {
            Path path = Paths.get("src/test/resources/valid_cn_x509.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            assertFalse(accessToken.confirmX509CertHash(cert));
        } catch (IOException ignored) {
            fail();
        }
    }
}
