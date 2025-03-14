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
package com.yahoo.athenz.auth.token.jwts;

import com.nimbusds.jose.JOSEException;
import com.yahoo.athenz.auth.util.Crypto;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import static org.mockito.Mockito.verify;
import static org.testng.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class JwtsHelperTest {

    @Test
    public void testExtractJwksUri() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\",\"jwks_uri\":\"https://localhost/oauth2/keys\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertEquals(helper.extractJwksUri("localhost", null), "https://localhost/oauth2/keys");
        assertNull(helper.extractJwksUri(null, null));
        assertNull(helper.extractJwksUri("", null));
    }

    @Test
    public void testExtractJwksNullUri() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertNull(helper.extractJwksUri("localhost", null));
    }

    @Test
    public void testExtractJwksEmptyUri() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\",\"jwks_uri\":\"\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertTrue(helper.extractJwksUri("localhost", null).isEmpty());
    }

    @Test
    public void testExtractJwksUriNullData() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertNull(helper.extractJwksUri("localhost", null));
    }

    @Test
    public void testExtractJwksUriInvalidData() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertNull(helper.extractJwksUri("localhost", null));
    }

    @Test
    public void testGetSocketFactory() {
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        JwtsHelper helper = new JwtsHelper();
        assertNull(helper.getSocketFactory(sslContext));
    }

    @Test
    public void testGetHttpData() throws Exception {
        String url = "https://localhost/";
        JwtsHelper helper = Mockito.spy(JwtsHelper.class);
        HttpsURLConnection mockHttpConn = Mockito.mock(HttpsURLConnection.class);
        Mockito.when(mockHttpConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        Mockito.when(mockHttpConn.getInputStream()).thenReturn(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)));
        Mockito.doReturn(mockHttpConn).when(helper).getUrlConnection(url);

        helper.getHttpData(url, null, null);

        verify(helper).getUrlConnection(url);
    }

    @Test
    public void testGetHttpDataProxy() throws Exception {
        String url = "https://localhost/";
        String proxyUrl = "http://localhost:8128";
        JwtsHelper helper = Mockito.spy(JwtsHelper.class);
        HttpsURLConnection mockHttpConn = Mockito.mock(HttpsURLConnection.class);
        Mockito.when(mockHttpConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        Mockito.when(mockHttpConn.getInputStream()).thenReturn(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)));
        Mockito.doReturn(mockHttpConn).when(helper).getUrlConnection(url, "localhost", 8128);

        helper.getHttpData(url, null, proxyUrl);

        verify(helper).getUrlConnection(url, "localhost", 8128);
    }

    @Test
    public void testSiaJwkResourceRetrieverFailures() throws IOException {
        JwtsHelper.SiaJwkResourceRetriever retriever = new JwtsHelper.SiaJwkResourceRetriever();
        assertNull(retriever.retrieveResource(new URL("file://unknown-file")));

        final String fileName = new File("src/test/resources/athenz_jwks_invalid.conf").getCanonicalPath();
        assertNull(retriever.retrieveResource(new URL("file://" + fileName)));
    }

    @Test
    public void testParseJWTWithoutSignatureFailure() {
        try {
            JwtsHelper.parseJWTWithoutSignature("header.payload.signature");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Token has a signature but no key resolver"));
        }
        try {
            JwtsHelper.parseJWTWithoutSignature("header.payload.signature.part4.part5");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Token has a signature but no key resolver"));
        }
        try {
            JwtsHelper.parseJWTWithoutSignature("header.payload");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Missing second delimiter"));
        }
    }

    @Test
    public void testGetJWSSigner() throws JOSEException {

        PrivateKey privateKey = Crypto.loadPrivateKey(new File("src/test/resources/unit_test_jwt_private.key"));
        assertNotNull(JwtsHelper.getJWSSigner(privateKey));

        privateKey = Crypto.loadPrivateKey(new File("src/test/resources/unit_test_ec_private.key"));
        assertNotNull(JwtsHelper.getJWSSigner(privateKey));

        try {
            privateKey = Mockito.mock(PrivateKey.class);
            Mockito.when(privateKey.getAlgorithm()).thenReturn("DSA");
            JwtsHelper.getJWSSigner(privateKey);
            fail();
        } catch (JOSEException ex) {
            assertTrue(ex.getMessage().contains("Unsupported algorithm: DSA"));
        }
    }

    @Test
    public void testGetJWSVerifierPublicKey() throws JOSEException {

        PublicKey publicKey = Crypto.loadPublicKey(new File("src/test/resources/jwt_public.key"));
        assertNotNull(JwtsHelper.getJWSVerifier(publicKey));

        publicKey = Crypto.loadPublicKey(new File("src/test/resources/ec_public.key"));
        assertNotNull(JwtsHelper.getJWSVerifier(publicKey));

        try {
            publicKey = Mockito.mock(PublicKey.class);
            Mockito.when(publicKey.getAlgorithm()).thenReturn("DSA");
            JwtsHelper.getJWSVerifier(publicKey);
            fail();
        } catch (JOSEException ex) {
            assertTrue(ex.getMessage().contains("Unsupported algorithm: DSA"));
        }
    }

    @Test
    public void testGetJWSVerifierSecret() throws JOSEException {

        final byte[] secret = "athenz-service-authentication-authorization".getBytes(StandardCharsets.UTF_8);
        assertNotNull(JwtsHelper.getJWSVerifier(secret));
    }
}
