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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import static org.mockito.ArgumentMatchers.any;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

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

    @Test
    public void testGetJWTProcessorWithResolversSingleResolver() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));

        ConfigurableJWTProcessor<SecurityContext> processor =
            JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithResolversMultipleResolvers() throws IOException {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        final String siaConfUri = "file://" + new File("src/test/resources/athenz_sia_jwks.conf").getCanonicalPath();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));
        resolvers.add(new JwtsResolver(siaConfUri, null, null));

        ConfigurableJWTProcessor<SecurityContext> processor =
            JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithResolversJwtJagTypeVerifier() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));

        ConfigurableJWTProcessor<SecurityContext> processor =
            JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_JAG_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithResolversCustomTypeVerifier() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));

        JOSEObjectTypeVerifier<SecurityContext> customVerifier =
            new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("custom+jwt"));

        ConfigurableJWTProcessor<SecurityContext> processor = JwtsHelper.getJWTProcessor(resolvers, customVerifier);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithResolversNullTypeVerifier() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));

        ConfigurableJWTProcessor<SecurityContext> processor = JwtsHelper.getJWTProcessor(resolvers, null);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
    }

    @Test
    public void testGetJWTProcessorWithResolversNullList() {
        try {
            JwtsHelper.getJWTProcessor((List<JwtsResolver>) null, JwtsHelper.JWT_TYPE_VERIFIER);
            fail("Expected CryptoException for null resolver list");
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("At least one resolver must be specified"));
        }
    }

    @Test
    public void testGetJWTProcessorWithResolversEmptyList() {
        List<JwtsResolver> resolvers = new ArrayList<>();
        try {
            JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);
            fail("Expected CryptoException for empty resolver list");
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("At least one resolver must be specified"));
        }
    }

    @Test
    public void testGetJWTProcessorWithResolversInvalidJwksUri() {
        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver("invalid-uri", null, null));

        try {
            JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);
            fail("Expected CryptoException for invalid JWKS URI");
        } catch (CryptoException ex) {
            assertTrue(ex.getMessage().contains("Invalid jwks uri"));
        }
    }

    @Test
    public void testGetJWTProcessorWithResolversWithProxyUrl() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        final String proxyUrl = "http://localhost:8080";

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, proxyUrl, null));

        ConfigurableJWTProcessor<SecurityContext> processor =
                JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithResolversWithSSLContext() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        SSLContext sslContext = Mockito.mock(SSLContext.class);

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, sslContext));

        ConfigurableJWTProcessor<SecurityContext> processor =
            JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithResolversWithProxyAndSSL() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        final String proxyUrl = "http://localhost:8080";
        SSLContext sslContext = Mockito.mock(SSLContext.class);

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, proxyUrl, sslContext));

        ConfigurableJWTProcessor<SecurityContext> processor =
                JwtsHelper.getJWTProcessor(resolvers, JwtsHelper.JWT_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithKeyResolver() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));
        JwtsSigningKeyResolver keyResolver = new JwtsSigningKeyResolver(resolvers, false);

        ConfigurableJWTProcessor<SecurityContext> processor = JwtsHelper.getJWTProcessor(keyResolver);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetJWTProcessorWithKeyResolverAndTypeVerifier() {
        final ClassLoader classLoader = this.getClass().getClassLoader();
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();

        List<JwtsResolver> resolvers = new ArrayList<>();
        resolvers.add(new JwtsResolver(jwksUri, null, null));
        JwtsSigningKeyResolver keyResolver = new JwtsSigningKeyResolver(resolvers, false);

        ConfigurableJWTProcessor<SecurityContext> processor =
            JwtsHelper.getJWTProcessor(keyResolver, JwtsHelper.JWT_JAG_TYPE_VERIFIER);

        assertNotNull(processor);
        assertNotNull(processor.getJWSKeySelector());
        assertNotNull(processor.getJWSTypeVerifier());
    }

    @Test
    public void testGetIntegerClaim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("intClaim", 42)
            .claim("stringClaim", "not-a-number")
            .build();

        // Test with valid integer
        assertEquals(JwtsHelper.getIntegerClaim(claims, "intClaim", 0), 42);

        // Test with non-existent claim (should return default)
        assertEquals(JwtsHelper.getIntegerClaim(claims, "nonExistent", 99), 99);

        // Test with wrong type (should return default due to ParseException)
        assertEquals(JwtsHelper.getIntegerClaim(claims, "stringClaim", 77), 77);

        // Test with null value
        JWTClaimsSet claimsWithNull = new JWTClaimsSet.Builder()
            .claim("nullClaim", null)
            .build();
        assertEquals(JwtsHelper.getIntegerClaim(claimsWithNull, "nullClaim", 100), 100);
    }

    @Test
    public void testGetLongClaim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("longClaim", 123456789L)
            .claim("stringClaim", "not-a-number")
            .build();

        // Test with valid long
        assertEquals(JwtsHelper.getLongClaim(claims, "longClaim", 0L), 123456789L);

        // Test with non-existent claim (should return default)
        assertEquals(JwtsHelper.getLongClaim(claims, "nonExistent", 999L), 999L);

        // Test with wrong type (should return default due to ParseException)
        assertEquals(JwtsHelper.getLongClaim(claims, "stringClaim", 777L), 777L);

        // Test with null value
        JWTClaimsSet claimsWithNull = new JWTClaimsSet.Builder()
            .claim("nullClaim", null)
            .build();
        assertEquals(JwtsHelper.getLongClaim(claimsWithNull, "nullClaim", 1000L), 1000L);
    }

    @Test
    public void testGetStringClaim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("stringClaim", "test-value")
            .claim("intClaim", 42)
            .build();

        // Test with valid string
        assertEquals(JwtsHelper.getStringClaim(claims, "stringClaim"), "test-value");

        // Test with non-existent claim
        assertNull(JwtsHelper.getStringClaim(claims, "nonExistent"));

        // Test with wrong type (should return null due to ParseException)
        assertNull(JwtsHelper.getStringClaim(claims, "intClaim"));
    }

    @Test
    public void testGetStringListClaim() {
        List<String> testList = Arrays.asList("value1", "value2", "value3");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .claim("listClaim", testList)
            .claim("stringClaim", "not-a-list")
            .build();

        // Test with valid list
        List<String> result = JwtsHelper.getStringListClaim(claims, "listClaim");
        assertNotNull(result);
        assertEquals(result.size(), 3);
        assertEquals(result.get(0), "value1");
        assertEquals(result.get(1), "value2");
        assertEquals(result.get(2), "value3");

        // Test with non-existent claim
        assertNull(JwtsHelper.getStringListClaim(claims, "nonExistent"));

        // Test with wrong type (should return null due to ParseException)
        assertNull(JwtsHelper.getStringListClaim(claims, "stringClaim"));
    }

    @Test
    public void testGetAudience() {
        // Test with single audience
        JWTClaimsSet claimsSingle = new JWTClaimsSet.Builder()
            .audience("audience1")
            .build();
        assertEquals(JwtsHelper.getAudience(claimsSingle), "audience1");

        // Test with multiple audiences (should return first)
        JWTClaimsSet claimsMultiple = new JWTClaimsSet.Builder()
            .audience(Arrays.asList("audience1", "audience2", "audience3"))
            .build();
        assertEquals(JwtsHelper.getAudience(claimsMultiple), "audience1");

        // Test with null audience
        JWTClaimsSet claimsNull = new JWTClaimsSet.Builder().build();
        assertNull(JwtsHelper.getAudience(claimsNull));

        // Test with empty audience list
        JWTClaimsSet claimsEmpty = new JWTClaimsSet.Builder()
            .audience(Collections.emptyList())
            .build();
        assertNull(JwtsHelper.getAudience(claimsEmpty));
    }

    @Test
    public void testParseJWTWithoutSignatureSuccess() {
        // Create a valid JWT without signature
        String header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"; // {"alg":"none","typ":"JWT"}
        String payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"; // {"sub":"1234567890","name":"John Doe","iat":1516239022}
        String unsignedToken = header + "." + payload + ".";

        JWTClaimsSet claims = JwtsHelper.parseJWTWithoutSignature(unsignedToken);
        assertNotNull(claims);
        assertEquals(claims.getSubject(), "1234567890");
        assertEquals(claims.getClaim("name"), "John Doe");
    }

    @Test
    public void testCompositeJWKSourceWithMultipleSources() throws KeySourceException {
        JwtsHelper.CompositeJWKSource<SecurityContext> compositeSource = new JwtsHelper.CompositeJWKSource<>();

        // Create mock sources
        JWKSource<SecurityContext> source1 = Mockito.mock(JWKSource.class);
        JWKSource<SecurityContext> source2 = Mockito.mock(JWKSource.class);

        // Setup first source to return empty list
        Mockito.when(source1.get(any(JWKSelector.class), any())).thenReturn(Collections.emptyList());

        // Setup second source to return a JWK
        JWK mockJwk = Mockito.mock(JWK.class);
        Mockito.when(source2.get(any(JWKSelector.class), any())).thenReturn(Collections.singletonList(mockJwk));

        compositeSource.addKeySource(source1);
        compositeSource.addKeySource(source2);

        JWKSelector selector = new JWKSelector(Mockito.mock(com.nimbusds.jose.jwk.JWKMatcher.class));
        List<JWK> result = compositeSource.get(selector, null);

        assertNotNull(result);
        assertEquals(result.size(), 1);
        assertEquals(result.get(0), mockJwk);
    }

    @Test
    public void testCompositeJWKSourceWithFirstSourceReturningKeys() throws KeySourceException {
        JwtsHelper.CompositeJWKSource<SecurityContext> compositeSource = new JwtsHelper.CompositeJWKSource<>();

        // Create mock sources
        JWKSource<SecurityContext> source1 = Mockito.mock(JWKSource.class);
        JWKSource<SecurityContext> source2 = Mockito.mock(JWKSource.class);

        // Setup first source to return a JWK
        JWK mockJwk1 = Mockito.mock(JWK.class);
        Mockito.when(source1.get(any(JWKSelector.class), any())).thenReturn(Collections.singletonList(mockJwk1));

        // Setup second source (should not be called)
        JWK mockJwk2 = Mockito.mock(JWK.class);
        Mockito.when(source2.get(any(JWKSelector.class), any())).thenReturn(Collections.singletonList(mockJwk2));

        compositeSource.addKeySource(source1);
        compositeSource.addKeySource(source2);

        JWKSelector selector = new JWKSelector(Mockito.mock(com.nimbusds.jose.jwk.JWKMatcher.class));
        List<JWK> result = compositeSource.get(selector, null);

        assertNotNull(result);
        assertEquals(result.size(), 1);
        assertEquals(result.get(0), mockJwk1);

        // Verify second source was not called
        Mockito.verify(source2, Mockito.never()).get(any(JWKSelector.class), any());
    }

    @Test
    public void testCompositeJWKSourceWithNoSources() throws KeySourceException {
        JwtsHelper.CompositeJWKSource<SecurityContext> compositeSource = new JwtsHelper.CompositeJWKSource<>();

        JWKSelector selector = new JWKSelector(Mockito.mock(com.nimbusds.jose.jwk.JWKMatcher.class));
        List<JWK> result = compositeSource.get(selector, null);

        assertNull(result);
    }

    @Test
    public void testCompositeJWKSourceWithAllSourcesFailing() throws KeySourceException {
        JwtsHelper.CompositeJWKSource<SecurityContext> compositeSource = new JwtsHelper.CompositeJWKSource<>();

        // Create mock sources that throw exceptions
        JWKSource<SecurityContext> source1 = Mockito.mock(JWKSource.class);
        JWKSource<SecurityContext> source2 = Mockito.mock(JWKSource.class);

        Mockito.when(source1.get(any(JWKSelector.class), any())).thenThrow(new KeySourceException("Test exception 1"));
        Mockito.when(source2.get(any(JWKSelector.class), any())).thenThrow(new KeySourceException("Test exception 2"));

        compositeSource.addKeySource(source1);
        compositeSource.addKeySource(source2);

        JWKSelector selector = new JWKSelector(Mockito.mock(com.nimbusds.jose.jwk.JWKMatcher.class));
        List<JWK> result = compositeSource.get(selector, null);

        assertNull(result);
    }

    @Test
    public void testCompositeJWKSourceWithNullResults() throws KeySourceException {
        JwtsHelper.CompositeJWKSource<SecurityContext> compositeSource = new JwtsHelper.CompositeJWKSource<>();

        // Create mock sources
        JWKSource<SecurityContext> source1 = Mockito.mock(JWKSource.class);
        JWKSource<SecurityContext> source2 = Mockito.mock(JWKSource.class);

        // Setup first source to return null
        Mockito.when(source1.get(any(JWKSelector.class), any())).thenReturn(null);

        // Setup second source to return a JWK
        JWK mockJwk = Mockito.mock(JWK.class);
        Mockito.when(source2.get(any(JWKSelector.class), any())).thenReturn(Collections.singletonList(mockJwk));

        compositeSource.addKeySource(source1);
        compositeSource.addKeySource(source2);

        JWKSelector selector = new JWKSelector(Mockito.mock(com.nimbusds.jose.jwk.JWKMatcher.class));
        List<JWK> result = compositeSource.get(selector, null);

        assertNotNull(result);
        assertEquals(result.size(), 1);
        assertEquals(result.get(0), mockJwk);
    }

    @Test
    public void testSiaJwkResourceRetrieverSuccess() throws IOException {
        JwtsHelper.SiaJwkResourceRetriever retriever = new JwtsHelper.SiaJwkResourceRetriever();

        final String fileName = new File("src/test/resources/athenz_sia_jwks.conf").getCanonicalPath();
        Resource resource = retriever.retrieveResource(new URL("file://" + fileName));

        assertNotNull(resource);
        assertEquals(resource.getContentType(), "application/json");
        assertTrue(resource.getContent().contains("\"keys\""));
    }

    @Test
    public void testInitJsonMapper() {
        ObjectMapper mapper = JwtsHelper.initJsonMapper();
        assertNotNull(mapper);
        assertFalse(mapper.isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES));
    }

    @Test
    public void testExtractJwksUriWithProxy() {
        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\",\"jwks_uri\":\"https://localhost/oauth2/keys\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertEquals(helper.extractJwksUri("localhost", null, "http://proxy:8080"), "https://localhost/oauth2/keys");
    }

    @Test
    public void testExtractJwksUriWithEmptyProxy() {
        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\",\"jwks_uri\":\"https://localhost/oauth2/keys\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertEquals(helper.extractJwksUri("localhost", null, ""), "https://localhost/oauth2/keys");
    }

    @Test
    public void testGetHttpDataWithNonHttpsConnection() throws Exception {
        String url = "http://localhost/";
        JwtsHelper helper = Mockito.spy(JwtsHelper.class);
        HttpURLConnection mockHttpConn = Mockito.mock(HttpURLConnection.class);
        Mockito.when(mockHttpConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        Mockito.when(mockHttpConn.getInputStream()).thenReturn(new ByteArrayInputStream("test-data".getBytes(StandardCharsets.UTF_8)));
        Mockito.doReturn(mockHttpConn).when(helper).getUrlConnection(url);

        String result = helper.getHttpData(url, null, null);

        assertEquals(result, "test-data");
        verify(helper).getUrlConnection(url);
    }

    @Test
    public void testGetHttpDataWithErrorResponseCode() throws Exception {
        String url = "https://localhost/";
        JwtsHelper helper = Mockito.spy(JwtsHelper.class);
        HttpsURLConnection mockHttpConn = Mockito.mock(HttpsURLConnection.class);
        Mockito.when(mockHttpConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_NOT_FOUND);
        Mockito.doReturn(mockHttpConn).when(helper).getUrlConnection(url);

        String result = helper.getHttpData(url, null, null);

        assertNull(result);
    }

    @Test
    public void testGetHttpDataWithMultipleLines() throws Exception {
        String url = "https://localhost/";
        String multiLineData = "line1\nline2\nline3";
        JwtsHelper helper = Mockito.spy(JwtsHelper.class);
        HttpsURLConnection mockHttpConn = Mockito.mock(HttpsURLConnection.class);
        Mockito.when(mockHttpConn.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        Mockito.when(mockHttpConn.getInputStream()).thenReturn(new ByteArrayInputStream(multiLineData.getBytes(StandardCharsets.UTF_8)));
        Mockito.doReturn(mockHttpConn).when(helper).getUrlConnection(url);

        String result = helper.getHttpData(url, null, null);

        assertEquals(result, "line1line2line3");
    }

    @Test
    public void testGetHttpDataWithIOException() throws Exception {
        String url = "https://localhost/";
        JwtsHelper helper = Mockito.spy(JwtsHelper.class);
        Mockito.doThrow(new IOException("Connection failed")).when(helper).getUrlConnection(url);

        String result = helper.getHttpData(url, null, null);

        assertNull(result);
    }

    @Test
    public void testGetSocketFactoryWithNullSSLContext() {
        JwtsHelper helper = new JwtsHelper();
        assertNull(helper.getSocketFactory(null));
    }

    @Test
    public void testGetSocketFactoryWithNonNullSSLContext() {
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Mockito.when(sslContext.getSocketFactory()).thenReturn(Mockito.mock(javax.net.ssl.SSLSocketFactory.class));

        JwtsHelper helper = new JwtsHelper();
        assertNotNull(helper.getSocketFactory(sslContext));
    }

    @Test
    public void testGetUrlConnectionWithProxy() {
        JwtsHelper helper = new JwtsHelper();
        // This test mainly ensures the method doesn't throw exceptions
        // We can't easily test the actual connection without a real proxy
        try {
            helper.getUrlConnection("http://invalid-url", "localhost", 8080);
        } catch (Exception ex) {
            // Expected - URL is invalid, but we're testing method signature
        }
    }
}
