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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.DPoPProof;
import com.yahoo.athenz.auth.token.DPoPProofOptions;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.io.File;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.yahoo.athenz.zts.AccessTokenTestFileHelper.setupTokenFile;
import static org.testng.Assert.*;

public class ZTSClientDPoPTest {

    private static final String ZTS_URL = "http://localhost:4080";
    private static final String CORETECH_REQUEST = "grant_type=client_credentials&expires_in=3600&scope=coretech%3Adomain";
    private static final String OAUTH_JAG_TOKEN = "urn:ietf:params:oauth:token-type:id-jag";
    private static final String PROOF_ZTS_URL = "https://zts.athenz.io/zts/v1";
    private static final String PROOF_HTU = PROOF_ZTS_URL + "/oauth2/token";

    private final Authority principalAuthority = new PrincipalAuthority();
    private KeyPair dpopKey;
    private KeyPair otherKey;

    @BeforeClass
    public void init() throws Exception {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "false");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        dpopKey = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
    }

    @BeforeMethod
    public void setup() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZTSClient.ACCESS_TOKEN_CACHE.clear();
    }

    @AfterMethod
    public void cleanup() {
        ZTSClient.ACCESS_TOKEN_CACHE.clear();
        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        ZTSClient.initConfigValues();
    }

    private ZTSClient createClient(ZTSRDLGeneratedClient rdlClient) {
        Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds", principalAuthority);
        ZTSClient client = new ZTSClient(ZTS_URL, principal);
        client.setZTSRDLGeneratedClient(rdlClient);
        return client;
    }

    private static AccessTokenResponse tokenResponse(final String accessToken, final String tokenType) {
        return new AccessTokenResponse().setAccess_token(accessToken).setToken_type(tokenType).setExpires_in(3600);
    }

    @Test
    public void testDPoPConfiguration() {

        ZTSClient client = createClient(Mockito.mock(ZTSRDLGeneratedClient.class));
        assertFalse(client.getDPoPBinding().isEnabled());
        assertNull(client.getDPoPKeyPair());
        assertEquals(ZTSClient.getDPoPCacheKey("p=user_domain.user;d=coretech", client.getDPoPBinding()),
                "p=user_domain.user;d=coretech");

        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        assertTrue(client.getDPoPBinding().isEnabled());
        assertEquals(client.getDPoPKeyPair().getPublic(), dpopKey.getPublic());
        assertEquals(client.getDPoPKeyPair().getPrivate(), dpopKey.getPrivate());
        assertEquals(ZTSClient.getDPoPCacheKey("p=user_domain.user;d=coretech", client.getDPoPBinding()),
                "p=user_domain.user;d=coretech;j=" + DPoPProof.computeJwkThumbprint(dpopKey.getPublic()));
        assertNull(ZTSClient.getDPoPCacheKey(null, client.getDPoPBinding()));

        // bearer fallback clients use their own cache entries

        client.setDPoPAllowBearerFallback(true);
        assertTrue(client.getDPoPBinding().allowBearerFallback);
        assertEquals(ZTSClient.getDPoPCacheKey("p=user_domain.user;d=coretech", client.getDPoPBinding()),
                "p=user_domain.user;d=coretech;j=" + DPoPProof.computeJwkThumbprint(dpopKey.getPublic()) + ";fb");
        client.setDPoPAllowBearerFallback(false);

        // a provider returning no key disables dpop

        client.setDPoPKeyProvider(() -> null);
        assertFalse(client.getDPoPBinding().isEnabled());

        client.setDPoPKeyProvider(null);
        assertFalse(client.getDPoPBinding().isEnabled());
        client.close();
    }

    /**
     * Key provider that rotates to the next key pair every time it is called
     */
    private static DPoPKeyProvider rotatingProvider(KeyPair... keyPairs) {
        final AtomicInteger calls = new AtomicInteger();
        return () -> keyPairs[calls.getAndIncrement() % keyPairs.length];
    }

    private static String proofThumbprint(final String proof) {
        DPoPProofOptions options = DPoPProofOptions.builder().addAllowedHtu(PROOF_HTU).build();
        return new DPoPProof(proof, "POST", options, System.currentTimeMillis() / 1000).getJwkThumbprint();
    }

    @Test
    public void testGetAccessTokenDPoPKeySampledOncePerRequest() throws Exception {

        // the interceptor signs the proof with the key sampled for the request
        // so the token is cached under the thumbprint of the key it is bound to

        final String[] proofThumbprints = new String[2];
        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        ZTSClient client = createClient(rdlClient);
        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(PROOF_ZTS_URL, client::getRequestDPoPKeyPair);
        final AtomicInteger requests = new AtomicInteger();
        Mockito.when(rdlClient.postAccessTokenRequest(CORETECH_REQUEST)).thenAnswer(invocation -> {
            BasicHttpRequest post = new BasicHttpRequest("POST", "/zts/v1/oauth2/token");
            interceptor.process(post, null, null);
            final int idx = requests.getAndIncrement();
            proofThumbprints[idx] = proofThumbprint(post.getFirstHeader(DPoPProof.HTTP_HEADER).getValue());
            return tokenResponse("dpop-token" + idx, "DPoP");
        });

        client.setDPoPKeyProvider(rotatingProvider(dpopKey, otherKey));
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token0");

        // the provider was called once for the first request (dpopKey)

        final String baseKey = client.getAccessTokenCacheKey("coretech", null, null, null, null, null);
        final String dpopKeyThumbprint = DPoPProof.computeJwkThumbprint(dpopKey.getPublic());
        assertEquals(proofThumbprints[0], dpopKeyThumbprint);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.keySet(), Collections.singleton(baseKey + ";j=" + dpopKeyThumbprint));

        // the second request samples otherKey once: cache miss for that thumbprint,
        // proof signed with otherKey and token cached under otherKey's thumbprint

        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token1");
        final String otherKeyThumbprint = DPoPProof.computeJwkThumbprint(otherKey.getPublic());
        assertEquals(proofThumbprints[1], otherKeyThumbprint);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.get(baseKey + ";j=" + otherKeyThumbprint)
                .accessTokenResponse().getAccess_token(), "dpop-token1");
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.get(baseKey + ";j=" + dpopKeyThumbprint)
                .accessTokenResponse().getAccess_token(), "dpop-token0");
        client.close();
    }

    @Test
    public void testGetAccessTokenDPoPKeyRemovedDuringRequest() throws Exception {

        // a provider that stops returning a key after the request started must
        // not send the request without a proof and cache a bearer token under
        // the dpop cache key

        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("coretech").expiryTime(3600);

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        ZTSClient client = createClient(rdlClient);
        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(PROOF_ZTS_URL, client::getRequestDPoPKeyPair);
        Mockito.when(rdlClient.postAccessTokenRequest(builder.getRequestBody())).thenAnswer(invocation -> {
            BasicHttpRequest post = new BasicHttpRequest("POST", "/zts/v1/oauth2/token");
            interceptor.process(post, null, null);
            final boolean hasProof = post.getFirstHeader(DPoPProof.HTTP_HEADER) != null;
            return tokenResponse(hasProof ? "dpop-token" : "bearer-token", hasProof ? "DPoP" : "Bearer");
        });

        client.setDPoPKeyProvider(rotatingProvider(dpopKey, null));
        assertEquals(client.getAccessToken(builder, false).getAccess_token(), "dpop-token");

        // outside of a token request the interceptor uses the provider's current key

        assertNull(client.getRequestDPoPKeyPair());
        assertEquals(client.getRequestDPoPKeyPair(), dpopKey);
        client.close();
    }

    @Test
    public void testGetAccessTokenDPoP() throws Exception {

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenReturn(tokenResponse("dpop-token1", "DPoP"), tokenResponse("dpop-token2", "DPoP"));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());

        AccessTokenResponse response = client.getAccessToken("coretech", null, 3600);
        assertEquals(response.getAccess_token(), "dpop-token1");
        assertEquals(response.getToken_type(), "DPoP");

        // the second request is served from the cache

        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token1");

        // a different dpop key must not reuse the cached token

        client.setDPoPKey(otherKey.getPrivate(), otherKey.getPublic());
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token2");
        client.close();
    }

    @Test
    public void testGetAccessTokenBearerAndDPoPCacheSeparation() throws Exception {

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenReturn(tokenResponse("bearer-token", "Bearer"), tokenResponse("dpop-token", "DPoP"));

        ZTSClient client = createClient(rdlClient);
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "bearer-token");

        // once dpop is enabled the cached bearer token is not returned

        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token");

        // and without dpop we get the bearer token from the cache again

        client.setDPoPKeyProvider(null);
        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "bearer-token");
        client.close();
    }

    @Test
    public void testGetAccessTokenDPoPBearerResponseRejected() throws Exception {

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenReturn(tokenResponse("bearer-token", "Bearer"), tokenResponse("dpop-token", "DPoP"));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());

        try {
            client.getAccessToken("coretech", null, 3600);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), ClientResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("DPoP-bound token requested but server returned token type: Bearer"),
                    ex.getMessage());
        }

        // the bearer token was not cached so the next call goes to the server

        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token");
        client.close();
    }

    @Test
    public void testGetAccessTokenDPoPBearerFallback() throws Exception {

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenReturn(tokenResponse("bearer-token", "Bearer"), tokenResponse("bearer-token2", "Bearer"));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        client.setDPoPAllowBearerFallback(true);

        AccessTokenResponse response = client.getAccessToken("coretech", null, 3600);
        assertEquals(response.getAccess_token(), "bearer-token");
        assertEquals(response.getToken_type(), "Bearer");

        // the fallback client is served its bearer token from the cache

        assertEquals(client.getAccessToken("coretech", null, 3600).getAccess_token(), "bearer-token");
        client.close();
    }

    @Test
    public void testGetAccessTokenDPoPBearerFallbackNotSharedWithStrictClient() throws Exception {

        ZTSRDLGeneratedClient fallbackRdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(fallbackRdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenReturn(tokenResponse("bearer-token", "Bearer"));

        ZTSClient fallbackClient = createClient(fallbackRdlClient);
        fallbackClient.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        fallbackClient.setDPoPAllowBearerFallback(true);
        assertEquals(fallbackClient.getAccessToken("coretech", null, 3600).getAccess_token(), "bearer-token");

        // a strict client with the same identity, request and dpop key
        // must not be served the bearer token from the cache

        ZTSRDLGeneratedClient strictRdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(strictRdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenReturn(tokenResponse("bearer-token2", "Bearer"), tokenResponse("dpop-token", "DPoP"));

        ZTSClient strictClient = createClient(strictRdlClient);
        strictClient.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        try {
            strictClient.getAccessToken("coretech", null, 3600);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), ClientResourceException.BAD_REQUEST);
        }

        // and when the server fails the stale fallback entry is not returned either

        ZTSRDLGeneratedClient failingRdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(failingRdlClient.postAccessTokenRequest(CORETECH_REQUEST))
                .thenThrow(new ClientResourceException(503, "unavailable"));
        strictClient.setZTSRDLGeneratedClient(failingRdlClient);
        try {
            strictClient.getAccessToken("coretech", null, 3600);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 503);
        }

        strictClient.setZTSRDLGeneratedClient(strictRdlClient);
        assertEquals(strictClient.getAccessToken("coretech", null, 3600).getAccess_token(), "dpop-token");
        assertEquals(fallbackClient.getAccessToken("coretech", null, 3600).getAccess_token(), "bearer-token");
        fallbackClient.close();
        strictClient.close();
    }

    @Test
    public void testLookupAccessTokenResponseInCacheRejectsBearerForStrictClient() throws Exception {

        // a bearer token under a strict dpop cache key is ignored on cache
        // hits and stale responses

        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("coretech").expiryTime(3600);

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(builder.getRequestBody()))
                .thenThrow(new ClientResourceException(503, "unavailable"))
                .thenThrow(new IllegalStateException("network error"))
                .thenReturn(tokenResponse("dpop-token", "DPoP"));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());

        final DPoPBinding binding = client.getDPoPBinding();
        final String cacheKey = ZTSClient.getDPoPCacheKey(builder.getCacheKey("user_domain", "user", null), binding);
        ZTSClient.ACCESS_TOKEN_CACHE.put(cacheKey,
                new AccessTokenResponseCacheEntry(tokenResponse("bearer-token", "Bearer")));
        assertNull(client.lookupAccessTokenResponseInCache(cacheKey, 3600, binding));
        assertNull(client.lookupAccessTokenResponseInCache(cacheKey, -1, binding));

        try {
            client.getAccessToken(builder, false);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 503);
        }
        try {
            client.getAccessToken(builder, false);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), ClientResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("network error"), ex.getMessage());
        }
        assertEquals(client.getAccessToken(builder, false).getAccess_token(), "dpop-token");

        // the cached dpop token now replaces the bearer entry

        assertEquals(client.lookupAccessTokenResponseInCache(cacheKey, 3600, binding).getAccess_token(), "dpop-token");

        // clients without dpop are not affected

        ZTSClient.ACCESS_TOKEN_CACHE.put(cacheKey,
                new AccessTokenResponseCacheEntry(tokenResponse("bearer-token", "Bearer")));
        assertEquals(client.lookupAccessTokenResponseInCache(cacheKey, 3600, DPoPBinding.NONE).getAccess_token(),
                "bearer-token");
        client.close();
    }

    @Test
    public void testGetAccessTokenBuilderDPoP() throws Exception {

        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                .domainName("coretech").expiryTime(3600);

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(builder.getRequestBody()))
                .thenReturn(tokenResponse("bearer-token", "Bearer"), tokenResponse("dpop-token1", "DPoP"),
                        tokenResponse("dpop-token2", "DPoP"));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());

        try {
            client.getAccessToken(builder, false);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), ClientResourceException.BAD_REQUEST);
        }

        assertEquals(client.getAccessToken(builder, false).getAccess_token(), "dpop-token1");
        assertEquals(client.getAccessToken(builder, false).getAccess_token(), "dpop-token1");
        assertEquals(client.getAccessToken(builder, true).getAccess_token(), "dpop-token2");
        client.close();
    }

    @Test
    public void testGetJAGTokenDPoP() throws Exception {

        // the id-jag issued by the token exchange is never dpop bound

        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_TOKEN_EXCHANGE)
                .domainName("coretech").expiryTime(3600);

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(builder.getRequestBody()))
                .thenReturn(tokenResponse("id-jag", "N_A").setIssued_token_type(OAUTH_JAG_TOKEN));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());

        AccessTokenResponse response = client.getJAGToken(builder);
        assertEquals(response.getAccess_token(), "id-jag");
        assertEquals(response.getToken_type(), "N_A");
        client.close();
    }

    @Test
    public void testGetIdTokenExchangeDPoP() throws Exception {

        // the id token issued by the id token exchange is never dpop bound

        OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_TOKEN_EXCHANGE)
                .requestedTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID)
                .domainName("coretech").expiryTime(3600);

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(builder.getRequestBody()))
                .thenReturn(new AccessTokenResponse().setId_token("id-token").setToken_type("Bearer")
                        .setIssued_token_type(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID).setExpires_in(3600));

        ZTSClient client = createClient(rdlClient);
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());

        AccessTokenResponse response = client.getAccessToken(builder, false);
        assertEquals(response.getId_token(), "id-token");
        assertEquals(response.getToken_type(), "Bearer");

        // the cached response is returned as well

        assertSame(client.getAccessToken(builder, false), response);
        client.close();
    }

    @Test
    public void testDPoPKeyChangeInvalidatesTlsSessions() {

        final AtomicInteger invalidations = new AtomicInteger();
        SSLSession session = Mockito.mock(SSLSession.class);
        Mockito.doAnswer(invocation -> invalidations.incrementAndGet()).when(session).invalidate();

        final byte[] sessionId = {1};
        final byte[] removedSessionId = {2};
        SSLSessionContext sessionContext = Mockito.mock(SSLSessionContext.class);
        Mockito.when(sessionContext.getIds())
                .thenAnswer(invocation -> Collections.enumeration(List.of(sessionId, removedSessionId)));
        Mockito.when(sessionContext.getSession(sessionId)).thenReturn(session);
        Mockito.when(sessionContext.getSession(removedSessionId)).thenReturn(null);

        SSLContext sslContext = Mockito.mock(SSLContext.class);
        Mockito.when(sslContext.getClientSessionContext()).thenReturn(sessionContext);

        ZTSClient client = new ZTSClient(ZTS_URL, sslContext);
        client.getDPoPBinding();
        assertEquals(invalidations.get(), 0);

        // the first key used with the ssl context drops sessions created before dpop was enabled

        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        client.getDPoPBinding();
        assertEquals(invalidations.get(), 1);
        client.getDPoPBinding();
        assertEquals(invalidations.get(), 1);

        // prefetch clients sharing the ssl context and key keep the sessions

        ZTSClient prefetchClient = new ZTSClient(ZTS_URL, sslContext);
        prefetchClient.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        prefetchClient.getDPoPBinding();
        assertEquals(invalidations.get(), 1);

        // a rotated key drops the sessions authenticated with the old certificate

        client.setDPoPKey(otherKey.getPrivate(), otherKey.getPublic());
        client.getDPoPBinding();
        assertEquals(invalidations.get(), 2);
        client.getDPoPBinding();
        assertEquals(invalidations.get(), 2);

        prefetchClient.close();
        client.close();
    }

    @Test
    public void testDPoPBindingWithoutSslContext() {

        ZTSClient client = createClient(Mockito.mock(ZTSRDLGeneratedClient.class));
        client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
        assertTrue(client.getDPoPBinding().isEnabled());
        client.close();
    }

    @Test
    public void testGetAccessTokenDPoPSkipsDiskTokens() throws Exception {

        File jwksUri = new File("./src/test/resources/jwt_jwks.json");
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver("file://" + jwksUri.getCanonicalPath(), null);
        System.setProperty(ZTSAccessTokenFileLoader.ACCESS_TOKEN_PATH_PROPERTY, Paths.get("./src/test/resources/").toString());
        setupTokenFile();

        ZTSRDLGeneratedClient rdlClient = Mockito.mock(ZTSRDLGeneratedClient.class);
        Mockito.when(rdlClient.postAccessTokenRequest(
                "grant_type=client_credentials&expires_in=3600&scope=test.domain%3Arole.admin"))
                .thenReturn(tokenResponse("dpop-token", "DPoP"));

        ZTSClient.setAccessTokenSignKeyResolver(resolver);
        ZTSClient.resetZTSAccessTokenFileLoader();
        ZTSClient.initZTSAccessTokenFileLoader(ZTS_URL, null);
        try {
            ZTSClient client = createClient(rdlClient);

            // without dpop the bearer token from disk is returned

            AccessTokenResponse response = client.getAccessToken("test.domain", Collections.singletonList("admin"), 3600);
            assertEquals(response.getToken_type(), "Bearer");
            assertEquals((int) response.getExpires_in(), 28800);

            // with dpop the disk token is skipped and the server is called

            client.setDPoPKey(dpopKey.getPrivate(), dpopKey.getPublic());
            response = client.getAccessToken("test.domain", Collections.singletonList("admin"), 3600);
            assertEquals(response.getAccess_token(), "dpop-token");

            OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder
                    .newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_CLIENT_CREDENTIALS)
                    .domainName("test.domain").roleNames(Collections.singletonList("admin")).expiryTime(3600);
            assertEquals(client.getAccessToken(builder, true).getAccess_token(), "dpop-token");
            client.close();
        } finally {
            ZTSClient.resetZTSAccessTokenFileLoader();
            System.clearProperty(ZTSAccessTokenFileLoader.ACCESS_TOKEN_PATH_PROPERTY);
        }
    }

    @Test
    public void testPrefetchTaskClientInheritsDPoP() throws Exception {

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);

        DPoPKeyProvider provider = () -> dpopKey;
        ZTSClient.PrefetchTokenScheduledItem item = new ZTSClient.PrefetchTokenScheduledItem()
                .setProvidedZTSUrl(ZTS_URL)
                .setSslContext(sslContext)
                .setDPoPKeyProvider(provider)
                .setDPoPAllowBearerFallback(true);

        try (ZTSClient client = new ZTSClient.TokenPrefetchTask().getZTSClient(item)) {
            assertEquals(client.getDPoPKeyPair(), dpopKey);
        }

        // items with different dpop providers or fallback modes are different prefetch entries

        ZTSClient.PrefetchTokenScheduledItem item2 = new ZTSClient.PrefetchTokenScheduledItem()
                .setProvidedZTSUrl(ZTS_URL)
                .setSslContext(sslContext)
                .setDPoPKeyProvider(provider)
                .setDPoPAllowBearerFallback(true);
        assertEquals(item, item2);
        assertEquals(item.hashCode(), item2.hashCode());

        item2.setDPoPAllowBearerFallback(false);
        assertNotEquals(item, item2);
        assertNotEquals(item.hashCode(), item2.hashCode());
        item2.setDPoPAllowBearerFallback(true);

        item2.setDPoPKeyProvider(() -> otherKey);
        assertNotEquals(item, item2);

        item2.setDPoPKeyProvider(null);
        assertNotEquals(item, item2);
        assertNotEquals(item2, item);
    }
}
