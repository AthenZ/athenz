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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.token.AccessTokenScope;
import com.yahoo.rdl.Timestamp;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.Response;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static org.testng.Assert.*;

/**
 * End-to-end proof of concept for PSECBUGS-116078 - JWT replay via the
 * /oauth2/token client_assertion parameter, driven entirely through the public
 * ZTS API.
 *
 * <p>The scenario uses two real ZTS API calls against a fully configured server:
 * <ol>
 *   <li>The victim (user_domain.user) logs in through OIDC with weather.api as
 *       the relying party. ZTS issues a genuine ID token via
 *       {@code getOIDCResponse} - sub = user_domain.user, aud = weather.api,
 *       iss = the ZTS OpenID issuer. Handing this token to weather.api is the
 *       entire point of the OIDC flow, so weather.api legitimately holds it.</li>
 *   <li>weather.api replays that ID token as its own {@code client_assertion}
 *       to {@code postAccessTokenRequest}, asking for the victim's roles in the
 *       unrelated sports domain.</li>
 * </ol>
 *
 * <p>Before the fix, ZTS validated only the signature (the token is genuinely
 * ZTS-signed), took the caller identity from the {@code sub} claim, and minted a
 * brand new access token with sub = user_domain.user and scp = [writers] in the
 * sports domain, because nothing tied the assertion to the service that actually
 * holds it.
 *
 * <p>These are now regression tests for the fix:
 * <ul>
 *   <li>{@code testIdTokenReplayedAsClientAssertion} - the id token's audience is
 *       the relying party, so it fails the RFC 7523 audience check added in
 *       {@code AccessTokenRequest.validateClientAuthAudience}.</li>
 *   <li>{@code testOnBehalfOfTokenReplayedAsClientAssertionRejected} - a token
 *       whose audience does target the endpoint is still rejected because its
 *       {@code client_id} (holder) does not match its {@code sub}, enforced in
 *       {@code OAuth2Token.parseOAuth2Token}.</li>
 *   <li>{@code testSelfSignedAssertionForVictimIsRejected} - the pre-existing
 *       self-signed branch still rejects a forged (non-ZTS) token.</li>
 * </ul>
 *
 * @see com.yahoo.athenz.auth.token.OAuth2Token
 */
public class ZTSImplClientAssertionIdTokenReplayTest {

    private ZTSImpl zts = null;
    private Metric ztsMetric = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String MOCKCLIENTADDR = "10.11.12.13";

    private static final String VICTIM = "user_domain.user";
    private static final String HOLDER_DOMAIN = "weather";
    private static final String HOLDER_SERVICE = "api";
    private static final String HOLDER = HOLDER_DOMAIN + "." + HOLDER_SERVICE;
    private static final String TARGET_DOMAIN = "sports";
    private static final String TARGET_SCOPE = TARGET_DOMAIN + ":role.writers";

    private static final String JWT_BEARER_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    @Mock private HttpServletRequest mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;

    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);

        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS,
                "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES,
                "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS, "screwdriver,rbac.*");

        ztsMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
    }

    @BeforeMethod
    public void setup() {

        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(Crypto.encodedFile(new File(privKeyName))));

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_IDENTITY, "false");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");

        ChangeLogStore structStore = new MockZMSFileChangeLogStore(ZTS_DATA_STORE_PATH, privateKey, "0");
        cloudStore = new CloudStore();

        store = new DataStore(structStore, cloudStore, ztsMetric);

        // build the server with the dedicated token signing key - the default
        // unit test key is too small to sign JSON web objects with.

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_at_private.pem");
        zts = new ZTSImpl(cloudStore, store);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");

        ZTSImpl.serverHostName = "localhost";

        AccessTokenScope.setSupportOpenIdScope(true);
        AccessTokenScope.setMaxDomains(1);
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        AccessTokenScope.setMaxDomains(1);
    }

    /**
     * The full attack, end to end through the ZTS API. With the fix in place the
     * replay must be rejected; before the fix ZTS minted a victim-scoped access
     * token here.
     */
    @Test
    public void testIdTokenReplayedAsClientAssertion() throws JOSEException, java.text.ParseException {

        setupDomains();

        // ------------------------------------------------------------------
        // step 1 - the victim logs in through OIDC with weather.api as the
        // relying party. ZTS hands weather.api a genuine ID token for the user.
        // ------------------------------------------------------------------

        final String idToken = getIdTokenForVictim();

        JWTClaimsSet idClaims = parseAndVerify(idToken);
        assertEquals(idClaims.getSubject(), VICTIM, "id token subject is the victim user");
        assertEquals(idClaims.getAudience().get(0), HOLDER, "id token was issued to weather.api");
        assertEquals(idClaims.getIssuer(), zts.ztsOpenIDIssuer, "id token was issued by ZTS");

        // ------------------------------------------------------------------
        // step 2 - weather.api replays the victim's ID token as its own
        // client_assertion and asks for the victim's roles in the sports
        // domain, which has nothing to do with the weather domain.
        //
        // the caller presents no client certificate; authentication on
        // /oauth2/token is optional precisely so that the client_assertion can
        // establish the caller identity. see ZTSImpl.postAccessTokenRequest.
        // ------------------------------------------------------------------

        ResourceContext anonymousContext = createResourceContext(null);

        // ------------------------------------------------------------------
        // FIXED - the id token's audience is the relying party (weather.api),
        // not the ZTS token endpoint, so it is rejected as a client assertion
        // (RFC 7523 audience check). Before the fix this minted an access token
        // with sub=user_domain.user and scp=[writers] in the sports domain.
        // ------------------------------------------------------------------

        try {
            zts.postAccessTokenRequest(anonymousContext,
                    "grant_type=client_credentials"
                            + "&scope=" + TARGET_SCOPE
                            + "&client_assertion_type=" + JWT_BEARER_ASSERTION_TYPE
                            + "&client_assertion=" + idToken);
            fail("id token replayed as a client assertion must be rejected");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("does not identify the token endpoint"),
                    "expected the audience check to reject it, got: " + ex.getMessage());
        }
    }

    /**
     * A ZTS-signed on-behalf-of token that DOES target the token endpoint (so it
     * passes the audience check) is still rejected, because its client_id (the
     * holder service) does not match its subject (the victim user). This covers
     * the delegation/impersonation vector, which the audience check alone would
     * not catch.
     */
    @Test
    public void testOnBehalfOfTokenReplayedAsClientAssertionRejected() {

        setupDomains();

        // sub = victim, client_id = holder service, aud = the ZTS token endpoint
        final String onBehalfOfToken = createOnBehalfOfTokenForEndpoint();

        ResourceContext anonymousContext = createResourceContext(null);
        try {
            zts.postAccessTokenRequest(anonymousContext,
                    "grant_type=client_credentials"
                            + "&scope=" + TARGET_SCOPE
                            + "&client_assertion_type=" + JWT_BEARER_ASSERTION_TYPE
                            + "&client_assertion=" + onBehalfOfToken);
            fail("on-behalf-of token replayed as a client assertion must be rejected");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("does not match client_id"),
                    "expected the client_id binding check to reject it, got: " + ex.getMessage());
        }
    }

    /**
     * Control case - the same replay attempted by an attacker who does not hold
     * a ZTS-signed token is correctly rejected. This shows the replay above
     * succeeds specifically because ZTS signed the token, not because the
     * endpoint accepts anything.
     */
    @Test
    public void testSelfSignedAssertionForVictimIsRejected() {

        setupDomains();

        // a token the attacker signs itself, claiming to be the victim.
        // the non-ZTS issuer branch enforces iss == sub, so this is rejected.
        final String forgedToken = createSelfSignedAssertion();

        ResourceContext anonymousContext = createResourceContext(null);
        try {
            zts.postAccessTokenRequest(anonymousContext,
                    "grant_type=client_credentials"
                            + "&scope=" + TARGET_SCOPE
                            + "&client_assertion_type=" + JWT_BEARER_ASSERTION_TYPE
                            + "&client_assertion=" + forgedToken);
            fail("self-signed assertion claiming to be the victim must be rejected");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("mismatched issuer"),
                    "expected the iss == sub check to reject it, got: " + ex.getMessage());
        }
    }

    // ----------------------------------------------------------------------
    // helpers
    // ----------------------------------------------------------------------

    /**
     * Ask ZTS for a real OIDC ID token for the victim, with weather.api as the
     * relying party - exactly what happens when the user logs into that service.
     */
    private String getIdTokenForVictim() {

        Principal victim = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext victimContext = createResourceContext(victim);

        Response response = zts.getOIDCResponse(victimContext, "id_token", HOLDER,
                null, "openid", null, "nonce", null,
                null, null, "json", null, null);

        assertEquals(response.getStatus(), ResourceException.OK);
        OIDCResponse oidcResponse = (OIDCResponse) response.getEntity();
        assertNotNull(oidcResponse);
        assertTrue(oidcResponse.getSuccess());

        final String idToken = oidcResponse.getId_token();
        assertNotNull(idToken);
        return idToken;
    }

    /**
     * A genuine ZTS-signed on-behalf-of token: sub = victim, client_id = holder
     * service, aud = the ZTS token endpoint. The audience is valid, so this
     * exercises the client_id binding rather than the audience check.
     */
    private String createOnBehalfOfTokenForEndpoint() {
        try {
            PrivateKey ztsSigningKey = getSignPrivateKey().getKey();
            com.nimbusds.jose.JWSSigner signer = JwtsHelper.getJWSSigner(ztsSigningKey);
            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(VICTIM)                    // acting-for user
                    .issuer(zts.ztsOAuthIssuer)         // signed by ZTS
                    .audience(zts.ztsOAuthIssuer)       // targets the token endpoint
                    .claim("client_id", HOLDER)         // issued to the holder service
                    .issueTime(java.util.Date.from(java.time.Instant.ofEpochSecond(now)))
                    .expirationTime(java.util.Date.from(java.time.Instant.ofEpochSecond(now + 3600)))
                    .build();
            SignedJWT signedJWT = new SignedJWT(
                    new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.parse(
                            getSignPrivateKey().getAlgorithm()))
                            .keyID(getSignPrivateKey().getId()).build(), claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException ex) {
            fail("unable to create on-behalf-of token: " + ex.getMessage());
            return null;
        }
    }

    /**
     * A token the attacker signs with its own key while claiming sub = victim.
     */
    private String createSelfSignedAssertion() {
        try {
            PrivateKey attackerKey = Crypto.loadPrivateKey(
                    new File("src/test/resources/unit_test_zts_private_ec.pem"));
            com.nimbusds.jose.JWSSigner signer = JwtsHelper.getJWSSigner(attackerKey);
            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(VICTIM)        // claims to be the victim ...
                    .issuer(HOLDER)         // ... but signed by the attacker service
                    .audience(zts.ztsOAuthIssuer)
                    .issueTime(java.util.Date.from(java.time.Instant.ofEpochSecond(now)))
                    .expirationTime(java.util.Date.from(java.time.Instant.ofEpochSecond(now + 3600)))
                    .build();
            SignedJWT signedJWT = new SignedJWT(
                    new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                            .keyID("0").build(), claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException ex) {
            fail("unable to create self-signed assertion: " + ex.getMessage());
            return null;
        }
    }

    /**
     * Verify a ZTS-issued JWT against the server's own signing key and return
     * its claims.
     */
    private JWTClaimsSet parseAndVerify(final String token) throws JOSEException {
        ServerPrivateKey signingKey = getSignPrivateKey();
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(signingKey.getKey()));
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            assertTrue(signedJWT.verify(verifier), "token must be signed by ZTS");
            return signedJWT.getJWTClaimsSet();
        } catch (java.text.ParseException ex) {
            fail("unable to parse token: " + ex.getMessage());
            return null;
        }
    }

    private ServerPrivateKey getSignPrivateKey() {
        return zts.getSignPrivateKey(zts.keyAlgoForJsonWebObjects);
    }

    /**
     * Register the domains the scenario needs:
     * <ul>
     *   <li>sys.auth with the zts service publishing the server's signing key,
     *       so ZTS can verify its own tokens - what a real deployment has.</li>
     *   <li>weather, holding the weather.api service (the OIDC relying party
     *       and the attacker).</li>
     *   <li>sports, where the victim is a member of the writers role.</li>
     * </ul>
     */
    private void setupDomains() {

        // sys.auth.zts publishes the ZTS signing public key under the same key
        // id ZTS stamps into the tokens it issues.

        ServerPrivateKey signingKey = getSignPrivateKey();
        PublicKey publicKey = Crypto.extractPublicKey(signingKey.getKey());
        final String ybase64PublicKey = Crypto.ybase64EncodeString(Crypto.convertToPEMFormat(publicKey));

        com.yahoo.athenz.zms.ServiceIdentity ztsService =
                new com.yahoo.athenz.zms.ServiceIdentity().setName("sys.auth.zts");
        setServicePublicKey(ztsService, signingKey.getId(), ybase64PublicKey);
        store.processSignedDomain(createSignedDomain("sys.auth", List.of(),
                List.of(ztsService)), false);

        // the weather domain with the weather.api service - the OIDC relying
        // party that legitimately receives the victim's id token.

        com.yahoo.athenz.zms.ServiceIdentity holderService =
                new com.yahoo.athenz.zms.ServiceIdentity().setName(HOLDER);
        setServicePublicKey(holderService, "0", ybase64PublicKey);

        Role weatherRole = new Role().setName(HOLDER_DOMAIN + ":role.users")
                .setRoleMembers(List.of(new RoleMember().setMemberName(VICTIM)));
        store.processSignedDomain(createSignedDomain(HOLDER_DOMAIN, List.of(weatherRole),
                List.of(holderService)), false);

        // the target domain, unrelated to weather, where the victim holds a role

        Role targetRole = new Role().setName(TARGET_DOMAIN + ":role.writers")
                .setRoleMembers(List.of(new RoleMember().setMemberName(VICTIM)));
        store.processSignedDomain(createSignedDomain(TARGET_DOMAIN, List.of(targetRole),
                List.of()), false);
    }

    private void setServicePublicKey(com.yahoo.athenz.zms.ServiceIdentity service,
            final String id, final String key) {
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry =
                new com.yahoo.athenz.zms.PublicKeyEntry().setId(id).setKey(key);
        List<com.yahoo.athenz.zms.PublicKeyEntry> keys = new ArrayList<>();
        keys.add(keyEntry);
        service.setPublicKeys(keys);
    }

    private SignedDomain createSignedDomain(final String domainName, List<Role> roles,
            List<com.yahoo.athenz.zms.ServiceIdentity> services) {

        DomainPolicies domainPolicies = new DomainPolicies().setDomain(domainName)
                .setPolicies(new ArrayList<>());

        SignedPolicies signedPolicies = new SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(new ArrayList<>(roles));
        domain.setServices(new ArrayList<>(services));
        domain.setGroups(new ArrayList<>());
        domain.setEntities(new ArrayList<>());
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        SignedDomain signedDomain = new SignedDomain();
        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");
        return signedDomain;
    }

    private ResourceContext createResourceContext(Principal principal) {
        ServerResourceContext rsrcCtx = Mockito.mock(ServerResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        if (principal != null) {
            Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return rsrcCtxWrapper;
    }
}
