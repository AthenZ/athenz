/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts;

import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.pdp.ExternalPdpContext;
import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import com.yahoo.athenz.common.server.pdp.ExternalPolicyDecisionPoint;
import com.yahoo.athenz.common.server.pdp.authzen.*;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.pdp.ExternalPdpConfig;
import com.yahoo.athenz.zts.pdp.ExternalPdpManager;
import com.yahoo.athenz.zts.pdp.ExternalPdpMode;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.token.AccessTokenRequest;
import com.yahoo.athenz.zts.token.AccessTokenRequest.RequestType;
import com.yahoo.athenz.zts.token.AccessTokenScope;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.ServerCommonConsts.METRIC_DEFAULT_FACTORY_CLASS;
import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.testng.Assert.*;

public class ExternalPdpTokenProcessorTest {

    private static final String ZTS_DATA_STORE_PATH = "target/zts_pdp_unit_tests/zts_root";
    private static final String USER = "user_domain.user";
    private static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final Set<String> VOLATILE_CLAIMS = Set.of("jti", "iat", "exp", "auth_time");

    private static final String[] PDP_PROPS = {
        ExternalPdpConfig.PROP_MODE, ExternalPdpConfig.PROP_AUDIT_TARGET, ExternalPdpConfig.PROP_ENDPOINT,
        ExternalPdpConfig.PROP_FLOWS, ExternalPdpConfig.PROP_TIMEOUT_MS, ExternalPdpConfig.PROP_FAIL_OPEN,
        ExternalPdpConfig.PROP_FAIL_OPEN_MAX_EXPIRES_IN, ExternalPdpConfig.PROP_REQUIRE_DEFINED_ROLES,
        ExternalPdpConfig.PROP_MAX_CANDIDATE_ROLES, ExternalPdpConfig.PROP_CLAIMS_ENABLED,
        ExternalPdpConfig.PROP_CLAIMS_STRICT, ExternalPdpConfig.PROP_AUDIT_QUEUE_SIZE
    };

    /** Scriptable in-memory decision point. */
    public static final class FakePdp implements ExternalPolicyDecisionPoint {

        interface Handler {
            EvaluationsResponse handle(EvaluationsRequest request) throws ExternalPdpException;
        }

        volatile Handler handler = FakePdp::permitAll;
        final List<EvaluationsRequest> requests = new CopyOnWriteArrayList<>();
        volatile CountDownLatch latch;

        @Override
        public void initialize(ExternalPdpContext context) {
        }

        @Override
        public EvaluationsResponse evaluations(EvaluationsRequest request) throws ExternalPdpException {
            requests.add(request);
            try {
                return handler.handle(request);
            } finally {
                if (latch != null) {
                    latch.countDown();
                }
            }
        }

        static EvaluationsResponse permitAll(EvaluationsRequest request) {
            return respond(request, Collections.emptySet(), true, null);
        }

        static Handler deny(Set<String> deniedIds, boolean gate, Map<String, Object> gateContext) {
            return request -> respond(request, deniedIds, gate, gateContext);
        }

        // denies items whose "type/id" is listed, to tell role and permission items with the same id apart
        static Handler denyTyped(Set<String> deniedTypedIds) {
            return request -> {
                List<EvaluationResponse> results = new ArrayList<>();
                for (int i = 0; i < request.getEvaluations().size(); i++) {
                    Resource resource = request.getEvaluations().get(i).getResource();
                    results.add(new EvaluationResponse(i == 0
                            || !deniedTypedIds.contains(resource.getType() + "/" + resource.getId()), null));
                }
                return new EvaluationsResponse(results);
            };
        }

        static EvaluationsResponse respond(EvaluationsRequest request, Set<String> deniedIds, boolean gate,
                Map<String, Object> gateContext) {
            List<EvaluationResponse> results = new ArrayList<>();
            for (int i = 0; i < request.getEvaluations().size(); i++) {
                if (i == 0) {
                    results.add(new EvaluationResponse(gate, gateContext));
                    continue;
                }
                Resource resource = request.getEvaluations().get(i).getResource();
                results.add(new EvaluationResponse(!deniedIds.contains(resource.getId()), null));
            }
            return new EvaluationsResponse(results);
        }
    }

    private ZTSImpl zts;
    private DataStore store;
    private CloudStore cloudStore;
    private PrivateKey privateKey;
    private FakePdp pdp;
    private ExternalPdpTokenProcessor processor;
    private MockHttpServletRequest servletRequest;

    @BeforeClass
    public void setupClass() {
        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, METRIC_DEFAULT_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME, "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");
    }

    @BeforeMethod
    public void setup() {
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(Crypto.encodedFile(
                new File("src/test/resources/unit_test_zts_private.pem"))));
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, "2400");
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, "96000");
        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS, "user_domain.proxy");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_IDENTITY, "false");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, ZTS_DATA_STORE_PATH + "_certs");

        ChangeLogStore structStore = Mockito.mock(ChangeLogStore.class);
        cloudStore = new CloudStore();
        Metric metric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        store = new DataStore(structStore, cloudStore, metric);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        zts = new ZTSImpl(cloudStore, store);
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        ZTSImpl.serverHostName = "localhost";
        assertNull(zts.externalPdpProcessor);

        AccessTokenScope.setSupportOpenIdScope(true);
        AccessTokenScope.setMaxDomains(2);

        addDomain("coretech", List.of(
                ZTSTestUtils.createRoleObject("coretech", "readers", USER, "user_domain.proxy"),
                ZTSTestUtils.createRoleObject("coretech", "writers", USER),
                ZTSTestUtils.createRoleObject("coretech", "admin", "user_domain.adminuser")));
        addDomain("weather", List.of(ZTSTestUtils.createRoleObject("weather", "forecasters", USER)));

        pdp = new FakePdp();
        servletRequest = new MockHttpServletRequest() {
            @Override
            public String getRemoteAddr() {
                return "10.11.12.13";
            }
        };
    }

    @AfterMethod
    public void shutdown() {
        if (processor != null) {
            processor.close();
            processor = null;
        }
        for (String prop : PDP_PROPS) {
            System.clearProperty(prop);
        }
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH);
        AccessTokenScope.setMaxDomains(1);
    }

    private void addDomain(String domainName, List<Role> roles) {
        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(domainName,
                roles == null ? null : new ArrayList<>(roles),
                new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), privateKey);
        store.processSignedDomain(signedDomain, false);
    }

    private ExternalPdpTokenProcessor.Services services() {
        return new ExternalPdpTokenProcessor.Services.Builder()
                .privateKeyStore(zts.privateKeyStore)
                .dataStore(store)
                .authorizer(zts.authorizer)
                .issuerResolver(zts.issuerResolver)
                .providerConfigManager(zts.providerConfigManager)
                .metric(zts.metric)
                .validator(ZTSImpl.validator)
                .userDomain(zts.userDomain)
                .spiffeUriManager(zts.spiffeUriManager)
                .tokenIssuanceConfig(zts.tokenIssuanceConfig)
                .signingKeys(zts.keyAlgoForJsonWebObjects, zts.privateRSAKey, zts.privateECKey, zts.privateOrigKey)
                .legacyFlow(zts::processAccessTokenRequestType)
                .build();
    }

    private ExternalPdpMode lastMode;
    private String[] lastProps;

    // the processor receives its collaborators at creation time, so
    // replacing the authorizer requires creating the processor again

    private void setAuthorizer(ZTSAuthorizer authorizer) {
        zts.authorizer = authorizer;
        if (processor != null) {
            processor.close();
            enable(lastMode, lastProps);
        }
    }

    private ExternalPdpTokenProcessor enable(ExternalPdpMode mode, String... props) {
        lastMode = mode;
        lastProps = props;
        System.setProperty(ExternalPdpConfig.PROP_MODE, mode.name());
        System.setProperty(ExternalPdpConfig.PROP_ENDPOINT, "class://fake");
        for (int i = 0; i < props.length; i += 2) {
            System.setProperty(props[i], props[i + 1]);
        }
        ExternalPdpConfig config = ExternalPdpConfig.fromSystemProperties();
        try {
            processor = new ExternalPdpTokenProcessor(config,
                    new ExternalPdpManager(config, pdp, new ExternalPdpContext.Builder()), services());
        } catch (ExternalPdpException ex) {
            fail(ex.getMessage());
        }
        zts.externalPdpProcessor = processor;
        return processor;
    }

    private ResourceContext context(Principal principal, String requestDomain) {
        RsrcCtxWrapper ctx = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(ctx.principal()).thenReturn(principal);
        Mockito.when(ctx.request()).thenReturn(servletRequest);
        Mockito.when(ctx.getApiName()).thenReturn("postaccesstokenrequest");
        Mockito.when(ctx.logPrincipal()).thenReturn(principal.getFullName());
        Mockito.when(ctx.getPrincipalDomain()).thenReturn(principal.getDomain());
        Mockito.when(ctx.getRequestDomain()).thenReturn(requestDomain);
        return ctx;
    }

    private static java.security.cert.X509Certificate certificate() {
        try {
            return Crypto.loadX509Certificate(new String(java.nio.file.Files.readAllBytes(
                    java.nio.file.Paths.get("src/test/resources/mtls_token_spec.cert"))));
        } catch (java.io.IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Principal user() {
        return SimplePrincipal.create("user_domain", "user", "v=U1;d=user_domain;n=user;s=sig", 0, null);
    }

    private AccessTokenResponse post(Principal principal, String body) {
        return zts.postAccessTokenRequest(context(principal, "coretech"), body);
    }

    private static String scopeBody(String scope) {
        return "grant_type=client_credentials&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8);
    }

    static Map<String, Object> claims(String token) {
        try {
            Map<String, Object> claims = new HashMap<>(SignedJWT.parse(token).getJWTClaimsSet().getClaims());
            claims.keySet().removeAll(VOLATILE_CLAIMS);
            return claims;
        } catch (java.text.ParseException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static int status(Runnable call) {
        try {
            call.run();
        } catch (ResourceException ex) {
            return ex.getCode();
        }
        return ResourceException.OK;
    }

    private EvaluationsRequest lastRequest() {
        return pdp.requests.get(pdp.requests.size() - 1);
    }

    private static List<String> roleIds(EvaluationsRequest request) {
        List<String> ids = new ArrayList<>();
        for (EvaluationRequest item : request.getEvaluations()) {
            if (AuthZenRequestBuilder().equals(item.getResource().getType())) {
                ids.add(item.getResource().getId());
            }
        }
        return ids;
    }

    private static String AuthZenRequestBuilder() {
        return com.yahoo.athenz.zts.pdp.AuthZenRequestBuilder.RESOURCE_ROLE;
    }

    // ---------------------------------------------------------------- creation

    @Test
    public void testCreate() {
        assertNull(ExternalPdpTokenProcessor.create(services()));

        System.setProperty(ExternalPdpConfig.PROP_MODE, "FILTER");
        System.setProperty(ExternalPdpConfig.PROP_ENDPOINT, "class://" + FakePdp.class.getName());
        ExternalPdpTokenProcessor created = ExternalPdpTokenProcessor.create(services());
        assertNotNull(created);
        assertEquals(created.getMode(), ExternalPdpMode.FILTER);
        created.close();

        zts.loadExternalPdpProcessor();
        assertNotNull(zts.externalPdpProcessor);
        zts.externalPdpProcessor.close();
        zts.externalPdpProcessor = null;

        System.setProperty(ExternalPdpConfig.PROP_ENDPOINT, "https://");
        assertThrows(IllegalArgumentException.class,
                () -> ExternalPdpTokenProcessor.create(services()));
    }

    @Test
    public void testCreateDisabledIgnoresOtherProperties() {
        System.setProperty(ExternalPdpConfig.PROP_TIMEOUT_MS, "abc");
        System.setProperty(ExternalPdpConfig.PROP_FLOWS, "unknown_flow");
        assertNull(ExternalPdpTokenProcessor.create(services()));

        System.setProperty(ExternalPdpConfig.PROP_MODE, "disabled");
        assertNull(ExternalPdpTokenProcessor.create(services()));
    }

    @Test
    public void testHandles() {
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_FLOWS, "access_token,jag");
        assertTrue(processor.handles(RequestType.ACCESS_TOKEN));
        assertFalse(processor.handles(RequestType.ACCESS_TOKEN_EXCHANGE));
        assertTrue(processor.handles(RequestType.JAG_TOKEN_EXCHANGE));
        assertTrue(processor.handles(RequestType.JAG_JWT_BEARER));
        assertFalse(processor.handles(RequestType.ID_TOKEN_EXCHANGE));
    }

    // ---------------------------------------------------------- role credentials

    @Test
    public void testRoleCredentialsRejectedWhenEnforcing() {
        enable(ExternalPdpMode.FILTER);
        ResourceContext ctx = context(user(), "coretech");
        assertEquals(status(() -> zts.getRoleToken(ctx, "coretech", null, null, null, null)),
                ResourceException.FORBIDDEN);
        assertEquals(status(() -> zts.postRoleCertificateRequest(ctx, "coretech", "readers",
                new RoleCertificateRequest())), ResourceException.FORBIDDEN);
        assertEquals(status(() -> zts.postRoleCertificateRequestExt(ctx, new RoleCertificateRequest())),
                ResourceException.FORBIDDEN);
        assertTrue(pdp.requests.isEmpty());
    }

    @Test
    public void testRoleCredentialsAllowedInAudit() {
        enable(ExternalPdpMode.AUDIT);
        ResourceContext ctx = context(user(), "coretech");
        processor.checkRoleCredentialRequest(ctx, "getroletoken", "user_domain");

        RsrcCtxWrapper noPrincipal = Mockito.mock(RsrcCtxWrapper.class);
        processor.checkRoleCredentialRequest(noPrincipal, "getroletoken", "user_domain");

        RoleToken roleToken = zts.getRoleToken(ctx, "coretech", "readers", null, null, null);
        assertNotNull(roleToken.getToken());
    }

    // ------------------------------------------------------------ standard flow

    @Test
    public void testStandardFilterParity() {
        AccessTokenResponse legacy = post(user(), scopeBody("coretech:domain"));
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse filtered = post(user(), scopeBody("coretech:domain"));

        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(filtered.getScope(), legacy.getScope());
        assertEquals(filtered.getExpires_in(), legacy.getExpires_in());
        assertEquals(filtered.getToken_type(), legacy.getToken_type());

        EvaluationsRequest request = lastRequest();
        assertEquals(request.getSubject().getId(), USER);
        assertEquals(request.getContext().get("mode"), "FILTER");
        assertEquals(request.getContext().get("client_ip"), "10.11.12.13");
        assertEquals(new TreeSet<>(roleIds(request)), Set.of("coretech:role.readers", "coretech:role.writers"));
        assertTrue(((String) servletRequest.getAttribute(ExternalPdpTokenProcessor.ACCESS_LOG_ADDL_QUERY))
                .contains("pdp_mode=filter&pdp_request_id="));
    }

    @Test
    public void testStandardFilterParityOpenIdAndMultiDomain() {
        final String body = scopeBody("coretech:domain weather:role.forecasters") + "&audience=coretech";
        AccessTokenResponse legacy = post(user(), body);
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse filtered = post(user(), body);
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(filtered.getScope(), legacy.getScope());
        assertEquals(roleIds(lastRequest()).size(), 3);

        processor.close();
        zts.externalPdpProcessor = null;
        final String openIdBody = scopeBody("coretech:domain openid coretech:service.api");
        legacy = post(user(), openIdBody);
        enable(ExternalPdpMode.FILTER);
        filtered = post(user(), openIdBody);
        assertNotNull(filtered.getId_token());
        assertEquals(claims(filtered.getId_token()), claims(legacy.getId_token()));
        assertEquals(filtered.getScope(), legacy.getScope());
    }

    @Test
    public void testStandardFilterNarrowsScope() {
        enable(ExternalPdpMode.FILTER);
        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers"), true, null);
        AccessTokenResponse response = post(user(), scopeBody("coretech:domain"));
        assertEquals(claims(response.getAccess_token()).get("scp"), List.of("readers"));
        assertEquals(response.getScope(), "coretech:role.readers");
        assertTrue(((String) servletRequest.getAttribute(ExternalPdpTokenProcessor.ACCESS_LOG_ADDL_QUERY))
                .contains("pdp_removed=1"));
    }

    @Test
    public void testStandardFilterDenials() {
        enable(ExternalPdpMode.FILTER);
        pdp.handler = FakePdp.deny(Collections.emptySet(), false, null);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain"))), ResourceException.FORBIDDEN);

        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers", "coretech:role.readers"), true, null);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain"))), ResourceException.FORBIDDEN);

        // rbac denial happens before the pdp is consulted
        int calls = pdp.requests.size();
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.admin"))), ResourceException.FORBIDDEN);
        assertEquals(pdp.requests.size(), calls);
    }

    @Test
    public void testStandardMaxExpiresIn() {
        enable(ExternalPdpMode.FILTER);
        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("max_expires_in", 120));
        AccessTokenResponse response = post(user(), scopeBody("coretech:role.readers"));
        assertEquals(response.getExpires_in(), Integer.valueOf(120));
    }

    @Test
    public void testStandardClaims() {
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true");
        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("tier", "gold")));
        AccessTokenResponse response = post(user(), scopeBody("coretech:role.readers"));
        assertEquals(claims(response.getAccess_token()).get("tier"), "gold");

        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("sub", "user.evil")));
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.readers"))), ResourceException.FORBIDDEN);

        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", "bad"));
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.readers"))), ResourceException.FORBIDDEN);

        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of()));
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.readers"))), ResourceException.OK);
    }

    @Test
    public void testStandardClaimsLenientAndDisabled() {
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true",
                ExternalPdpConfig.PROP_CLAIMS_STRICT, "false");
        pdp.handler = FakePdp.deny(Collections.emptySet(), true,
                Map.of("claims", Map.of("sub", "user.evil", "tier", "gold")));
        Map<String, Object> claims = claims(post(user(), scopeBody("coretech:role.readers")).getAccess_token());
        assertEquals(claims.get("sub"), USER);
        assertEquals(claims.get("tier"), "gold");

        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", "bad"));
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.readers"))), ResourceException.OK);

        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("sub", "user.evil")));
        claims = claims(post(user(), scopeBody("coretech:role.readers")).getAccess_token());
        assertEquals(claims.get("sub"), USER);

        processor.close();
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_CLAIMS_ENABLED, "false");
        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("tier", "gold")));
        assertNull(claims(post(user(), scopeBody("coretech:role.readers")).getAccess_token()).get("tier"));
    }

    @Test
    public void testStandardFailureModes() {
        enable(ExternalPdpMode.FILTER);
        pdp.handler = request -> {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down");
        };
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain"))), ResourceException.SERVICE_UNAVAILABLE);
        pdp.handler = request -> {
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "slow");
        };
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain"))), ResourceException.SERVICE_UNAVAILABLE);

        processor.close();
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_FAIL_OPEN, "true",
                ExternalPdpConfig.PROP_FAIL_OPEN_MAX_EXPIRES_IN, "60", ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true");
        pdp.handler = request -> {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down");
        };
        AccessTokenResponse response = post(user(), scopeBody("coretech:domain"));
        assertEquals(response.getExpires_in(), Integer.valueOf(60));
        assertEquals(new TreeSet<>((List<?>) claims(response.getAccess_token()).get("scp")),
                new TreeSet<>(List.of("readers", "writers")));
    }

    @Test
    public void testStandardProxyForPrincipal() {
        Principal proxy = SimplePrincipal.create("user_domain", "proxy", "v=U1;d=user_domain;n=proxy;s=sig", 0, null);
        final String body = scopeBody("coretech:domain") + "&proxy_for_principal=" + USER;
        AccessTokenResponse legacy = post(proxy, body);
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse filtered = post(proxy, body);
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(lastRequest().getSubject().getId(), USER);

        processor.close();
        enable(ExternalPdpMode.AUTHORITATIVE);
        pdp.handler = request -> {
            List<EvaluationResponse> results = new ArrayList<>();
            for (EvaluationRequest item : request.getEvaluations()) {
                boolean clientItem = item.getSubject() != null;
                results.add(new EvaluationResponse(!(clientItem
                        && "coretech:role.writers".equals(item.getResource().getId())), null));
            }
            return new EvaluationsResponse(results);
        };
        AccessTokenResponse response = post(proxy, body);
        assertEquals(claims(response.getAccess_token()).get("scp"), List.of("admin", "readers"));

        assertEquals(status(() -> post(proxy, scopeBody("coretech:domain openid coretech:service.api")
                + "&proxy_for_principal=" + USER)), ResourceException.BAD_REQUEST);
    }

    @Test
    public void testStandardValidationFailures() {
        enable(ExternalPdpMode.FILTER);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain weather:domain"))),
                ResourceException.BAD_REQUEST);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain") + "&audience=weather")),
                ResourceException.BAD_REQUEST);
        assertEquals(status(() -> post(user(), scopeBody("unknown:domain"))), ResourceException.NOT_FOUND);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain unknown:domain") + "&audience=coretech")),
                ResourceException.NOT_FOUND);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain weather:domain")
                + "&audience=coretech&authorization_details=%5B%5D")), ResourceException.BAD_REQUEST);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain") + "&actor=invalid%20actor")),
                ResourceException.BAD_REQUEST);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain") + "&actor=coretech.api")),
                ResourceException.OK);
    }

    @Test
    public void testStandardRoleCertPrincipal() {
        enable(ExternalPdpMode.AUTHORITATIVE);
        Principal rolePrincipal = SimplePrincipal.create("coretech", "creds", List.of("readers"), null);
        ((SimplePrincipal) rolePrincipal).setX509Certificate(certificate());
        ResourceContext ctx = context(rolePrincipal, "coretech");
        assertEquals(status(() -> zts.postAccessTokenRequest(ctx, scopeBody("coretech:role.writers"))),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testStandardAuthoritative() {
        enable(ExternalPdpMode.AUTHORITATIVE);

        // admin is not granted by rbac but the pdp is authoritative
        AccessTokenResponse response = post(user(), scopeBody("coretech:role.admin"));
        assertEquals(claims(response.getAccess_token()).get("scp"), List.of("admin"));
        EvaluationRequest roleItem = lastRequest().getEvaluations().get(1);
        assertFalse(roleItem.getResource().getProperties().containsKey("rbac_granted"));

        // domain scope enumerates all defined roles
        response = post(user(), scopeBody("coretech:domain"));
        assertEquals(new TreeSet<>((List<?>) claims(response.getAccess_token()).get("scp")),
                new TreeSet<>(List.of("admin", "readers", "writers")));

        // undefined roles are dropped when required
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.unknown"))), ResourceException.FORBIDDEN);

        // gate denial and role denials
        pdp.handler = FakePdp.deny(Collections.emptySet(), false, null);
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.admin"))), ResourceException.FORBIDDEN);
        pdp.handler = FakePdp.deny(Set.of("coretech:role.admin"), true, null);
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.admin"))), ResourceException.FORBIDDEN);

        // no fail open in authoritative mode
        pdp.handler = request -> {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down");
        };
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.admin"))),
                ResourceException.SERVICE_UNAVAILABLE);
    }

    @Test
    public void testStandardAuthoritativeUndefinedRoles() {
        enable(ExternalPdpMode.AUTHORITATIVE, ExternalPdpConfig.PROP_REQUIRE_DEFINED_ROLES, "false");
        AccessTokenResponse response = post(user(), scopeBody("coretech:role.unknown"));
        assertEquals(claims(response.getAccess_token()).get("scp"), List.of("unknown"));
        assertEquals(lastRequest().getEvaluations().get(1).getResource().getProperties().get("defined"), false);
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain"))), ResourceException.BAD_REQUEST);
    }

    @Test
    public void testStandardAuthoritativeCandidateLimit() {
        enable(ExternalPdpMode.AUTHORITATIVE, ExternalPdpConfig.PROP_MAX_CANDIDATE_ROLES, "2");
        assertEquals(status(() -> post(user(), scopeBody("coretech:domain"))), ResourceException.BAD_REQUEST);
        com.yahoo.athenz.zts.cache.DataCache empty = new com.yahoo.athenz.zts.cache.DataCache();
        empty.setDomainData(new com.yahoo.athenz.zms.DomainData().setRoles(
                List.of(new Role().setName("invalid-role-name"))));
        assertTrue(ExternalPdpTokenProcessor.definedRoles(empty).isEmpty());
        empty.setDomainData(new com.yahoo.athenz.zms.DomainData());
        assertTrue(ExternalPdpTokenProcessor.definedRoles(empty).isEmpty());
    }

    @Test
    public void testDispatchBypass() {
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_FLOWS, "jag");
        AccessTokenResponse response = post(user(), scopeBody("coretech:domain"));
        assertNotNull(response.getAccess_token());
        assertTrue(pdp.requests.isEmpty());
    }

    // ------------------------------------------------------------------- audit

    @Test
    public void testAuditTokenUnchanged() throws Exception {
        AccessTokenResponse legacy = post(user(), scopeBody("coretech:domain"));
        enable(ExternalPdpMode.AUDIT);
        pdp.latch = new CountDownLatch(1);
        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers"), true, Map.of("claims", Map.of("x", 1)));
        AccessTokenResponse audited = post(user(), scopeBody("coretech:domain"));
        assertEquals(claims(audited.getAccess_token()), claims(legacy.getAccess_token()));
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));
        EvaluationsRequest request = lastRequest();
        assertEquals(request.getContext().get("mode"), "AUDIT");
        assertEquals(new TreeSet<>(roleIds(request)), Set.of("coretech:role.readers", "coretech:role.writers"));
        assertEquals(request.getEvaluations().get(1).getResource().getProperties().get("rbac_granted"), true);

        // multi-domain tokens carry qualified role names
        pdp.latch = new CountDownLatch(1);
        post(user(), scopeBody("coretech:role.readers weather:role.forecasters") + "&audience=coretech");
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));
        assertEquals(new TreeSet<>(roleIds(lastRequest())),
                Set.of("coretech:role.readers", "weather:role.forecasters"));
    }

    @Test
    public void testAuditLegacyDenied() throws Exception {
        enable(ExternalPdpMode.AUDIT, ExternalPdpConfig.PROP_AUDIT_TARGET, "AUTHORITATIVE");
        pdp.latch = new CountDownLatch(1);
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.admin"))), ResourceException.FORBIDDEN);
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));
        EvaluationsRequest request = lastRequest();
        assertEquals(roleIds(request), List.of("coretech:role.admin"));
        assertFalse(request.getEvaluations().get(1).getResource().getProperties().containsKey("rbac_granted"));

        // pdp failures are also shadowed
        pdp.latch = new CountDownLatch(1);
        pdp.handler = request2 -> {
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "slow");
        };
        assertEquals(status(() -> post(user(), scopeBody("coretech:role.admin"))), ResourceException.FORBIDDEN);
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));

        // requests the authoritative flow rejects before the pdp call are not sent to the pdp
        final int sent = pdp.requests.size();
        assertEquals(status(() -> post(user(), scopeBody("unknown:domain"))), ResourceException.NOT_FOUND);
        assertEquals(pdp.requests.size(), sent);

        AccessTokenRequest broken = Mockito.mock(AccessTokenRequest.class);
        Mockito.when(broken.getRequestType()).thenReturn(RequestType.ACCESS_TOKEN);
        Mockito.when(broken.getScope()).thenThrow(new IllegalStateException("bad"));
        assertThrows(IllegalStateException.class, () -> processor.process(context(user(), "coretech"), user(),
                broken, "user_domain", "postaccesstokenrequest"));
    }

    @Test
    public void testAuditAuthoritativeTargetCandidates() throws Exception {
        enable(ExternalPdpMode.AUDIT, ExternalPdpConfig.PROP_AUDIT_TARGET, "AUTHORITATIVE");

        // domain scope: the candidates are all defined roles, not only the legacy issued ones
        pdp.latch = new CountDownLatch(1);
        AccessTokenResponse response = post(user(), scopeBody("coretech:domain"));
        assertEquals(new TreeSet<>((List<?>) claims(response.getAccess_token()).get("scp")),
                Set.of("readers", "writers"));
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));
        EvaluationsRequest request = lastRequest();
        assertEquals(request.getContext().get("mode"), "AUDIT");
        assertEquals(new TreeSet<>(roleIds(request)),
                Set.of("coretech:role.admin", "coretech:role.readers", "coretech:role.writers"));
        assertFalse(request.getEvaluations().get(1).getResource().getProperties().containsKey("rbac_granted"));

        // the simulation does not emit errors or change the request when the target flow rejects
        processor.close();
        System.setProperty(ExternalPdpConfig.PROP_REQUIRE_DEFINED_ROLES, "false");
        enable(ExternalPdpMode.AUDIT, ExternalPdpConfig.PROP_AUDIT_TARGET, "AUTHORITATIVE");
        final int sent = pdp.requests.size();
        assertNotNull(post(user(), scopeBody("coretech:domain")).getAccess_token());
        assertEquals(pdp.requests.size(), sent);
    }

    @Test
    public void testAuditShadowOutcome() {
        enable(ExternalPdpMode.AUDIT, ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true");
        Map<String, Set<String>> legacy = Map.of("coretech", Set.of("readers"));

        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("tier", "gold")));
        assertEquals(processor.runShadow(shadowEvaluation("readers"), legacy, ResourceException.OK, "r1",
                "access_token", USER, "coretech", Collections.emptyList()), "match");
        assertEquals(processor.runShadow(shadowEvaluation("readers", "writers"), legacy, ResourceException.OK, "r1",
                "access_token", USER, "coretech", List.of("coretech:role.unknown")), "pdp_broader");

        // strict claims validation denies the token in enforcing mode
        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("sub", "other")));
        assertEquals(processor.runShadow(shadowEvaluation("readers"), legacy, ResourceException.OK, "r1",
                "access_token", USER, "coretech", Collections.emptyList()), "pdp_deny");
        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", "not-an-object"));
        assertEquals(processor.runShadow(shadowEvaluation("readers"), legacy, ResourceException.OK, "r1",
                "access_token", USER, "coretech", Collections.emptyList()), "pdp_deny");

        // lenient validation drops the claim but issues the token
        processor.close();
        System.setProperty(ExternalPdpConfig.PROP_CLAIMS_STRICT, "false");
        enable(ExternalPdpMode.AUDIT, ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true");
        pdp.handler = FakePdp.deny(Collections.emptySet(), true, Map.of("claims", Map.of("sub", "other")));
        assertEquals(processor.runShadow(shadowEvaluation("readers"), legacy, ResourceException.OK, "r1",
                "access_token", USER, "coretech", Collections.emptyList()), "match");

        pdp.handler = request -> {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down");
        };
        assertEquals(processor.runShadow(shadowEvaluation("readers"), legacy, ResourceException.OK, "r1",
                "access_token", USER, "coretech", Collections.emptyList()), "error");
    }

    private static com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation shadowEvaluation(String... roles) {
        com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation evaluation = new com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation(
                new Subject("user", USER, null), null,
                com.yahoo.athenz.zts.pdp.AuthZenRequestBuilder.tokenResource("coretech", Set.of("coretech")));
        for (String role : roles) {
            evaluation.addRole("subject", "coretech", role, true, null, null);
        }
        return evaluation;
    }

    @Test
    public void testAuditErrorsAndQueue() throws Exception {
        enable(ExternalPdpMode.AUDIT, ExternalPdpConfig.PROP_AUDIT_QUEUE_SIZE, "1");
        CountDownLatch block = new CountDownLatch(1);
        pdp.handler = request -> {
            try {
                block.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE, "down");
        };
        for (int i = 0; i < 4; i++) {
            assertNotNull(post(user(), scopeBody("coretech:domain")).getAccess_token());
        }
        block.countDown();
    }

    @Test
    public void testAuditHelpers() throws Exception {
        assertEquals(ExternalPdpTokenProcessor.requestedRoles(Mockito.mock(AccessTokenRequest.class), "user_domain"),
                Collections.emptyMap());

        AccessTokenRequest request = Mockito.mock(AccessTokenRequest.class);
        Mockito.when(request.getScope()).thenReturn("coretech:domain weather:role.forecasters");
        assertEquals(ExternalPdpTokenProcessor.requestedRoles(request, "user_domain"),
                Map.of("weather", Set.of("forecasters")));

        Mockito.when(request.getRequestType()).thenReturn(RequestType.ACCESS_TOKEN);
        assertEquals(ExternalPdpTokenProcessor.shadowSubjectName(request, user()), USER);
        OAuth2Token subjectToken = Mockito.mock(OAuth2Token.class);
        Mockito.when(request.getSubjectTokenObj()).thenReturn(subjectToken);
        assertEquals(ExternalPdpTokenProcessor.shadowSubjectName(request, user()), USER);
        Mockito.when(subjectToken.getSubject()).thenReturn("user_domain.other");
        assertEquals(ExternalPdpTokenProcessor.shadowSubjectName(request, user()), "user_domain.other");
        AccessToken jagToken = Mockito.mock(AccessToken.class);
        Mockito.when(jagToken.getSubject()).thenReturn("user_domain.jag");
        Mockito.when(request.getRequestType()).thenReturn(RequestType.JAG_JWT_BEARER);
        Mockito.when(request.getJagTokenObj()).thenReturn(jagToken);
        assertEquals(ExternalPdpTokenProcessor.shadowSubjectName(request, user()), "user_domain.jag");

        AccessToken token = new AccessToken();
        token.setScope(List.of("readers", "weather:role.forecasters"));
        token.setIssueTime(1);
        token.setExpiryTime(2);
        com.yahoo.athenz.auth.ServerPrivateKey signKey = zts.getSignPrivateKey(null);
        final String signed = token.getSignedToken(signKey.getKey(), signKey.getId(), signKey.getAlgorithm());
        assertEquals(ExternalPdpTokenProcessor.issuedRoles(signed, null), Map.of("weather", Set.of("forecasters")));
        assertEquals(ExternalPdpTokenProcessor.issuedSubject(signed, user()), USER);
        AccessToken noScope = new AccessToken();
        noScope.setIssueTime(1);
        noScope.setExpiryTime(2);
        assertTrue(ExternalPdpTokenProcessor.issuedRoles(noScope.getSignedToken(signKey.getKey(), signKey.getId(),
                signKey.getAlgorithm()),
                "coretech").isEmpty());
    }

    // ------------------------------------------------------------ exchange flows

    private AccessTokenRequest exchangeRequest(OAuth2Token actorToken) {
        OAuth2Token subjectToken = Mockito.mock(OAuth2Token.class);
        Mockito.when(subjectToken.getAudience()).thenReturn("weather");
        Mockito.when(subjectToken.getSubject()).thenReturn(USER);
        Mockito.when(subjectToken.getClaim(AccessToken.CLAIM_SCOPE_STD)).thenReturn("coretech:role.readers coretech:role.writers");
        AccessTokenRequest request = Mockito.mock(AccessTokenRequest.class);
        Mockito.when(request.getRequestType()).thenReturn(RequestType.ACCESS_TOKEN_EXCHANGE);
        Mockito.when(request.getGrantType()).thenReturn(TOKEN_EXCHANGE_GRANT);
        Mockito.when(request.getAudience()).thenReturn("coretech");
        Mockito.when(request.getSubjectTokenObj()).thenReturn(subjectToken);
        Mockito.when(request.getActorTokenObj()).thenReturn(actorToken);
        return request;
    }

    private ZTSAuthorizer exchangeAuthorizer(Principal principal, boolean source, boolean target) {
        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access(eq(ZTSConsts.ZTS_ACTION_TOKEN_SOURCE_EXCHANGE), eq("weather:coretech"),
                eq(principal), isNull())).thenReturn(source);
        for (String role : List.of("readers", "writers")) {
            Mockito.when(authorizer.access(eq(ZTSConsts.ZTS_ACTION_TOKEN_TARGET_EXCHANGE),
                    eq("coretech:weather:role." + role), eq(principal), isNull())).thenReturn(target);
        }
        return authorizer;
    }

    @Test
    public void testImpersonationFilterParity() {
        Principal client = SimplePrincipal.create("weather", "api", "creds", 0, null);
        setAuthorizer(exchangeAuthorizer(client, true, true));
        AccessTokenRequest request = exchangeRequest(null);
        ResourceContext ctx = context(client, "coretech");

        AccessTokenResponse legacy = zts.processAccessTokenExchangeRequest(ctx, client, request, "weather", "api");
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse filtered = processor.process(ctx, client, request, "weather", "api");
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(filtered.getScope(), legacy.getScope());
        assertEquals(lastRequest().getSubject().getId(), USER);
        assertEquals(lastRequest().getContext().get("exchange_type"), "impersonation");
        assertNotNull(lastRequest().getContext().get("subject_token"));

        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers"), true, null);
        assertEquals(processor.process(ctx, client, request, "weather", "api").getScope(), "coretech:role.readers");

        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers", "coretech:role.readers"), true, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);
        pdp.handler = FakePdp.deny(Collections.emptySet(), false, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);

        setAuthorizer(exchangeAuthorizer(client, false, true));
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);
        setAuthorizer(exchangeAuthorizer(client, true, false));
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testImpersonationValidation() {
        Principal client = SimplePrincipal.create("weather", "api", "creds", 0, null);
        enable(ExternalPdpMode.FILTER);
        ResourceContext ctx = context(client, "coretech");

        AccessTokenRequest request = exchangeRequest(null);
        Mockito.when(request.getAudience()).thenReturn("unknown");
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.NOT_FOUND);

        AccessTokenRequest source = exchangeRequest(null);
        Mockito.when(source.getSubjectTokenObj().getAudience()).thenReturn("unknown");
        assertEquals(status(() -> processor.process(ctx, client, source, "weather", "api")),
                ResourceException.NOT_FOUND);

        AccessTokenRequest scope = exchangeRequest(null);
        Mockito.when(scope.getSubjectTokenObj().getClaim(AccessToken.CLAIM_SCOPE_STD)).thenReturn(null);
        assertEquals(status(() -> processor.process(ctx, client, scope, "weather", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest rbac = exchangeRequest(null);
        Mockito.when(rbac.getSubjectTokenObj().getSubject()).thenReturn("user_domain.nobody");
        assertEquals(status(() -> processor.process(ctx, client, rbac, "weather", "api")),
                ResourceException.FORBIDDEN);

        SimplePrincipal authorized = (SimplePrincipal) SimplePrincipal.create("weather", "api", "creds", 0, null);
        authorized.setAuthorizedService("weather.backend");
        assertEquals(status(() -> processor.process(ctx, authorized, exchangeRequest(null), "weather", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testImpersonationAuthoritative() {
        Principal client = SimplePrincipal.create("weather", "api", "creds", 0, null);
        enable(ExternalPdpMode.AUTHORITATIVE);
        ResourceContext ctx = context(client, "coretech");
        AccessTokenRequest request = exchangeRequest(null);

        // subject without any rbac membership is granted by the pdp
        Mockito.when(request.getSubjectTokenObj().getSubject()).thenReturn("user_domain.nobody");
        AccessTokenResponse response = processor.process(ctx, client, request, "weather", "api");
        assertEquals(response.getScope(), "coretech:role.readers coretech:role.writers");
        EvaluationsRequest evaluations = lastRequest();
        long permissions = evaluations.getEvaluations().stream()
                .filter(item -> "athenz_resource".equals(item.getResource().getType())).count();
        assertEquals(permissions, 3);

        pdp.handler = FakePdp.deny(Set.of("weather:coretech"), true, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);
        pdp.handler = FakePdp.deny(Set.of("coretech:weather:role.writers"), true, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);

        // exchange permissions only matter for the roles the pdp permitted
        pdp.handler = FakePdp.denyTyped(Set.of("athenz_role/coretech:role.writers",
                "athenz_resource/coretech:weather:role.writers"));
        response = processor.process(ctx, client, request, "weather", "api");
        assertEquals(response.getScope(), "coretech:role.readers");
        pdp.handler = FakePdp.denyTyped(Set.of("athenz_resource/coretech:weather:role.writers"));
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.FORBIDDEN);

        AccessTokenRequest undefined = exchangeRequest(null);
        Mockito.when(undefined.getSubjectTokenObj().getClaim(AccessToken.CLAIM_SCOPE_STD))
                .thenReturn("coretech:role.unknown");
        assertEquals(status(() -> processor.process(ctx, client, undefined, "weather", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testDelegationFilterParity() {
        Principal client = SimplePrincipal.create("weather", "api", "creds", 0, null);
        setAuthorizer(exchangeAuthorizer(client, true, true));
        OAuth2Token actorToken = Mockito.mock(OAuth2Token.class);
        Mockito.when(actorToken.getSubject()).thenReturn("weather.api");
        AccessTokenRequest request = exchangeRequest(actorToken);
        Mockito.when(request.getActor()).thenReturn("coretech.next");
        LinkedHashMap<String, Object> act = new LinkedHashMap<>();
        act.put("sub", "weather.first");
        Mockito.when(request.getSubjectTokenObj().getAct()).thenReturn(act);
        ResourceContext ctx = context(client, "coretech");

        AccessTokenResponse legacy = zts.processAccessTokenExchangeRequest(ctx, client, request, "weather", "api");
        enable(ExternalPdpMode.FILTER, ExternalPdpConfig.PROP_CLAIMS_ENABLED, "true");
        AccessTokenResponse filtered = processor.process(ctx, client, request, "weather", "api");
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(lastRequest().getContext().get("exchange_type"), "delegation");
        assertNotNull(lastRequest().getContext().get("actor_token"));

        // the source exchange check is impersonation only
        setAuthorizer(exchangeAuthorizer(client, false, true));
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")), ResourceException.OK);

        processor.close();
        enable(ExternalPdpMode.AUTHORITATIVE);
        AccessTokenResponse authoritative = processor.process(ctx, client, request, "weather", "api");
        assertEquals(authoritative.getScope(), "coretech:role.readers coretech:role.writers");
        long permissions = lastRequest().getEvaluations().stream()
                .filter(item -> "athenz_resource".equals(item.getResource().getType())).count();
        assertEquals(permissions, 2);
    }

    @Test
    public void testDelegationValidation() {
        Principal client = SimplePrincipal.create("weather", "api", "creds", 0, null);
        enable(ExternalPdpMode.FILTER);
        ResourceContext ctx = context(client, "coretech");

        OAuth2Token otherActor = Mockito.mock(OAuth2Token.class);
        Mockito.when(otherActor.getSubject()).thenReturn("weather.other");
        assertEquals(status(() -> processor.process(ctx, client, exchangeRequest(otherActor), "weather", "api")),
                ResourceException.FORBIDDEN);

        OAuth2Token boundActor = Mockito.mock(OAuth2Token.class);
        Mockito.when(boundActor.getSubject()).thenReturn("weather.api");
        Mockito.when(boundActor.getConfirmJwkThumbprint()).thenReturn("jkt");
        assertEquals(status(() -> processor.process(ctx, client, exchangeRequest(boundActor), "weather", "api")),
                ResourceException.FORBIDDEN);

        OAuth2Token actor = Mockito.mock(OAuth2Token.class);
        Mockito.when(actor.getSubject()).thenReturn("weather.api");
        AccessTokenRequest request = exchangeRequest(actor);
        Mockito.when(request.getActor()).thenReturn("invalid actor");
        assertEquals(status(() -> processor.process(ctx, client, request, "weather", "api")),
                ResourceException.BAD_REQUEST);
    }

    // ------------------------------------------------------------------ jag flows

    private AccessTokenRequest jagIssueRequest(String scope) {
        OAuth2Token subjectToken = Mockito.mock(OAuth2Token.class);
        Mockito.when(subjectToken.getIssuer()).thenReturn("https://idp.athenz.io");
        Mockito.when(subjectToken.getAudience()).thenReturn("coretech.api");
        Mockito.when(subjectToken.getSubject()).thenReturn(USER);
        AccessTokenRequest request = Mockito.mock(AccessTokenRequest.class);
        Mockito.when(request.getRequestType()).thenReturn(RequestType.JAG_TOKEN_EXCHANGE);
        Mockito.when(request.getGrantType()).thenReturn(TOKEN_EXCHANGE_GRANT);
        Mockito.when(request.getAudience()).thenReturn("https://app.athenz.io");
        Mockito.when(request.getScope()).thenReturn(scope);
        Mockito.when(request.getSubjectTokenObj()).thenReturn(subjectToken);
        Mockito.when(request.getQueryLogData()).thenReturn("grant_type=jag");
        return request;
    }

    private ZTSAuthorizer jagAuthorizer(Principal principal, boolean result) {
        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        for (String role : List.of("coretech:role.readers", "coretech:role.writers", "weather:role.forecasters")) {
            Mockito.when(authorizer.access(eq(ZTSConsts.ZTS_ACTION_JAG_EXCHANGE), eq(role), eq(principal),
                    isNull())).thenReturn(result);
        }
        return authorizer;
    }

    @Test
    public void testJAGIssueFilterParity() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        setAuthorizer(jagAuthorizer(client, true));
        AccessTokenRequest request = jagIssueRequest("coretech:role.readers coretech:role.writers");
        ResourceContext ctx = context(client, "coretech");

        AccessTokenResponse legacy = zts.processJAGTokenIssueRequest(ctx, client, request, "coretech", "api");
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse filtered = processor.process(ctx, client, request, "coretech", "api");
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(filtered.getScope(), legacy.getScope());
        assertEquals(filtered.getIssued_token_type(), legacy.getIssued_token_type());

        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers"), true, null);
        assertEquals(processor.process(ctx, client, request, "coretech", "api").getScope(), "coretech:role.readers");
        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers", "coretech:role.readers"), true, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "coretech", "api")),
                ResourceException.FORBIDDEN);
        pdp.handler = FakePdp.deny(Collections.emptySet(), false, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "coretech", "api")),
                ResourceException.FORBIDDEN);

        setAuthorizer(jagAuthorizer(client, false));
        assertEquals(status(() -> processor.process(ctx, client, request, "coretech", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testJAGIssueValidation() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        setAuthorizer(jagAuthorizer(client, true));
        enable(ExternalPdpMode.FILTER);
        ResourceContext ctx = context(client, "coretech");

        assertEquals(status(() -> processor.process(ctx, client, jagIssueRequest("coretech:domain"), "coretech", "api")),
                ResourceException.BAD_REQUEST);
        assertEquals(status(() -> processor.process(ctx, client, jagIssueRequest("unknown:role.readers"),
                "coretech", "api")), ResourceException.NOT_FOUND);

        AccessTokenRequest audience = jagIssueRequest("coretech:role.readers");
        Mockito.when(audience.getSubjectTokenObj().getAudience()).thenReturn("other.client");
        assertEquals(status(() -> processor.process(ctx, client, audience, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest subject = jagIssueRequest("coretech:role.readers");
        Mockito.when(subject.getSubjectTokenObj().getSubject()).thenReturn(null);
        assertEquals(status(() -> processor.process(ctx, client, subject, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest rbac = jagIssueRequest("coretech:role.admin");
        assertEquals(status(() -> processor.process(ctx, client, rbac, "coretech", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testJAGIssueAuthoritative() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        enable(ExternalPdpMode.AUTHORITATIVE);
        ResourceContext ctx = context(client, "coretech");

        AccessTokenResponse response = processor.process(ctx, client, jagIssueRequest("coretech:role.admin"),
                "coretech", "api");
        assertEquals(response.getScope(), "coretech:role.admin");

        pdp.handler = FakePdp.deny(Set.of("coretech:role.admin"), true, null);
        assertEquals(status(() -> processor.process(ctx, client, jagIssueRequest("coretech:role.admin"),
                "coretech", "api")), ResourceException.FORBIDDEN);
        assertEquals(status(() -> processor.process(ctx, client, jagIssueRequest("coretech:role.unknown"),
                "coretech", "api")), ResourceException.FORBIDDEN);

        // exchange permissions only matter for the roles the pdp permitted
        final AccessTokenRequest twoRoles = jagIssueRequest("coretech:role.readers coretech:role.writers");
        pdp.handler = FakePdp.denyTyped(Set.of("athenz_role/coretech:role.writers",
                "athenz_resource/coretech:role.writers"));
        assertEquals(processor.process(ctx, client, twoRoles, "coretech", "api").getScope(), "coretech:role.readers");
        pdp.handler = FakePdp.denyTyped(Set.of("athenz_resource/coretech:role.writers"));
        assertEquals(status(() -> processor.process(ctx, client, twoRoles, "coretech", "api")),
                ResourceException.FORBIDDEN);
    }

    private AccessTokenRequest jagExchangeRequest(String scope) {
        AccessToken jagToken = Mockito.mock(AccessToken.class);
        Mockito.when(jagToken.getAudience()).thenReturn(zts.ztsOAuthIssuer);
        Mockito.when(jagToken.getClientId()).thenReturn("coretech.api");
        Mockito.when(jagToken.getScopeStd()).thenReturn(scope);
        Mockito.when(jagToken.getIssuer()).thenReturn(zts.ztsOAuthIssuer);
        Mockito.when(jagToken.getSubject()).thenReturn(USER);
        AccessTokenRequest request = Mockito.mock(AccessTokenRequest.class);
        Mockito.when(request.getRequestType()).thenReturn(RequestType.JAG_JWT_BEARER);
        Mockito.when(request.getGrantType()).thenReturn("urn:ietf:params:oauth:grant-type:jwt-bearer");
        Mockito.when(request.getJagTokenObj()).thenReturn(jagToken);
        Mockito.when(request.getQueryLogData()).thenReturn("grant_type=jwt-bearer");
        return request;
    }

    @Test
    public void testJAGExchangeFilterParity() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        ResourceContext ctx = context(client, "coretech");
        AccessTokenRequest request = jagExchangeRequest("coretech:domain");

        AccessTokenResponse legacy = zts.processJAGTokenExchangeRequest(ctx, client, request, "coretech", "api");
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse filtered = processor.process(ctx, client, request, "coretech", "api");
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(filtered.getScope(), legacy.getScope());

        AccessTokenRequest multi = jagExchangeRequest("coretech:role.readers weather:role.forecasters");
        Mockito.when(multi.getAudience()).thenReturn("coretech");
        enable(ExternalPdpMode.FILTER);
        legacy = zts.processJAGTokenExchangeRequest(ctx, client, multi, "coretech", "api");
        filtered = processor.process(ctx, client, multi, "coretech", "api");
        assertEquals(claims(filtered.getAccess_token()), claims(legacy.getAccess_token()));
        assertEquals(filtered.getScope(), legacy.getScope());

        pdp.handler = FakePdp.deny(Collections.emptySet(), false, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "coretech", "api")),
                ResourceException.FORBIDDEN);
        pdp.handler = FakePdp.deny(Set.of("coretech:role.writers", "coretech:role.readers"), true, null);
        assertEquals(status(() -> processor.process(ctx, client, request, "coretech", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testJAGExchangeOptions() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        ((SimplePrincipal) client).setX509Certificate(certificate());
        ResourceContext ctx = context(client, "coretech");
        enable(ExternalPdpMode.FILTER);

        AccessTokenRequest fullArn = jagExchangeRequest("coretech:role.readers");
        Mockito.when(fullArn.isFullArn()).thenReturn(true);
        Mockito.when(fullArn.getAudience()).thenReturn("coretech.backend");
        Mockito.when(fullArn.isRoleInAudClaim()).thenReturn(true);
        Mockito.when(fullArn.getActor()).thenReturn("coretech.next");
        Mockito.when(fullArn.getScope()).thenReturn("coretech:role.readers");
        Map<String, Object> claims = claims(processor.process(ctx, client, fullArn, "coretech", "api").getAccess_token());
        assertEquals(claims.get("aud"), List.of("coretech.backend:coretech:role.readers"));
        assertNotNull(claims.get("may_act"));

        Mockito.when(fullArn.isRoleInAudClaim()).thenReturn(false);
        claims = claims(processor.process(ctx, client, fullArn, "coretech", "api").getAccess_token());
        assertEquals(claims.get("aud"), List.of("coretech.backend"));
    }

    @Test
    public void testJAGExchangeValidation() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        ResourceContext ctx = context(client, "coretech");
        enable(ExternalPdpMode.FILTER);

        AccessTokenRequest audience = jagExchangeRequest("coretech:domain");
        Mockito.when(audience.getJagTokenObj().getAudience()).thenReturn("https://other");
        assertEquals(status(() -> processor.process(ctx, client, audience, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest clientId = jagExchangeRequest("coretech:domain");
        Mockito.when(clientId.getJagTokenObj().getClientId()).thenReturn("other.client");
        assertEquals(status(() -> processor.process(ctx, client, clientId, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest actor = jagExchangeRequest("coretech:domain");
        Mockito.when(actor.getActor()).thenReturn("coretech.next");
        assertEquals(status(() -> processor.process(ctx, client, actor, "coretech", "api")),
                ResourceException.FORBIDDEN);

        assertEquals(status(() -> processor.process(ctx, client, jagExchangeRequest(""), "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest subset = jagExchangeRequest("coretech:role.readers");
        Mockito.when(subset.getScope()).thenReturn("coretech:role.writers");
        assertEquals(status(() -> processor.process(ctx, client, subset, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest subject = jagExchangeRequest("coretech:domain");
        Mockito.when(subject.getJagTokenObj().getSubject()).thenReturn(null);
        assertEquals(status(() -> processor.process(ctx, client, subject, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest multi = jagExchangeRequest("coretech:domain weather:domain");
        assertEquals(status(() -> processor.process(ctx, client, multi, "coretech", "api")),
                ResourceException.BAD_REQUEST);
        Mockito.when(multi.getAudience()).thenReturn("sports");
        assertEquals(status(() -> processor.process(ctx, client, multi, "coretech", "api")),
                ResourceException.BAD_REQUEST);

        AccessTokenRequest unknown = jagExchangeRequest("coretech:domain unknown:domain");
        Mockito.when(unknown.getAudience()).thenReturn("coretech");
        assertEquals(status(() -> processor.process(ctx, client, unknown, "coretech", "api")),
                ResourceException.NOT_FOUND);

        AccessTokenRequest rbac = jagExchangeRequest("coretech:role.admin");
        assertEquals(status(() -> processor.process(ctx, client, rbac, "coretech", "api")),
                ResourceException.FORBIDDEN);
    }

    @Test
    public void testJAGExchangeAuthoritative() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        ResourceContext ctx = context(client, "coretech");
        enable(ExternalPdpMode.AUTHORITATIVE);
        AccessTokenResponse response = processor.process(ctx, client, jagExchangeRequest("coretech:role.admin"),
                "coretech", "api");
        assertEquals(claims(response.getAccess_token()).get("scp"), List.of("admin"));
        assertEquals(status(() -> processor.process(ctx, client, jagExchangeRequest("coretech:role.unknown"),
                "coretech", "api")), ResourceException.FORBIDDEN);
    }

    @Test
    public void testAuditShadowRolePermissions() {
        enable(ExternalPdpMode.AUDIT);
        Map<String, Set<String>> legacy = Map.of("coretech", Set.of("readers"));
        java.util.function.Supplier<com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation> evaluation = () -> {
            com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation e = new com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation(
                    new Subject("user", USER, null), null,
                    com.yahoo.athenz.zts.pdp.AuthZenRequestBuilder.tokenResource("coretech", Set.of("coretech")));
            for (String role : new String[] { "readers", "writers" }) {
                e.addRole("subject", "coretech", role, true, null, null);
                e.addRolePermission("target_exchange", "zts.jag_exchange", "coretech:role." + role, null,
                        "coretech", role);
            }
            return e;
        };

        pdp.handler = FakePdp.denyTyped(Set.of("athenz_role/coretech:role.writers", "athenz_resource/coretech:role.writers"));
        assertEquals(processor.runShadow(evaluation.get(), legacy, ResourceException.OK, "r1",
                "jag_exchange", USER, "coretech", Collections.emptyList()), "match");
        pdp.handler = FakePdp.denyTyped(Set.of("athenz_resource/coretech:role.writers"));
        assertEquals(processor.runShadow(evaluation.get(), legacy, ResourceException.OK, "r1",
                "jag_exchange", USER, "coretech", Collections.emptyList()), "pdp_deny");
    }

    // ------------------------------------------------------------ extra branches

    @Test
    public void testStandardContextAndReasons() {
        enable(ExternalPdpMode.FILTER);
        pdp.handler = request -> {
            List<EvaluationResponse> results = new ArrayList<>();
            for (int i = 0; i < request.getEvaluations().size(); i++) {
                results.add(new EvaluationResponse(true, i == 1 ? Map.of("reason_admin", "policy-1") : null));
            }
            return new EvaluationsResponse(results);
        };
        AccessTokenResponse response = post(user(), scopeBody("coretech:role.readers") + "&expires_in=600");
        assertEquals(response.getExpires_in(), Integer.valueOf(600));
        assertEquals(lastRequest().getContext().get("requested_expires_in"), 600);
        assertEquals(lastRequest().getContext().get("dpop_bound"), false);
    }

    @Test
    public void testStandardProxyIntersectionEmpty() {
        enable(ExternalPdpMode.FILTER);
        Principal proxy = SimplePrincipal.create("user_domain", "proxy", "v=U1;d=user_domain;n=proxy;s=sig", 0, null);
        assertEquals(status(() -> post(proxy, scopeBody("coretech:role.readers")
                + "&proxy_for_principal=user_domain.adminuser")), ResourceException.FORBIDDEN);
        assertTrue(pdp.requests.isEmpty());
    }

    @Test
    public void testImpersonationSpiffeClaim() {
        Principal client = SimplePrincipal.create("weather", "api", "creds", 0, null);
        enable(ExternalPdpMode.AUTHORITATIVE);
        final String spiffe = "spiffe://athenz.io/sa/user_domain.user";
        AccessTokenRequest request = exchangeRequest(null);
        Mockito.when(request.getSubjectTokenObj().getSubject()).thenReturn(spiffe);
        Mockito.when(request.getSubjectTokenObj().getClaim("spiffe")).thenReturn(spiffe);
        AccessTokenResponse response = processor.process(context(client, "coretech"), client, request, "weather", "api");
        Map<String, Object> claims = claims(response.getAccess_token());
        assertEquals(claims.get("spiffe"), spiffe);
        assertEquals(claims.get("sub"), spiffe);
    }

    private com.yahoo.athenz.auth.TokenExchangeIdentityProvider identityProvider(OAuth2Token token,
            List<String> exchangeClaims) {
        com.yahoo.athenz.auth.TokenExchangeIdentityProvider provider =
                Mockito.mock(com.yahoo.athenz.auth.TokenExchangeIdentityProvider.class);
        Mockito.when(provider.getTokenAudience(eq(token))).thenReturn("coretech.api");
        Mockito.when(provider.getTokenIdentity(eq(token))).thenReturn(USER);
        Mockito.when(provider.getTokenExchangeClaims()).thenReturn(exchangeClaims);
        return provider;
    }

    @Test
    public void testJAGIdentityProviderParity() {
        Principal client = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        setAuthorizer(jagAuthorizer(client, true));
        ResourceContext ctx = context(client, "coretech");

        AccessTokenRequest issue = jagIssueRequest("coretech:role.readers");
        OAuth2Token subjectToken = issue.getSubjectTokenObj();
        Mockito.when(subjectToken.getAudience()).thenReturn("idp-client-id");
        Mockito.when(subjectToken.getClaim("email")).thenReturn("user@athenz.io");
        AccessTokenRequest exchange = jagExchangeRequest("coretech:role.readers");
        AccessToken jagToken = exchange.getJagTokenObj();
        Mockito.when(jagToken.getClaim("email")).thenReturn("user@athenz.io");

        com.yahoo.athenz.zts.token.ProviderConfigManager providers =
                Mockito.mock(com.yahoo.athenz.zts.token.ProviderConfigManager.class);
        com.yahoo.athenz.auth.TokenExchangeIdentityProvider issueProvider =
                identityProvider(subjectToken, List.of("email"));
        Mockito.when(issueProvider.getTokenAudience(eq(subjectToken))).thenReturn("idp-client-id");
        Mockito.when(providers.getProvider(eq("https://idp.athenz.io"))).thenReturn(issueProvider);
        com.yahoo.athenz.auth.TokenExchangeIdentityProvider exchangeProvider =
                identityProvider(jagToken, List.of("groups", "email"));
        Mockito.when(providers.getProvider(eq(zts.ztsOAuthIssuer))).thenReturn(exchangeProvider);
        zts.providerConfigManager = providers;

        // the subject token audience does not match the client id so the request is rejected
        assertEquals(status(() -> zts.processJAGTokenIssueRequest(ctx, client, issue, "coretech", "api")),
                ResourceException.BAD_REQUEST);
        Mockito.when(issueProvider.getTokenAudience(eq(subjectToken))).thenReturn("coretech.api");
        Mockito.when(subjectToken.getAudience()).thenReturn("coretech.api");

        AccessTokenResponse legacyIssue = zts.processJAGTokenIssueRequest(ctx, client, issue, "coretech", "api");
        AccessTokenResponse legacyExchange = zts.processJAGTokenExchangeRequest(ctx, client, exchange, "coretech", "api");
        enable(ExternalPdpMode.FILTER);
        AccessTokenResponse pdpIssue = processor.process(ctx, client, issue, "coretech", "api");
        AccessTokenResponse pdpExchange = processor.process(ctx, client, exchange, "coretech", "api");
        assertEquals(claims(pdpIssue.getAccess_token()), claims(legacyIssue.getAccess_token()));
        assertEquals(claims(pdpIssue.getAccess_token()).get("email"), "user@athenz.io");
        assertEquals(claims(pdpExchange.getAccess_token()), claims(legacyExchange.getAccess_token()));
        assertEquals(claims(pdpExchange.getAccess_token()).get("groups"), List.of("readers"));
    }

    @Test
    public void testAuditExchangeAndJAGFlows() throws Exception {
        Principal weatherClient = SimplePrincipal.create("weather", "api", "creds", 0, null);
        Principal coretechClient = SimplePrincipal.create("coretech", "api", "creds", 0, null);
        enable(ExternalPdpMode.AUDIT);

        setAuthorizer(exchangeAuthorizer(weatherClient, true, true));
        pdp.latch = new CountDownLatch(1);
        AccessTokenResponse response = processor.process(context(weatherClient, "coretech"), weatherClient,
                exchangeRequest(null), "weather", "api");
        assertNotNull(response.getAccess_token());
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));
        assertEquals(lastRequest().getSubject().getId(), USER);

        setAuthorizer(jagAuthorizer(coretechClient, true));
        pdp.latch = new CountDownLatch(1);
        response = processor.process(context(coretechClient, "coretech"), coretechClient,
                jagIssueRequest("coretech:role.readers"), "coretech", "api");
        assertNotNull(response.getAccess_token());
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));

        pdp.latch = new CountDownLatch(1);
        response = processor.process(context(coretechClient, "coretech"), coretechClient,
                jagExchangeRequest("coretech:role.readers"), "coretech", "api");
        assertNotNull(response.getAccess_token());
        assertTrue(pdp.latch.await(5, TimeUnit.SECONDS));
    }

    // ------------------------------------------------------------------ helpers

    @Test
    public void testOutcomeForException() {
        ExternalPdpTokenProcessor.PdpRequest pr = new ExternalPdpTokenProcessor.PdpRequest("flow", 0);
        assertEquals(ExternalPdpTokenProcessor.outcomeForException(new IllegalStateException(), pr), "error");
        assertEquals(ExternalPdpTokenProcessor.outcomeForException(new ResourceException(403), pr), "deny");
        assertEquals(ExternalPdpTokenProcessor.outcomeForException(new ResourceException(400), pr), "rejected");
        assertEquals(ExternalPdpTokenProcessor.outcomeForException(new ResourceException(503), pr), "error");
        pr.errorCode = ExternalPdpException.Code.TIMEOUT;
        assertEquals(ExternalPdpTokenProcessor.outcomeForException(new ResourceException(503), pr), "timeout");
        assertEquals(ExternalPdpTokenProcessor.PdpRequest.countRoles(null), 0);
    }

    @Test
    public void testAuditDiff() {
        Map<String, Set<String>> legacy = Map.of("coretech", Set.of("readers", "writers"));
        assertEquals(ExternalPdpTokenProcessor.auditDiff(false, legacy, legacy, true), "match");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(false, Map.of("coretech", Set.of("readers")), legacy, true),
                "pdp_narrower");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(false,
                Map.of("coretech", Set.of("readers", "writers", "admin")), legacy, true), "pdp_broader");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(false,
                Map.of("coretech", Set.of("readers"), "weather", Set.of("forecasters")), legacy, true), "pdp_mismatch");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(false, Map.of("weather", Set.of("forecasters")), legacy, true),
                "pdp_mismatch");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(true, null, legacy, true), "pdp_deny");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(false, legacy, Collections.emptyMap(), false),
                "pdp_permit_legacy_deny");
        assertEquals(ExternalPdpTokenProcessor.auditDiff(true, null, Collections.emptyMap(), false), "match_deny");
    }

    @Test
    public void testSimulatedRoles() {
        com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation evaluation = new com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation(
                new Subject("user", USER, null), null,
                com.yahoo.athenz.zts.pdp.AuthZenRequestBuilder.tokenResource("coretech", Set.of("coretech", "weather")));
        assertNull(ExternalPdpTokenProcessor.simulatedRoles(evaluation, decide(evaluation, true)));

        evaluation.addRole("subject", "coretech", "readers", true, null, null);
        evaluation.addRole("subject", "coretech", "writers", true, null, null);
        evaluation.addRole("client", "coretech", "readers", true, null, null);
        evaluation.addRole("client", "coretech", "writers", true, null, null);
        evaluation.addRole("subject", "weather", "forecasters", true, null, null);

        // client permitted roles limit the subject roles only for the evaluated domains
        assertEquals(ExternalPdpTokenProcessor.simulatedRoles(evaluation,
                decide(evaluation, true, true, true, true, false, true)),
                Map.of("coretech", Set.of("readers"), "weather", Set.of("forecasters")));
        // a domain without any permitted role rejects the request
        assertNull(ExternalPdpTokenProcessor.simulatedRoles(evaluation,
                decide(evaluation, true, true, true, true, true, false)));
        assertNull(ExternalPdpTokenProcessor.simulatedRoles(evaluation,
                decide(evaluation, true, true, false, false, true, true)));
    }

    private static com.yahoo.athenz.zts.pdp.ExternalPdpDecision decide(
            com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation evaluation, boolean... decisions) {
        List<EvaluationResponse> results = new ArrayList<>();
        for (boolean decision : decisions) {
            results.add(new EvaluationResponse(decision, null));
        }
        try {
            return evaluation.decide(new EvaluationsResponse(results));
        } catch (ExternalPdpException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
