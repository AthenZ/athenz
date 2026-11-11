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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.PolicyBundle;
import com.yahoo.athenz.zms.PolicyBundleFile;
import com.yahoo.athenz.zts.bundle.TarTestUtils;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
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
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.testng.Assert.*;

public class ZTSImplPolicyBundleTest {

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final long MODIFIED_MILLIS = 1700000000123L;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ZTSImpl zts;
    private DataStore store;
    private CloudStore cloudStore;
    private PrivateKey privateKey;
    private KeyPair ecKeyPair;
    private KeyPair rsaKeyPair;

    @Mock private HttpServletRequest mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;

    @BeforeClass
    public void setupClass() throws Exception {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn("10.11.12.13");
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);

        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, METRIC_DEFAULT_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_at_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz-2048.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = ecGen.generateKeyPair();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        rsaKeyPair = rsaGen.generateKeyPair();
    }

    @BeforeMethod
    public void setup() {
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));

        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        String privKey = Crypto.encodedFile(new File(privKeyName));
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        ChangeLogStore structStore = new MockZMSFileChangeLogStore(ZTS_DATA_STORE_PATH, privateKey, "0");
        cloudStore = new CloudStore();
        Metric metric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        store = new DataStore(structStore, cloudStore, metric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        // we use our own known keys so we can verify the signatures

        zts.privateECKey = new ServerPrivateKey(ecKeyPair.getPrivate(), "ec-1");
        zts.privateRSAKey = null;
        zts.keyAlgoForJsonWebObjects = ZTSConsts.EC;
        zts.policyBundleEnabled = new com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean(true);
        zts.policyBundleSigningEnabled = true;
        zts.policyBundleIncludeJwks = false;

        // authorizer stub: principals are authorized for resources in their own
        // domain plus any explicit grants of the form "action|resource|principal"

        grants.clear();
        zts.authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(zts.authorizer.access(Mockito.anyString(), Mockito.anyString(), Mockito.any(Principal.class),
                Mockito.any())).thenAnswer(inv -> {
            final String action = inv.getArgument(0);
            final String resource = inv.getArgument(1);
            final Principal principal = inv.getArgument(2);
            return resource.startsWith(principal.getDomain() + ":")
                    || grants.contains(action + "|" + resource + "|" + principal.getFullName());
        });
    }

    private final Set<String> grants = new HashSet<>();

    private void grantGetBundle(String domain, String bundleName, String principalName) {
        grants.add(ZTSConsts.ZTS_ACTION_GET_BUNDLE + "|" + domain + ":bundle." + bundleName + "|" + principalName);
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
    }

    private ResourceContext createResourceContext(Principal principal) {
        ServerResourceContext rsrcCtx = Mockito.mock(ServerResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);

        RsrcCtxWrapper wrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(wrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(wrapper.principal()).thenReturn(principal);
        Mockito.when(wrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(wrapper.response()).thenReturn(mockServletResponse);
        Mockito.when(wrapper.getApiName()).thenReturn("policybundle");
        if (principal != null) {
            Mockito.when(wrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(wrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return wrapper;
    }

    private Principal principal(String domain, String name) {
        return SimplePrincipal.create(domain, name, "v=S1;d=" + domain + ";n=" + name + ";s=signature", 0, null);
    }

    private PolicyBundleFile file(String path, String content) {
        return new PolicyBundleFile().setPath(path).setContent(content)
                .setSha256(java.util.HexFormat.of().formatHex(Crypto.sha256(content.getBytes(StandardCharsets.UTF_8))));
    }

    private PolicyBundle bundle(String name, String engine) {
        return new PolicyBundle().setName("sports:bundle." + name).setEngine(engine).setVersion("v1")
                .setModified(Timestamp.fromMillis(MODIFIED_MILLIS))
                .setFiles(new ArrayList<>(Collections.singletonList(file("sports/" + name + "/p.rego", "package x\n"))));
    }

    private void addDomain(String domainName, PolicyBundle... bundles) {
        DataCache cache = new DataCache();
        for (PolicyBundle bundle : bundles) {
            cache.addPolicyBundle(bundle.getName().substring(bundle.getName().indexOf(":bundle.") + 8), bundle);
        }
        store.getCacheStore().put(domainName, cache);
    }

    private ResourceException expectError(Runnable call, int code) {
        try {
            call.run();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), code);
            return ex;
        }
        fail("expected ResourceException " + code);
        return null;
    }

    private String eTag(Response response) {
        return response.getHeaders().getFirst("ETag").toString();
    }

    // access checks

    @Test
    public void testIsPolicyBundleAccessAllowed() {
        assertFalse(zts.isPolicyBundleAccessAllowed(null, "sports", "api"));
        assertTrue(zts.isPolicyBundleAccessAllowed(principal("sports", "svc"), "sports", "api"));
        assertFalse(zts.isPolicyBundleAccessAllowed(principal("weather", "svc"), "sports", "api"));

        grantGetBundle("sports", "api", "weather.svc");
        assertTrue(zts.isPolicyBundleAccessAllowed(principal("weather", "svc"), "sports", "api"));
        assertFalse(zts.isPolicyBundleAccessAllowed(principal("weather", "svc2"), "sports", "api"));
        assertFalse(zts.isPolicyBundleAccessAllowed(principal("weather", "svc"), "sports", "other"));

        Mockito.verify(zts.authorizer, Mockito.atLeastOnce()).access(Mockito.eq("zts.getbundle"),
                Mockito.eq("sports:bundle.api"), Mockito.any(Principal.class), Mockito.isNull());
    }

    @Test
    public void testGetPolicyBundleTag() {
        PolicyBundle bundle = bundle("api", "rego");
        assertEquals(zts.getPolicyBundleTag(bundle),
                "\"" + Timestamp.fromMillis(MODIFIED_MILLIS) + "\"");
        assertEquals(zts.getPolicyBundleTag(new PolicyBundle()), "\"0\"");
    }

    // archive api

    @Test
    public void testGetPolicyBundleDisabled() {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));
        zts.policyBundleEnabled = new com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean(false);
        try {
            zts.getPolicyBundle(ctx, "sports", "api", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Policy bundle support is not enabled"));
        }
    }

    @Test
    public void testgetPolicyBundleEc() throws Exception {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));

        Response response = zts.getPolicyBundle(ctx, "sports", "api", null);
        assertEquals(response.getStatus(), 200);
        assertEquals(response.getMediaType().toString(), "application/gzip");
        assertEquals(eTag(response), zts.getPolicyBundleTag(bundle("api", "rego")));

        byte[] archive = (byte[]) response.getEntity();
        Map<String, byte[]> entries = TarTestUtils.readTar(TarTestUtils.gunzip(archive));
        assertTrue(entries.containsKey(".signatures.json"));
        assertTrue(entries.containsKey(".manifest"));
        assertEquals(new String(entries.get("sports/api/p.rego"), StandardCharsets.UTF_8), "package x\n");

        String jwt = MAPPER.readTree(entries.get(".signatures.json")).get("signatures").get(0).asText();
        String[] parts = jwt.split("\\.");
        JsonNode header = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));
        assertEquals(header.get("alg").asText(), "ES256");
        assertEquals(header.get("kid").asText(), "ec-1");
        Signature sig = Signature.getInstance("SHA256withECDSAinP1363Format");
        sig.initVerify(ecKeyPair.getPublic());
        sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        assertTrue(sig.verify(Base64.getUrlDecoder().decode(parts[2])));

        // second request is served from the cache

        Response response2 = zts.getPolicyBundle(ctx, "sports", "api", null);
        assertSame(response2.getEntity(), archive);
    }

    @Test
    public void testgetPolicyBundleCaseInsensitive() {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));
        Response response = zts.getPolicyBundle(ctx, "SPORTS", "API", null);
        assertEquals(response.getStatus(), 200);
    }

    @Test
    public void testgetPolicyBundleNotModified() {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));

        Response response = zts.getPolicyBundle(ctx, "sports", "api", "\"" + Timestamp.fromMillis(MODIFIED_MILLIS) + "\"");
        assertEquals(response.getStatus(), 304);
        assertNull(response.getEntity());
        assertEquals(eTag(response), "\"" + Timestamp.fromMillis(MODIFIED_MILLIS) + "\"");

        // different revision returns the bundle

        response = zts.getPolicyBundle(ctx, "sports", "api", "\"0\"");
        assertEquals(response.getStatus(), 200);
    }

    @Test
    public void testgetPolicyBundleRevisionChangeRebuilds() {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));
        Response response = zts.getPolicyBundle(ctx, "sports", "api", null);

        PolicyBundle updated = bundle("api", "rego").setModified(Timestamp.fromMillis(MODIFIED_MILLIS + 5000));
        addDomain("sports", updated);
        Response response2 = zts.getPolicyBundle(ctx, "sports", "api", eTag(response));
        assertEquals(response2.getStatus(), 200);
        assertNotSame(response2.getEntity(), response.getEntity());
        assertNotEquals(eTag(response2), eTag(response));
    }

    @Test
    public void testgetPolicyBundleSigningDisabled() throws Exception {
        zts.policyBundleSigningEnabled = false;
        addDomain("sports", bundle("api", "rego"));
        Response response = zts.getPolicyBundle(createResourceContext(principal("sports", "svc")),
                "sports", "api", null);
        Map<String, byte[]> entries = TarTestUtils.readTar(TarTestUtils.gunzip((byte[]) response.getEntity()));
        assertFalse(entries.containsKey(".signatures.json"));
        assertTrue(entries.containsKey(".manifest"));

        // enabling signing does not return the cached unsigned archive

        zts.policyBundleSigningEnabled = true;
        response = zts.getPolicyBundle(createResourceContext(principal("sports", "svc")),
                "sports", "api", null);
        entries = TarTestUtils.readTar(TarTestUtils.gunzip((byte[]) response.getEntity()));
        assertTrue(entries.containsKey(".signatures.json"));
    }

    @Test
    public void testgetPolicyBundleRsa() throws Exception {
        zts.privateECKey = null;
        zts.privateRSAKey = new ServerPrivateKey(rsaKeyPair.getPrivate(), "rsa-1");
        zts.keyAlgoForJsonWebObjects = ZTSConsts.RSA;
        addDomain("sports", bundle("api", "rego"));
        Response response = zts.getPolicyBundle(createResourceContext(principal("sports", "svc")),
                "sports", "api", null);
        Map<String, byte[]> entries = TarTestUtils.readTar(TarTestUtils.gunzip((byte[]) response.getEntity()));
        String jwt = MAPPER.readTree(entries.get(".signatures.json")).get("signatures").get(0).asText();
        String[] parts = jwt.split("\\.");
        assertEquals(MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0])).get("alg").asText(), "RS256");
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(rsaKeyPair.getPublic());
        sig.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        assertTrue(sig.verify(Base64.getUrlDecoder().decode(parts[2])));
    }

    @Test
    public void testgetPolicyBundleWithJwks() throws Exception {
        zts.policyBundleIncludeJwks = true;
        addDomain("sports", bundle("api", "rego"));
        Response response = zts.getPolicyBundle(createResourceContext(principal("sports", "svc")),
                "sports", "api", null);
        Map<String, byte[]> entries = TarTestUtils.readTar(TarTestUtils.gunzip((byte[]) response.getEntity()));
        byte[] jwks = entries.get("sports/api/athenz/zts/keys/data.json");
        assertNotNull(jwks);
        // must be valid json
        assertNotNull(MAPPER.readTree(jwks));
    }

    @Test
    public void testgetPolicyBundleBuildFailure() {
        // invalid data.json cannot be digested when signing
        PolicyBundle bundle = bundle("api", "rego");
        bundle.getFiles().add(file("sports/api/data.json", "{not json"));
        addDomain("sports", bundle);
        expectError(() -> zts.getPolicyBundle(createResourceContext(principal("sports", "svc")),
                "sports", "api", null), 500);

        // failures are not cached - after disabling the signing the archive is generated

        zts.policyBundleSigningEnabled = false;
        assertEquals(zts.getPolicyBundle(createResourceContext(principal("sports", "svc")),
                "sports", "api", null).getStatus(), 200);
    }

    @Test
    public void testgetPolicyBundleErrors() {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));
        ResourceContext otherCtx = createResourceContext(principal("weather", "svc"));

        // unknown domain
        expectError(() -> zts.getPolicyBundle(ctx, "unknown", "api", null), 404);
        // unknown bundle
        expectError(() -> zts.getPolicyBundle(ctx, "sports", "unknown", null), 404);
        // principal from another domain
        expectError(() -> zts.getPolicyBundle(otherCtx, "sports", "api", null), 403);
        // invalid names
        expectError(() -> zts.getPolicyBundle(ctx, "sports$bad", "api", null), 400);
        expectError(() -> zts.getPolicyBundle(ctx, "sports", "api$bad", null), 400);

        // allowed service from another domain
        grantGetBundle("sports", "api", "weather.svc");
        assertEquals(zts.getPolicyBundle(otherCtx, "sports", "api", null).getStatus(), 200);
        expectError(() -> zts.getPolicyBundle(createResourceContext(principal("weather", "svc2")),
                "sports", "api", null), 403);
    }

    // entries api

    @Test
    public void testGetPolicyBundleEntries() {
        PolicyBundle rego1 = bundle("b-rego", "rego");
        PolicyBundle rego2 = bundle("a-rego", "rego");
        grantGetBundle("sports", "a-rego", "weather.svc");
        PolicyBundle rego3 = bundle("c-rego", "rego").setVersion("v7");
        addDomain("sports", rego1, rego2, rego3);

        // domain principal sees all bundles sorted by name

        ResourceContext ctx = createResourceContext(principal("sports", "svc"));
        PolicyBundleEntries entries = zts.getPolicyBundleEntries(ctx, "sports", null);
        assertEquals(entries.getList().size(), 3);
        assertEquals(entries.getList().get(0).getName(), "a-rego");
        assertEquals(entries.getList().get(1).getName(), "b-rego");
        assertEquals(entries.getList().get(2).getName(), "c-rego");
        PolicyBundleEntry entry = entries.getList().get(2);
        assertEquals(entry.getDomain(), "sports");
        assertEquals(entry.getEngine(), "rego");
        assertEquals(entry.getVersion(), "v7");
        assertEquals(entry.getRevision(), Timestamp.fromMillis(MODIFIED_MILLIS).toString());

        // engine filter (case insensitive)

        entries = zts.getPolicyBundleEntries(ctx, "SPORTS", "Rego");
        assertEquals(entries.getList().size(), 3);
        entries = zts.getPolicyBundleEntries(ctx, "sports", "unknown");
        assertTrue(entries.getList().isEmpty());

        // principal from another domain only sees the bundles that allow it

        ResourceContext otherCtx = createResourceContext(principal("weather", "svc"));
        entries = zts.getPolicyBundleEntries(otherCtx, "sports", null);
        assertEquals(entries.getList().size(), 1);
        assertEquals(entries.getList().get(0).getName(), "a-rego");

        entries = zts.getPolicyBundleEntries(createResourceContext(principal("weather", "other")), "sports", null);
        assertTrue(entries.getList().isEmpty());
    }

    @Test
    public void testGetPolicyBundleEntriesErrors() {
        addDomain("sports", bundle("api", "rego"));
        ResourceContext ctx = createResourceContext(principal("sports", "svc"));
        expectError(() -> zts.getPolicyBundleEntries(ctx, "unknown", null), 404);
        expectError(() -> zts.getPolicyBundleEntries(ctx, "sports$bad", null), 400);
        expectError(() -> zts.getPolicyBundleEntries(ctx, "sports", "bad$engine"), 400);
    }
}
