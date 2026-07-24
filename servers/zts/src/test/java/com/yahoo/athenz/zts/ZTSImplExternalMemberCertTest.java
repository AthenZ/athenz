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

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Collections;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ZTSImplExternalMemberCertTest {

    private ZTSImpl zts = null;
    private Metric ztsMetric = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String MOCKCLIENTADDR = "10.11.12.13";

    @Mock private HttpServletRequest mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;

    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);

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

        ztsMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
    }

    @BeforeMethod
    public void setup() {
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, Integer.toString(2400));
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, Integer.toString(96000));
        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS,
                "user_domain.proxy-user1,user_domain.proxy-user2");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_IDENTITY, "false");

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));

        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        cloudStore = new CloudStore();

        store = new DataStore(structStore, cloudStore, ztsMetric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_PROVIDER);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_DEFAULT_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_ALLOWED_DOMAINS);
        System.clearProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_SIGNER_KEY_ID_LIST);
    }

    private ResourceContext createResourceContext(Principal principal) {
        ServerResourceContext rsrcCtx = Mockito.mock(ServerResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);
        Mockito.when(mockServletRequest.getAttribute(anyString())).thenReturn(null);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        Mockito.when(rsrcCtxWrapper.getApiName()).thenReturn("postexternalmembercertificaterequest");
        if (principal != null) {
            Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return rsrcCtxWrapper;
    }

    private String generateExternalMemberCsr(final String cn) throws Exception {
        return generateExternalMemberCsr(cn, "Athenz");
    }

    private String generateExternalMemberCsr(final String cn, final String org) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                "cn=" + cn + ",o=" + org, null);
    }

    private static String readResourceFile(final String filename) {
        try {
            Path path = Paths.get("src/test/resources/" + filename);
            return new String(Files.readAllBytes(path));
        } catch (Exception ex) {
            throw new RuntimeException("Failed to read test resource: " + filename, ex);
        }
    }

    @Test
    public void testGetExternalMemberX509KeySignerIdRequestInAllowedList() {
        zts.validExternalMemberX509CertSignerKeyIds = new java.util.HashSet<>(
                java.util.Arrays.asList("key-id-1", "key-id-2"));

        assertEquals(zts.getExternalMemberX509KeySignerId("key-id-1"), "key-id-1");
    }

    @Test
    public void testGetExternalMemberX509KeySignerIdRequestNotInAllowedList() {
        zts.validExternalMemberX509CertSignerKeyIds = new java.util.HashSet<>(
                java.util.Arrays.asList("key-id-1", "key-id-2"));

        assertNull(zts.getExternalMemberX509KeySignerId("unknown-key-id"));
    }

    @Test
    public void testGetExternalMemberX509KeySignerIdRequestNullWithAllowedList() {
        zts.validExternalMemberX509CertSignerKeyIds = new java.util.HashSet<>(
                java.util.Arrays.asList("key-id-1", "key-id-2"));

        assertNull(zts.getExternalMemberX509KeySignerId(null));
    }

    @Test
    public void testGetExternalMemberCertTimeout() {
        zts.externalMemberCertDefaultTimeout = 60;
        zts.externalMemberCertMaxTimeout = 120;

        assertEquals(zts.getExternalMemberCertTimeout(null), 60);
        assertEquals(zts.getExternalMemberCertTimeout(30), 30);
        assertEquals(zts.getExternalMemberCertTimeout(180), 60);

        zts.externalMemberCertDefaultTimeout = 180;
        assertEquals(zts.getExternalMemberCertTimeout(null), 120);
    }

    @Test
    public void testValidateExternalMemberPrincipalForCert() {
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        assertTrue(zts.validateExternalMemberPrincipalForCert("email:ext.joe@athenz.io"));
        assertFalse(zts.validateExternalMemberPrincipalForCert(null));
        assertFalse(zts.validateExternalMemberPrincipalForCert(""));
        assertFalse(zts.validateExternalMemberPrincipalForCert("email:ext.*@athenz.io"));
        assertFalse(zts.validateExternalMemberPrincipalForCert("email:ext."));
        assertFalse(zts.validateExternalMemberPrincipalForCert(":ext.athenz_user@athenz.io"));
        assertFalse(zts.validateExternalMemberPrincipalForCert("email:group.name:ext.athenz_user@athenz.io"));
        assertFalse(zts.validateExternalMemberPrincipalForCert("hosts:ext.host1.example.com"));
    }

    @Test
    public void testParseDomainList() {
        assertTrue(zts.parseDomainList(null).isEmpty());
        assertTrue(zts.parseDomainList("").isEmpty());
        assertEquals(zts.parseDomainList(" email, HOSTS ,,email "),
                new java.util.HashSet<>(java.util.Arrays.asList("email", "hosts")));
    }

    @Test
    public void testIsExternalMemberCertDomainAllowedInvalidName() {
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        assertFalse(zts.isExternalMemberCertDomainAllowed(null));
        assertFalse(zts.isExternalMemberCertDomainAllowed("email.ext.joe@athenz.io"));
    }

    @Test
    public void testLoadExternalMemberCertSignerKeyIdList() {
        System.setProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_SIGNER_KEY_ID_LIST,
                "key-id-1,key-id-2");

        zts.loadConfigurationSettings();

        assertEquals(zts.validExternalMemberX509CertSignerKeyIds,
                new java.util.HashSet<>(java.util.Arrays.asList("key-id-1", "key-id-2")));
    }

    @Test
    public void testLoadExternalMemberCertTimeoutSettingsInvalidValues() {
        System.setProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_MAX_TIMEOUT, "0");
        System.setProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_DEFAULT_TIMEOUT, "-5");

        zts.loadExternalMemberCertTimeoutSettings();

        assertEquals(zts.externalMemberCertMaxTimeout, 60);
        assertEquals(zts.externalMemberCertDefaultTimeout, 60);
    }

    @Test
    public void testLoadExternalMemberCertTimeoutSettingsMaxLessThanDefault() {
        System.setProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_MAX_TIMEOUT, "30");
        System.setProperty(ZTSConsts.ZTS_PROP_EXTERNAL_MEMBER_CERT_DEFAULT_TIMEOUT, "120");

        zts.loadExternalMemberCertTimeoutSettings();

        assertEquals(zts.externalMemberCertMaxTimeout, 120);
        assertEquals(zts.externalMemberCertDefaultTimeout, 120);
    }

    @Test
    public void testPostExternalMemberCertificateRequestReadOnlyMode() {

        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true);
        zts.readOnlyMode = dynamicConfigBoolean;

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        try {
            zts.postExternalMemberCertificateRequest(ctx, new ExternalMemberCertificateRequest());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }
    }

    @Test
    public void testPostExternalMemberCertificateRequestRequiresExternalProvider() throws Exception {

        final String externalPrincipal = "email:ext.joe@athenz.io";

        zts.userCertProvider = "user.provider";
        zts.externalMemberCertProvider = null;
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr(generateExternalMemberCsr(externalPrincipal))
                .setAttestationData("attestation-data");

        try {
            zts.postExternalMemberCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("External member certificate configuration is not set"));
        }
    }

    @Test
    public void testPostExternalMemberCertificateRequestSuccessUsesExternalProvider() throws Exception {

        final String externalPrincipal = "email:ext.joe@athenz.io";

        zts.userAuthority = null;
        zts.userCertProvider = "user.provider";
        zts.externalMemberCertProvider = "external.provider";
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");
        zts.validExternalMemberX509CertSignerKeyIds = new java.util.HashSet<>(
                Collections.singleton("request-signer-key"));
        zts.externalMemberCertDefaultTimeout = 60;
        zts.externalMemberCertMaxTimeout = 60;

        String csr = generateExternalMemberCsr(externalPrincipal);

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr(csr)
                .setAttestationData("attestation-data")
                .setExpiryTime(3600)
                .setX509CertSignerKeyId("request-signer-key");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("external.provider"), Mockito.any(), Mockito.any()))
                .thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService(externalPrincipal).setProvider("external.provider");
        when(providerClient.confirmInstance(Mockito.argThat(arg ->
                externalPrincipal.equals(arg.getService()) &&
                        "external.provider".equals(arg.getProvider())))).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        String pemCert = readResourceFile("valid_provider_refresh.pem");

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(eq("external.provider"), Mockito.any(),
                eq(csr), eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT), eq(60), Mockito.any(),
                eq("request-signer-key"))).thenReturn(pemCert);
        Mockito.doNothing().when(certManager).logX509Cert(Mockito.any(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any());
        zts.instanceCertManager = certManager;

        ExternalMemberCertificate result = zts.postExternalMemberCertificateRequest(ctx, req);
        assertNotNull(result);
        assertEquals(result.getX509Certificate(), pemCert);
        Mockito.verify((RsrcCtxWrapper) ctx).logPrincipal(externalPrincipal);
        Mockito.verify(instanceProviderManager, Mockito.never())
                .getProvider(eq("user.provider"), Mockito.any(), Mockito.any());
    }

    @Test
    public void testPostExternalMemberCertificateRequestDisallowedDomain() throws Exception {

        final String externalPrincipal = "hosts:ext.host1.example.com";

        zts.externalMemberCertProvider = "external.provider";
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr(generateExternalMemberCsr(externalPrincipal))
                .setAttestationData("attestation-data");

        try {
            zts.postExternalMemberCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("External member name is not valid"));
        }
    }

    @Test
    public void testPostExternalMemberCertificateRequestInvalidCsr() {

        final String externalPrincipal = "email:ext.joe@athenz.io";

        zts.externalMemberCertProvider = "external.provider";
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr("invalid-csr")
                .setAttestationData("attestation-data");

        try {
            zts.postExternalMemberCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Unable to parse PKCS10 CSR"));
        }
    }

    @Test
    public void testPostExternalMemberCertificateRequestInvalidSubjectOrg() throws Exception {

        final String externalPrincipal = "email:ext.joe@athenz.io";

        zts.externalMemberCertProvider = "external.provider";
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr(generateExternalMemberCsr(externalPrincipal, "Invalid Company"))
                .setAttestationData("attestation-data");

        try {
            zts.postExternalMemberCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Unable to validate cert request"));
        }
    }

    @Test
    public void testPostExternalMemberCertificateRequestCnMismatch() throws Exception {

        final String externalPrincipal = "email:ext.joe@athenz.io";

        zts.externalMemberCertProvider = "external.provider";
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr(generateExternalMemberCsr("email:ext.differentuser@athenz.io"))
                .setAttestationData("attestation-data");

        try {
            zts.postExternalMemberCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("External Member Certificate Request mismatch"));
        }
    }

    @Test
    public void testPostExternalMemberCertificateRequestCertSignerFailure() throws Exception {

        final String externalPrincipal = "email:ext.joe@athenz.io";

        zts.externalMemberCertProvider = "external.provider";
        zts.externalMemberCertAllowedDomains = Collections.singleton("email");
        zts.externalMemberCertDefaultTimeout = 60;
        zts.externalMemberCertMaxTimeout = 60;

        String csr = generateExternalMemberCsr(externalPrincipal);

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        ExternalMemberCertificateRequest req = new ExternalMemberCertificateRequest()
                .setName(externalPrincipal)
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("external.provider"), Mockito.any(), Mockito.any()))
                .thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService(externalPrincipal).setProvider("external.provider");
        when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(eq("external.provider"), Mockito.any(),
                eq(csr), eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT), eq(60), Mockito.any(),
                Mockito.isNull())).thenReturn(null);
        zts.instanceCertManager = certManager;

        try {
            zts.postExternalMemberCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("Unable to create certificate from the cert signer"));
        }
    }
}
