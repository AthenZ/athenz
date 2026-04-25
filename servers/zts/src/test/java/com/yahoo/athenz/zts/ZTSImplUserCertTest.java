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
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
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

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class ZTSImplUserCertTest {

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
        System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_PROVIDER);
        System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_USER_CERT_DEFAULT_TIMEOUT);
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
        Mockito.when(rsrcCtxWrapper.getApiName()).thenReturn("postusercertificaterequest");
        if (principal != null) {
            Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return rsrcCtxWrapper;
    }

    private String generateUserCsr(final String cn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                "cn=" + cn + ",o=Athenz", null);
    }

    private static String readResourceFile(final String filename) {
        try {
            Path path = Paths.get("src/test/resources/" + filename);
            return new String(Files.readAllBytes(path));
        } catch (Exception ex) {
            throw new RuntimeException("Failed to read test resource: " + filename, ex);
        }
    }

    // -----------------------------------------------------------------------
    // getUserX509KeySignerId tests
    // -----------------------------------------------------------------------

    @Test
    public void testGetUserX509KeySignerIdAuthorityReturnsValue() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn("authority-key-id");
        zts.userAuthority = mockAuthority;

        assertEquals(zts.getUserX509KeySignerId("user.joe", "request-key-id"), "authority-key-id");
    }

    @Test
    public void testGetUserX509KeySignerIdAuthorityReturnsNull() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn(null);
        zts.userAuthority = mockAuthority;

        assertEquals(zts.getUserX509KeySignerId("user.joe", "request-key-id"), "request-key-id");
    }

    @Test
    public void testGetUserX509KeySignerIdAuthorityReturnsEmpty() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn("");
        zts.userAuthority = mockAuthority;

        assertEquals(zts.getUserX509KeySignerId("user.joe", "request-key-id"), "request-key-id");
    }

    @Test
    public void testGetUserX509KeySignerIdBothNull() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn(null);
        zts.userAuthority = mockAuthority;

        assertNull(zts.getUserX509KeySignerId("user.joe", null));
    }

    @Test
    public void testGetUserX509KeySignerIdAuthorityEmptyRequestNull() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn("");
        zts.userAuthority = mockAuthority;

        assertNull(zts.getUserX509KeySignerId("user.joe", null));
    }

    // -----------------------------------------------------------------------
    // validateUserPrincipalForCert tests
    // -----------------------------------------------------------------------

    @Test
    public void testValidateUserPrincipalForCertNull() {
        assertFalse(zts.validateUserPrincipalForCert(null));
    }

    @Test
    public void testValidateUserPrincipalForCertEmpty() {
        assertFalse(zts.validateUserPrincipalForCert(""));
    }

    @Test
    public void testValidateUserPrincipalForCertWildcard() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        assertFalse(zts.validateUserPrincipalForCert("user.*"));
    }

    @Test
    public void testValidateUserPrincipalForCertWildcardInMiddle() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        assertFalse(zts.validateUserPrincipalForCert("user.us*r1"));
    }

    @Test
    public void testValidateUserPrincipalForCertWrongDomainPrefix() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        assertFalse(zts.validateUserPrincipalForCert("wrong_domain.user1"));
    }

    @Test
    public void testValidateUserPrincipalForCertNotStartWithPrefix() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        assertFalse(zts.validateUserPrincipalForCert("athenz.service1"));
    }

    @Test
    public void testValidateUserPrincipalForCertUserNotActive() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zts.userAuthority = mockAuthority;
        assertFalse(zts.validateUserPrincipalForCert("user.joe"));
    }

    @Test
    public void testValidateUserPrincipalForCertUserInvalid() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_INVALID);
        zts.userAuthority = mockAuthority;
        assertFalse(zts.validateUserPrincipalForCert("user.joe"));
    }

    @Test
    public void testValidateUserPrincipalForCertValid() {
        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        assertTrue(zts.validateUserPrincipalForCert("user.joe"));
    }

    // -----------------------------------------------------------------------
    // postUserCertificateRequest tests
    // -----------------------------------------------------------------------

    @Test
    public void testPostUserCertificateRequestReadOnlyMode() {

        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true);
        zts.readOnlyMode = dynamicConfigBoolean;

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        try {
            zts.postUserCertificateRequest(ctx, new UserCertificateRequest());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }
    }

    @Test
    public void testPostUserCertificateRequestNoUserAuthority() {

        zts.userAuthority = null;
        zts.userCertProvider = "test.provider";

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        try {
            zts.postUserCertificateRequest(ctx, new UserCertificateRequest());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User authority configuration is not set"));
        }
    }

    @Test
    public void testPostUserCertificateRequestNoUserCertProvider() {

        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = null;

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        try {
            zts.postUserCertificateRequest(ctx, new UserCertificateRequest());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User authority configuration is not set"));
        }
    }

    @Test
    public void testPostUserCertificateRequestBothNull() {

        zts.userAuthority = null;
        zts.userCertProvider = null;

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        try {
            zts.postUserCertificateRequest(ctx, new UserCertificateRequest());
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User authority configuration is not set"));
        }
    }

    @Test
    public void testPostUserCertificateRequestInvalidPrincipalName() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("wrong_domain.user1")).thenReturn(Authority.UserType.USER_INVALID);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("wrong_domain.user1");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("wrong_domain.user1")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User name is not valid"));
        }
    }

    @Test
    public void testPostUserCertificateRequestEmptyPrincipalName() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User name is not valid"));
        }
    }

    @Test
    public void testPostUserCertificateRequestInvalidCsr() {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr("invalid-csr")
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Unable to parse PKCS10 CSR"));
        }
    }

    @Test
    public void testPostUserCertificateRequestCnMismatch() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.differentuser");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User Certificate Request mismatch"));
        }
    }

    @Test
    public void testPostUserCertificateRequestCsrValidationFailureInvalidOrg() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        String csr = Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                "cn=user.joe,o=InvalidOrg", null);

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Unable to validate cert request"));
        }
    }

    @Test
    public void testPostUserCertificateRequestProviderNotFound() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "unknown.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        when(instanceProviderManager.getProvider(eq("unknown.provider"), Mockito.any(), Mockito.any())).thenReturn(null);
        zts.instanceProviderManager = instanceProviderManager;

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("unable to get instance for provider"));
        }
    }

    @Test
    public void testPostUserCertificateRequestProviderWrongType() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.JWT);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);
        zts.instanceProviderManager = instanceProviderManager;

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("invalid instance provider type"));
        }
    }

    @Test
    public void testPostUserCertificateRequestProviderConfirmationFailure() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);
        when(providerClient.confirmInstance(Mockito.any()))
                .thenThrow(new ProviderResourceException(403, "Forbidden"));
        zts.instanceProviderManager = instanceProviderManager;

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("unable to verify attestation data"));
        }
    }

    @Test
    public void testPostUserCertificateRequestProviderConfirmationTimeout() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);
        when(providerClient.confirmInstance(Mockito.any()))
                .thenThrow(new ProviderResourceException(504, "Gateway Timeout"));
        zts.instanceProviderManager = instanceProviderManager;

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.GATEWAY_TIMEOUT);
        }
    }

    @Test
    public void testPostUserCertificateRequestCertSignerFailure() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn(null);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService("joe").setProvider("test.provider");
        when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(Mockito.anyString(), Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyInt(), Mockito.any(),
                Mockito.any())).thenReturn(null);
        zts.instanceCertManager = certManager;

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("Unable to create certificate from the cert signer"));
        }
    }

    @Test
    public void testPostUserCertificateRequestCertSignerEmptyResult() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn(null);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService("joe").setProvider("test.provider");
        when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(Mockito.anyString(), Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyInt(), Mockito.any(),
                Mockito.any())).thenReturn("");
        zts.instanceCertManager = certManager;

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("Unable to create certificate from the cert signer"));
        }
    }

    @Test
    public void testPostUserCertificateRequestSuccess() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn("authority-signer-key");
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data")
                .setExpiryTime(3600);

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService("joe").setProvider("test.provider");
        when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        String pemCert = readResourceFile("valid_provider_refresh.pem");

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(eq("test.provider"), Mockito.any(),
                eq(csr), eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT), eq(60), Mockito.any(),
                eq("authority-signer-key"))).thenReturn(pemCert);
        Mockito.doNothing().when(certManager).logX509Cert(Mockito.any(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any());
        zts.instanceCertManager = certManager;

        UserCertificate result = zts.postUserCertificateRequest(ctx, req);
        assertNotNull(result);
        assertEquals(result.getX509Certificate(), pemCert);
    }

    @Test
    public void testPostUserCertificateRequestSuccessWithRequestSignerKeyId() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn(null);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data")
                .setX509CertSignerKeyId("request-signer-key");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService("joe").setProvider("test.provider");
        when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        String pemCert = readResourceFile("valid_provider_refresh.pem");

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(eq("test.provider"), Mockito.any(),
                eq(csr), eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT), Mockito.anyInt(), Mockito.any(),
                eq("request-signer-key"))).thenReturn(pemCert);
        Mockito.doNothing().when(certManager).logX509Cert(Mockito.any(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any());
        zts.instanceCertManager = certManager;

        UserCertificate result = zts.postUserCertificateRequest(ctx, req);
        assertNotNull(result);
        assertEquals(result.getX509Certificate(), pemCert);
    }

    @Test
    public void testPostUserCertificateRequestSuccessDefaultTimeout() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_ACTIVE);
        when(mockAuthority.getSignerKeyId("user.joe")).thenReturn(null);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        when(providerClient.getSVIDType()).thenReturn(InstanceProvider.SVIDType.X509);
        when(instanceProviderManager.getProvider(eq("test.provider"), Mockito.any(), Mockito.any())).thenReturn(providerClient);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("user").setService("joe").setProvider("test.provider");
        when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        zts.instanceProviderManager = instanceProviderManager;

        String pemCert = readResourceFile("valid_provider_refresh.pem");

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        when(certManager.generateX509Certificate(eq("test.provider"), Mockito.any(),
                eq(csr), eq(InstanceProvider.ZTS_CERT_USAGE_CLIENT),
                Mockito.anyInt(), Mockito.any(),
                Mockito.any())).thenReturn(pemCert);
        Mockito.doNothing().when(certManager).logX509Cert(Mockito.any(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any());
        zts.instanceCertManager = certManager;

        UserCertificate result = zts.postUserCertificateRequest(ctx, req);
        assertNotNull(result);
        assertEquals(result.getX509Certificate(), pemCert);
    }

    @Test
    public void testPostUserCertificateRequestWildcardPrincipalName() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.*")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User name is not valid"));
        }
    }

    @Test
    public void testPostUserCertificateRequestSuspendedUser() throws Exception {

        Authority mockAuthority = Mockito.mock(Authority.class);
        when(mockAuthority.getUserType("user.joe")).thenReturn(Authority.UserType.USER_SUSPENDED);
        zts.userAuthority = mockAuthority;
        zts.userCertProvider = "test.provider";

        String csr = generateUserCsr("user.joe");

        PrincipalAuthority authority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "joe",
                "v=U1;d=user;n=joe;s=signature", 0, authority);
        ResourceContext ctx = createResourceContext(principal);

        UserCertificateRequest req = new UserCertificateRequest()
                .setName("user.joe")
                .setCsr(csr)
                .setAttestationData("attestation-data");

        try {
            zts.postUserCertificateRequest(ctx, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("User name is not valid"));
        }
    }
}
