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
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
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
import java.security.PrivateKey;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.testng.Assert.*;

/**
 * Verifies that over-long values passed through the ZTS API are rejected with a
 * proper 400 error based on the maxSize constraints added to the RDL name types.
 * Without a maxSize, the underlying regex matcher throws a StackOverflowError on
 * very long values (the recursive compound-name patterns), which would surface as
 * an unhandled 500. These tests drive the real ZTS API methods end to end.
 */
public class ZTSImplValidateMaxSizeTest {

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String MOCKCLIENTADDR = "10.11.12.13";

    private Metric ztsMetric = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    @Mock private HttpServletRequest mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;

    private ZTSImpl zts = null;

    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.openMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        Mockito.when(mockServletRequest.isSecure()).thenReturn(true);

        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, METRIC_DEFAULT_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.cloud:4443/zts/v1");

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

        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        cloudStore = new CloudStore();

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");

        // make sure no ssh/workload record store factory settings leaked
        // from other test classes since the execution order is not guaranteed

        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_WORKLOAD_RECORD_STORE_FACTORY_CLASS);

        store = new DataStore(structStore, cloudStore, ztsMetric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
    }

    private ResourceContext createResourceContext(Principal principal, String apiName) {
        ServerResourceContext rsrcCtx = Mockito.mock(ServerResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        Mockito.when(rsrcCtxWrapper.getApiName()).thenReturn(apiName);
        if (principal != null) {
            Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return rsrcCtxWrapper;
    }

    private ResourceContext createResourceContext(final String apiName) {
        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        return createResourceContext(principal, apiName);
    }

    // a value well over any name maxSize - large enough that, without a maxSize
    // constraint, the recursive compound-name regex would overflow the stack
    private String longName(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append('a');
        }
        return sb.toString();
    }

    @Test
    public void testGetServiceIdentityDomainNameTooLong() {
        ResourceContext ctx = createResourceContext("getserviceidentity");
        final String longDomain = longName(9000);
        try {
            zts.getServiceIdentity(ctx, longDomain, "storage");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("getserviceidentity: Invalid DomainName value: "),
                    ex.getMessage());
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type DomainName"),
                    ex.getMessage());
            // the reported value must be truncated and not contain the full input
            assertTrue(ex.getMessage().contains("..."), ex.getMessage());
        }
    }

    @Test
    public void testGetServiceIdentityServiceNameTooLong() {
        ResourceContext ctx = createResourceContext("getserviceidentity");
        final String longService = longName(9000);
        try {
            zts.getServiceIdentity(ctx, "coretech", longService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("getserviceidentity: Invalid SimpleName value: "),
                    ex.getMessage());
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type SimpleName"),
                    ex.getMessage());
        }
    }

    @Test
    public void testGetPublicKeyEntryDomainNameTooLong() {
        ResourceContext ctx = createResourceContext("getpublickeyentry");
        final String longDomain = longName(9000);
        try {
            zts.getPublicKeyEntry(ctx, longDomain, "storage", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type DomainName"),
                    ex.getMessage());
        }
    }

    @Test
    public void testGetTenantDomainsEntityNameTooLong() {
        ResourceContext ctx = createResourceContext("gettenantdomains");
        final String longUser = longName(9000);
        try {
            zts.getTenantDomains(ctx, "provider-domain", longUser, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 512 for type EntityName"),
                    ex.getMessage());
        }
    }

    @Test
    public void testGetTenantDomainsServiceNameTooLong() {
        ResourceContext ctx = createResourceContext("gettenantdomains");
        // ServiceName allows up to 1024 - make sure we exceed that as well
        final String longService = longName(9000);
        try {
            zts.getTenantDomains(ctx, "provider-domain", "user_domain.user1", null, longService);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("String larger than maxSize of 1024 for type ServiceName"),
                    ex.getMessage());
        }
    }
}
