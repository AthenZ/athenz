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
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.asn1.x509.GeneralName;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.*;

/**
 * End-to-end test verifying that a service can only obtain a role certificate
 * for a role it is actually a member of. The sports domain has two roles - ops
 * and system-ops - and the sports.api service is only a member of system-ops.
 * A role certificate request for the ops role must be rejected.
 */
public class ZTSImplRoleCertAccessTest {

    private ZTSImpl zts = null;
    private Metric ztsMetric = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String MOCKCLIENTADDR = "10.11.12.13";

    private static final String DOMAIN_NAME = "sports";
    private static final String SERVICE_NAME = "sports.api";
    private static final String PROXY_USER = "user_domain.user1";
    private static final String OPS_ROLE = "ops";
    private static final String SYSTEM_OPS_ROLE = "system-ops";

    @Mock private HttpServletRequest mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;

    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.openMocks(this);

        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
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

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "false");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS, SERVICE_NAME);

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));

        ChangeLogStore structStore = new MockZMSFileChangeLogStore(ZTS_DATA_STORE_PATH, privateKey, "0");

        cloudStore = new CloudStore();
        store = new DataStore(structStore, cloudStore, ztsMetric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP);
        System.clearProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS);
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
        Mockito.when(rsrcCtxWrapper.getApiName()).thenReturn("postrolecertificaterequestext");
        Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
        Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        return rsrcCtxWrapper;
    }

    /**
     * Set up the sports domain with two roles: ops - which the sports.api
     * service is not a member of - and system-ops - which includes sports.api.
     */
    private void setupDomain() {

        List<Role> roles = new ArrayList<>();
        roles.add(ZTSTestUtils.createRoleObject(DOMAIN_NAME, OPS_ROLE, "sports.ops-service", "user_domain.user1"));
        roles.add(ZTSTestUtils.createRoleObject(DOMAIN_NAME, SYSTEM_OPS_ROLE, SERVICE_NAME));

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(DOMAIN_NAME, roles,
                new ArrayList<>(), null, null, privateKey);
        store.processSignedDomain(signedDomain, false);
    }

    /**
     * Set up the sports domain for our proxy principal tests: the sports.api
     * service is a member of both the ops and system-ops roles while the proxy
     * user is only a member of system-ops.
     */
    private void setupProxyDomain() {

        List<Role> roles = new ArrayList<>();
        roles.add(ZTSTestUtils.createRoleObject(DOMAIN_NAME, OPS_ROLE, SERVICE_NAME));
        roles.add(ZTSTestUtils.createRoleObject(DOMAIN_NAME, SYSTEM_OPS_ROLE, SERVICE_NAME, PROXY_USER));

        SignedDomain signedDomain = ZTSTestUtils.createSignedDomain(DOMAIN_NAME, roles,
                new ArrayList<>(), null, null, privateKey);
        store.processSignedDomain(signedDomain, false);
    }

    private Principal createServicePrincipal() {
        PrincipalAuthority authority = new PrincipalAuthority();
        return SimplePrincipal.create("sports", "api", "v=S1;d=sports;n=api;s=signature", 0, authority);
    }

    /**
     * Generate a role certificate CSR with the given role as the common name
     * and the requesting service in the rfc822 (email) san field.
     */
    private String generateRoleCsr(final String roleName, final String serviceName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        GeneralName[] sanArray = new GeneralName[1];
        sanArray[0] = new GeneralName(GeneralName.rfc822Name, serviceName + "@zts.athenz.cloud");

        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                "cn=" + DOMAIN_NAME + ":role." + roleName + ",o=Athenz", sanArray);
    }

    /**
     * Generate a role certificate CSR for a proxy request - the requested role
     * is the common name, the proxy-for principal is in the rfc822 (email) san
     * field and the requesting service is in the proxy user uri san field.
     */
    private String generateProxyRoleCsr(final String roleName, final String proxyForPrincipal,
            final String serviceName) throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        GeneralName[] sanArray = new GeneralName[2];
        sanArray[0] = new GeneralName(GeneralName.rfc822Name, proxyForPrincipal + "@zts.athenz.cloud");
        sanArray[1] = new GeneralName(GeneralName.uniformResourceIdentifier,
                ZTSConsts.ZTS_CERT_PROXY_USER_URI + serviceName);

        return Crypto.generateX509CSR(keyPair.getPrivate(), keyPair.getPublic(),
                "cn=" + DOMAIN_NAME + ":role." + roleName + ",o=Athenz", sanArray);
    }

    @Test
    public void testPostRoleCertificateRequestExtRoleNotMember() throws Exception {

        setupDomain();

        ResourceContext context = createResourceContext(createServicePrincipal());

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(generateRoleCsr(OPS_ROLE, SERVICE_NAME))
                .setExpiryTime(3600L);

        try {
            RoleCertificate roleCertificate = zts.postRoleCertificateRequestExt(context, req);
            fail("role certificate request for the ops role should have been rejected, instead zts issued: "
                    + Crypto.loadX509Certificate(roleCertificate.getX509Certificate())
                            .getSubjectX500Principal().getName());
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains(SERVICE_NAME), ex.getMessage());
            assertTrue(ex.getMessage().contains("not included in the requested role"), ex.getMessage());
        }
    }

    @Test
    public void testPostRoleCertificateRequestExtRoleMember() throws Exception {

        setupDomain();

        ResourceContext context = createResourceContext(createServicePrincipal());

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(generateRoleCsr(SYSTEM_OPS_ROLE, SERVICE_NAME))
                .setExpiryTime(3600L);

        RoleCertificate roleCertificate = zts.postRoleCertificateRequestExt(context, req);
        assertNotNull(roleCertificate);
        assertNotNull(roleCertificate.getX509Certificate());
    }

    @Test
    public void testPostRoleCertificateRequestRoleNotMember() throws Exception {

        setupDomain();

        ResourceContext context = createResourceContext(createServicePrincipal());

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(generateRoleCsr(OPS_ROLE, SERVICE_NAME))
                .setExpiryTime(3600L);

        try {
            RoleToken roleToken = zts.postRoleCertificateRequest(context, DOMAIN_NAME, OPS_ROLE, req);
            fail("role certificate request for the ops role should have been rejected, instead zts issued: "
                    + Crypto.loadX509Certificate(roleToken.getToken())
                            .getSubjectX500Principal().getName());
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains(SERVICE_NAME), ex.getMessage());
            assertTrue(ex.getMessage().contains("not included in the requested role"), ex.getMessage());
        }
    }

    /**
     * The requesting service is a member of both the ops and system-ops roles
     * while the proxy user is only a member of system-ops. Since the two
     * principals do share a role, the intersection of their role sets is not
     * empty, but it does not include the requested ops role, so zts must
     * reject the request instead of issuing an ops role certificate for a
     * proxy user that is not a member of that role.
     */
    @Test
    public void testPostRoleCertificateRequestExtProxyNotMember() throws Exception {

        setupProxyDomain();

        ResourceContext context = createResourceContext(createServicePrincipal());

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(generateProxyRoleCsr(OPS_ROLE, PROXY_USER, SERVICE_NAME))
                .setProxyForPrincipal(PROXY_USER)
                .setExpiryTime(3600L);

        try {
            RoleCertificate roleCertificate = zts.postRoleCertificateRequestExt(context, req);
            fail("proxy role certificate request for the ops role should have been rejected, instead zts issued: "
                    + Crypto.loadX509Certificate(roleCertificate.getX509Certificate())
                            .getSubjectX500Principal().getName());
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains(PROXY_USER), ex.getMessage());
            assertTrue(ex.getMessage().contains("not included in the requested role"), ex.getMessage());
        }
    }

    @Test
    public void testPostRoleCertificateRequestExtProxyMember() throws Exception {

        setupProxyDomain();

        ResourceContext context = createResourceContext(createServicePrincipal());

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(generateProxyRoleCsr(SYSTEM_OPS_ROLE, PROXY_USER, SERVICE_NAME))
                .setProxyForPrincipal(PROXY_USER)
                .setExpiryTime(3600L);

        RoleCertificate roleCertificate = zts.postRoleCertificateRequestExt(context, req);
        assertNotNull(roleCertificate);
        assertNotNull(roleCertificate.getX509Certificate());
    }

    @Test
    public void testPostRoleCertificateRequestProxyNotMember() throws Exception {

        setupProxyDomain();

        ResourceContext context = createResourceContext(createServicePrincipal());

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(generateProxyRoleCsr(OPS_ROLE, PROXY_USER, SERVICE_NAME))
                .setProxyForPrincipal(PROXY_USER)
                .setExpiryTime(3600L);

        try {
            RoleToken roleToken = zts.postRoleCertificateRequest(context, DOMAIN_NAME, OPS_ROLE, req);
            fail("proxy role certificate request for the ops role should have been rejected, instead zts issued: "
                    + Crypto.loadX509Certificate(roleToken.getToken())
                            .getSubjectX500Principal().getName());
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains(PROXY_USER), ex.getMessage());
            assertTrue(ex.getMessage().contains("not included in the requested role"), ex.getMessage());
        }
    }
}
