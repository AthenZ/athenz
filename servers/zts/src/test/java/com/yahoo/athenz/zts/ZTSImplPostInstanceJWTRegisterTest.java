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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.CertificateAuthority;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.utils.SignUtils;
import java.text.ParseException;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
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

import javax.net.ssl.SSLContext;
import java.io.File;
import java.security.PrivateKey;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.mockito.ArgumentMatchers.*;
import static org.testng.Assert.*;

public class ZTSImplPostInstanceJWTRegisterTest {

    private ZTSImpl zts = null;
    private Metric ztsMetric = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String MOCKCLIENTADDR = "10.11.12.13";

    @Mock
    private HttpServletRequest mockServletRequest;
    @Mock
    private HttpServletResponse mockServletResponse;

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
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS, "screwdriver,rbac.*");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_MAX_TIMEOUT, "43200");
        System.setProperty(ZTSConsts.ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT, "3600");

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
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "true");
        System.setProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS, ".athenz2.com,.athenz.com");
        System.setProperty("athenz.instance.test.provider.svid", "jwt");

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
        System.clearProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS);
        System.clearProperty("athenz.instance.test.provider.svid");
        System.clearProperty("athenz.instance.test.provider.confirm.exception");
        System.clearProperty("athenz.instance.test.provider.argument.exception");
        System.clearProperty("athenz.instance.test.provider.confirm.gateway.timeout");
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
        if (principal != null) {
            Mockito.when(rsrcCtxWrapper.logPrincipal()).thenReturn(principal.getFullName());
            Mockito.when(rsrcCtxWrapper.getPrincipalDomain()).thenReturn(principal.getDomain());
        }
        return rsrcCtxWrapper;
    }

    private SignedDomain createSignedDomainWithProvider(final String domainName, final String serviceName,
                                                        final String providerName) {

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setEnabled(true);

        com.yahoo.athenz.zms.ServiceIdentity service = new com.yahoo.athenz.zms.ServiceIdentity();
        service.setName(serviceName);
        domain.setServices(Collections.singletonList(service));

        if (providerName != null) {
            com.yahoo.athenz.zms.ServiceIdentity provider = new com.yahoo.athenz.zms.ServiceIdentity();
            provider.setName(providerName);
            provider.setProviderEndpoint("class://com.yahoo.athenz.zts.InstanceTestProvider");
            domain.setServices(new ArrayList<>(domain.getServices()));
            domain.getServices().add(provider);

            Role role = new Role();
            role.setName(ResourceUtils.roleResourceName(domainName, "providers"));
            List<RoleMember> members = new ArrayList<>();
            members.add(new RoleMember().setMemberName(providerName));
            role.setRoleMembers(members);
            domain.setRoles(Collections.singletonList(role));

            com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
            com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
            assertion.setResource(domainName + ":service." + serviceName);
            assertion.setAction("launch");
            assertion.setRole(ResourceUtils.roleResourceName(domainName, "providers"));

            List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
            assertions.add(assertion);

            policy.setAssertions(assertions);
            policy.setName(ResourceUtils.policyResourceName(domainName, "providers"));

            com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
            domainPolicies.setDomain(domainName);
            domainPolicies.setPolicies(Collections.singletonList(policy));

            com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
            signedPolicies.setContents(domainPolicies);

            domain.setPolicies(signedPolicies);
        }

        SignedDomain signedDomain = new SignedDomain();
        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private JWTClaimsSet parseIdToken(String tokenString) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(tokenString);
        return signedJWT.getJWTClaimsSet();
    }

    private InstanceRegisterInformation createInstanceRegisterInformation(final String instanceId,
            final String spiffeUri, Boolean spiffeSubject, final String audience, final String nonce,
            final Integer expiryTime, final String keyType, final String namespace) {

        InstanceRegisterInformation info = new InstanceRegisterInformation();
        info.setJwtSVIDInstanceId(instanceId);
        info.setJwtSVIDSpiffe(spiffeUri);
        info.setJwtSVIDSpiffeSubject(spiffeSubject);
        info.setJwtSVIDAudience(audience);
        info.setJwtSVIDNonce(nonce);
        info.setExpiryTime(expiryTime);
        info.setJwtSVIDKeyType(keyType);
        info.setNamespace(namespace);
        return info;
    }

    @Test
    public void testPostInstanceJWTRegisterSuccess() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-001", "spiffe://athenz/sa/production",
                false, "audience-123", "nonce-456", 3600, null, null);

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        assertNotNull(response.getEntity());
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        assertEquals(identity.getName(), "athenz.production");
        assertEquals(identity.getProvider(), "athenz.provider");
        assertEquals(identity.getInstanceId(), "instance-001");
        assertNotNull(identity.getServiceToken());

        // Verify Location header
        String location = response.getHeaderString("Location");
        assertNotNull(location);
        assertEquals(location, "/zts/v1/instance/athenz.provider/athenz/production/instance-001");

        // Verify IdToken can be parsed
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());
        assertEquals(idToken.getAudience().get(0), "audience-123");
        assertEquals(idToken.getStringClaim("nonce"), "nonce-456");
        assertEquals(idToken.getSubject(), "athenz.production");
        assertEquals(idToken.getStringClaim("spiffe"), "spiffe://athenz/sa/production");
    }

    @Test
    public void testPostInstanceJWTRegisterWithSpiffeSubject() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-002",
                "spiffe://athenz/sa/production", true, "audience-123", "nonce-456", 3600, null, null);

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());
        assertEquals(idToken.getSubject(), "spiffe://athenz/sa/production");
        assertNull(idToken.getStringClaim("spiffe")); // Should not be set when subject is spiffe
    }

    @Test
    public void testPostInstanceJWTRegisterInvalidSpiffeUri() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-003",
                "spiffe://wrong-domain/sa/production", false, "audience-123", "nonce-456", 3600, null, null);

        try {
            zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                    "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("SPIFFE URI validation failed"));
        }
    }

    @Test
    public void testPostInstanceJWTRegisterMissingSpiffeUriWhenRequired() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-004", null, true,
                "audience-123", "nonce-456", 3600, null, null);

        try {
            zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                    "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("SPIFFE URI is required when jwtSVIDSpiffeSubject is true"));
        }
    }

    @Test
    public void testPostInstanceJWTRegisterProviderNotFound() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", null);
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-005",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);

        try {
            zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                    "athenz.production", "athenz", "unknown.provider", "postInstanceJWTRegister");
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("unable to get instance for provider"));
        }
    }

    @Test
    public void testPostInstanceJWTRegisterProviderConfirmationFailure() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        // Configure provider to throw exception
        System.setProperty("athenz.instance.test.provider.confirm.exception", "true");

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-006",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);

        try {
            zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                    "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("unable to verify attestation data"));
            assertTrue(ex.getMessage().contains("request-forbidden"));
        }

        // now let's throw an illegal argument exception

        System.setProperty("athenz.instance.test.provider.argument.exception", "true");
        try {
            zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                    "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("unable to verify attestation data"));
            assertFalse(ex.getMessage().contains("request-forbidden"));
        }
    }

    @Test
    public void testPostInstanceJWTRegisterProviderGatewayTimeout() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        // Create a custom provider that throws GatewayTimeout
        InstanceProvider testProvider = new InstanceProvider() {

            @Override
            public SVIDType getSVIDType() {
                return SVIDType.JWT;
            }

            @Override
            public Scheme getProviderScheme() {
                return Scheme.CLASS;
            }

            @Override
            public void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore) {
            }

            @Override
            public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
                throw new ProviderResourceException(ProviderResourceException.GATEWAY_TIMEOUT, "Gateway timeout");
            }

            @Override
            public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
                return null;
            }
        };

        // Replace the provider manager's getProvider to return our custom provider
        InstanceProviderManager originalManager = zts.instanceProviderManager;
        InstanceProviderManager mockManager = Mockito.mock(InstanceProviderManager.class);
        Mockito.when(mockManager.getProvider(Mockito.eq("athenz.provider"), Mockito.any())).thenReturn(testProvider);
        zts.instanceProviderManager = mockManager;

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-007",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);

        try {
            zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                    "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.GATEWAY_TIMEOUT);
            assertTrue(ex.getMessage().contains("unable to verify attestation data"));
        } finally {
            zts.instanceProviderManager = originalManager;
            testProvider.close();
        }
    }

    @Test
    public void testPostInstanceJWTRegisterWithRSAKeyType() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-008",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, "RSA", null);

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        assertNotNull(identity.getServiceToken());

        // Verify token can be parsed
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());
        assertNotNull(idToken);
    }

    @Test
    public void testPostInstanceJWTRegisterWithECKeyType() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-009",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, "EC", null
        );

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        assertNotNull(identity.getServiceToken());

        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());
        assertNotNull(idToken);
    }

    @Test
    public void testPostInstanceJWTRegisterWithCustomExpiryTime() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        int customExpiry = 7200; // 2 hours
        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-010",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", customExpiry, null, null
        );

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());

        // Verify expiry time is approximately correct (within 5 seconds tolerance)
        long expectedExpiry = (System.currentTimeMillis() / 1000) + customExpiry;
        assertTrue(Math.abs(idToken.getExpirationTime().getTime() / 1000 - expectedExpiry) < 5);
    }

    @Test
    public void testPostInstanceJWTRegisterWithLargeExpiryTime() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        int largeExpiry = 100000; // Larger than max timeout
        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-012",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", largeExpiry, null, null);

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());

        // Should be capped at max timeout (12 hours = 43200 seconds)
        long expectedExpiry = (System.currentTimeMillis() / 1000) + 43200;
        assertTrue(Math.abs(idToken.getExpirationTime().getTime() / 1000 - expectedExpiry) < 5);
    }

    @Test
    public void testPostInstanceJWTRegisterWithoutSpiffeUri() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-013", null, false,
                "audience-123", "nonce-456", 3600, null, null);

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());
        assertEquals(idToken.getSubject(), "athenz.production");
        assertNull(idToken.getStringClaim("spiffe"));
    }

    @Test
    public void testPostInstanceJWTRegisterWithNamespace() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-014",
                "spiffe://athenz.io/ns/prod/sa/athenz.production", false, "audience-123", "nonce-456", 3600, null, "prod");

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        assertNotNull(identity.getServiceToken());
    }

    @Test
    public void testPostInstanceJWTRegisterAccessLogAttribute() {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-015",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);

        zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        // Verify that access log attribute was set
        Mockito.verify(mockServletRequest, Mockito.atLeastOnce()).setAttribute(
                Mockito.eq("com.yahoo.athenz.uri.addl_query"),
                Mockito.anyString()
        );
    }

    @Test
    public void testPostInstanceJWTRegisterIdTokenFields() throws ParseException {

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        String audience = "test-audience";
        String nonce = "test-nonce";
        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-016",
                "spiffe://athenz/sa/production", false, audience, nonce, 3600, null, null);

        Response response = zts.postInstanceJWTRegister(ctx, info, "athenz", "production",
                "athenz.production", "athenz", "athenz.provider", "postInstanceJWTRegister");

        assertEquals(response.getStatus(), ResourceException.CREATED);
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());

        // Verify all IdToken fields
        assertEquals(idToken.getIntegerClaim("ver"), Integer.valueOf(1));
        assertEquals(idToken.getAudience().get(0), audience);
        assertEquals(idToken.getStringClaim("nonce"), nonce);
        assertEquals(idToken.getIssuer(), "https://athenz.io:4443/zts/v1");
        assertEquals(idToken.getSubject(), "athenz.production");
        assertEquals(idToken.getStringClaim("spiffe"), "spiffe://athenz/sa/production");
        assertNotNull(idToken.getIssueTime());
        assertNotNull(idToken.getDateClaim("auth_time"));
        assertNotNull(idToken.getExpirationTime());
        assertTrue(idToken.getExpirationTime().getTime() > idToken.getIssueTime().getTime());
    }

    @Test
    public void testPostInstanceRegisterInformationSuccess() throws ParseException {

        SignedDomain providerDomain = ZTSTestUtils.signedAuthorizedProviderDomain(privateKey);
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-001",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);
        info.setDomain("athenz");
        info.setService("production");
        info.setProvider("athenz.provider");

        Response response = zts.postInstanceRegisterInformation(ctx, info);

        assertEquals(response.getStatus(), ResourceException.CREATED);
        assertNotNull(response.getEntity());
        InstanceIdentity identity = (InstanceIdentity) response.getEntity();
        assertEquals(identity.getName(), "athenz.production");
        assertEquals(identity.getProvider(), "athenz.provider");
        assertEquals(identity.getInstanceId(), "instance-001");
        assertNotNull(identity.getServiceToken());

        // Verify Location header
        String location = response.getHeaderString("Location");
        assertNotNull(location);
        assertEquals(location, "/zts/v1/instance/athenz.provider/athenz/production/instance-001");

        // Verify IdToken can be parsed
        JWTClaimsSet idToken = parseIdToken(identity.getServiceToken());
        assertEquals(idToken.getAudience().get(0), "audience-123");
        assertEquals(idToken.getStringClaim("nonce"), "nonce-456");
        assertEquals(idToken.getSubject(), "athenz.production");
        assertEquals(idToken.getStringClaim("spiffe"), "spiffe://athenz/sa/production");
    }

    @Test
    public void testPostInstanceRegisterInformationFailure() throws ParseException {

        SignedDomain providerDomain = ZTSTestUtils.signedAuthorizedProviderDomain(privateKey);
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-001",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);
        info.setDomain("athenz");
        info.setService("unknown-service");
        info.setProvider("athenz.provider");

        try {
            zts.postInstanceRegisterInformation(ctx, info);
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("provider 'athenz.provider' not authorized to launch athenz.unknown-service instances"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationInvalidSpiffe() throws ParseException {

        SignedDomain providerDomain = ZTSTestUtils.signedAuthorizedProviderDomain(privateKey);
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-001",
                "spiffe://athenz/sa/unknown", false, "audience-123", "nonce-456", 3600, null, null);
        info.setDomain("athenz");
        info.setService("production");
        info.setProvider("athenz.provider");

        try {
            zts.postInstanceRegisterInformation(ctx, info);
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("SPIFFE URI validation failed"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationFailureProviderType() throws ParseException {

        SignedDomain providerDomain = ZTSTestUtils.signedAuthorizedProviderDomain(privateKey);
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = createSignedDomainWithProvider("athenz", "production", "athenz.provider");
        store.processSignedDomain(tenantDomain, false);

        CertificateAuthority certAuthority = new CertificateAuthority();
        Principal principal = SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext ctx = createResourceContext(principal);

        InstanceRegisterInformation info = createInstanceRegisterInformation("instance-001",
                "spiffe://athenz/sa/production", false, "audience-123", "nonce-456", 3600, null, null);
        info.setDomain("athenz");
        info.setService("production");
        info.setProvider("athenz.provider");

        System.setProperty("athenz.instance.test.provider.svid", "x509");

        try {
            zts.postInstanceRegisterInformation(ctx, info);
            fail("Should have thrown ResourceException");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("invalid instance provider type for JWT"));
        }

        System.clearProperty("athenz.instance.test.provider.svid");
    }
}

