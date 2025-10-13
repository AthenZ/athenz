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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.*;
import com.yahoo.athenz.auth.impl.*;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.token.AccessTokenScope;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.testng.Assert.*;

public class ZTSImplAccessTokenTest {

    private ZTSImpl zts = null;
    private Metric ztsMetric = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String ZTS_Y64_CERT0 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84a"
            + "EtFVWZTU2dwWHIzQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbE"
            + "dVT0VnMmpzbWRha1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY"
            + "0cmJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_Y64_PUB_EC = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FR"
            + "WUlLb1pJemowREFRY0RRZ0FFalRIckFSU1RsUFNHeVZwUHpjTTFYTG12M3hlYwpic2NDTkRLZU1LdHgwSjRCT"
            + "jFYWjV1bDUrb0dXTDlKZG5DOHZmN3M2SVBjeE92SVp0SDdORklWbit3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS"
            + "0tLS0tCg--";

    private static final String MOCKCLIENTADDR = "10.11.12.13";
    @Mock private HttpServletRequest  mockServletRequest;
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
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS, "screwdriver,rbac.*");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.cloud:4443/zts/v1");

        // setup our metric class

        ztsMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
    }

    @BeforeMethod
    public void setup() {

        // we want to make sure we start we clean dir structure

        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);

        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");

        /* create our data store */

        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT, Integer.toString(2400));
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT, Integer.toString(96000));

        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS,
                "user_domain.proxy-user1,user_domain.proxy-user2");

        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        cloudStore = new CloudStore();

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_IDENTITY, "false");
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.cloud:4443/zts/v1");

        // enable ip validation for cert requests

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "true");

        store = new DataStore(structStore, cloudStore, ztsMetric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        // enable openid scope

        AccessTokenScope.setSupportOpenIdScope(true);
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
    }

    private ServerPrivateKey getServerPrivateKey(ZTSImpl ztsImpl, final String keyType) {

        // look for the preferred key type - RSA or EC.
        // if the preferred key type is not available then default
        // to the other algorithm - e.g. if the preferred is EC
        // and EC key is not available, then default to RSA.
        // Before returning, check again if we have a valid key
        // and if not then it indicates that both RSA and EC keys
        // are null, thus we must have the original single key
        // specified, so that's what we'll return.

        ServerPrivateKey serverPrivateKey;
        switch (keyType) {
            case ZTSConsts.RSA:
                serverPrivateKey = ztsImpl.privateRSAKey;
                if (serverPrivateKey == null) {
                    serverPrivateKey = ztsImpl.privateECKey;
                }
                break;
            case ZTSConsts.EC:
            default:
                serverPrivateKey = ztsImpl.privateECKey;
                if (serverPrivateKey == null) {
                    serverPrivateKey = ztsImpl.privateRSAKey;
                }
                break;
        }
        if (serverPrivateKey == null) {
            serverPrivateKey = ztsImpl.privateOrigKey;
        }
        return serverPrivateKey;
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

    private String generateRoleName(String domain, String role) {
        return domain + ":role." + role;
    }

    private String generatePolicyName(String domain, String policy) {
        return domain + ":policy." + policy;
    }

    private String generateServiceIdentityName(String domain, String service) {
        return domain + "." + service;
    }

    private SignedDomain createSignedDomain(String domainName, String tenantDomain,
            String serviceName, boolean includeServices) {

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.user"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));
        writers.add(new RoleMember().setMemberName("coretech.jwt"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.user3"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        return createSignedDomain(domainName, tenantDomain, serviceName, writers,
                readers, includeServices);
    }

    private SignedDomain createSignedDomain(String domainName, String tenantDomain,
            String serviceName, List<RoleMember> writers, List<RoleMember> readers,
            boolean includeServices) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "writers"));
        role.setRoleMembers(writers);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "readers"));
        role.setRoleMembers(readers);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "tenant.readers"));
        role.setTrust(tenantDomain);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain + ".admin"));
        role.setTrust(tenantDomain);
        roles.add(role);

        List<Entity> entities = new ArrayList<>();
        String authzDetails = "{\"type\":\"message_access\",\"roles\":[" +
                "{\"name\":\"writers\",\"optional\":false},{\"name\":" +
                "\"editors\"}],\"fields\":[{\"name\":\"location\",\"optional\":true}," +
                "{\"name\":\"identifier\",\"optional\":false},{\"name\":\"resource\"}]}";
        Entity entity = new Entity().setName(ResourceUtils.entityResourceName(domainName, "zts.authorization_details_setup1"))
                .setValue(new Struct().with("data", authzDetails));
        entities.add(entity);

        authzDetails = "{\"type\":\"record_access\",\"roles\":[" +
                "{\"name\":\"writers\",\"optional\":false},{\"name\":" +
                "\"editors\"}],\"fields\":[{\"name\":\"location\",\"optional\":true}," +
                "{\"name\":\"identifier\",\"optional\":false}]}";
        entity = new Entity().setName(ResourceUtils.entityResourceName(domainName, "zts.authorization_details_setup2"))
                .setValue(new Struct().with("data", authzDetails));
        entities.add(entity);

        entity = new Entity().setName(ResourceUtils.entityResourceName(domainName, "entity1"))
                .setValue(new Struct().with("key", "value"));
        entities.add(entity);

        // this one is invalid and will be skipped

        authzDetails = "{\"type\":\"record_access\",\"data\":[" +
                "{\"name\":\"writers\",\"optional\":false},{\"name\":" +
                "\"editors\"}],\"fields\":[{\"name\":\"location\",\"optional\":true}," +
                "{\"name\":\"identifier\",\"optional\":false}]}";
        entity = new Entity().setName(ResourceUtils.entityResourceName(domainName, "zts.authorization_details_setup3"))
                .setValue(new Struct().with("data", authzDetails));
        entities.add(entity);

        List<ServiceIdentity> services = new ArrayList<>();

        if (includeServices) {
            services = createServices(domainName, serviceName);
        }

        List<Policy> policies = new ArrayList<>();

        Policy policy = new Policy();
        Assertion assertion = new Assertion();
        assertion.setResource(domainName + ":tenant." + tenantDomain + ".*");
        assertion.setAction("read");
        assertion.setRole(generateRoleName(domainName, "tenant.readers"));

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "tenant.reader"));
        policies.add(policy);

        // tenant admin domain

        policy = new Policy();
        assertion = new Assertion();
        assertion.setResource(domainName + ":service." + serviceName + ".tenant." + tenantDomain + ".*");
        assertion.setAction("read");
        assertion.setRole(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain + ".admin"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, serviceName + ".tenant." + tenantDomain + ".admin"));
        policies.add(policy);

        DomainPolicies domainPolicies = new DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        SignedPolicies signedPolicies = new SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setGroups(null);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        domain.setEntities(entities);
        domain.setModified(Timestamp.fromCurrentTime());

        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private List<ServiceIdentity> createServices(String domainName, String serviceName) {
        List<ServiceIdentity> services = new ArrayList<>();
        ServiceIdentity service = new ServiceIdentity();
        service.setName(generateServiceIdentityName(domainName, serviceName));
        service.setProviderEndpoint("https://localhost:4443/zts");
        service.setModified(Timestamp.fromCurrentTime());
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);

        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        service.setHosts(hosts);
        services.add(service);

        service = new ServiceIdentity();
        service.setName(generateServiceIdentityName(domainName, "backup"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);

        hosts = new ArrayList<>();
        hosts.add("host2");
        hosts.add("host3");
        service.setHosts(hosts);
        service.setModified(Timestamp.fromCurrentTime());
        services.add(service);

        service = new ServiceIdentity();
        service.setName(generateServiceIdentityName(domainName, "jwt"));
        setServicePublicKey(service, "0", ZTS_Y64_PUB_EC);
        services.add(service);

        return services;
    }

    private void setServicePublicKey(ServiceIdentity service, String id, String key) {
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry.setId(id);
        keyEntry.setKey(key);
        List<com.yahoo.athenz.zms.PublicKeyEntry> listKeys = new ArrayList<>();
        listKeys.add(keyEntry);
        service.setPublicKeys(listKeys);
    }

    @Test
    public void testPostAccessTokenRequest() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String scope = URLEncoder.encode("coretech:domain", StandardCharsets.UTF_8);
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope);
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertNotNull(claimSet.getJWTID());
            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(claimSet.getStringClaim("scope"), "writers");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context1 = createResourceContext(principal1);

        resp = ztsImpl.postAccessTokenRequest(context1,
                "grant_type=client_credentials&scope=coretech:domain&expires_in=100");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.readers coretech:role.writers");

        accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);
        assertEquals(Integer.valueOf(100), resp.getExpires_in());

        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.user1");
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(claimSet.getExpirationTime().getTime() - claimSet.getIssueTime().getTime(), 100 * 1000);
            assertEquals(claimSet.getStringClaim("scope"), "readers writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestEmptyProxyPrincipal() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String scope = URLEncoder.encode("coretech:domain", StandardCharsets.UTF_8);
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&proxy_for_principal=&scope=" + scope);
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers");
    }

    @Test
    public void testPostAccessTokenRequestRoleAuthority() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, new CertificateAuthority());
        assertNotNull(principal);
        ResourceContext context = createResourceContext(principal);

        List<String> principalRoles = new ArrayList<>();
        principalRoles.add("coretech:role.readers");
        principal.setRoles(principalRoles);

        // initially we only have a single role so our request
        // is going to be rejected

        try {
            ztsImpl.postAccessTokenRequest(context, "grant_type=client_credentials&scope=coretech:domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // now add the second role as well

        principalRoles.add("coretech:role.writers");

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain&expires_in=100");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.readers coretech:role.writers");
    }

    @Test
    public void testPostAccessTokenRequestmTLSBound() throws IOException, JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "x509-certificate-details", 0, new CertificateAuthority());
        assertNotNull(principal);

        Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);
        ((SimplePrincipal) principal).setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertNotNull(claimSet.getJWTID());
            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
            assertEquals(claimSet.getStringClaim("scope"), "writers");

            Map<String, Object> cnf = (Map<String, Object>) claimSet.getClaim("cnf");
            assertEquals(cnf.get("x5t#S256"), "A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestECPrivateKey() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private_ec.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertNotNull(claimSet.getJWTID());
            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
            assertEquals(claimSet.getStringClaim("scope"), "writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestSingleRole() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers");
        assertNotNull(resp);
        assertNull(resp.getScope());
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScope() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String scope = URLEncoder.encode("coretech:domain openid coretech:service.api", StandardCharsets.UTF_8);
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope + "&expires_in=240");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers openid");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        String idToken = resp.getId_token();
        assertNotNull(idToken);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getStringClaim("scope"), "writers");
            assertEquals(claimSet.getExpirationTime().getTime() - claimSet.getIssueTime().getTime(), 240 * 1000);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOpenIDIssuer() throws JOSEException {

        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://openid.athenz.cloud:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER, "https://oauth.athenz.cloud:4443/zts/v1");

        testPostAccessTokenRequestOpenIdScope("https://openid.athenz.cloud:4443/zts/v1", "&openid_issuer=true");

        System.clearProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER);
        System.clearProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER);
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOAuthIssuer() throws JOSEException {

        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://openid.athenz.cloud:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER, "https://oauth.athenz.cloud:4443/zts/v1");

        testPostAccessTokenRequestOpenIdScope("https://oauth.athenz.cloud:4443/zts/v1", "&openid_issuer=false");

        System.clearProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER);
        System.clearProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER);
    }

    private void testPostAccessTokenRequestOpenIdScope(final String issuer, final String reqComp) throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String scope = URLEncoder.encode("coretech:domain openid coretech:service.api", StandardCharsets.UTF_8);
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope + "&expires_in=240" + reqComp);
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers openid");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(issuer, claimSet.getIssuer());
            assertEquals(claimSet.getStringClaim("scope"), "writers");
            assertEquals(claimSet.getExpirationTime().getTime() - claimSet.getIssueTime().getTime(), 240 * 1000);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }

        String idTokenStr = resp.getId_token();
        assertNotNull(idTokenStr);

        try {
            SignedJWT signedJWT = SignedJWT.parse(idTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        assertNotNull(claimSet);
        assertEquals(issuer, claimSet.getIssuer());
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeMaxTimeout() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // default max timeout is 12 hours so we'll pick a value
        // bigger than that

        final String scope = URLEncoder.encode("coretech:domain openid coretech:service.api", StandardCharsets.UTF_8);
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope + "&expires_in=57600");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers openid");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        String idToken = resp.getId_token();
        assertNotNull(idToken);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        assertNotNull(claimSet);

        // the value should be 12 hours - the default max

        assertEquals(claimSet.getExpirationTime().getTime() - claimSet.getIssueTime().getTime(), 12 * 60 * 60 * 1000);
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOnly() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // we should only get back openid scope

        try {
            final String scope = URLEncoder.encode("coretech:role.role999 openid coretech:service.api", StandardCharsets.UTF_8);
            zts.postAccessTokenRequest(context, "grant_type=client_credentials&scope=" + scope);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOnlyDisabled() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        AccessTokenScope.setSupportOpenIdScope(false);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // no role access and no openid - we should get back 403
        try {
            final String scope = URLEncoder.encode("coretech:role.role999 openid coretech:service.api", StandardCharsets.UTF_8);
            ztsImpl.postAccessTokenRequest(context, "grant_type=client_credentials&scope=" + scope);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain openid coretech:service.api");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech:role.writers");

        assertNotNull(resp.getAccess_token());
        assertNull(resp.getId_token());
    }

    @Test
    public void testPostAccessTokenRequestInvalidDomain() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials&scope=sportstest:domain");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testPostAccessTokenRequestNoRoleMatch() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials&scope=coretech:role.testrole");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPostAccessTokenRequestInvalidRequest() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postAccessTokenRequest(context, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.postAccessTokenRequest(context, "");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=unknown_type&scope=openid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid grant request"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type%=client_credentials");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("no grant type provided"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials%");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("no grant type provided"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials_bad");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Invalid grant request"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("no grant type provided"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("no scope provided"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials&scope=");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("no scope provided"));
        }
    }

    @Test
    public void testPostAccessTokenRequestProxyUser() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.joe"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        readers.add(new RoleMember().setMemberName("user_domain.jane"));

        SignedDomain signedDomain = createSignedDomain("coretech-proxy2", "weather-proxy2", "storage",
                writers, readers, true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech-proxy2:domain&proxy_for_principal=user_domain.joe");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech-proxy2:role.writers");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.joe");
            assertEquals(claimSet.getStringClaim("proxy"), "user_domain.proxy-user1");
            assertEquals(claimSet.getAudience().get(0), "coretech-proxy2");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestProxyUserMismatchRolesIntersection() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.joe"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        readers.add(new RoleMember().setMemberName("user_domain.jane"));
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));

        SignedDomain signedDomain = createSignedDomain("coretech-proxy3", "weather-proxy3", "storage",
                writers, readers, true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech-proxy3:domain&proxy_for_principal=user_domain.joe");
        assertNotNull(resp);
        assertEquals(resp.getScope(), "coretech-proxy3:role.writers");

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.joe");
            assertEquals(claimSet.getStringClaim("proxy"), "user_domain.proxy-user1");
            assertEquals(claimSet.getAudience().get(0), "coretech-proxy3");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestProxyUserMismatchRolesEmptySet() {

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.joe"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        readers.add(new RoleMember().setMemberName("user_domain.jane"));
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));

        SignedDomain signedDomain = createSignedDomain("coretech-proxy4", "weather-proxy4", "storage",
                writers, readers, true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech-proxy4:domain&proxy_for_principal=user_domain.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPostAccessTokenRequestProxyUserOpenidScope() {

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.joe"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        readers.add(new RoleMember().setMemberName("user_domain.jane"));
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));

        SignedDomain signedDomain = createSignedDomain("coretech-proxy4", "weather-proxy4", "storage",
                writers, readers, true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            final String scope = URLEncoder.encode("openid coretech-proxy4:domain coretech-proxy4:service.api",
                    StandardCharsets.UTF_8);
            zts.postAccessTokenRequest(context, "grant_type=client_credentials&scope=" + scope +
                    "&proxy_for_principal=user_domain.jane");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Proxy Principal cannot request id tokens"));
        }
    }

    @Test
    public void testPostAccessTokenRequestProxyUserSpecificRole() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.joe"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        readers.add(new RoleMember().setMemberName("user_domain.jane"));
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));

        SignedDomain signedDomain = createSignedDomain("coretech-proxy4", "weather-proxy4", "storage",
                writers, readers, true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech-proxy4:role.writers&proxy_for_principal=user_domain.joe");
        assertNotNull(resp);

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.joe");
            assertEquals(claimSet.getStringClaim("proxy"), "user_domain.proxy-user1");
            assertEquals(claimSet.getAudience().get(0), "coretech-proxy4");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestWithAuthorizationDetails() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
            "\"https://location2\"],\"identifier\":\"id1\"}]";
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
        assertNotNull(resp);
        assertNull(resp.getScope());

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        final String accessTokenStr = resp.getAccess_token();
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
            assertEquals(claimSet.getStringClaim("authorization_details"), authzDetails);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestWithSystemAuthorizationDetails() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_single_authz_details.json");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);

        // set back to our zts rsa private key and clear authz details path

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // first role based match

        String authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
        assertNotNull(resp);
        assertNull(resp.getScope());

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        String accessTokenStr = resp.getAccess_token();
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
            assertEquals(claimSet.getStringClaim("authorization_details"), authzDetails);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }

        // next system based match

        authzDetails = "[{\"type\":\"proxy_access\",\"principal\":[\"spiffe://athenz/sa/api\"]}]";
        resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
        assertNotNull(resp);
        assertNull(resp.getScope());

        accessTokenStr = resp.getAccess_token();
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            assertEquals(claimSet.getStringClaim("authorization_details"), authzDetails);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }

        // now match both - role and system based authz details

        authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}," +
                "{\"type\":\"proxy_access\",\"principal\":[\"spiffe://athenz.proxy/sa/api\"]}]";
        resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
        assertNotNull(resp);
        assertNull(resp.getScope());

        accessTokenStr = resp.getAccess_token();
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            assertEquals(claimSet.getStringClaim("authorization_details"), authzDetails);
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestWithSystemAuthorizationDetailsFailures() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_single_authz_details.json");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);

        // set back to our zts rsa private key and clear authz details path

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";

        // no roles - should be rejected due to no match with system filters

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:domain&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }

        // multiple roles - should be rejected due to no match with system filters

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers coretech:role.readers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }

        // missing role configuration - readers has no access

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.readers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }

        // invalid authz details request

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details={\"type\"}");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid Authorization Details data"));
        }

        // max length restriction

        ztsImpl.maxAuthzDetailsLength = 10;
        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details exceeds configured length limit"));
        }
        ztsImpl.maxAuthzDetailsLength = 1024;

        // unknown type of authorization details

        authzDetails = "[{\"type\":\"file_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";
        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }

        // unknown field value should be rejected

        authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"uuid\":\"id1\"}]";
        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }
    }

    @Test
    public void testPostAccessTokenRequestWithAuthorizationDetailsFailures() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";

        // no roles - should be rejected

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:domain&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details not valid for this request"));
        }

        // multiple roles - should be rejected

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers coretech:role.readers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details not valid for this request"));
        }

        // missing role configuration - readers has no access

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.readers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details not valid for this request"));
        }

        // invalid authz details request

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details={\"type\"}");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid Authorization Details data"));
        }

        // max length restriction

        ztsImpl.maxAuthzDetailsLength = 10;
        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details exceeds configured length limit"));
        }
        ztsImpl.maxAuthzDetailsLength = 1024;

        // unknown type of authorization details

        authzDetails = "[{\"type\":\"file_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";
        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }

        // unknown field value should be rejected

        authzDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"uuid\":\"id1\"}]";
        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Authorization Details configuration mismatch"));
        }
    }

    @Test
    public void testPostAccessTokenRequestWithProxyPrincipals() throws IOException, JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);
        final String proxyPrincipalsEncoded = "spiffe%3A%2F%2Fathenz%2Fsa%2Fapi%2Cspiffe%3A%2F%2Fsports%2Fsa%2Fapi";
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers&proxy_principal_spiffe_uris=" + proxyPrincipalsEncoded);
        assertNotNull(resp);
        assertNull(resp.getScope());

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        final String accessTokenStr = resp.getAccess_token();
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWT.verify(verifier));
            claimSet = signedJWT.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(claimSet.getIssuer(), ztsImpl.ztsOAuthIssuer);
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");

            Map<String, Object> cnf = (Map<String, Object>) claimSet.getClaim("cnf");
            assertNotNull(cnf);
            List<String> spiffeUris = (List<String>) cnf.get("proxy-principals#spiffe");
            assertNotNull(spiffeUris);
            assertEquals(spiffeUris.size(), 2);
            assertTrue(spiffeUris.contains("spiffe://athenz/sa/api"));
            assertTrue(spiffeUris.contains("spiffe://sports/sa/api"));
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestWithJWTBearerToken() throws JOSEException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_single_authz_details.json");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);

        // set back to our zts rsa private key and clear authz details path

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        ResourceContext context = new RsrcCtxWrapper(null, servletRequest, null, null, true,
                null, null, null, "postaccesstoken");

        // first let's try without any client assertions which should
        // return the request at not authenticated

        try {
            ztsImpl.postAccessTokenRequest(context, "grant_type=client_credentials&scope=coretech:role.writers");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.UNAUTHORIZED);
        }

        // now let's generate our bearer token and try again
        
        long now = System.currentTimeMillis() / 1000;

        File privateKeyFile = new File("src/test/resources/unit_test_zts_private_ec.pem");
        JWSSigner signer = new ECDSASigner((ECPrivateKey) Crypto.loadPrivateKey(privateKeyFile));
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("coretech.jwt")
                .issueTime(Date.from(Instant.ofEpochSecond(now)))
                .expirationTime(Date.from(Instant.ofEpochSecond(now + 3600)))
                .issuer("coretech.jwt")
                .audience(zts.ztsOAuthIssuer)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("0").build(), claimsSet);
        signedJWT.sign(signer);
        final String jwtToken = signedJWT.serialize();

        // first role based match

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers" +
                "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
                "&client_assertion=" + jwtToken);
        assertNotNull(resp);
        assertNull(resp.getScope());

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        String accessTokenStr = resp.getAccess_token();
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(privateKey.getKey()));
        JWTClaimsSet claimSet = null;
        try {
            SignedJWT signedJWTRes = SignedJWT.parse(accessTokenStr);
            assertTrue(signedJWTRes.verify(verifier));
            claimSet = signedJWTRes.getJWTClaimsSet();
        } catch(Exception ex) {
            fail(ex.getMessage());
        }
        try {
            assertNotNull(claimSet);
            assertEquals(claimSet.getAudience().get(0), "coretech");
            assertEquals(ztsImpl.ztsOAuthIssuer, claimSet.getIssuer());
            List<String> scopes = claimSet.getStringListClaim("scp");
            assertNotNull(scopes);
            assertEquals(scopes.size(), 1);
            assertEquals(scopes.get(0), "writers");
        } catch (ParseException ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    public void testPostAccessTokenRequestNotImplemented() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // not yet implemented

        try {
            ztsImpl.postAccessTokenRequest(context,
                    "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
                    + "&requested_token_type=urn:ietf:params:oauth:token-type:id-jag"
                    + "&audience=sports&subject_token=token123"
                    + "&subject_token_type=urn:ietf:params:oauth:token-type:id_token");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Not yet implemented"));
        }
    }
}
