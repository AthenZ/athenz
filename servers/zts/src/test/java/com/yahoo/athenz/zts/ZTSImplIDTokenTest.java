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
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.impl.CertificateAuthority;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.token.AccessTokenScope;
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

import java.io.File;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.testng.Assert.*;

public class ZTSImplIDTokenTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

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
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS, "screwdriver,rbac.*");
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
        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://athenz.io:4443/zts/v1");

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "true");

        store = new DataStore(structStore, cloudStore, ztsMetric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        AccessTokenScope.setSupportOpenIdScope(true);
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
    }

    private ConfigurableJWTProcessor<SecurityContext> createIDTokenProcessor() {
        final String jwksUri = Objects.requireNonNull(classLoader.getResource("jwt_jwks.json")).toString();
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(jwksUri, null, null, true);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSTypeVerifier(JwtsHelper.JWT_TYPE_VERIFIER);
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JwtsHelper.JWS_SUPPORTED_ALGORITHMS,
                resolver.getKeySource()));
        return jwtProcessor;
    }

    private ServerPrivateKey getServerPrivateKey(ZTSImpl ztsImpl, final String keyType) {
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
        service.setClientId("client-id-001");
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

    private String createIdToken(PrivateKey privateKey, String keyId, String subject,
            String audience, long expiryTime) {
        return createIdToken(privateKey, keyId, subject, audience, expiryTime, null);
    }

    private String createIdToken(PrivateKey privateKey, String keyId, String subject,
            String audience, long expiryTime, String issuer) {
        return createIdToken(privateKey, keyId, subject, audience, expiryTime, issuer, null);
    }

    private String createIdToken(PrivateKey privateKey, String keyId, String subject,
            String audience, long expiryTime, String issuer, String spiffe) {
        try {
            JWSSigner signer = JwtsHelper.getJWSSigner(privateKey);
            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issueTime(Date.from(Instant.ofEpochSecond(now)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(expiryTime)))
                    .issuer(issuer != null ? issuer : "https://athenz.io:4443/zts/v1")
                    .audience(audience)
                    .claim("ver", 1)
                    .claim("auth_time", now);
            if (spiffe != null) {
                builder.claim("spiffe", spiffe);
            }
            JWTClaimsSet claimsSet = builder.build();
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(keyId)
                            .build(),
                    claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception ex) {
            fail("Failed to create ID token: " + ex.getMessage());
            return null;
        }
    }

    private String createIdTokenNoSubject(PrivateKey privateKey, String keyId,
            String audience, long expiryTime) {
        try {
            JWSSigner signer = JwtsHelper.getJWSSigner(privateKey);
            long now = System.currentTimeMillis() / 1000;
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issueTime(Date.from(Instant.ofEpochSecond(now)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(expiryTime)))
                    .issuer("https://athenz.io:4443/zts/v1")
                    .audience(audience)
                    .claim("ver", 1)
                    .claim("auth_time", now)
                    .build();
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(keyId)
                            .build(),
                    claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (Exception ex) {
            fail("Failed to create ID token: " + ex.getMessage());
            return null;
        }
    }

    private void addIdTokenExchangePolicy(String domainName, String principalName, String roleName) {
        DataCache data = store.getDataCache(domainName);
        if (data == null) {
            return;
        }

        DomainData domainData = data.getDomainData();

        final String exchangerRoleName = generateRoleName(domainName, "id_token_exchanger_" + roleName);

        // create a role for the principal allowed to request id token exchanges

        Role principalRole = new Role();
        principalRole.setName(exchangerRoleName);
        List<RoleMember> principalMembers = new ArrayList<>();
        principalMembers.add(new RoleMember().setMemberName(principalName));
        principalRole.setRoleMembers(principalMembers);

        // Add role to domain if it doesn't exist
        List<Role> roles = new ArrayList<>(domainData.getRoles());
        boolean roleExists = roles.stream().anyMatch(r -> r.getName().equals(principalRole.getName()));
        if (!roleExists) {
            roles.add(principalRole);
            domainData.setRoles(roles);
        }

        Policy idTokenPolicy = new Policy();
        idTokenPolicy.setName(generatePolicyName(domainName, "id_token_exchange_" + roleName));

        Assertion assertion = new Assertion();
        assertion.setRole(exchangerRoleName);
        assertion.setResource(domainName + ":role." + roleName);
        assertion.setAction(ZTSConsts.ZTS_ACTION_ID_TOKEN_EXCHANGE);
        assertion.setEffect(com.yahoo.athenz.zms.AssertionEffect.ALLOW);

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        idTokenPolicy.setAssertions(assertions);

        SignedPolicies signedPolicies = domainData.getPolicies();
        DomainPolicies domainPolicies = signedPolicies.getContents();
        List<Policy> policies = new ArrayList<>(domainPolicies.getPolicies());
        policies.add(idTokenPolicy);
        domainPolicies.setPolicies(policies);

        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));

        domainData.setPolicies(signedPolicies);

        store.processSignedDomain(new SignedDomain()
                .setDomain(domainData)
                .setSignature(Crypto.sign(SignUtils.asCanonicalString(domainData), privateKey))
                .setKeyId("0"), false);

        Policy principalPolicy = new Policy();
        principalPolicy.setName(generatePolicyName(domainName, "id_token_exchange_principal_" + roleName));

        Assertion principalAssertion = new Assertion();
        principalAssertion.setRole(exchangerRoleName);
        principalAssertion.setResource(domainName + ":principal.*");
        principalAssertion.setAction(ZTSConsts.ZTS_ACTION_ID_TOKEN_EXCHANGE);
        principalAssertion.setEffect(com.yahoo.athenz.zms.AssertionEffect.ALLOW);

        List<Assertion> principalAssertions = new ArrayList<>();
        principalAssertions.add(principalAssertion);
        principalPolicy.setAssertions(principalAssertions);

        policies.add(principalPolicy);
        domainPolicies.setPolicies(policies);

        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));

        domainData.setPolicies(signedPolicies);

        store.processSignedDomain(new SignedDomain()
                .setDomain(domainData)
                .setSignature(Crypto.sign(SignUtils.asCanonicalString(domainData), privateKey))
                .setKeyId("0"), false);
    }

    private String buildIdTokenExchangeRequest(String subjectToken, String audience) {
        return buildIdTokenExchangeRequest(subjectToken, audience, null);
    }

    private String buildIdTokenExchangeRequest(String subjectToken, String audience, String scope) {
        StringBuilder sb = new StringBuilder();
        sb.append("grant_type=urn:ietf:params:oauth:grant-type:token-exchange");
        sb.append("&requested_token_type=urn:ietf:params:oauth:token-type:id_token");
        sb.append("&subject_token=").append(subjectToken);
        sb.append("&subject_token_type=urn:ietf:params:oauth:token-type:id_token");
        sb.append("&audience=").append(audience);
        if (scope != null) {
            if (!scope.contains("openid")) {
                sb.append("&scope=openid ").append(scope);
            } else {
                sb.append("&scope=").append(scope);
            }
        } else {
            sb.append("&scope=openid");
        }
        return sb.toString();
    }

    private ZTSImpl createZtsImpl() {
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        CloudStore cs = new CloudStore();
        ZTSImpl ztsImpl = new ZTSImpl(cs, store);
        ztsImpl.tokenConfigOptions.setJwtIDTProcessor(createIDTokenProcessor());
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        return ztsImpl;
    }

    private PrivateKey loadECPrivateKey() {
        return Crypto.loadPrivateKey(new File("./src/test/resources/unit_test_zts_private_ec.pem"));
    }

    // ========================
    // Test: Success - basic id token exchange
    // ========================

    @Test
    public void testIdTokenExchangeSuccess() throws JOSEException {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);
        assertTrue(response.getExpires_in() > 0);
        assertNull(response.getAccess_token());

        ServerPrivateKey serverPrivateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(serverPrivateKey.getKey()));

        try {
            SignedJWT signedJWT = SignedJWT.parse(response.getId_token());
            assertTrue(signedJWT.verify(verifier));
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();

            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech.storage");
            assertNotNull(claimSet.getClaim("nonce"));
            assertNotNull(claimSet.getIssueTime());
            assertNotNull(claimSet.getClaim("auth_time"));
            assertTrue(claimSet.getExpirationTime().getTime() > System.currentTimeMillis());

            List<String> groups = claimSet.getStringListClaim("groups");
            assertNotNull(groups);
            assertTrue(groups.contains("coretech:role.writers"));
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        ztsImpl.cloudStore.close();
    }

    @Test
    public void testIdTokenExchangeSuccessWithSpiffeClaim() throws JOSEException {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        final String spiffeId = "spiffe://athenz.io/ns/default/sa/coretech.weather";
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime, null, spiffeId);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);
        assertTrue(response.getExpires_in() > 0);
        assertNull(response.getAccess_token());

        ServerPrivateKey serverPrivateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(serverPrivateKey.getKey()));

        try {
            SignedJWT signedJWT = SignedJWT.parse(response.getId_token());
            assertTrue(signedJWT.verify(verifier));
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();

            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech.storage");
            assertNotNull(claimSet.getClaim("nonce"));
            assertNotNull(claimSet.getIssueTime());
            assertNotNull(claimSet.getClaim("auth_time"));
            assertTrue(claimSet.getExpirationTime().getTime() > System.currentTimeMillis());
            assertEquals(claimSet.getStringClaim("spiffe"), spiffeId);

            List<String> groups = claimSet.getStringListClaim("groups");
            assertNotNull(groups);
            assertTrue(groups.contains("coretech:role.writers"));
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Success - multiple roles in scope
    // ========================

    @Test
    public void testIdTokenExchangeSuccessMultipleRoles() throws JOSEException {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");
        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "readers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user1",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers coretech:role.readers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);

        ServerPrivateKey serverPrivateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(serverPrivateKey.getKey()));

        try {
            SignedJWT signedJWT = SignedJWT.parse(response.getId_token());
            assertTrue(signedJWT.verify(verifier));
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();

            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.user1");
            List<String> groups = claimSet.getStringListClaim("groups");
            assertNotNull(groups);
            assertTrue(groups.size() >= 2);
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Success - no scope (domain-level roles)
    // ========================

    @Test
    public void testIdTokenExchangeSuccessNoScope() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - authorized service principal
    // ========================

    @Test
    public void testIdTokenExchangeAuthorizedServicePrincipal() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        principal.setAuthorizedService("coretech.storage");
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Authorized service principal forbidden for id token exchange"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - role identity principal
    // ========================

    @Test
    public void testIdTokenExchangeRoleIdentityPrincipal() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, new CertificateAuthority());
        List<String> roles = new ArrayList<>();
        roles.add("coretech:role.readers");
        principal.setRoles(roles);

        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Role Identity not authorized"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - invalid audience (null domain from audience)
    // ========================

    @Test
    public void testIdTokenExchangeInvalidAudience() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "invalid-no-domain");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid client id"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - domain not found
    // ========================

    @Test
    public void testIdTokenExchangeDomainNotFound() {

        ZTSImpl ztsImpl = createZtsImpl();

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "nonexistent.service",
                "nonexistent:role.admin");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("No such domain"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - subject token audience doesn't match principal, no client id
    // ========================

    @Test
    public void testIdTokenExchangeSubjectTokenAudienceMismatchNoClientId() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "wrong.audience", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid subject token audience"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Success - subject token audience matches via client-id
    // ========================

    @Test
    public void testIdTokenExchangeSubjectTokenAudienceMatchViaClientId() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "coretech.backup", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "client-id-001", expiryTime);

        Principal principal = SimplePrincipal.create("coretech", "backup",
                "v=U1;d=coretech;n=backup;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - subject token audience doesn't match principal and client-id doesn't match
    // ========================

    @Test
    public void testIdTokenExchangeSubjectTokenAudienceMismatchClientIdNoMatch() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "wrong-client-id", expiryTime);

        Principal principal = SimplePrincipal.create("coretech", "backup",
                "v=U1;d=coretech;n=backup;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid subject token audience"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - empty subject identity (no subject in token, no provider)
    // ========================

    @Test
    public void testIdTokenExchangeEmptySubjectIdentity() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdTokenNoSubject(ecPrivateKey, "0",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid subject token - missing subject"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - principal not authorized for id token exchange
    // ========================

    @Test
    public void testIdTokenExchangePrincipalNotAuthorized() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Principal not authorized for id token exchange"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - subject not authorized for requested role
    // ========================

    @Test
    public void testIdTokenExchangeSubjectNotAuthorizedForRole() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.nouser",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Success with external identity provider
    // ========================

    @Test
    public void testIdTokenExchangeWithExternalProvider() throws JOSEException {

        System.setProperty(ZTSConsts.ZTS_PROP_PROVIDER_CONFIG_FILE, "src/test/resources/provider.config.json");

        TokenExchangeIdentityProvider provider = new TokenExchangeIdentityProvider() {
            @Override
            public String getTokenIdentity(OAuth2Token token) {
                return "user_domain.user";
            }

            @Override
            public String getTokenAudience(OAuth2Token token) {
                return token.getAudience();
            }

            @Override
            public List<String> getTokenExchangeClaims() {
                return List.of();
            }
        };

        ZTSImpl ztsImpl = createZtsImpl();
        ztsImpl.providerConfigManager.putProvider("https://athenz.io:4443/zts/v1", provider);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "ext-user-001",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);

        ServerPrivateKey serverPrivateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(serverPrivateKey.getKey()));

        try {
            SignedJWT signedJWT = SignedJWT.parse(response.getId_token());
            assertTrue(signedJWT.verify(verifier));
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();
            assertEquals(claimSet.getSubject(), "user_domain.user");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_PROVIDER_CONFIG_FILE);
        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - external provider returns null identity
    // ========================

    @Test
    public void testIdTokenExchangeExternalProviderNullIdentity() {

        TokenExchangeIdentityProvider provider = new TokenExchangeIdentityProvider() {
            @Override
            public String getTokenIdentity(OAuth2Token token) {
                return null;
            }

            @Override
            public String getTokenAudience(OAuth2Token token) {
                return token.getAudience();
            }

            @Override
            public List<String> getTokenExchangeClaims() {
                return List.of();
            }
        };

        ZTSImpl ztsImpl = createZtsImpl();
        ztsImpl.providerConfigManager.putProvider("https://athenz.io:4443/zts/v1", provider);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "ext-user-001",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid subject token - missing subject"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - external provider audience check with client id
    // ========================

    @Test
    public void testIdTokenExchangeExternalProviderAudienceViaClientId() {

        TokenExchangeIdentityProvider provider = new TokenExchangeIdentityProvider() {
            @Override
            public String getTokenIdentity(OAuth2Token token) {
                return "user_domain.user";
            }

            @Override
            public String getTokenAudience(OAuth2Token token) {
                return "client-id-001";
            }

            @Override
            public List<String> getTokenExchangeClaims() {
                return List.of();
            }
        };

        ZTSImpl ztsImpl = createZtsImpl();
        ztsImpl.providerConfigManager.putProvider("https://athenz.io:4443/zts/v1", provider);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "coretech.backup", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "ext-user-001",
                "some-external-aud", expiryTime);

        Principal principal = SimplePrincipal.create("coretech", "backup",
                "v=U1;d=coretech;n=backup;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - external provider audience mismatch via client id
    // ========================

    @Test
    public void testIdTokenExchangeExternalProviderAudienceMismatch() {

        TokenExchangeIdentityProvider provider = new TokenExchangeIdentityProvider() {
            @Override
            public String getTokenIdentity(OAuth2Token token) {
                return "user_domain.user";
            }

            @Override
            public String getTokenAudience(OAuth2Token token) {
                return "wrong-client-id";
            }

            @Override
            public List<String> getTokenExchangeClaims() {
                return List.of();
            }
        };

        ZTSImpl ztsImpl = createZtsImpl();
        ztsImpl.providerConfigManager.putProvider("https://athenz.io:4443/zts/v1", provider);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "ext-user-001",
                "some-external-aud", expiryTime);

        Principal principal = SimplePrincipal.create("coretech", "backup",
                "v=U1;d=coretech;n=backup;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid subject token audience"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - subject not member of any requested role (empty roles returned)
    // ========================

    @Test
    public void testIdTokenExchangeSubjectNoRoleMembership() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.unknownuser",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getCode() == ResourceException.FORBIDDEN || ex.getCode() == ResourceException.BAD_REQUEST);
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Failure - subject authorized for principal check but not for role-level check
    // ========================

    @Test
    public void testIdTokenExchangeSubjectNotAuthorizedForRoleExchange() {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        // only set up principal policy but NOT the role-level policy
        DataCache data = store.getDataCache("coretech");
        assertNotNull(data);
        DomainData domainData = data.getDomainData();

        // add a policy that allows the principal to do id_token_exchange at the principal level
        Role principalRole = new Role();
        principalRole.setName(generateRoleName("coretech", "id_token_exchanger_writers"));
        List<RoleMember> principalMembers = new ArrayList<>();
        principalMembers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        principalRole.setRoleMembers(principalMembers);

        List<Role> roles = new ArrayList<>(domainData.getRoles());
        roles.add(principalRole);
        domainData.setRoles(roles);

        Policy principalPolicy = new Policy();
        principalPolicy.setName(generatePolicyName("coretech", "id_token_exchange_principal_writers"));

        Assertion principalAssertion = new Assertion();
        principalAssertion.setRole(generateRoleName("coretech", "id_token_exchanger_writers"));
        principalAssertion.setResource("coretech:principal.*");
        principalAssertion.setAction(ZTSConsts.ZTS_ACTION_ID_TOKEN_EXCHANGE);
        principalAssertion.setEffect(com.yahoo.athenz.zms.AssertionEffect.ALLOW);

        principalPolicy.setAssertions(List.of(principalAssertion));

        SignedPolicies signedPolicies = domainData.getPolicies();
        DomainPolicies domainPolicies = signedPolicies.getContents();
        List<Policy> policies = new ArrayList<>(domainPolicies.getPolicies());
        policies.add(principalPolicy);
        domainPolicies.setPolicies(policies);

        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        domainData.setPolicies(signedPolicies);

        store.processSignedDomain(new SignedDomain()
                .setDomain(domainData)
                .setSignature(Crypto.sign(SignUtils.asCanonicalString(domainData), privateKey))
                .setKeyId("0"), false);

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Principal not authorized for token exchange for the requested role"));
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Success - audience matches principal name directly
    // ========================

    @Test
    public void testIdTokenExchangeAudienceMatchesPrincipal() throws JOSEException {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "coretech.storage", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "coretech.storage", expiryTime);

        Principal principal = SimplePrincipal.create("coretech", "storage",
                "v=U1;d=coretech;n=storage;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertEquals(response.getToken_type(), "Bearer");
        assertEquals(response.getIssued_token_type(), ZTSConsts.OAUTH_TOKEN_TYPE_ID);

        ServerPrivateKey serverPrivateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(serverPrivateKey.getKey()));

        try {
            SignedJWT signedJWT = SignedJWT.parse(response.getId_token());
            assertTrue(signedJWT.verify(verifier));
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();

            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech.storage");
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Empty request body
    // ========================

    @Test
    public void testIdTokenExchangeEmptyRequestBody() {

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postAccessTokenRequest(context, "");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Empty request body"));
        }
    }

    // ========================
    // Test: Null request body
    // ========================

    @Test
    public void testIdTokenExchangeNullRequestBody() {

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postAccessTokenRequest(context, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Empty request body"));
        }
    }

    // ========================
    // Test: Unauthenticated request (null principal)
    // ========================

    @Test
    public void testIdTokenExchangeNullPrincipal() {

        ZTSImpl ztsImpl = createZtsImpl();

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        ResourceContext context = createResourceContext(null);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        try {
            ztsImpl.postAccessTokenRequest(context, tokenRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.UNAUTHORIZED);
        }

        ztsImpl.cloudStore.close();
    }

    // ========================
    // Test: Success - verify id token claims in detail
    // ========================

    @Test
    public void testIdTokenExchangeVerifyDetailedClaims() throws JOSEException {

        ZTSImpl ztsImpl = createZtsImpl();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        addIdTokenExchangePolicy("coretech", "user_domain.proxy-user1", "writers");

        PrivateKey ecPrivateKey = loadECPrivateKey();
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        String subjectToken = createIdToken(ecPrivateKey, "0", "user_domain.user",
                "user_domain.proxy-user1", expiryTime);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        String tokenRequest = buildIdTokenExchangeRequest(subjectToken, "coretech.storage",
                "coretech:role.writers");

        AccessTokenResponse response = ztsImpl.postAccessTokenRequest(context, tokenRequest);

        assertNotNull(response);
        assertNotNull(response.getId_token());
        assertNull(response.getAccess_token());

        ServerPrivateKey serverPrivateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = JwtsHelper.getJWSVerifier(Crypto.extractPublicKey(serverPrivateKey.getKey()));

        try {
            SignedJWT signedJWT = SignedJWT.parse(response.getId_token());
            assertTrue(signedJWT.verify(verifier));
            JWTClaimsSet claimSet = signedJWT.getJWTClaimsSet();

            assertNotNull(claimSet);
            assertEquals(claimSet.getSubject(), "user_domain.user");
            assertEquals(claimSet.getAudience().get(0), "coretech.storage");
            assertEquals(claimSet.getIssuer(), ztsImpl.ztsOpenIDIssuer);
            assertNotNull(claimSet.getClaim("nonce"));
            assertNotNull(claimSet.getIssueTime());
            assertNotNull(claimSet.getClaim("auth_time"));
            assertNotNull(claimSet.getExpirationTime());
            assertEquals(claimSet.getIntegerClaim("ver").intValue(), 1);

            List<String> groups = claimSet.getStringListClaim("groups");
            assertNotNull(groups);
            assertTrue(groups.contains("coretech:role.writers"));
        } catch (Exception ex) {
            fail(ex.getMessage());
        }

        ztsImpl.cloudStore.close();
    }
}
