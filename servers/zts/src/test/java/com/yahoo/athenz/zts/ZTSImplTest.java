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
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.impl.*;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AuthzDetailsEntity;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.cert.Priority;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.store.impl.ZMSFileChangeLogStore;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.ZTSAuthorizer.AccessStatus;
import com.yahoo.athenz.zts.ZTSImpl.AthenzObject;
import com.yahoo.athenz.zts.ZTSImpl.ServiceX509RefreshRequestStatus;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cache.DataCacheTest;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.cert.X509CertRequest;
import com.yahoo.athenz.zts.cert.X509RoleCertRequest;
import com.yahoo.athenz.zts.cert.X509ServiceCertRequest;
import com.yahoo.athenz.zts.external.gcp.GcpAccessTokenProvider;
import com.yahoo.athenz.zts.external.gcp.GcpAccessTokenProviderTest;
import com.yahoo.athenz.zts.status.MockStatusCheckerNoException;
import com.yahoo.athenz.zts.status.MockStatusCheckerThrowException;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockCloudStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.token.AccessTokenRequest;
import com.yahoo.athenz.zts.token.IdTokenRequest;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.ServletContext;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.Response;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItems;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ZTSImplTest {

    private int roleTokenDefaultTimeout = 2400;
    private int roleTokenMaxTimeout = 96000;

    private ZTSImpl zts = null;
    private Metric ztsMetric = null;
    private ZTSAuthorizer authorizer = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    private CloudStore cloudStore = null;
    @Mock private CloudStore mockCloudStore;

    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String ZTS_Y64_CERT0 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84a"
            + "EtFVWZTU2dwWHIzQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbE"
            + "dVT0VnMmpzbWRha1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY"
            + "0cmJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT0 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1tGSVCA8wl5ew5Y76Wj2rJAUD\n"
            + "YanEJfKmAlx5cQ/8hKEUfSSgpXr3Czdh1a26dlb7mmK29qmXJXh6umW9AyfTOKVo\n"
            + "+6ASloVU3avvuflGUOEg2jsmdakR24KcLjAu6QrUe417lG3t8qSPIGjS5C+CsJUw\n"
            + "h04hHx5f+PEwxV4rbQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private final static String ROLE_CERT_DB_REQUEST =
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIBujCCASMCAQAwOzELMAkGA1UEBhMCVVMxDjAMBgNVBAoTBVlhaG9vMRwwGgYD\n"
            + "VQQDExNzcG9ydHM6cm9sZS5yZWFkZXJzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
            + "iQKBgQCu0nOEra8WmmU91u2KrDdcKRDcZn3oSwsZD/55d0bkMwEiMzfQ+xHVRFI1\n"
            + "PPGjhG167oRhTRKE3a3uakMGmMDM5WWcDLbLo+PHZGqUyhJrvq5BF4VWrUWpY+rp\n"
            + "paklBTUPY0asmlObVpFBVoujkSyxMIXmOi9qK/O+Bs0BI4jo6QIDAQABoD8wPQYJ\n"
            + "KoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjgiFhcGkuY29yZXRlY2gtdGVzdC5hd3Mu\n"
            + "eWFob28uY2xvdWQwDQYJKoZIhvcNAQELBQADgYEAQSEWI7eRM5Xv0oENQ+zzdoQI\n"
            + "MgzgsXRKGxlZFBpHNvT1R/4pkrU2XdpU1sQP8nrs3Xl+jUd70Ke7K1b2qL6D9op8\n"
            + "eE/qKXv+mcEBGlSCaJtK9MBUnOh4TVZ3EePxbc41Ha2/zWn+J3RFBMz9i1Nxy+Nq\n"
            + "s1K+2Aj6SbErxrEunNI=\n"
            + "-----END CERTIFICATE REQUEST-----\n";
    private final static String ROLE_CERT_CORETECH_REQUEST =
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIBXzCCAQkCAQAwZDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ8wDQYDVQQK\n"
            + "EwZBdGhlbnoxFzAVBgNVBAsTDlRlc3RpbmcgRG9tYWluMR4wHAYDVQQDExVjb3Jl\n"
            + "dGVjaDpyb2xlLnJlYWRlcnMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAn70OSBIw\n"
            + "2Pqht+LT8fa+eqxpAv/T7jVPFmy61dHa+o7e1aLl0m19lJIQu/15YfUo8+XY83fT\n"
            + "QOVHACUQa82PvwIDAQABoEAwPgYJKoZIhvcNAQkOMTEwLzAtBgNVHREEJjAkgSJ1\n"
            + "c2VyX2RvbWFpbi51c2VyMUB6dHMuYXRoZW56LmNsb3VkMA0GCSqGSIb3DQEBCwUA\n"
            + "A0EAfxmNOBAUUBjtmfH4ytJ1FrL8cuADVeQnJb7pX4ZJyNjFbdRwklmRMQgtY7As\n"
            + "zs7g629IN4L2xC1zopG4NcNEdw=="
            + "\n-----END CERTIFICATE REQUEST-----\n";

    private static final String MOCKCLIENTADDR = "10.11.12.13";
    @Mock private HttpServletRequest  mockServletRequest;
    @Mock private HttpServletResponse mockServletResponse;
    @Mock private ServletContext mockServletContext;

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

        roleTokenDefaultTimeout = 2400;
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT,
                Integer.toString(roleTokenDefaultTimeout));

        roleTokenMaxTimeout = 96000;
        System.setProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT,
                Integer.toString(roleTokenMaxTimeout));

        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS,
                "user_domain.proxy-user1,user_domain.proxy-user2");

        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");

        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/unit_test_private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_IDENTITY, "false");

        // enable ip validation for cert requests

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "true");

        store = new DataStore(structStore, cloudStore, ztsMetric);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        authorizer = new ZTSAuthorizer(store);

        // enable openid scope

        AccessTokenRequest.setSupportOpenIdScope(true);
    }

    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
    }

    private ResourceContext createResourceContext(Principal principal) {
        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
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

    private ResourceContext createResourceContext(Principal principal, HttpServletRequest request) {
        if (request == null) {
            return createResourceContext(principal);
        }

        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(request);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(request);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        return rsrcCtxWrapper;
    }

    private Metric getMetric(){
        com.yahoo.athenz.common.metrics.MetricFactory metricFactory;
        com.yahoo.athenz.common.metrics.Metric metric;
        try {
            metricFactory = (com.yahoo.athenz.common.metrics.MetricFactory)
                Class.forName(System.getProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS)).newInstance();
            metric = metricFactory.create();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException exc) {
            System.out.println("Invalid MetricFactory class: " + METRIC_DEFAULT_FACTORY_CLASS
                    + " error: " + exc.getMessage());
            metric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        }
        return metric;
    }

    private String generateRoleName(String domain, String role) {
        return domain + ":role." + role;
    }

    private String generateGroupName(String domain, String group) {
        return domain + ":group." + group;
    }

    private String generatePolicyName(String domain, String policy) {
        return domain + ":policy." + policy;
    }

    private String generateServiceIdentityName(String domain, String service) {
        return domain + "." + service;
    }

    private SignedDomain createSignedDomain(String domainName, String tenantDomain,
            String serviceName, boolean includeServices) {
        return createSignedDomain(domainName, tenantDomain, serviceName, includeServices, null);
    }

    private SignedDomain createSignedDomain(String domainName, String tenantDomain,
            String serviceName, boolean includeServices, List<Group> groups) {

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.user"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.user3"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        return createSignedDomain(domainName, tenantDomain, serviceName, writers,
                readers, includeServices, groups);
    }

    private SignedDomain createSignedDomain(String domainName, String tenantDomain,
            String serviceName, List<RoleMember> writers, List<RoleMember> readers,
            boolean includeServices) {
        return createSignedDomain(domainName, tenantDomain, serviceName, writers, readers, includeServices, null);
    }

    private SignedDomain createSignedDomain(String domainName, String tenantDomain,
            String serviceName, List<RoleMember> writers, List<RoleMember> readers,
            boolean includeServices, List<Group> groups) {

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

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":tenant." + tenantDomain + ".*");
        assertion.setAction("read");
        assertion.setRole(generateRoleName(domainName, "tenant.readers"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "tenant.reader"));
        policies.add(policy);

        // tenant admin domain

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":service." + serviceName + ".tenant." + tenantDomain + ".*");
        assertion.setAction("read");
        assertion.setRole(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain + ".admin"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, serviceName + ".tenant." + tenantDomain + ".admin"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setGroups(groups);
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
        return services;
    }

    private SignedDomain createSignedDomainExpiration(String domainName, String serviceName) {
        return createSignedDomainExpiration(domainName, serviceName, null);
    }

    private SignedDomain createSignedDomainExpiration(String domainName, String serviceName,
            Boolean enabled) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();
        String memberName = "user_domain.user1";
        Role role = new Role();
        role.setName(generateRoleName(domainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName("user_domain.adminuser");
        members.add(roleMember);
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "role1"));
        members = new ArrayList<>();
        roleMember = new RoleMember();
        roleMember.setMemberName(memberName);
        roleMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 100));
        members.add(roleMember);
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "role2"));
        members = new ArrayList<>();
        roleMember = new RoleMember();
        roleMember.setMemberName(memberName);
        roleMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1)));
        members.add(roleMember);
        role.setRoleMembers(members);
        roles.add(role);

        List<ServiceIdentity> services = new ArrayList<>();

        ServiceIdentity service = new ServiceIdentity();
        service.setName(generateServiceIdentityName(domainName, serviceName));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        services.add(service);

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setModified(Timestamp.fromCurrentTime());
        domain.setEnabled(enabled);

        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private SignedDomain createMultipleSignedDomains(String domainName, String tenantDomain1,
            String tenantDomain2, String serviceName, boolean includeServices) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain1 + ".admin"));
        role.setTrust(tenantDomain1);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain2 + ".admin"));
        role.setTrust(tenantDomain2);
        roles.add(role);

        List<ServiceIdentity> services = new ArrayList<>();

        if (includeServices) {

            ServiceIdentity service = new ServiceIdentity();
            service.setName(generateServiceIdentityName(domainName, serviceName));
            setServicePublicKey(service, "0", ZTS_Y64_CERT0);

            List<String> hosts = new ArrayList<>();
            hosts.add("host1");
            hosts.add("host2");
            service.setHosts(hosts);
            services.add(service);
        }

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        // tenant admin domain

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":service." + serviceName + ".tenant." + tenantDomain1 + ".*");
        assertion.setAction("read");
        assertion.setRole(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain1 + ".admin"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, serviceName + ".tenant." + tenantDomain1 + ".admin"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":service." + serviceName + ".tenant." + tenantDomain2 + ".*");
        assertion.setAction("read");
        assertion.setRole(generateRoleName(domainName, serviceName + ".tenant." + tenantDomain2 + ".admin"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, serviceName + ".tenant." + tenantDomain2 + ".admin"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private SignedDomain createTenantSignedDomain(String domainName, String providerDomain, String providerService) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "tenancy." + providerDomain + "." + providerService + ".admin"));
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user100"));
        members.add(new RoleMember().setMemberName("user_domain.user101"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "readers"));
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user100"));
        members.add(new RoleMember().setMemberName("user_domain.user101"));
        role.setRoleMembers(members);
        roles.add(role);

        ServiceIdentity service = new ServiceIdentity();
        service.setName(domainName + ".storage");
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);

        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(generateRoleName(providerDomain, "tenant.readers"));
        assertion.setAction("assume_role");
        assertion.setRole(generateRoleName(domainName, "readers"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "tenancy.readers"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(generateRoleName(providerDomain, providerService + ".tenant." + domainName + ".admin"));
        assertion.setAction("assume_role");
        assertion.setRole(generateRoleName(domainName, "tenancy." + providerDomain + "." + providerService + ".admin"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "tenancy." + providerDomain + "." + providerService + ".admin"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);

        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private SignedDomain createSignedDomainWildCard(String domainName, String tenantDomain) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "superusers"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.admin_user"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "users"));
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "netops_superusers"));
        role.setTrust(tenantDomain);
        roles.add(role);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":node.*");
        assertion.setAction("node_user");
        assertion.setRole(generateRoleName(domainName, "users"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "users"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":node.*");
        assertion.setAction("node_sudo");
        assertion.setRole(generateRoleName(domainName, "netops_superusers"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "netops_superusers"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":node.*");
        assertion.setAction("node_user");
        assertion.setRole(generateRoleName(domainName, "superusers"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "superusers"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private SignedDomain createTenantSignedDomainWildCard(String domainName) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "superusers"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.siteops_user_1"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "users"));
        roles.add(role);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("*:role.netops_superusers");
        assertion.setAction("assume_role");
        assertion.setRole(generateRoleName(domainName, "superusers"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "netops_superusers"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + "netops:node.*");
        assertion.setAction("node_user");
        assertion.setRole(generateRoleName(domainName, "users"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "users"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + "netops:node.*");
        assertion.setAction("node_sudo");
        assertion.setRole(generateRoleName(domainName, "superusers"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "superusers"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setPolicies(signedPolicies);

        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private SignedDomain createAwsSignedDomain(String domainName, String account) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(domainName, "aws_role"));
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user100"));
        members.add(new RoleMember().setMemberName("user_domain.user101"));
        role.setRoleMembers(members);
        roles.add(role);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":aws_role_name");
        assertion.setAction("assume_aws_role");
        assertion.setRole(generateRoleName(domainName, "aws_role"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "aws_policy"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setAccount(account);
        domain.setRoles(roles);
        domain.setPolicies(signedPolicies);

        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private void setServicePublicKey(ServiceIdentity service, String id, String key) {
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry.setId(id);
        keyEntry.setKey(key);
        List<com.yahoo.athenz.zms.PublicKeyEntry> listKeys = new ArrayList<>();
        listKeys.add(keyEntry);
        service.setPublicKeys(listKeys);
    }

    private void setServicePublicKey(com.yahoo.athenz.zts.ServiceIdentity service, String id, String key) {
        com.yahoo.athenz.zts.PublicKeyEntry keyEntry = new com.yahoo.athenz.zts.PublicKeyEntry();
        keyEntry.setId(id);
        keyEntry.setKey(key);
        List<com.yahoo.athenz.zts.PublicKeyEntry> listKeys = new ArrayList<>();
        listKeys.add(keyEntry);
        service.setPublicKeys(listKeys);
    }

    @Test
    public void testGetPublicKeyNotExistent() {

        String domain = "unknown";
        String service = "unknown";

        String pubKey = zts.getPublicKey(domain, service, "0");
        assertNull(pubKey);

        pubKey = zts.getPublicKey(null, service, "0");
        assertNull(pubKey);

        pubKey = zts.getPublicKey(domain, null, "0");
        assertNull(pubKey);
    }

    @Test
    public void testGetPublicKey() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        String pubKey = zts.getPublicKey("coretech", "storage", "0");
        assertEquals(pubKey, ZTS_PEM_CERT0);

        pubKey = zts.getPublicKey("coretech", "storage", "100");
        assertNull(pubKey);
    }

    @Test
    public void testEvaluateAccessNoAssertions() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role = new Role().setName("coretech:role.role1");
        domainData.getRoles().add(role);
        Policy policy = new Policy().setName("coretech:policy.policy1");
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        assertEquals(authorizer.evaluateAccess(domain, null, null, null, null), AccessStatus.DENIED);
    }

    @Test
    public void testEvaluateAccessAssertionDeny() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role = ZTSTestUtils.createRoleObject("coretech", "role1", "user_domain.user1");
        domainData.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.DENY);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<>());
        policy.getAssertions().add(assertion);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);

        assertEquals(authorizer.evaluateAccess(domain, "user_domain.user1", "read", "coretech:resource1", null), AccessStatus.DENIED);
    }

    @Test
    public void testEvaluateAccessAssertionDenyCaseSensitive() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role = ZTSTestUtils.createRoleObject("coretech", "role1", "user_domain.user1");
        domainData.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("ReaD");
        assertion.setEffect(AssertionEffect.DENY);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<>());
        policy.getAssertions().add(assertion);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);

        ZTSAuthorizer spiedZtsAuthorizer = Mockito.spy(authorizer);
        AccessStatus result = spiedZtsAuthorizer.evaluateAccess(domain, "user_domain.user1", "read", "coretech:resource1", null);
        assertEquals(result, AccessStatus.DENIED);

        // Verify that it was denied by explicit "Deny" assertion and not because no match was found
        Mockito.verify(spiedZtsAuthorizer, times(1)).matchPrincipal(
                eq(domainData.getRoles()),
                eq("^coretech:role\\.role1$"),
                eq("user_domain.user1"),
                eq(null));
    }

    @Test
    public void testEvaluateAccessAssertionAllow() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role = ZTSTestUtils.createRoleObject("coretech", "role1", "user_domain.user1");
        domainData.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion1 = new Assertion();
        assertion1.setAction("read");
        assertion1.setEffect(AssertionEffect.ALLOW);
        assertion1.setResource("coretech:*");
        assertion1.setRole("coretech:role.role1");
        Assertion assertion2 = new Assertion();
        assertion2.setAction("read");
        assertion2.setEffect(AssertionEffect.ALLOW);
        assertion2.setResource("coretech:resource1");
        assertion2.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<>());
        policy.getAssertions().add(assertion1);
        policy.getAssertions().add(assertion2);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);

        assertEquals(authorizer.evaluateAccess(domain, "user_domain.user1", "read", "coretech:resource1", null), AccessStatus.ALLOWED);

        // we're going to mark the policy as inactive in which case
        // our access will return denied

        policy.setActive(false);
        assertEquals(authorizer.evaluateAccess(domain, "user_domain.user1", "read", "coretech:resource1", null), AccessStatus.DENIED);
    }

    @Test
    public void testEvaluateAccessAssertionAllowCaseSensitive() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role = ZTSTestUtils.createRoleObject("coretech", "role1", "user_domain.user1");
        domainData.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion1 = new Assertion();
        assertion1.setAction("ReaD");
        assertion1.setEffect(AssertionEffect.ALLOW);
        assertion1.setResource("coretech:*");
        assertion1.setRole("coretech:role.role1");
        Assertion assertion2 = new Assertion();
        assertion2.setAction("ReaD");
        assertion2.setEffect(AssertionEffect.ALLOW);
        assertion2.setResource("coretech:ResourcE1");
        assertion2.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<>());
        policy.getAssertions().add(assertion1);
        policy.getAssertions().add(assertion2);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);

        assertEquals(authorizer.evaluateAccess(domain, "user_domain.user1", "read", "coretech:resource1", null), AccessStatus.ALLOWED);
    }

    @Test
    public void testGetHostServices() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        HostServices hosts = zts.getHostServices(context, "host1");
        assertEquals(1, hosts.getNames().size());
        assertTrue(hosts.getNames().contains("coretech.storage"));

        hosts = zts.getHostServices(context, "host2");
        assertEquals(2, hosts.getNames().size());
        assertTrue(hosts.getNames().contains("coretech.storage"));
        assertTrue(hosts.getNames().contains("coretech.backup"));

        hosts = zts.getHostServices(context, "host3");
        assertEquals(1, hosts.getNames().size());
        assertTrue(hosts.getNames().contains("coretech.backup"));
    }

    @Test
    public void testGetJWKList() {

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        JWKList list = zts.getJWKList(context, false);
        assertNotNull(list);
        List<JWK> keys = list.getKeys();
        assertEquals(keys.size(), 2);

        JWK key1 = keys.get(0);
        assertEquals(key1.getKty(), "RSA", key1.getKty());
        assertEquals(key1.getKid(), "0", key1.getKid());

        JWK key2 = keys.get(1);
        assertEquals(key2.getKty(), "EC", key2.getKty());
        assertEquals(key2.getKid(), "ec.0", key2.getKid());
        assertEquals(key2.getCrv(), "prime256v1", key2.getCrv());

        // execute the same test with argument passed as null
        // for the Boolean rfc object so it should be same result

        list = zts.getJWKList(context, null);
        assertNotNull(list);
        keys = list.getKeys();
        assertEquals(keys.size(), 2);

        key1 = keys.get(0);
        assertEquals(key1.getKty(), "RSA", key1.getKty());
        assertEquals(key1.getKid(), "0", key1.getKid());

        key2 = keys.get(1);
        assertEquals(key2.getKty(), "EC", key2.getKty());
        assertEquals(key2.getKid(), "ec.0", key2.getKid());
        assertEquals(key2.getCrv(), "prime256v1", key2.getCrv());

        // now let's try with rfc option on in which case
        // we'll get the curve name as P-256

        list = zts.getJWKList(context, true);
        assertNotNull(list);
        keys = list.getKeys();
        assertEquals(keys.size(), 2);

        key1 = keys.get(0);
        assertEquals(key1.getKty(), "RSA", key1.getKty());
        assertEquals(key1.getKid(), "0", key1.getKid());

        key2 = keys.get(1);
        assertEquals(key2.getKty(), "EC", key2.getKty());
        assertEquals(key2.getKid(), "ec.0", key2.getKid());
        assertEquals(key2.getCrv(), "P-256", key2.getCrv());
    }

    @Test
    public void testGetHostServicesInvalidHost() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        HostServices hosts = zts.getHostServices(context, "unknownHost");
        assertNull(hosts.getNames());
        }

    @Test
    public void testGetPolicyList() {

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("coretech:tenant.weather.*");
        assertion.setAction("read");
        assertion.setRole("coretech:role.readers");
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName("coretech:policy.reader");
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("coretech:tenant.weather.*");
        assertion.setAction("write");
        assertion.setRole("coretech:role.writers");
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName("coretech:policy.writer");
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain("coretech");
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain, null);
        assertEquals(policyList.size(), 2);
        assertEquals(policyList.get(0).getName(), "coretech:policy.reader");
        assertEquals(policyList.get(1).getName(), "coretech:policy.writer");
    }

    @Test
    public void testGetPolicyListInactive() {

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("coretech:tenant.weather.*");
        assertion.setAction("read");
        assertion.setRole("coretech:role.readers");
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName("coretech:policy.reader");
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("coretech:tenant.weather.*");
        assertion.setAction("write");
        assertion.setRole("coretech:role.writers");
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName("coretech:policy.writer");
        policy.setActive(false);
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain("coretech");
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain, null);
        assertEquals(policyList.size(), 1);
        assertEquals(policyList.get(0).getName(), "coretech:policy.reader");
    }

    @Test
    public void testGetPolicyListPoliciesNull() {

        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setPolicies(null);
        domain.setModified(Timestamp.fromCurrentTime());

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain, null);
        assertEquals(policyList.size(), 0);
    }

    @Test
    public void testGetPolicyListPoliciesEmpty() {

        DomainData domain = new DomainData();
        domain.setName("coretech");

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain("coretech");
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain, null);
        assertEquals(policyList.size(), 0);
    }

    @Test
    public void testGetPolicyListVersionFilter() {

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();

        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("coretech:tenant.weather.*").setAction("read").setRole("coretech:role.readers");
        assertions.add(assertion);

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        policy.setAssertions(assertions).setName("coretech:policy.reader").setVersion("0").setActive(true);
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        policy.setAssertions(assertions).setName("coretech:policy.reader").setVersion("1").setActive(false);
        policies.add(policy);

        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("coretech:tenant.weather.*").setAction("write").setRole("coretech:role.writers");
        assertions.add(assertion);

        policy = new com.yahoo.athenz.zms.Policy();
        policy.setAssertions(assertions).setName("coretech:policy.writer").setVersion("0").setActive(false);
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        policy.setAssertions(assertions).setName("coretech:policy.writer").setVersion("1").setActive(true);
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        policy.setAssertions(assertions).setName("coretech:policy.editor").setVersion("0").setActive(true);
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        policy.setAssertions(assertions).setName("coretech:policy.editor").setVersion("1").setActive(false);
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain("coretech");
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);

        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        // first only active versions

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain, Collections.emptyMap());
        assertEquals(policyList.size(), 3);
        assertEquals(policyList.get(0).getName(), "coretech:policy.reader");
        assertEquals(policyList.get(0).getVersion(), "0");
        assertEquals(policyList.get(1).getName(), "coretech:policy.writer");
        assertEquals(policyList.get(1).getVersion(), "1");
        assertEquals(policyList.get(2).getName(), "coretech:policy.editor");
        assertEquals(policyList.get(2).getVersion(), "0");

        // now ask for specific version for reader only

        Map<String, String> versions = new HashMap<>();
        versions.put("coretech:policy.reader", "1");

        policyList = zts.getPolicyList(domain, versions);
        assertEquals(policyList.size(), 3);
        assertEquals(policyList.get(0).getName(), "coretech:policy.reader");
        assertEquals(policyList.get(0).getVersion(), "1");
        assertEquals(policyList.get(1).getName(), "coretech:policy.writer");
        assertEquals(policyList.get(1).getVersion(), "1");
        assertEquals(policyList.get(2).getName(), "coretech:policy.editor");
        assertEquals(policyList.get(2).getVersion(), "0");

        // now ask for all versions

        versions.put("coretech:policy.writer", "1");
        versions.put("coretech:policy.editor", "1");
        policyList = zts.getPolicyList(domain, versions);
        assertEquals(policyList.size(), 3);
        assertEquals(policyList.get(0).getName(), "coretech:policy.reader");
        assertEquals(policyList.get(0).getVersion(), "1");
        assertEquals(policyList.get(1).getName(), "coretech:policy.writer");
        assertEquals(policyList.get(1).getVersion(), "1");
        assertEquals(policyList.get(2).getName(), "coretech:policy.editor");
        assertEquals(policyList.get(2).getVersion(), "1");
    }

    @Test
    public void testGetRoleTokenAuthorizedService() {
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        signedDomain.domain.setApplicationId("application_id");
        store.processSignedDomain(signedDomain, false);

        //success
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        assertNotNull(principal);
        principal.setApplicationId("coretech.api");
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);

        //success - no authorized service available
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);

        //failure - domain name and principal authorized service doesn't match
        principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        assertNotNull(principal);
        principal.setAuthorizedService("sports.hockey.api");
        context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech", null, 600,
                    1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetRoleToken() {
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
        assertTrue(roleToken.getToken().contains(";h=localhost;"));
        assertTrue(roleToken.getToken().contains(";i=10.11.12.13"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.user;"));
        assertEquals(roleToken.getExpiryTime(), token.getExpiryTime());

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context1 = createResourceContext(principal1);

        roleToken = zts.getRoleToken(context1, "coretech", null, null, 1200, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 2);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(token.getRoles().contains("writers"));

        Principal principal4 = SimplePrincipal.create("user_domain", "user4",
                "v=U1;d=user_domain;n=user4;s=signature", 0, null);
        ResourceContext context4 = createResourceContext(principal4);

        roleToken = zts.getRoleToken(context4, "coretech", null, 600,
                null, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.user4;"));
        assertTrue(roleToken.getToken().contains(";c=1;"));

        // turn off the include role complete set flag

        zts.includeRoleCompleteFlag = false;
        roleToken = zts.getRoleToken(context4, "coretech", null, 600,
                null, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.user4;"));
        assertFalse(roleToken.getToken().contains(";c=1;"));
        zts.includeRoleCompleteFlag = true;
    }

    @Test
    public void testGetRoleTokenWithRoleAuthority() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, new CertificateAuthority());
        assertNotNull(principal);
        ResourceContext context = createResourceContext(principal);

        // for the first principal we're not going to match - not including
        // the writers role so that it would fail

        List<String> principalRoles = new ArrayList<>();
        principalRoles.add("coretech:role.readers");
        principal.setRoles(principalRoles);

        try {
            zts.getRoleToken(context, "coretech", null, 600, 1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }

        // now include the role and verify valid response

        principalRoles.add("coretech:role.writers");
        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, 600, 1200, null);
        assertNotNull(roleToken);
    }

    @Test
    public void testGetRoleTokenDisabledDomain() {

        SignedDomain signedDomain = createSignedDomainExpiration("coretech-disabled",
                "weather", Boolean.FALSE);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech-disabled", null, 600,
                    1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetRoleTokenExpire() {

        SignedDomain signedDomain = createSignedDomainExpiration("coretech-expire", "weather");
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "coretech-expire",
                null, 600, 1200, null);
        com.yahoo.athenz.auth.token.RoleToken token =
                new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertTrue(token.getRoles().contains("role2"));
        assertFalse(token.getRoles().contains("role1"));
    }

    @Test
    public void testGetRoleTokenEmptyArguments() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "coretech", "", null, null, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
    }

    @Test
    public void testGetRoleTokenNoRoleMatch() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "invalidUser",
                "v=U1;d=user_domain;n=invalidUuser;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech", null, 600,
                    1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetRoleTokenInvalidDomain() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "invalidDomain", null, 600,
                    1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetRoleTokenSpecifiedRoleValid() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "coretech", "writers", 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context1 = createResourceContext(principal1);

        roleToken = zts.getRoleToken(context1, "coretech", "writers", null, 1200, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));

        Principal principal4 = SimplePrincipal.create("user_domain", "user4",
                "v=U1;d=user_domain;n=user4;s=signature", 0, null);
        ResourceContext context4 = createResourceContext(principal4);

        roleToken = zts.getRoleToken(context4, "coretech", "readers", 600, null, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
        assertFalse(token.getRoles().contains(";c=1;"));
    }

    @Test
    public void testGetRoleTokenSpecifiedRoleInValid() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech", "coretech:role.readers", 600,
                    1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetRoleTokenLeastPrivilegedEnabled() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        zts.leastPrivilegePrincipal = true;
        try {
            zts.getRoleToken(context, "coretech", null, 600, 1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("must specify a roleName"));
        }
    }

    @Test
    public void testGetRoleTokenSpecifiedRoleNoMatch() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech", "updaters", 600,
                    1200, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetRoleTokenTrustDomainWildCard() {

        SignedDomain signedDomain = createSignedDomainWildCard("weather", "netops");
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomainWildCard("netops");
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "siteops_user_1",
                "v=U1;d=user_domain;n=siteops_user_1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "weather", null, null, null, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("netops_superusers"));
    }

    @Test
    public void testGetRoleTokenTrustDomainWildCardGivenRole() {

        SignedDomain signedDomain = createSignedDomainWildCard("weather", "netops");
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomainWildCard("netops");
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "siteops_user_1",
                "v=U1;d=user_domain;n=siteops_user_1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "weather", "netops_superusers", null, null, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("netops_superusers"));
    }

    @Test
    public void testGetRoleAccess() {
        SignedDomain signedDomain = createSignedDomain("roleaccess", "tenantrole", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user", "v=U1;d=user_domain;n=user;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleAccess roleAccess = zts.getRoleAccess(context, "roleaccess", "user_domain.user");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("writers"));

        Principal principal1 = SimplePrincipal.create("user_domain", "user1", "v=U1;d=user_domain;n=user1;s=sig", 0, null);
        ResourceContext context1 = createResourceContext(principal1);

        roleAccess = zts.getRoleAccess(context1, "roleaccess", "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 2);
        assertTrue(roleAccess.getRoles().contains("readers"));
        assertTrue(roleAccess.getRoles().contains("writers"));

        Principal principal4 = SimplePrincipal.create("user_domain", "user4", "v=U1;d=user_domain;n=user1;s=sig", 0, null);
        ResourceContext context4 = createResourceContext(principal4);

        roleAccess = zts.getRoleAccess(context4, "roleaccess", "user_domain.user4");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("readers"));

        // invalid domain

        try {
            zts.getRoleAccess(context4, "unknowndomain", "user_domain.user4");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetRoleTokenUnauthorizedProxy() {
        SignedDomain signedDomain = createSignedDomain("coretech-proxy1", "weather-proxy1", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user", "v=U1;d=user_domain;n=user;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech-proxy1", null, 600,
                    1200, "user_domain.unknown-proxy-user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("not authorized for proxy role token request"));
        }
    }

    @Test
    public void testGetRoleTokenProxyUser() {

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

        RoleToken roleToken = zts.getRoleToken(context, "coretech-proxy2", null, 600,
                1200, "user_domain.joe");
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
        assertTrue(roleToken.getToken().contains(";h=localhost;"));
        assertTrue(roleToken.getToken().contains(";i=10.11.12.13"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.joe;"));
        assertTrue(roleToken.getToken().contains(";proxy=user_domain.proxy-user1;"));
        assertEquals(roleToken.getExpiryTime(), token.getExpiryTime());

        principal = SimplePrincipal.create("user_domain", "proxy-user2",
                "v=U1;d=user_domain;n=proxy-user2;s=sig", 0, null);
        context = createResourceContext(principal);

        roleToken = zts.getRoleToken(context, "coretech-proxy2", null, 600,
                1200, "user_domain.jane");
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(roleToken.getToken().contains(";h=localhost;"));
        assertTrue(roleToken.getToken().contains(";i=10.11.12.13"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.jane;"));
        assertTrue(roleToken.getToken().contains(";proxy=user_domain.proxy-user2;"));
        assertEquals(roleToken.getExpiryTime(), token.getExpiryTime());
    }

    @Test
    public void testGetRoleTokenProxyUserMismatchRolesIntersection() {

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

        RoleToken roleToken = zts.getRoleToken(context, "coretech-proxy3", null,
                600, 1200, "user_domain.joe");
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());

        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
    }

    @Test
    public void testGetRoleTokenProxyUserMismatchRolesEmptySet() {

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
            zts.getRoleToken(context, "coretech-proxy4", null, 600,
                    1200, "user_domain.joe");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetRoleTokenProxyUserSpecificRole() {

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

        RoleToken roleToken = zts.getRoleToken(context, "coretech-proxy4", "writers", 600,
                1200, "user_domain.joe");
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
        assertTrue(roleToken.getToken().contains(";h=localhost;"));
        assertTrue(roleToken.getToken().contains(";i=10.11.12.13"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.joe;"));
        assertTrue(roleToken.getToken().contains(";proxy=user_domain.proxy-user1;"));
        assertEquals(roleToken.getExpiryTime(), token.getExpiryTime());
    }

    @Test
    public void testLookupServiceIdentity() {

        List<ServiceIdentity> services = new ArrayList<>();

        ServiceIdentity service = new ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "storage"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        services.add(service);

        service = new ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "backup"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        services.add(service);

        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setServices(services);

        com.yahoo.athenz.zts.ServiceIdentity svc = zts.lookupServiceIdentity(domain, "coretech.storage");
        assertNotNull(svc);
    }

    @Test
    public void testLookupServiceIdentityNull() {
        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setServices(null);

        com.yahoo.athenz.zts.ServiceIdentity svc = zts.lookupServiceIdentity(domain, "coretech.storage");
        assertNull(svc);
    }

    @Test
    public void testLookupServiceIdentityNoMatch() {
        List<ServiceIdentity> services = new ArrayList<>();

        ServiceIdentity service = new ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "storage"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        services.add(service);

        service = new ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "backup"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        services.add(service);

        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setServices(services);

        com.yahoo.athenz.zts.ServiceIdentity svc = zts.lookupServiceIdentity(domain, "coretech.sync");
        assertNull(svc);
    }

    @Test
    public void testGetPublicKeyEntry() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        PublicKeyEntry entry = zts.getPublicKeyEntry(context, "coretech", "storage", "0");
        assertEquals(entry.getId(), "0");
        assertEquals(entry.getKey(), ZTS_Y64_CERT0);
    }

    @Test
    public void testGetPublicKeyEntryInvalidKeyId() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        // with null we get 400
        try {
            zts.getPublicKeyEntry(context, "coretech", "storage", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // with nonexistent we get 404
        try {
            zts.getPublicKeyEntry(context, "coretech", "storage", "999999");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetPublicKeyEntryInvalidDomain() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getPublicKeyEntry(context, "nonexistentdomain", "storage", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetPublicKeyEntryInvalidService() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getPublicKeyEntry(context, "coretech", "nonexistentservice", "0");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetServiceIdentity() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        com.yahoo.athenz.zts.ServiceIdentity svc = zts.getServiceIdentity(context, "coretech", "storage");
        assertNotNull(svc);
        assertEquals(svc.getName(), "coretech.storage");

        svc = zts.getServiceIdentity(context, "coretech", "backup");
        assertNotNull(svc);
        assertEquals(svc.getName(), "coretech.backup");
    }

    @Test
    public void testGetAthenzJwkNoServices() throws InterruptedException {
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        try {
            zts.getAthenzJWKConfig(context);
            fail();
        } catch (ResourceException e) { // sys.auth domain does not exist
            assertEquals(e.getCode(), 404);
        }

        // process sys.auth domain without zms service
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);
        providerDomain.getDomain().setServices(createServices("sys.auth", "zts"));
        try {
            zts.getAthenzJWKConfig(context);
            fail();
        } catch (ResourceException e) { // sys.auth.zms does not exist
            assertEquals(e.getCode(), 404);
        }

        // add zms service without public key
        ServiceIdentity sysAuthZms = createServices("sys.auth", "zms").get(0);
        sysAuthZms.setPublicKeys(null);
        providerDomain.getDomain().getServices().add(sysAuthZms);

        AthenzJWKConfig conf = zts.getAthenzJWKConfig(context);
        assertNull(conf.zms);
        assertNull(conf.zts);

        // invalid public key
        com.yahoo.athenz.zms.PublicKeyEntry pk = new com.yahoo.athenz.zms.PublicKeyEntry()
                .setKey("key");
        sysAuthZms.setPublicKeys(Collections.singletonList(pk));
        conf = zts.getAthenzJWKConfig(context);
        assertNull(conf.zms);
        assertNull(conf.zts);
    }

    @Test
    public void testGetAthenzJWK() throws InterruptedException {

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);
        providerDomain.getDomain().setServices(
                Stream.of(createServices("sys.auth", "zts"),
                                createServices("sys.auth", "zms"))
                        .flatMap(List::stream).collect(Collectors.toList())
        );

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        AthenzJWKConfig initialConf = zts.getAthenzJWKConfig(context);

        // add public key to sys.auth domain
        DomainData sysAuthDomain = zts.dataStore.getDomainData("sys.auth");
        ServiceIdentity ztsSrv = sysAuthDomain.getServices().stream()
                .filter(s -> s.getName().equals("sys.auth.zts"))
                .findFirst().get();
        ztsSrv.getPublicKeys().add(new com.yahoo.athenz.zms.PublicKeyEntry().setId("1").setKey(DataCacheTest.ZTS_Y64_CERT2));
        ztsSrv.setModified(Timestamp.fromMillis(System.currentTimeMillis() + 24 * 60 * 60 * 1000));
        zts.dataStore.processDomainData(sysAuthDomain);

        // since not enough time left (default is 24h) - AthenzJWKConfig should remain the same
        assertEquals(initialConf, zts.getAthenzJWKConfig(context));

        // now, change the time between config updates
        int backup = zts.millisBetweenAthenzJWKUpdates;
        zts.millisBetweenAthenzJWKUpdates = 0;

        Thread.sleep(10);
        AthenzJWKConfig newConfig = zts.getAthenzJWKConfig(context);

        // zts keys should be updated
        assertNotEquals(initialConf, newConfig);
        assertEquals(newConfig.getZts().getKeys().size(), 2);

        zts.millisBetweenAthenzJWKUpdates = backup;
    }

    @Test
    public void testAthenzJWKConfChangedNoModifyTime() {

        zts.jwkConfig = new AthenzJWKConfig().setModified(Timestamp.fromMillis(100));

        Timestamp zmsModified = Timestamp.fromMillis(99);
        assertFalse(zts.hasNewJWKConfig(zmsModified, null));
    }

    @Test
    public void testInvalidSysAuthService() {
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);
        com.yahoo.athenz.zts.ServiceIdentity ztsService = zts.sysAuthService(ZTS_SERVICE);
        com.yahoo.athenz.zts.ServiceIdentity zmsService = zts.sysAuthService(ZMS_SERVICE);
        assertNull(ztsService);
        assertNull(zmsService);
    }


    @Test
    public void testAthenzJWKConfChanged() {

        zts.jwkConfig = new AthenzJWKConfig().setModified(Timestamp.fromMillis(100));

        Timestamp zmsModified = Timestamp.fromMillis(99);
        Timestamp ztsModified = Timestamp.fromMillis(99);

        assertFalse(zts.hasNewJWKConfig(zmsModified, ztsModified));

        zmsModified = Timestamp.fromMillis(101);
        assertTrue(zts.hasNewJWKConfig(zmsModified, ztsModified));

    }

    @Test
    public void testFillAthenzJWKConfig() {
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);
        providerDomain.getDomain().setServices(
                Stream.of(createServices("sys.auth", "zts"),
                                createServices("sys.auth", "zms"))
                        .flatMap(List::stream).collect(Collectors.toList())
        );

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        InstanceIdentity id = new InstanceIdentity();

        // with older timestamp only - should not fill the config
        zts.fillAthenzJWKConfig(context, false, Timestamp.fromMillis(99), id);
        assertNull(id.getAthenzJWK());

        // without athenz config - should not fill the config
        zts.fillAthenzJWKConfig(context, false, null, id);
        assertNull(id.getAthenzJWK());

        // with athenz config and newer timestamp - should not fill the config
        zts.fillAthenzJWKConfig(context, true, Timestamp.fromDate(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24))), id);
        assertNull(id.getAthenzJWK());

        // with athenz config and without timestamp - should fill the config
        zts.fillAthenzJWKConfig(context, true, null, id);
        assertEquals(id.getAthenzJWK(), zts.jwkConfig);

        InstanceIdentity id1 = new InstanceIdentity();

        // with athenz config and older timestamp - should fill the config
        zts.fillAthenzJWKConfig(context, true, Timestamp.fromMillis(99), id1);
        assertEquals(id1.getAthenzJWK(), zts.jwkConfig);
    }

    @Test
    public void testLoadAthenzJWK() {

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);
        providerDomain.getDomain().setServices(
                Stream.of(createServices("sys.auth", "zts"),
                                createServices("sys.auth", "zms"))
                        .flatMap(List::stream).collect(Collectors.toList())
        );

        ZTSImpl newZts = new ZTSImpl(cloudStore, store);

        assertNotNull(newZts.jwkConfig);
        assertNotNull(newZts.jwkConfig.zts);
        assertNotNull(newZts.jwkConfig.zms);
        assertNotNull(newZts.jwkConfig.modified);
    }

    @Test
    public void testGetServiceIdentityInvalid() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getServiceIdentity(context, "coretech", "storage2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }

        try {
            zts.getServiceIdentity(context, "testDomain2", "storage");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetServiceIdentityList() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        com.yahoo.athenz.zts.ServiceIdentityList svcList = zts.getServiceIdentityList(context, "coretech");
        assertEquals(svcList.getNames().size(), 2);
        assertTrue(svcList.getNames().contains("storage"));
        assertTrue(svcList.getNames().contains("backup"));
    }

    @Test
    public void testGetServiceIdentityListInvalidDomain() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getServiceIdentityList(context, "testDomain2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetServiceIdentityListNoServices() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", false);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        com.yahoo.athenz.zts.ServiceIdentityList svcList = zts.getServiceIdentityList(context, "coretech");
        assertEquals(svcList.getNames().size(), 0);
    }

    @Test
    public void testGenerateServiceIdentityList() {

        // null service case

        ServiceIdentityList svcList = zts.generateServiceIdentityList("coretech", null);
        assertNull(svcList.getNames());

        // empty service case

        List<com.yahoo.athenz.zms.ServiceIdentity> services = new ArrayList<>();
        svcList = zts.generateServiceIdentityList("coretech", services);
        assertEquals(svcList.getNames().size(), 0);

        // no match of domain name

        ServiceIdentity svc = new ServiceIdentity().setName("athenz.storage");
        services.add(svc);

        svcList = zts.generateServiceIdentityList("coretech", services);
        assertEquals(svcList.getNames().size(), 0);

        // single entry in list

        svc = new ServiceIdentity().setName("coretech.storage");
        services.add(svc);

        svcList = zts.generateServiceIdentityList("coretech", services);
        assertEquals(svcList.getNames().size(), 1);
        assertEquals(svcList.getNames().get(0), "storage");

        // two entries in the list

        svc = new ServiceIdentity().setName("coretech.api");
        services.add(svc);

        svcList = zts.generateServiceIdentityList("coretech", services);
        assertEquals(svcList.getNames().size(), 2);
        assertEquals(svcList.getNames().get(0), "storage");
        assertEquals(svcList.getNames().get(1), "api");
    }

    @Test
    public void testValidate() {
        com.yahoo.athenz.zts.ServiceIdentity service = new com.yahoo.athenz.zts.ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "storage"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        zts.validate(service, "ServiceIdentity", "principal-domain", "testValidate");
        assertTrue(true);
    }

    @Test
    public void testValidateObjNull() {
        try {
            zts.validate(null, "SignedDomain", "principal-domain", "testValidate");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testValidateObjInvalid() {
        com.yahoo.athenz.zts.ServiceIdentity service = new com.yahoo.athenz.zts.ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "storage"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        try {
            zts.validate(service, "Policy", "principal-domain", "testValidate");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testConvertEmptyStringToNullStringNull() {
        assertNull(zts.convertEmptyStringToNull(null));
    }

    @Test
    public void testConvertEmptyStringToNullStringEmpty() {
        assertNull(zts.convertEmptyStringToNull(""));
    }

    @Test
    public void testConvertEmptyStringToNullStringNotEmpty() {
        assertEquals(zts.convertEmptyStringToNull("test"), "test");
    }

    @Test
    public void testEmitMonmetricError() {
        int errorCode = 403;
        String caller = "forbiddenError";
        boolean isEmitMonmetricError;
        com.yahoo.athenz.common.metrics.Metric metric = getMetric();
        // negative tests
        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, null, ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                "principal-domain", metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, "", ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                "principal-domain", metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, "", null, "principal-domain", metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(0, caller, null, "principal-domain", metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(-100, caller, null, "principal-domain", metric);
        assertFalse(isEmitMonmetricError);

        // positive tests
        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, caller, null, "principal-domain", metric);
        assertTrue(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, " " + caller + " ", null,
                "principal-domain", metric);
        assertTrue(isEmitMonmetricError);
    }

    @Test
    public void testDetermineAccessIdTokenTimeout() {
        assertEquals(zts.determineAccessIdTokenTimeout(3600), 3600);
        assertEquals(zts.determineAccessIdTokenTimeout(360000), zts.idTokenMaxTimeout);
    }

    @Test
    public void testDetermineOIDCIdTokenTimeout() {
        assertEquals(zts.determineOIDCIdTokenTimeout("athenz", null), zts.idTokenMaxTimeout);
        assertEquals(zts.determineOIDCIdTokenTimeout("athenz", zts.idTokenMaxTimeout + 1), zts.idTokenMaxTimeout);
        assertEquals(zts.determineOIDCIdTokenTimeout("athenz", zts.idTokenMaxTimeout - 1), zts.idTokenMaxTimeout - 1);
        assertEquals(zts.determineOIDCIdTokenTimeout("user", null), zts.idTokenDefaultTimeout);
        assertEquals(zts.determineOIDCIdTokenTimeout("user", zts.idTokenDefaultTimeout + 1), zts.idTokenDefaultTimeout);
        assertEquals(zts.determineOIDCIdTokenTimeout("user", zts.idTokenDefaultTimeout - 1), zts.idTokenDefaultTimeout - 1);
    }

    @Test
    public void testDetermineTokenTimeoutWithRoleExpiry() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers").setTokenExpiryMins(10);
        data.processRole(role1);

        DomainData domainData = new DomainData();
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        // token expiry is in mins and our api requires seconds
        // so we're going to get 600 secs instead of 10 mins
        // configured value

        assertEquals(zts.determineTokenTimeout(data, roles, null, 1200), 600);
    }

    @Test
    public void testDetermineTokenTimeoutWithDomainExpiry() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers");
        data.processRole(role1);

        DomainData domainData = new DomainData().setTokenExpiryMins(5);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        // token expiry is in mins and our api requires seconds
        // so we're going to get 300 secs instead of 5 mins
        // configured value

        assertEquals(zts.determineTokenTimeout(data, roles, null, 1200), 300);
    }

    @Test
    public void testDetermineTokenTimeoutWithRoleExpiryBigger() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers").setTokenExpiryMins(30);
        data.processRole(role1);

        DomainData domainData = new DomainData();
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        assertEquals(zts.determineTokenTimeout(data, roles, null, 1200), 1200);

        // with no expiry values specified by the caller we'll
        // get our limit of 30 mins

        assertEquals(zts.determineTokenTimeout(data, roles, null, null), 1800);
    }

    @Test
    public void testDetermineTokenTimeoutWithDomainExpiryBigger() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers");
        data.processRole(role1);

        DomainData domainData = new DomainData().setTokenExpiryMins(25);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        assertEquals(zts.determineTokenTimeout(data, roles, null, 1200), 1200);

        // with no expiry values specified by the caller we'll
        // get our limit of 25 mins

        assertEquals(zts.determineTokenTimeout(data, roles, null, null), 1500);
    }

    @Test
    public void testDetermineTokenTimeoutWithNoRoleMeta() {

        DataCache data = new DataCache();
        DomainData domainData = new DomainData();
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        assertEquals(zts.determineTokenTimeout(data, roles, null, 1200), 1200);
        assertEquals(zts.determineTokenTimeout(data, roles, null, null), roleTokenDefaultTimeout);
    }

    @Test
    public void testDetermineTokenTimeoutWithMultipleRoles() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers").setTokenExpiryMins(9);
        Role role2 = new Role().setName("athenz:role.writers").setTokenExpiryMins(10);
        data.processRole(role1);
        data.processRole(role2);

        DomainData domainData = new DomainData().setTokenExpiryMins(25);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        roles.add("writers");

        assertEquals(zts.determineTokenTimeout(data, roles, null, 1200), 540);
        assertEquals(zts.determineTokenTimeout(data, roles, null, 500), 500);
        assertEquals(zts.determineTokenTimeout(data, roles, null, null), 540);
    }

    @Test
    public void testDetermineTokenTimeoutBothNull() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), null, null), roleTokenDefaultTimeout);
    }

    @Test
    public void testDetermineTokenTimeoutMinNull() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), null, 100), 100);
    }

    @Test
    public void testDetermineTokenTimeoutMaxNull() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), 100, null), roleTokenDefaultTimeout);
    }

    @Test
    public void testDetermineTokenTimeoutMinInvalid() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), -10, null), roleTokenDefaultTimeout);
    }

    @Test
    public void testDetermineTokenTimeoutMaxInvalid() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), null, -10), roleTokenDefaultTimeout);
    }

    @Test
    public void testDetermineTokenTimeoutDefaultBigger() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), 3200, null), 3200);
    }

    @Test
    public void testDetermineTokeTimeoutDefaultSmaller() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), 1200, null), roleTokenDefaultTimeout);
    }

    @Test
    public void testDetermineTokeTimeoutMaxValueMaxExceeded() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), null, 120000), roleTokenMaxTimeout);
    }

    @Test
    public void testDetermineTokeTimeoutMinValueMaxExceeded() {
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(new DomainData());
        assertEquals(zts.determineTokenTimeout(dataCache, Collections.emptySet(), 120000, null), roleTokenMaxTimeout);
    }

    @Test
    public void testRoleTokenAddrNoLoopback() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.10.10.11");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);

        RoleToken roleToken = ztsImpl.getRoleToken(context, "coretech", null, 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
    }

    @Test
    public void testGetRoleTokenAddrLoopbackNoXFF() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);

        RoleToken roleToken = ztsImpl.getRoleToken(context, "coretech", null, 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
        assertNotNull(token.getUnsignedToken());
    }

    @Test
    public void testGetRoleTokenAddrLoopbackXFFSingeValue() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.getHeader("X-Forwarded-For")).thenReturn("10.10.10.12");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);

        RoleToken roleToken = ztsImpl.getRoleToken(context, "coretech", null, 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
    }

    @Test
    public void testGetRoleTokenAddrLoopbackXFFMultipleValues() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.getHeader("X-Forwarded-For")).thenReturn("10.10.10.11, 10.11.11.11, 10.12.12.12");
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);

        RoleToken roleToken = ztsImpl.getRoleToken(context, "coretech", null, 600,
                1200, null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
    }

    @Test
    public void testRetrieveTenantDomainNameInvalidEntries() {

        // less than 4 components

        assertNull(zts.retrieveTenantDomainName("dom1", null));
        assertNull(zts.retrieveTenantDomainName("dom1.tenant", null));
        assertNull(zts.retrieveTenantDomainName("dom1.tenant.dom3", null));

        // second component is not tenant

        assertNull(zts.retrieveTenantDomainName("dom1.dom2.dom3.admin", null));
        assertNull(zts.retrieveTenantDomainName("dom1.dom2.tenant.read", null));
        assertNull(zts.retrieveTenantDomainName("tenant.dom2.dom3.write", null));

        // service name does not match to the given value

        assertNull(zts.retrieveTenantDomainName("service1.tenant.dom3.read", "service2"));
        assertNull(zts.retrieveTenantDomainName("service2.tenant.dom3.dom4.admin", "service"));
    }

    @Test
    public void testRetrieveTenantDomainName4CompsValidDomain() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        assertEquals("coretech", zts.retrieveTenantDomainName("storage.tenant.coretech.admin", "storage"));
        assertEquals("coretech", zts.retrieveTenantDomainName("storage.tenant.coretech.admin", null));
    }

    @Test
    public void testRetrieveTenantDomainName4CompsInvalidDomain() {

        assertNull(zts.retrieveTenantDomainName("storage.tenant.coretech_unknown.admin", "storage"));
        assertNull(zts.retrieveTenantDomainName("storage.tenant.coretech_unknown.admin", null));
    }

    @Test
    public void testRetrieveTenantDomainName4PlusCompsValidDomainWithResourceGroup() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        assertEquals("coretech", zts.retrieveTenantDomainName("storage.tenant.coretech.resource_group.admin", "storage"));
        assertEquals("coretech", zts.retrieveTenantDomainName("storage.tenant.coretech.resource_group.admin", null));

        signedDomain = createSignedDomain("coretech.office.burbank", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.resource_group.admin", "storage"));
        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.resource_group.admin", null));
    }

    @Test
    public void testRetrieveTenantDomainName4PlusCompsValidDomainWithOutResourceGroup() {

        SignedDomain signedDomain = createSignedDomain("coretech.office.burbank", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.admin", "storage"));
        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.admin", null));
    }

    @Test
    public void testRetrieveTenantDomainName4PlusCompsInvalidDomain() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        assertNull(zts.retrieveTenantDomainName("storage.tenant.coretech.office.glendale.admin", "storage"));
        assertNull(zts.retrieveTenantDomainName("storage.tenant.coretech.office.glendale.resource_group.admin", null));
    }

    @Test
    public void testGetTenantDomainsSingleDomain() {

        SignedDomain signedDomain = createSignedDomain("athenz.product", "weather.frontpage", "storage", true);
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        TenantDomains tenantDomains = zts.getTenantDomains(context, "athenz.product",
                "user_domain.user100", null, null);
        assertNotNull(tenantDomains);
        assertEquals(tenantDomains.getTenantDomainNames().size(), 1);
        assertEquals(tenantDomains.getTenantDomainNames().get(0), "weather.frontpage");
    }

    @Test
    public void testGetTenantDomainsSingleDomainRoleSvcName() {

        SignedDomain signedDomain = createSignedDomain("athenz.product", "weather.frontpage", "storage", true);
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        TenantDomains tenantDomains = zts.getTenantDomains(context, "athenz.product",
                "user_domain.user100", "storage.tenant.weather.frontpage.admin", "storage");
        assertNotNull(tenantDomains);
        assertEquals(tenantDomains.getTenantDomainNames().size(), 1);
        assertEquals(tenantDomains.getTenantDomainNames().get(0), "weather.frontpage");
    }

    @Test
    public void testGetTenantDomainsMultipleDomains() {

        SignedDomain signedDomain = createMultipleSignedDomains("athenz.multiple", "hockey.kings", "hockey.stars",
                "storage", true);
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("hockey.kings", "athenz.multiple", "storage");
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("hockey.stars", "athenz.multiple", "storage");
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        TenantDomains tenantDomains = zts.getTenantDomains(context, "athenz.multiple",
                "user_domain.user100", null, null);
        assertNotNull(tenantDomains);
        assertEquals(tenantDomains.getTenantDomainNames().size(), 2);
        assertTrue(tenantDomains.getTenantDomainNames().contains("hockey.kings"));
        assertTrue(tenantDomains.getTenantDomainNames().contains("hockey.stars"));
    }

    @Test
    public void testGetTenantDomainsInvalidUser() {

        SignedDomain signedDomain = createSignedDomain("athenz.product", "weather.frontpage", "storage", true);
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        TenantDomains tenantDomains = zts.getTenantDomains(context, "athenz.product", "user1099", null, null);
        assertNotNull(tenantDomains);
        assertEquals(tenantDomains.getTenantDomainNames().size(), 0);
    }

    @Test
    public void testGetTenantDomainsInvalidDomain() {

        SignedDomain signedDomain = createSignedDomain("athenz.product", "weather.frontpage", "storage", true);
        store.processSignedDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getTenantDomains(context, "athenz.non_product", "user100", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testResourceContext() {
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) zts.newResourceContext(mockServletContext, mockServletRequest,
                mockServletResponse, "apiName");
        assertNotNull(ctx);
        assertNotNull(ctx.context());
        assertNull(ctx.principal());
        assertEquals(ctx.servletContext(), mockServletContext);
        assertEquals(ctx.request(), mockServletRequest);
        assertEquals(ctx.response(), mockServletResponse);

        // throw exception without struct
        try {
            com.yahoo.athenz.common.server.rest.ResourceException restExc
                = new com.yahoo.athenz.common.server.rest.ResourceException(401, "failed message");
            ctx.throwZtsException(restExc);
            fail();
        } catch (ResourceException ex) {
            assertEquals(401, ex.getCode());
            assertEquals( ((ResourceError) ex.getData()).message, "failed message");
        }
    }

    @Test
    public void testVerifyAWSAssumeRoleInvalidDomain() {
        assertFalse(zts.verifyAWSAssumeRole("unknown-domain", "role", "user_domain.user"));
    }

    @Test
    public void testVerifyAWSAssumeRoleNoRoles() {
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "role", "user_domain.user200"));
    }

    @Test
    public void testVerifyAWSAssumeRole() {
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        // our group includes user100 and user101
        assertTrue(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws_role_name", "user_domain.user100"));
        assertTrue(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws_role_name", "user_domain.user101"));
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws_role_name", "user_domain.user102"));
    }

    @Test
    public void testVerifyAWSAssumeRoleNoResourceMatch() {
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws2_role_name", "user_domain.user100"));
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws2_role_name", "user_domain.user101"));
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws2_role_name", "user_domain.user102"));
    }

    @Test
    public void testGetAWSTemporaryCredentialsNoCloudStore() {

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getAWSTemporaryCredentials(context, "athenz.product", "aws_role_name", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetAWSTemporaryCredentialsInvalidEncoding() {

        Principal principal = SimplePrincipal.create("user_domain", "user102",
                "v=U1;d=user_domain;n=user102;s=signature", 0, null);
        CloudStore cloudStore = Mockito.mock(CloudStore.class);
        Mockito.when(cloudStore.isAwsEnabled()).thenReturn(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        try {
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name%", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetAWSTemporaryCredentialsForbidden() {

        Principal principal = SimplePrincipal.create("user_domain", "user102",
                "v=U1;d=user_domain;n=user102;s=signature", 0, null);
        CloudStore cloudStore = Mockito.mock(CloudStore.class);
        Mockito.when(cloudStore.isAwsEnabled()).thenReturn(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        try {
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetAWSTemporaryCredentialsNoAwsAccount() {

        Principal principal = SimplePrincipal.create("user_domain", "user101",
                "v=U1;d=user_domain;n=user101;s=signature", 0, null);
        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processSignedDomain(signedDomain, false);

        try {
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetAWSTemporaryCredentials() {

        Principal principal = SimplePrincipal.create("user_domain", "user101",
                "v=U1;d=user_domain;n=user101;s=signature", 0, null);
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.setMockFields("1234", "aws_role_name", "user_domain.user101");
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        AWSTemporaryCredentials creds = zts.getAWSTemporaryCredentials(
                createResourceContext(principal), "athenz.product", "aws_role_name", null, null);
        assertNotNull(creds);

        // now try a failure case

        try {
            cloudStore.setMockFields("1234", "aws_role2_name", "user_domain.user101");
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testGetAWSTemporaryCredentialsAuthorizedPrincipal() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain",
                "user101", "v=U1;d=user_domain;n=user101;s=signature", 0, null);
        assertNotNull(principal);
        principal.setAuthorizedService("athenz.service");
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.setMockFields("1234", "aws_role_name", "user_domain.user101");
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processSignedDomain(signedDomain, false);

        try {
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product",
                    "aws_role_name", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorized Service Principals not allowed"));
        }
    }

    @Test
    public void testMatchPrincipalInRoleStdMemberMatch() {

        Role role = ZTSTestUtils.createRoleObject("weather", "Role", "user_domain.user2");
        assertTrue(authorizer.matchPrincipalInRole(role, null, "user_domain.user2", null));
    }

    @Test
    public void testMatchPrincipalInRoleStdMemberNoMatch() {

        Role role = ZTSTestUtils.createRoleObject("weather", "Role", "user_domain.user2");
        assertFalse(authorizer.matchPrincipalInRole(role, null, "user_domain.user23", null));
    }

    @Test
    public void testMatchPrincipalInRoleNoDelegatedTrust() {
        Role role = ZTSTestUtils.createRoleObject("weather", "Role", null, null);
        assertFalse(authorizer.matchPrincipalInRole(role, null, null, null));
        assertFalse(authorizer.matchPrincipalInRole(role, null, null, "weather"));
    }

    @Test
    public void testMatchPrincipalInRoleDelegatedTrustNoMatch() {
        Role role = ZTSTestUtils.createRoleObject("weather", "Role", "coretech_not_present", null);
        assertFalse(authorizer.matchPrincipalInRole(role, "Role", "user_domain.user1", "coretech_not_present"));
    }

    @Test
    public void testMatchPrincipalInRoleDelegatedTrustMatch() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretechtrust");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = ZTSTestUtils.createRoleObject("coretechtrust", "role1", "user_domain.user1");
        Role role2 = ZTSTestUtils.createRoleObject("coretechtrust", "role2", "user_domain.user2");
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = ZTSTestUtils.createPolicyObject("coretechtrust", "trust", "coretechtrust:role.role1",
                false, "ASSUME_ROLE", "weather:role.role1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);

        store.getCacheStore().put("coretechtrust", domain);
        Role role = ZTSTestUtils.createRoleObject("weather", "role1", "coretechtrust", null);
        assertTrue(authorizer.matchPrincipalInRole(role, "weather:role.role1", "user_domain.user1", "coretechtrust"));
        assertFalse(authorizer.matchPrincipalInRole(role, "weather:role.role1", "user_domain.user1", "coretechtrust2"));
        assertFalse(authorizer.matchPrincipalInRole(role, "weather:role.role1", "user_domain.user3", "coretechtrust"));

        // we're going to mark the policy as inactive in which case
        // we should not match any principal

        policy.setActive(false);
        assertFalse(authorizer.matchPrincipalInRole(role, "weather:role.role1", "user_domain.user1", "coretechtrust"));
        assertFalse(authorizer.matchPrincipalInRole(role, "weather:role.role1", "user_domain.user1", "coretechtrust2"));
        assertFalse(authorizer.matchPrincipalInRole(role, "weather:role.role1", "user_domain.user3", "coretechtrust"));

        store.getCacheStore().invalidate("coretechtrust");
    }

    @Test
    public void testAccessDelegatedTrust() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretechtrust");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = ZTSTestUtils.createRoleObject("coretechtrust", "role1", "user_domain.user1");
        Role role2 = ZTSTestUtils.createRoleObject("coretechtrust", "role2", "user_domain.user2");
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = ZTSTestUtils.createPolicyObject("coretechtrust", "trust", "coretechtrust:role.role1",
                false, "ASSUME_ROLE", "weather:role.role1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        store.getCacheStore().put("coretechtrust", domain);

        domain = new DataCache();
        domainData = new DomainData();
        domainData.setName("weather");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        role1 = ZTSTestUtils.createRoleObject("weather", "role1", "coretechtrust", null);
        domainData.getRoles().add(role1);

        policy = ZTSTestUtils.createPolicyObject("weather", "access", "weather:role.role1",
                false, "update", "weather:table1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        store.getCacheStore().put("weather", domain);

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        assertTrue(authorizer.access("update", "weather:table1", principal1, null));
        assertTrue(authorizer.access("update", "weather:table1", principal1, "coretechtrust"));
        assertFalse(authorizer.access("update", "weather:table1", principal1, "unknowntrust"));
        assertFalse(authorizer.access("update", "weather:table2", principal1, null));
        assertFalse(authorizer.access("delete", "weather:table1", principal1, null));

        Principal principal2 = SimplePrincipal.create("user_domain", "user2",
                "v=U1;d=user_domain;n=user2;s=signature", 0, null);
        assertFalse(authorizer.access("update", "weather:table1", principal2, null));

        Principal principal3 = SimplePrincipal.create("user_domain", "user3",
                "v=U1;d=user_domain;n=user3;s=signature", 0, null);
        assertFalse(authorizer.access("update", "weather:table1", principal3, null));

        store.getCacheStore().invalidate("coretechtrust");
        store.getCacheStore().invalidate("weather");
    }

    @Test
    public void testAccess() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretechtrust");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = ZTSTestUtils.createRoleObject("coretechtrust", "role1", "user_domain.user1");
        Role role2 = ZTSTestUtils.createRoleObject("coretechtrust", "role2", "user_domain.user2");
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = ZTSTestUtils.createPolicyObject("coretechtrust", "access", "coretechtrust:role.role1",
                false, "update", "coretechtrust:table1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        store.getCacheStore().put("coretechtrust", domain);

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        assertTrue(authorizer.access("update", "coretechtrust:table1", principal1, null));
        assertFalse(authorizer.access("update", "coretechtrust:table2", principal1, null));
        assertFalse(authorizer.access("delete", "coretechtrust:table1", principal1, null));

        Principal principal2 = SimplePrincipal.create("user_domain", "user2",
                "v=U1;d=user_domain;n=user2;s=signature", 0, null);
        assertFalse(authorizer.access("update", "coretechtrust:table1", principal2, null));

        Principal principal3 = SimplePrincipal.create("user_domain", "user3",
                "v=U1;d=user_domain;n=user3;s=signature", 0, null);
        assertFalse(authorizer.access("update", "coretechtrust:table1", principal3, null));

        store.getCacheStore().invalidate("coretechtrust");
    }

    @Test
    public void testAccessInvalidResource() {

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        try {
            authorizer.access("update", "coretechtrust:table1:test3", principal1, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }

    @Test
    public void testAccessInvalidDomain() {

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        try {
            authorizer.access("update", "unknowndoamin:table1", principal1, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }

    @Test
    public void testGetSchema() {
        Schema schema = zts.getRdlSchema(null);
        assertNotNull(schema);
    }

    @Test
    public void testGetSvcTokenExpiryTime() {

        long ZTS_NTOKEN_DEFAULT_EXPIRY = TimeUnit.SECONDS.convert(2, TimeUnit.HOURS);
        long ZTS_NTOKEN_MAX_EXPIRY = TimeUnit.SECONDS.convert(7, TimeUnit.DAYS);

        assertEquals(zts.getSvcTokenExpiryTime(null), ZTS_NTOKEN_DEFAULT_EXPIRY);
        assertEquals(zts.getSvcTokenExpiryTime(0), ZTS_NTOKEN_DEFAULT_EXPIRY);
        assertEquals(zts.getSvcTokenExpiryTime(-1), ZTS_NTOKEN_DEFAULT_EXPIRY);
        assertEquals(zts.getSvcTokenExpiryTime(100), 100);
        assertEquals(zts.getSvcTokenExpiryTime(2 * 60 * 60), ZTS_NTOKEN_DEFAULT_EXPIRY);
        assertEquals(zts.getSvcTokenExpiryTime(2 * 60 * 60 - 1), ZTS_NTOKEN_DEFAULT_EXPIRY - 1);
        assertEquals(zts.getSvcTokenExpiryTime(604799), 604799);
        assertEquals(zts.getSvcTokenExpiryTime(604800), ZTS_NTOKEN_MAX_EXPIRY);
        assertEquals(zts.getSvcTokenExpiryTime(604801), ZTS_NTOKEN_MAX_EXPIRY);
    }

    @Test
    public void testPostInstanceRefreshRequestPrincipalMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postInstanceRefreshRequest(context, "basketbal", "kings", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Principal mismatch"), ex.getMessage());
        }

        try {
            zts.postInstanceRefreshRequest(context, "hockey", "bruins", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Principal mismatch"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestUserAuthority() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user", "joe",
                "v=U1,d=user;n=joe;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postInstanceRefreshRequest(context, "user", "joe", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("TLS Certificates require ServiceTokens"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestUnknownAuthority() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user", "kings",
                "v=U1,d=user;n=kings;s=sig", 0, new UserAuthority());
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postInstanceRefreshRequest(context, "user", "kings", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPostInstanceRefreshRequest() throws IOException {

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");
        String publicKeyName = "athenz.syncer_0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        zts.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        Identity identity = zts.postInstanceRefreshRequest(context, "athenz", "syncer", req);
        assertNotNull(identity);

        X509Certificate cert = Crypto.loadX509Certificate(identity.getCertificate());
        assertNotNull(cert);

        // request same identity with expiry time

        req.setExpiryTime(1000);
        identity = zts.postInstanceRefreshRequest(context, "athenz", "syncer", req);
        assertNotNull(identity);
    }

    @Test
    public void testPostInstanceRefreshRequestSubjectOU() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.cert_ou.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "production", "v=S1,d=athenz;n=production;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");
        String publicKeyName = "athenz.production_0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALaJDb8CSq9tuzwSbe5bJurHLLvfkQ3a\n"
                + "jFGGJU4M8cz5+CbkJXRl/Cx1R0zOA+fdX5cGxYxL0Td31YDVw3tECWUCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        zts.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        zts.verifyCertSubjectOU = true;
        zts.verifyCertRequestIP = false;

        try {
            zts.postInstanceRefreshRequest(context, "athenz", "production", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        Set<String> ouValues = new HashSet<>();
        ouValues.add("Athenz");
        zts.validCertSubjectOrgUnitValues = ouValues;

        Identity identity = zts.postInstanceRefreshRequest(context, "athenz", "production", req);
        assertNotNull(identity);
    }

    @Test
    public void testPostInstanceRefreshRequestSubjOMismatch() throws IOException {

        Set<String> origOrgValues = zts.validCertSubjectOrgValues;
        Set<String> newOrgValues = new HashSet<>();
        newOrgValues.add("Mismatch Org");
        zts.validCertSubjectOrgValues = newOrgValues;

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");
        String publicKeyName = "athenz.syncer_0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKrvfvBgXWqWAorw5hYJu3dpOJe0gp3n\n"
                + "TgiiPGT7+jzm6BRcssOBTPFIMkePT2a8Tq+FYSmFnHfbQjwmYw2uMK8CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        zts.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // reset our original org values

        zts.validCertSubjectOrgValues = origOrgValues;
    }

    @Test
    public void testPostInstanceRefreshRequestSpiffeMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/spiffe_service_mismatch.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "production", "v=S1,d=athenz;n=production;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");
        String publicKeyName = "athenz.production_0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALHeQCsRDaTm97fVnH3gPKXH4gPirY0r\n"
                + "Tc/2dsgy9zdTlRntLotEhzO3NYYQRQZ/HdQ34AbVI35vwYDzlRogxq0CAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        zts.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postInstanceRefreshRequest(context, "athenz", "production", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("spiffe uri mismatch"));
        }
    }

    @Test
    public void testPostInstanceRefreshRequestMismatchIP() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "production", "v=S1,d=athenz;n=production;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");
        String publicKeyName = "athenz.production_0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMCfPNQO/3+rIwR4B1Ulr4w/CZR2i3LY\n"
                + "XH/dNcm+DCxpmEUtMVsnbYAJm2uVUVKk0UX1mxu5L8pDepBY+X1LEHsCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        zts.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.0.0.1");

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postInstanceRefreshRequest(context, "athenz", "production", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPostInstanceRefreshRequestMismatchIPVerifyDisabled() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "production", "v=S1,d=athenz;n=production;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");
        String publicKeyName = "athenz.production_0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMCfPNQO/3+rIwR4B1Ulr4w/CZR2i3LY\n"
                + "XH/dNcm+DCxpmEUtMVsnbYAJm2uVUVKk0UX1mxu5L8pDepBY+X1LEHsCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        zts.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.0.0.1");

        ResourceContext context = createResourceContext(principal, servletRequest);
        zts.verifyCertRequestIP = false;

        Identity identity = zts.postInstanceRefreshRequest(context, "athenz", "production", req);
        assertNotNull(identity);

        // enable verify flag again

        zts.verifyCertRequestIP = true;
    }

    @Test
    public void testPostInstanceRefreshRequestHcaCNMismatch() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("abc", "xyz",
                "v=S1,d=abc;n=xyz;s=sig", 0, new PrincipalAuthority());
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postInstanceRefreshRequest(context, "abc", "xyz", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPostInstanceRefreshRequestHcaPrincipalMismatch() throws IOException {
        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("abc", "xyz",
                "v=S1,d=abc;n=xyz;s=sig", 0, null);
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postInstanceRefreshRequest(context, "iaas.athenz", "syncer", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testResourceAccess() {

        final String domainName = "coretechaccess";

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = ZTSTestUtils.createRoleObject(domainName, "role1", "user.user1", "user.user3");
        Role role2 = ZTSTestUtils.createRoleObject(domainName, "role2", "user.user2");
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = ZTSTestUtils.createPolicyObject(domainName, "access", domainName + ":role.role1",
                false, "update", domainName + ":table1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        store.getCacheStore().put(domainName, domain);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        ResourceContext ctx = createResourceContext(principal, null);

        // process
        ResourceAccess access = zts.getResourceAccess(ctx, "update", domainName + ":table1", null, null);
        assertTrue(access.getGranted());

        access = zts.getResourceAccessExt(ctx, "update", domainName + ":table1", null, null);
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table2", null, null);
        assertFalse(access.getGranted());

        access = zts.getResourceAccessExt(ctx, "update", domainName + ":table2", null, null);
        assertFalse(access.getGranted());

        access = zts.getResourceAccess(ctx, "delete", domainName + ":table1", null, null);
        assertFalse(access.getGranted());

        access = zts.getResourceAccessExt(ctx, "delete", domainName + ":table1", null, null);
        assertFalse(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table1", null, "user.user2");
        assertFalse(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table1", null, "user.USER2");
        assertFalse(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table1", null, "user.user3");
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table1", null, "user.USER3");
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table2", null, "user.user3");
        assertFalse(access.getGranted());

        access = zts.getResourceAccess(ctx, "update", domainName + ":table2", null, "user.USER3");
        assertFalse(access.getGranted());

        store.getCacheStore().invalidate(domainName);
    }

    @Test
    public void testGetResourceAccessWithGroups() {

        final String domainName = "access-domain";
        ZTSTestUtils.setupDomainsWithGroups(store, privateKey, domainName, Collections.emptyList());

        // user1 and user3 have access to UPDATE/resource1

        Principal principal = SimplePrincipal.create("user", "user1",
                "v=U1;d=user;n=user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // user1 and user3 have access to UPDATE/resource1

        ResourceAccess access = zts.getResourceAccess(context, "update", domainName + "1:resource1", null, null);
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(context, "update", domainName + "1:resource2", null, null);
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(context, "update", domainName + "1:resource3", null, null);
        assertFalse(access.getGranted());

        access = zts.getResourceAccess(context, "update", domainName + "1:resource4", null, null);
        assertFalse(access.getGranted());
    }

    @Test
    public void testGetResourceAccessWithDelegatedGroups() {
        // we're going to try several cases with assume roles
        // first the assume role includes the full name without any wildcards

        getResourceAccessWithDelegatedGroups(false, false);

        // next we're going to test when the domain name is a wildcard
        // for example, resource: *:role.role1

        getResourceAccessWithDelegatedGroups(false, true);

        // next we're going to test when the role name is a wildcard
        // for example, resource: sports:role.*

        getResourceAccessWithDelegatedGroups(true, false);

        // finally we're going to test when the role and domain names are a wildcard
        // for example, resource: *:role.*

        getResourceAccessWithDelegatedGroups(true, true);
    }

    private void getResourceAccessWithDelegatedGroups(boolean wildCardRole, boolean wildCardDomain) {

        final String domainName1 = "access-domain-delegated-group1";
        final String domainName2 = "access-domain-delegated-group2";
        final String groupName1 = "group1";
        final String groupName2 = "group2";
        final String roleName1 = "role1";
        final String policyName1 = "policy1";

        List<Role> roles1 = new ArrayList<>();
        Role role1 = ZTSTestUtils.createRoleObject(domainName1, roleName1, "user.jane", "user.joey");
        role1.getRoleMembers().add(new RoleMember()
                .setMemberName(ResourceUtils.groupResourceName(domainName1, groupName1)));
        role1.getRoleMembers().add(new RoleMember()
                .setMemberName(ResourceUtils.groupResourceName(domainName1, groupName2))
                .setExpiration(Timestamp.fromMillis(100000)));
        roles1.add(role1);

        List<Group> groups1 = new ArrayList<>();
        Group group1 = ZTSTestUtils.createGroupObject(domainName1, groupName1, "user.john");
        groups1.add(group1);

        Group group2 = ZTSTestUtils.createGroupObject(domainName1, groupName2, "user.joe");
        groups1.add(group2);

        List<Policy> policies1 = new ArrayList<>();
        final String assumeRoleResource = ZTSTestUtils.getAssumeRoleResource(domainName2, roleName1,
                wildCardRole, wildCardDomain);
        Policy policy1 = ZTSTestUtils.createPolicyObject(domainName1, policyName1, roleName1,
                true, "assume_role", assumeRoleResource, AssertionEffect.ALLOW);
        policies1.add(policy1);

        List<Role> roles2 = new ArrayList<>();
        Role role2 = ZTSTestUtils.createRoleObject(domainName2, roleName1, domainName1, null);
        roles2.add(role2);

        List<Policy> policies2 = new ArrayList<>();
        Policy policy2 = ZTSTestUtils.createPolicyObject(domainName2, policyName1, roleName1,
                true, "update", domainName2 + ":resource1", AssertionEffect.ALLOW);
        policies2.add(policy2);

        SignedDomain signedDomain1 = ZTSTestUtils.createSignedDomain(domainName1, roles1, policies1, null,
                groups1, privateKey);
        store.processSignedDomain(signedDomain1, false);

        SignedDomain signedDomain2 = ZTSTestUtils.createSignedDomain(domainName2, roles2, policies2, null,
                null, privateKey);
        store.processSignedDomain(signedDomain2, false);

        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("user", "user1", "v=U1;d=user;n=user1;s=signature",
                0, principalAuthority);
        ResourceContext context = createResourceContext(principal, null);

        // role1 - jane & joey have regular role access, john (grp1), joe (grp2 but expired).

        ResourceAccess access = zts.getResourceAccess(context, "update", domainName2 + ":resource1", null, "user.jane");
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(context, "update", domainName2 + ":resource1", null, "user.joey");
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(context, "update", domainName2 + ":resource1", null, "user.john");
        assertTrue(access.getGranted());

        access = zts.getResourceAccess(context, "update", domainName2 + ":resource1", null, "user.joe");
        assertFalse(access.getGranted());

        // role access against the trusted domain

        RoleAccess roleAccess = zts.getRoleAccess(context, domainName2, "user.jane");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, domainName2, "user.joey");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, domainName2, "user.john");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, domainName2, "user.joe");
        assertTrue(roleAccess.getRoles().isEmpty());

        // role access against the domain itself

        roleAccess = zts.getRoleAccess(context, domainName1, "user.jane");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, domainName1, "user.joey");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, domainName1, "user.john");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, domainName1, "user.joe");
        assertTrue(roleAccess.getRoles().isEmpty());

        store.getCacheStore().invalidate(domainName1);
        store.getCacheStore().invalidate(domainName2);
    }

    @Test
    public void testGetAccess() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // user_domain.user only has access to writers

        Access access = zts.getAccess(context, "coretech", "writers", "user_domain.user");
        assertTrue(access.getGranted());

        access = zts.getAccess(context, "coretech", "readers", "user_domain.user");
        assertFalse(access.getGranted());

        // user_domain.user1 had access to readers and writers

        access = zts.getAccess(context, "coretech", "writers", "user_domain.user1");
        assertTrue(access.getGranted());

        access = zts.getAccess(context, "coretech", "readers", "user_domain.user1");
        assertTrue(access.getGranted());

        access = zts.getAccess(context, "coretech", "editors", "user_domain.user1");
        assertFalse(access.getGranted());

        // user_domain.user4 only has access to readers

        access = zts.getAccess(context, "coretech", "readers", "user_domain.user4");
        assertTrue(access.getGranted());

        access = zts.getAccess(context, "coretech", "writers", "user_domain.user4");
        assertFalse(access.getGranted());
    }

    @Test
    public void testGetAccessInvalidData() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // null and empty arguments

        try {
            zts.getAccess(context, "", "writers", "user_domain.user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.getAccess(context, null, "writers", "user_domain.user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.getAccess(context, "coretech", "", "user_domain.user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.getAccess(context, "coretech", null, "user_domain.user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.getAccess(context, "coretech", "writers", "");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            zts.getAccess(context, "coretech", "writers", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // now invalid domain

        try {
            zts.getAccess(context, "coretech-unknown", "writers", "user_domain.user");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testIsAuthorizedProxyUser() {
        assertFalse(zts.isAuthorizedProxyUser(null, "user.joe"));

        Set<String> proxyUsers = new HashSet<>();
        proxyUsers.add("user.joe");
        proxyUsers.add("user.jane");

        assertTrue(zts.isAuthorizedProxyUser(proxyUsers, "user.joe"));
        assertTrue(zts.isAuthorizedProxyUser(proxyUsers, "user.jane"));
        assertFalse(zts.isAuthorizedProxyUser(proxyUsers, "user.john"));
    }

    @Test
    public void testCompareRoleSets() {
        Set<String> set1 = new HashSet<>();
        Set<String> set2 = new HashSet<>();

        // empty sets should match

        assertTrue(zts.compareRoleSets(set1, set2));

        // not the same size so mismatch

        set1.add("role1");
        set1.add("role2");

        set2.add("role1");

        assertFalse(zts.compareRoleSets(set1, set2));

        // same size different values

        set2.add("role3");

        assertFalse(zts.compareRoleSets(set1, set2));

        // same values in both

        set1.add("role3");
        set2.add("role2");

        assertTrue(zts.compareRoleSets(set1, set2));
    }

    @Test
    public void testValidateRoleCertificateRequestMismatchEmail() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        zts.validCertSubjectOrgValues = null;
        assertFalse(zts.validateRoleCertificateRequest(certReq, "sports.standings",
                null, null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestNoEmail() throws IOException {

        Path path = Paths.get("src/test/resources/valid_noemail.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        zts.validCertSubjectOrgValues = null;
        assertFalse(zts.validateRoleCertificateRequest(certReq, "no-email", null,
                null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestInvalidOField() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        Set<String> validOValues = new HashSet<>();
        validOValues.add("InvalidCompany");
        zts.validCertSubjectOrgValues = validOValues;
        assertFalse(zts.validateRoleCertificateRequest(certReq, "sports.scores",
                null, null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequest() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        zts.validCertSubjectOrgValues = null;
        assertTrue(zts.validateRoleCertificateRequest(certReq, "sports.scores",
                null, null, "10.0.0.1"));

        Set<String> validOValues = new HashSet<>();
        validOValues.add("Athenz");
        zts.validCertSubjectOrgValues = validOValues;
        assertTrue(zts.validateRoleCertificateRequest(certReq, "sports.scores", null,
                null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestOU() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        zts.validCertSubjectOrgValues = null;

        Set<String> ouValues = new HashSet<>();
        ouValues.add("Testing Domain1");
        zts.validCertSubjectOrgUnitValues = ouValues;
        zts.verifyCertSubjectOU = true;

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);
        assertFalse(zts.validateRoleCertificateRequest(certReq, "sports.scores", null, null, "10.0.0.1"));

        ouValues.add("Testing Domain");
        assertTrue(zts.validateRoleCertificateRequest(certReq, "sports.scores", null, null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestWithUriHostname() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.examples.role-uri-hostname-only.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/athenz.examples.no-uri.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        // if the CSR has hostname, but the cert doesn't have hostname, it should result in false
        assertFalse(zts.validateRoleCertificateRequest(certReq, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));

        path = Paths.get("src/test/resources/athenz.examples.uri-hostname-only.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateRoleCertificateRequest(certReq, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));

        path = Paths.get("src/test/resources/athenz.examples.role-uri-instanceid-hostname.csr");
        csr = new String(Files.readAllBytes(path));
        certReq = new X509RoleCertRequest(csr);

        // if CSR has hostname+instanceid, and cert has only hostname, it should result in false
        assertFalse(zts.validateRoleCertificateRequest(certReq, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));

        path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateRoleCertificateRequest(certReq, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));
    }

    @Test
    public void testValidateUriHostname() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.examples.no-uri.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateUriHostname("", null));
        assertTrue(zts.validateUriHostname(null, null));

        assertFalse(zts.validateUriHostname("abc.athenz.com", cert));

        path = Paths.get("src/test/resources/athenz.examples.uri-hostname-only.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateUriHostname("abc.athenz.com", cert));
        assertFalse(zts.validateUriHostname("def.athenz.com", cert));
    }

    @Test
    public void testValidateInstanceId() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.examples.no-uri.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateInstanceId("", null));
        assertTrue(zts.validateInstanceId(null, null));

        assertFalse(zts.validateInstanceId("1001", cert));

        path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateInstanceId("1001", cert));
        assertFalse(zts.validateInstanceId("1002", cert));
    }

    @Test
    public void testValidateRoleCertificateRequestOUWithCert() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate validCert = Crypto.loadX509Certificate(pem);

        path = Paths.get("src/test/resources/svc_single_ip.pem");
        pem = new String(Files.readAllBytes(path));
        X509Certificate invalidCert = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        zts.validCertSubjectOrgValues = null;

        Set<String> ouValues = new HashSet<>();
        ouValues.add("Athenz");
        zts.validCertSubjectOrgUnitValues = ouValues;
        zts.verifyCertSubjectOU = true;

        assertFalse(zts.validateRoleCertificateRequest(certReq, "sports.scores",
                null, invalidCert, "10.0.0.1"));

        assertTrue(zts.validateRoleCertificateRequest(certReq, "sports.scores",
                null, validCert, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestMismatchIP() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        // disable IP validation and we should get success

        zts.verifyCertRequestIP = false;
        zts.validCertSubjectOrgValues = null;
        assertTrue(zts.validateRoleCertificateRequest(certReq, "athenz.production",
                null, cert, "10.11.12.13"));
        assertTrue(zts.validateRoleCertificateRequest(certReq, "athenz.production",
                null, cert, "10.11.12.14"));

        // enable validation and the mismatch one should fail

        zts.verifyCertRequestIP = true;
        assertTrue(zts.validateRoleCertificateRequest(certReq, "athenz.production",
                null, cert, "10.11.12.13"));
        assertFalse(zts.validateRoleCertificateRequest(certReq, "athenz.production",
                null, cert, "10.11.12.14"));
    }

    @Test
    public void testProcessRoleCertificateRequestFailedValidation() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleCertificateRequest req = new RoleCertificateRequest();

        X509RoleCertRequest certReq = new X509RoleCertRequest(ROLE_CERT_CORETECH_REQUEST);

        Set<String> origUnitValues = zts.validCertSubjectOrgUnitValues;
        boolean verifyCertSubjectOU = zts.verifyCertSubjectOU;

        zts.verifyCertSubjectOU = true;
        zts.validCertSubjectOrgUnitValues = new HashSet<>();

        try {
            zts.processRoleCertificateRequest(context, principal, "user_domain", certReq, null, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        zts.verifyCertSubjectOU = verifyCertSubjectOU;
        zts.validCertSubjectOrgUnitValues = origUnitValues;
    }

    @Test
    public void testPostRoleCertificateRequest() {

        // this csr is for sports:role.readers role
        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);
        req.setPrevCertNotAfter(Timestamp.fromCurrentTime());
        req.setPrevCertNotBefore(Timestamp.fromCurrentTime());

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.postRoleCertificateRequest(context, "coretech",
                "readers", req);
        assertNotNull(roleToken);
        // allow 10 sec offset (output is in seconds while input was in minutes)
        long diffExpiryTime = roleToken.getExpiryTime() - System.currentTimeMillis() / 1000;
        assertTrue(Math.abs(diffExpiryTime - expiry * 60) < 10);
    }

    @Test
    public void testPostRoleCertificateRequestUnauthorizedRole() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        // user101 does not have access to role readers

        Principal principal = SimplePrincipal.create("user_domain", "user101",
                "v=U1;d=user_domain;n=user101;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
            assertTrue(ex.getMessage().contains("is not included in the requested role(s)"));
        }
    }

    @Test
    public void testPostRoleCertificateRequestUnknownDomain() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
            assertTrue(ex.getMessage().contains("No such domain: coretech"));
        }
    }

    @Test
    public void testPostRoleCertificateRequestFailValidation() {

        // this csr is for sports:role.readers role
        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.postRoleCertificateRequest(context, "coretech",
                "readers", req);
        assertNotNull(roleToken);
        // allow 10 sec offset (output is in seconds while input was in minutes)
        long diffExpiryTime = roleToken.getExpiryTime() - System.currentTimeMillis() / 1000;
        assertTrue(Math.abs(diffExpiryTime - expiry * 60) < 10);
    }

    @Test
    public void testPostRoleCertificateRequestInvalidCSR() throws IOException {

        long expiry = 3600;

        Path path = Paths.get("src/test/resources/valid.csr");
        String csr = new String(Files.readAllBytes(path));

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(expiry);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // invalid csr due to service cn instead of cn

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Unable to parse PKCS10 CSR"));
        }

        // invalid csr

        req.setCsr("invalid-csr");
        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Unable to parse PKCS10 CSR"));
        }
    }

    @Test
    public void testPostRoleCertificateProxyUserRequest() throws IOException {

        Path path = Paths.get("src/test/resources/coretech_readers_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers role

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.postRoleCertificateRequest(context, "coretech",
                "readers", req);
        assertNotNull(roleToken);
    }

    @Test
    public void testPostRoleCertificateProxyUserRequestAccessMismatch() throws IOException {

        Path path = Paths.get("src/test/resources/coretech_readers_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers role

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("principal user_domain.user1 is not included in the requested role"));
        }
    }

    @Test
    public void testPostRoleCertificateInvalidProxyUserRequest() throws IOException {

        Path path = Paths.get("src/test/resources/coretech_readers_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers role

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user19"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user19"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user19",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("not authorized for proxy role certificate request"));
        }
    }

    @Test
    public void testPostRoleCertificateRequestNullCertReturn() {

        // this csr is for sports:role.readers role
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.generateIdentity("aws", null, ROLE_CERT_CORETECH_REQUEST,
                "coretech.weathers", "client", 3600, Priority.Unspecified_priority)).thenReturn(null);
        zts.instanceCertManager = certManager;

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("Unable to create certificate from the cert signer"));
        }
    }

    @Test
    public void testPostRoleCertificateRequestInvalidRequests() {

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // this time we're passing an invalid role name so we should
        // 400 - role name / cn mismatch

        try {
            zts.postRoleCertificateRequest(context, "coretech", "unknownrole", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // this time we're a different role name which should still
        // fail the cn/role name match and return 400

        try {
            zts.postRoleCertificateRequest(context, "coretech", "writers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // this time we're passing unknown domain

        try {
            zts.postRoleCertificateRequest(context, "unknown-domain", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPostRoleCertificateRequestMismatchDomain() {

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_DB_REQUEST).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // this time we're passing an invalid role name

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPostRoleCertificateRequestAuthorizedPrincipal() {

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_DB_REQUEST).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        assertNotNull(principal);
        principal.setAuthorizedService("athenz.api");
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequest(context, "sports", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorized Service Principals not allowed"));
        }
    }

    @Test
    public void testLogPrincipalEmpty() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResourceContext ctx = zts.newResourceContext(null, request, null, "apiName");
        zts.logPrincipalAndGetDomain(ctx);
        assertTrue(request.attributes.isEmpty());
    }

    @Test
    public void testConverToLowerCase() {

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setDomain("Domain").setService("Service").setProvider("Provider.Service");

        AthenzObject.INSTANCE_REGISTER_INFO.convertToLowerCase(info);
        assertEquals(info.getService(), "service");
        assertEquals(info.getDomain(), "domain");
        assertEquals(info.getProvider(), "provider.service");

        List<String> list = new ArrayList<>();
        list.add("Domain");
        list.add("service");

        AthenzObject.LIST.convertToLowerCase(list);
        assertEquals("domain", list.get(0));
        assertEquals("service", list.get(1));

        // should not cause any exceptions
        AthenzObject.LIST.convertToLowerCase(null);
    }

    private SignedDomain signedAuthorizedProviderDomain() {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName("sys.auth", "providers"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("athenz.provider"));
        members.add(new RoleMember().setMemberName("sys.auth.zts"));
        role.setRoleMembers(members);
        roles.add(role);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion1 = new com.yahoo.athenz.zms.Assertion();
        assertion1.setResource("sys.auth:instance");
        assertion1.setAction("launch");
        assertion1.setRole("sys.auth:role.providers");

        com.yahoo.athenz.zms.Assertion assertion2 = new com.yahoo.athenz.zms.Assertion();
        assertion2.setResource("sys.auth:dns.ostk.athenz.cloud");
        assertion2.setAction("launch");
        assertion2.setRole("sys.auth:role.providers");

        com.yahoo.athenz.zms.Assertion assertion3 = new com.yahoo.athenz.zms.Assertion();
        assertion3.setResource("sys.auth:hostname.athenz.cloud");
        assertion3.setAction("launch");
        assertion3.setRole("sys.auth:role.providers");

        com.yahoo.athenz.zms.Assertion assertion4 = new com.yahoo.athenz.zms.Assertion();
        assertion4.setResource("sys.auth:hostname.athenz.info");
        assertion4.setAction("launch");
        assertion4.setRole("sys.auth:role.providers");

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion1);
        assertions.add(assertion2);
        assertions.add(assertion3);
        assertions.add(assertion4);

        policy.setAssertions(assertions);
        policy.setName("sys.auth:policy.providers");
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain("sys.auth");
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName("sys.auth");
        domain.setRoles(roles);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    private SignedDomain signedBootstrapTenantDomain(String provider, String domainName,
            String serviceName) {
        return signedBootstrapTenantDomain(provider, domainName, serviceName, null);
    }

    private SignedDomain signedBootstrapTenantDomain(String provider, String domainName,
            String serviceName, String awsAccount) {

        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(generateRoleName(domainName, "providers"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName(provider));
        role.setRoleMembers(members);
        roles.add(role);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":service." + serviceName);
        assertion.setAction("launch");
        assertion.setRole(generateRoleName(domainName, "providers"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(domainName, "providers"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setAccount(awsAccount);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");

        return signedDomain;
    }

    @Test
    public void testPostInstanceRegisterInformation() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        Mockito.when(mockCloudStore.getAzureSubscription("athenz")).thenReturn("12345");
        Mockito.when(mockCloudStore.getGCPProjectId("athenz")).thenReturn("my-gcp-project-xsdc");
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.enableWorkloadStore = true;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true);

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        InstanceIdentity resIdentity = (InstanceIdentity) response.getEntity();
        assertNotNull(resIdentity.getX509Certificate());
        ztsImpl.enableWorkloadStore = false;
    }

    @Test
    public void testPostInstanceRegisterInformationInvalidDomain() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true)
                .setHostname("unknown.host.athenz.cloud");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("Domain not found: athenz"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationInvalidHostname() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(false);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider("athenz.provider", resolver)).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.hostnameResolver = resolver;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true)
                .setHostname("unknown.host.athenz.cloud");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }
    }

    @Test
    public void testPostInstanceRegisterInformationWithHostname() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.hostname.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());
        Mockito.doReturn(true).when(instanceManager).insertWorkloadRecord(any(WorkloadRecord.class));

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.enableWorkloadStore = true;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true)
                .setHostname("host1.athenz.cloud");

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        InstanceIdentity resIdentity = (InstanceIdentity) response.getEntity();
        assertNotNull(resIdentity.getX509Certificate());
        ztsImpl.enableWorkloadStore = false;
    }

    @Test
    public void testPostInstanceRegisterInformationWithHostnameCnames() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.cname.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        // setup the hostname resolver for our request
        List<String> cnames = new ArrayList<>();
        cnames.add("cname1.athenz.info");
        cnames.add("cname2.athenz.info");

        String service = "athenz.production";

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(service, "host1.athenz.cloud", cnames, CertType.X509)).thenReturn(true);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(true);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider("athenz.provider", resolver)).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.hostnameResolver = resolver;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true)
                .setHostname("host1.athenz.cloud")
                .setHostCnames(cnames);

        ResourceContext context = createResourceContext(null);



        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        InstanceIdentity resIdentity = (InstanceIdentity) response.getEntity();
        assertNotNull(resIdentity.getX509Certificate());
    }

    @Test
    public void testPostInstanceRegisterInformationWithHostnameInvalidCname() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.hostname.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true)
                .setHostname("host1.athenz.cloud")
                .setHostCnames(Collections.singletonList("cname1.athenz.cloud"));

        ResourceContext context = createResourceContext(null);

        // this should get rejected since we have a hostname specified
        // along with its cname but the cname is not present in the csr

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }
    }

    @Test
    public void testPostInstanceRegisterInformationNoSSH() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "false");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);
        Mockito.doThrow(new ResourceException(500, "Invalid SSH")).when(instanceManager)
                .generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(),
                        Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.anySet());

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setSsh("ssh-csr");

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        InstanceIdentity resIdentity = (InstanceIdentity) response.getEntity();
        assertNotNull(resIdentity.getX509Certificate());
        assertNull(resIdentity.getSshCertificate());
    }

    @Test
    public void testPostInstanceRegisterInformationSshHostCert() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/sshhost_valid_sample.csr");
        String sshCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);
        Mockito.when(instanceManager.generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.anySet())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem)
                .setSshCertificate("test ssh host certificate");
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider")
                .setHostname("host1.athenz.cloud")
                .setSsh(sshCsr);

        ResourceContext context = createResourceContext(null);

        // setup the hostname resolver for our request
        List<String> cnames = new ArrayList<>();
        cnames.add("cname.athenz.info");
        cnames.add("vip.athenz.info");

        String service = "athenz.production";

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(service, "host1.athenz.cloud", cnames, CertType.SSH_HOST)).thenReturn(true);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(true);
        ztsImpl.hostnameResolver = resolver;

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        InstanceIdentity resIdentity = (InstanceIdentity) response.getEntity();
        assertNotNull(resIdentity.getX509Certificate());
        assertNotNull(resIdentity.getSshCertificate());
    }

    @Test
    public void testPostInstanceRegisterInformationSubjectOU() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true);

        Set<String> orgUnitValues = new HashSet<>();
        ztsImpl.verifyCertSubjectOU = true;
        ztsImpl.validCertSubjectOrgUnitValues = orgUnitValues;

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        orgUnitValues.add("Testing Domain");
        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        assertNotNull(info.getToken());
    }

    @Test
    public void testPostInstanceRegisterInformationSubjectOUInstanceAttrs() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_CERT_SUBJECT_OU, "Testing Domain");
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true);

        ztsImpl.verifyCertSubjectOU = true;
        ztsImpl.validCertSubjectOrgUnitValues = null;

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        assertNotNull(info.getToken());
    }

    @Test
    public void testPostInstanceRegisterInformationAttrsReturned() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Map<String, String> instanceAttrs = new HashMap<>();
        instanceAttrs.put(InstanceProvider.ZTS_CERT_REFRESH, "false");
        instanceAttrs.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, "20");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider")
                .setAttributes(instanceAttrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true);

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        assertNotNull(info.getToken());
    }

    @Test
    public void testPostInstanceRegisterInformationInvalidIP() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceCertManager instanceManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceManager.verifyInstanceCertIPAddress(Mockito.any(), Mockito.any()))
                .thenReturn(false);
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true);

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unknown IP"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationWithIPAndAccount() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid_ip.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");
        Map<String, String> confirmAttrs = new HashMap<>();
        confirmAttrs.put("certUsage", "false");
        confirmation.setAttributes(confirmAttrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        Mockito.when(mockCloudStore.getAwsAccount("athenz")).thenReturn("1234");

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(false);

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        assertNotNull(info.getToken());
    }

    @Test
    public void testPostInstanceRegisterInformationNoProviderClient() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(null);

        ztsImpl.instanceProviderManager = instanceProviderManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to get instance for provider"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationAttestationFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenThrow(new ResourceException(400));

        ztsImpl.instanceProviderManager = instanceProviderManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("unable to verify attestation data"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationNetworkFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any()))
                .thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(504, "Connect Timeout"))
                .thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(403, "Instance Revoked"));

        ztsImpl.instanceProviderManager = instanceProviderManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        // first 504

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 504);
            assertTrue(ex.getMessage().contains("Connect Timeout"));
        }

        // then 403

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Instance Revoked"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationNoAuthorizedProvider() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.nonprovider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("not authorized to launch instances in Athenz"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationServiceNotAuthorizedProvider() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production2")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("not authorized to launch athenz.production2 instances"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationInvalidCSR() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr("csr")
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to parse PKCS10 CSR"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationCSRValidateFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.mismatch.cn.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("CSR validation failed"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationIdentityFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);

        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        Mockito.doReturn(null).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("unable to generate identity"));
        }
    }

    @Test
    public void testPostInstanceRegisterInformationSSHIdentityFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(false);

        Mockito.doReturn(false).when(instanceManager).generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.anySet());

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        assertNull(info.getSsh());
    }

    @Test
    public void testPostInstanceRegisterInformationCertRecordFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(false);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider");

        ResourceContext context = createResourceContext(null);

        try {
            ztsImpl.postInstanceRegisterInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("unable to update cert db"));
        }
    }

    private void testPostInstanceRefreshInformation(final String csrPath, final String hostname) throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get(csrPath);
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("169894876839995310717517774217024528903");
        certRecord.setPrevSerial("169894876839995310717517774217024528903");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.hostname.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);
        if (hostname != null) {
            info.setHostname(hostname);
        }

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
        assertNotNull(instanceIdentity.getServiceToken());

        ArgumentCaptor<X509CertRecord> captor = ArgumentCaptor.forClass(X509CertRecord.class);
        Mockito.verify(instanceManager, atLeastOnce()).updateX509CertRecord(captor.capture());
        X509CertRecord actualCert = captor.getValue();

        assertEquals(actualCert.getHostName(), hostname);
    }

    @Test
    public void testPostInstanceRefreshInformationSshHostCert() throws IOException {
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/sshhost_valid_sample.csr");
        String sshCsr = new String(Files.readAllBytes(path));

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certSSH", "true");

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);
        Mockito.when(instanceManager.generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyBoolean(), Mockito.anySet())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem)
                .setSshCertificate("test ssh host certificate");
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.enableWorkloadStore = true;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true)
                .setHostname("host1.athenz.cloud")
                .setSsh(sshCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        // setup the hostname resolver for our request
        List<String> cnames = new ArrayList<>();
        cnames.add("cname.athenz.info");
        cnames.add("vip.athenz.info");

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(principal.getFullName(), "host1.athenz.cloud", cnames, CertType.SSH_HOST)).thenReturn(true);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(true);
        ztsImpl.hostnameResolver = resolver;

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
        assertNotNull(instanceIdentity.getServiceToken());
        assertNotNull(instanceIdentity.getSshCertificate());
        ztsImpl.enableWorkloadStore = false;
    }

    @Test
    public void testPostInstanceRefreshInformationWithHostnameCnames() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.cname.csr");
        String certCsr = new String(Files.readAllBytes(path));

        List<String> cnames = new ArrayList<>();
        cnames.add("cname1.athenz.info");
        cnames.add("cname2.athenz.info");

        String service = "athenz.production";

        HostnameResolver resolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(resolver.isValidHostCnameList(service, "host1.athenz.cloud", cnames, CertType.X509)).thenReturn(true);
        Mockito.when(resolver.isValidHostname("host1.athenz.cloud")).thenReturn(true);

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider("athenz.provider", resolver)).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true)
                .setHostname("host1.athenz.cloud")
                .setHostCnames(cnames);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        // setup the hostname resolver for our request

        ztsImpl.hostnameResolver = resolver;

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
    }

    @Test
    public void testPostInstanceRefreshInformationInstanceIdDns() throws IOException {
        testPostInstanceRefreshInformation("src/test/resources/athenz.instanceid.csr", null);
    }

    @Test
    public void testPostInstanceRefreshInformationInstanceIdUri() throws IOException {
        testPostInstanceRefreshInformation("src/test/resources/athenz.instance.prod.uri.csr", null);
    }

    @Test
    public void testPostInstanceRefreshInformationInstanceWithHostname() throws IOException {
        testPostInstanceRefreshInformation("src/test/resources/athenz.instance.prod.uri.csr", "abc.athenz.cloud");
    }

    @Test
    public void testGetValidatedX509CertRecordForbidden() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceCertManager instanceCertManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceCertManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(null);
        Mockito.when(instanceCertManager.insertX509CertRecord(Mockito.any())).thenReturn(false);

        ztsImpl.instanceCertManager = instanceCertManager;

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        ztsImpl.x509CertRefreshResetTime =  new DynamicConfigLong(cert.getNotBefore().getTime() + 1);

        try {
            ztsImpl.getValidatedX509CertRecord(context, "athenz.provider", "1001",
                    "athenz.production", cert, "caller", "athenz", "athenz",
                    "localhost");
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }
    }

    @Test
    public void testGetValidatedX509CertRecord() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceCertManager instanceCertManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceCertManager.getX509CertRecord("athenz.provider", "1001", "athenz.production"))
                .thenReturn(null);
        Mockito.when(instanceCertManager.insertX509CertRecord(Mockito.any())).thenReturn(true);

        ztsImpl.instanceCertManager = instanceCertManager;

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        ztsImpl.x509CertRefreshResetTime = new DynamicConfigLong(cert.getNotBefore().getTime() + 1);

        X509CertRecord certRecord =  ztsImpl.getValidatedX509CertRecord(context, "athenz.provider",
                "1001", "athenz.production", cert, "caller", "athenz", "athenz",
                "localhost");
        assertNotNull(certRecord);
    }

    @Test
    public void testPostInstanceRefreshInformationNoCertRefeshCheck() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        Map<String, String> attrs = new HashMap<>();
        attrs.put("certRefresh", "false");
        attrs.put("certSSH", "true");

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider")
                .setAttributes(attrs);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production"))
                .thenThrow(new ResourceException(400, "unknown record"));

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
        assertNotNull(instanceIdentity.getServiceToken());
    }

    @Test
    public void testPostInstanceRefreshInformationSubjectOU() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        ztsImpl.verifyCertSubjectOU = true;

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        Set<String> ouValues = new HashSet<>();
        ouValues.add("Athenz");
        ouValues.add("Testing Domain");
        ztsImpl.validCertSubjectOrgUnitValues = ouValues;

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
        assertNotNull(instanceIdentity.getServiceToken());
    }

    @Test
    public void testPostInstanceRefreshInformationRefreshRequired() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        certRecord.setClientCert(true);
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
        assertNotNull(instanceIdentity.getServiceToken());
    }

    @Test
    public void testPostInstanceRefreshInformationInvalidIP() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceCertManager instanceManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceManager.verifyCertRefreshIPAddress(Mockito.any())).thenReturn(false);
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403, ex.getMessage());
            assertTrue(ex.getMessage().contains("Unknown IP"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshInformationForbidden() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any()))
                .thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(403, "Forbidden"))
                .thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(504, "Connect Timeout"))
                .thenThrow(new ResourceException(403, "Forbidden"));

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        // first we get std provider exception 403

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403, ex.getMessage());
            assertTrue(ex.getMessage().contains("unable to verify attestation data"), ex.getMessage());
        }

        // then 504 network timeout

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 504, ex.getMessage());
            assertTrue(ex.getMessage().contains("Connect Timeout"));
        }

        // final std 403

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403, ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshInformationNotFound() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(404, "Not Found"));

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider", "athenz",
                    "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }
    }

    @Test
    public void testPostInstanceRefreshInformationSSHFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);
        Mockito.when(instanceManager.generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.any(), eq("ssh-csr"),
                Mockito.any(), Mockito.any(), eq("user"), Mockito.anyBoolean(), Mockito.anySet())).thenReturn(false);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setSsh("ssh-csr").setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        identity = ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                "athenz", "production", "1001", info);
        assertNull(identity.getSshCertificate());
    }

    @Test
    public void testPostInstanceRefreshInformationPrevSerialMatch() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("101");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
    }

    @Test
    public void testPostInstanceRefreshInformationInvalidCSR() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);

        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation().setCsr("csr");

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("unable to parse PKCS10 CSR"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationProviderNotAuthorized() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider2",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("not authorized to launch instances in Athenz"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationCSRValidateFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.mismatch.cn.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("CSR validation failed"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationInstanceIdMismatch() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        path = Paths.get("src/test/resources/valid_cn_x509.cert");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400, ex.getMessage());
            assertTrue(ex.getMessage().contains("instance id mismatch"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationGetCertDBFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(null);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Unable to find certificate record"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationCertRecordCNMismatch() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz2.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("service name mismatch"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationSerialMismatch() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("101");
        certRecord.setPrevSerial("101");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Certificate revoked"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationSerialMismatchRevokeMigration() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("101");
        certRecord.setPrevSerial("101");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.x509CertRefreshResetTime = new DynamicConfigLong(System.currentTimeMillis());

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity refreshIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(refreshIdentity);
    }

    @Test
    public void testPostInstanceRefreshInformationIdentityFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        Mockito.doReturn(null).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("unable to generate identity"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationCertRecordFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(false);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("unable to update cert db"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationNoCertAuthority() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, authority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Unsupported authority for TLS Certs"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationInvalidPrincipal() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz2", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, authority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz2", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Principal mismatch"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationInvalidDomain() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, authority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                    "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("Domain not found: athenz"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationNullCSRs() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(null).setSsh("");

        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, authority);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("no csr provided"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationNoProviderClient() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(null);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(false);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.anyInt(), Mockito.any());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider",
                    "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400, ex.getMessage());
            assertTrue(ex.getMessage().contains("unable to get instance for provider"));
        }
    }

    @Test
    public void testPostInstanceRefreshInformationSSH() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, null, "ssh-csr",
                null, null, "user", true, null)).thenReturn(true);

        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation().setSsh("ssh-csr");

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
    }

    @Test
    public void testPostInstanceRefreshInformationSSHMatchPrevSerial() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("123413");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, null, "ssh-csr",
                null, null, "user", true, null)).thenReturn(true);

        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation().setSsh("ssh-csr");

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        InstanceIdentity instanceIdentity = ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
        assertNotNull(instanceIdentity);
    }

    @Test
    public void testPostInstanceRefreshInformationSSHIdentityFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, null, "ssh-csr",
                null, null, "user", true, Collections.emptySet())).thenReturn(false);

        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation().setSsh("ssh-csr");

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postInstanceRefreshInformation(context, "athenz.provider", "athenz",
                    "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
    }

    @Test
    public void testDeleteInstanceIdentity() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        InstanceCertManager instanceManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceManager.deleteX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(true);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("delete", "athenz:instance.1001", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        ztsImpl.instanceCertManager = instanceManager;

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.deleteInstanceIdentity(context, "athenz.provider",
                "athenz", "production", "1001");
        } catch (Exception ex) {
            fail();
        }
    }

    @Test
    public void testDeleteInstanceIdentityUnauthorized() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        InstanceCertManager instanceManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceManager.deleteX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(true);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("delete", "athenz:instance.1001", principal, null)).thenReturn(false);
        ztsImpl.authorizer = authorizer;

        ztsImpl.instanceCertManager = instanceManager;

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.deleteInstanceIdentity(context, "athenz.provider",
                    "athenz", "production", "1001");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }
    }

    @Test
    public void testDeleteInstanceIdentityProvider() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        InstanceCertManager instanceManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceManager.deleteX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(true);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "provider", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("delete", "athenz:instance.1001", principal, null)).thenReturn(false);
        ztsImpl.authorizer = authorizer;

        ztsImpl.instanceCertManager = instanceManager;

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.deleteInstanceIdentity(context, "athenz.provider",
                    "athenz", "production", "1001");
        } catch (Exception ex) {
            fail();
        }
    }

    @Test
    public void testGetSignedDomainPolicyData() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        Response response = ztsImpl.getDomainSignedPolicyData(context, "coretech", null);
        assertEquals(response.getStatus(), 200);

        // invalid domain

        try {
            ztsImpl.getDomainSignedPolicyData(context, "unknowndomain", null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testGetSignedDomainPolicyDataNoChanges() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        Timestamp modified = signedDomain.getDomain().getModified();
        EntityTag eTag = new EntityTag(modified.toString());

        Response response = ztsImpl.getDomainSignedPolicyData(context, "coretech", eTag.toString());
        assertEquals(response.getStatus(), ResourceException.NOT_MODIFIED);
    }

    @Test
    public void testCreatePrincipalForName() {
        Principal principal = zts.createPrincipalForName("athenz.provider");
        assertEquals(principal.getDomain(), "athenz");
        assertEquals(principal.getName(), "provider");

        principal = zts.createPrincipalForName("athenz.subdomain.provider");
        assertEquals(principal.getDomain(), "athenz.subdomain");
        assertEquals(principal.getName(), "provider");

        principal = zts.createPrincipalForName("provider");
        assertEquals(principal.getDomain(), zts.userDomain);
        assertEquals(principal.getName(), "provider");

        zts.userDomain = "user";
        zts.userDomainAlias = null;

        principal = zts.createPrincipalForName("joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zts.createPrincipalForName("joe-smith");
        assertEquals(principal.getFullName(), "user.joe-smith");

        principal = zts.createPrincipalForName("user.joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zts.createPrincipalForName("user.joe.storage");
        assertEquals(principal.getFullName(), "user.joe.storage");

        principal = zts.createPrincipalForName("alias.joe");
        assertEquals(principal.getFullName(), "alias.joe");

        principal = zts.createPrincipalForName("alias.joe.storage");
        assertEquals(principal.getFullName(), "alias.joe.storage");

        zts.userDomainAlias = "alias";

        principal = zts.createPrincipalForName("joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zts.createPrincipalForName("joe-smith");
        assertEquals(principal.getFullName(), "user.joe-smith");

        principal = zts.createPrincipalForName("user.joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zts.createPrincipalForName("user.joe.storage");
        assertEquals(principal.getFullName(), "user.joe.storage");

        principal = zts.createPrincipalForName("alias.joe");
        assertEquals(principal.getFullName(), "user.joe");

        principal = zts.createPrincipalForName("alias.joe.storage");
        assertEquals(principal.getFullName(), "alias.joe.storage");
    }

    @Test
    public void testGetChangeLogStore() {
        ChangeLogStore store = zts.getChangeLogStore(ZTS_DATA_STORE_PATH);
        assertNotNull(store);
    }

    @Test
    public void testNormalizeDomainAliasUser() {

        assertNull(zts.normalizeDomainAliasUser(null));
        assertEquals(zts.normalizeDomainAliasUser(""), "");

        zts.userDomainAlias = null;
        zts.userDomainAliasPrefix = null;
        assertEquals(zts.normalizeDomainAliasUser("user.joe"), "user.joe");
        assertEquals(zts.normalizeDomainAliasUser("useralias.joe"), "useralias.joe");
        assertEquals(zts.normalizeDomainAliasUser("useralias.joe.svc"), "useralias.joe.svc");
        assertEquals(zts.normalizeDomainAliasUser("joe"), "joe");

        zts.userDomainAlias = "useralias";
        zts.userDomainAliasPrefix = "useralias.";
        assertEquals(zts.normalizeDomainAliasUser("user.joe"), "user.joe");
        assertEquals(zts.normalizeDomainAliasUser("useralias.joe"), "user.joe");
        assertEquals(zts.normalizeDomainAliasUser("useralias.joe.svc"), "useralias.joe.svc");
        assertEquals(zts.normalizeDomainAliasUser("joe"), "joe");
    }

    @Test
    public void testValidateRequestSecureRequests() {
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = false;
        ztsImpl.statusPort = 0;

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);

        // if secure requests is false, no check is done

        ztsImpl.validateRequest(request, "principal-domain", "test");
        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
        ztsImpl.validateRequest(request, "principal-domain", "test", true, false);

        // should complete successfully since our request is true

        ztsImpl.secureRequestsOnly = true;
        ztsImpl.validateRequest(request, "principal-domain", "test");
        ztsImpl.validateRequest(request, "principal-domain", "test", false, true);
        ztsImpl.validateRequest(request, "principal-domain", "test", true, true);
    }

    @Test
    public void testValidateRequestNonSecureRequests() {
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = true;
        ztsImpl.statusPort = 0;

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);

        // if request is not secure, should be rejected

        Mockito.when(request.isSecure()).thenReturn(false);
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test");
            fail();
        } catch (ResourceException ignored) {
        }
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
            fail();
        } catch (ResourceException ignored) {
        }
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", true, true);
            fail();
        } catch (ResourceException ignored) {
        }
    }

    @Test
    public void testValidateRequestStatusRequestPort() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = true;

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(4443);

        // with status port 0, all requests are ok

        ztsImpl.statusPort = 0;
        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
        ztsImpl.validateRequest(request, "principal-domain", "test", true, false);

        // with status set to equal to http port - all requests are ok

        ztsImpl.statusPort = 4080;
        ztsImpl.httpPort = 4080;

        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
        ztsImpl.validateRequest(request, "principal-domain", "test", true, false);

        // with status set to equal to https port - all requests are ok

        ztsImpl.statusPort = 4443;
        ztsImpl.httpsPort = 4443;

        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
        ztsImpl.validateRequest(request, "principal-domain", "test", true, false);

        // non-status requests are allowed on port 4443 with different status port

        ztsImpl.statusPort = 8443;

        ztsImpl.validateRequest(request, "principal-domain", "test");
        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);

        // status requests are not allowed on port 4443

        try {
            ztsImpl.validateStatusRequest(request, "principal-domain", "test");
            fail();
        } catch (ResourceException ignored) {
        }
    }

    @Test
    public void testValidateRequestRegularRequestPort() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = true;
        ztsImpl.statusPort = 8443;
        ztsImpl.oidcPort = 443;

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(8443);

        // status requests are allowed on port 8443

        ztsImpl.validateStatusRequest(request, "test", "principal-domain");

        // non-status requests are not allowed on port 8443

        try {
            ztsImpl.validateRequest(request, "principal-domain", "test");
            fail();
        } catch (ResourceException ignored) {
        }

        try {
            ztsImpl.validateOIDCRequest(request, "principal-domain", "test");
            fail();
        } catch (ResourceException ignored) {
        }

        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
            fail();
        } catch (ResourceException ignored) {
        }
    }

    @Test
    public void testValidateRequestOIDCRequestPort() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = true;

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(443);

        // with oidc port 0, all requests are ok

        ztsImpl.oidcPort = 0;
        ztsImpl.validateOIDCRequest(request, "test", "principal-domain");
        ztsImpl.validateRequest(request, "principal-domain", "test", false, true);
        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);

        // with status set to equal to https port - all requests are ok

        ztsImpl.oidcPort = 4443;
        ztsImpl.httpsPort = 4443;

        ztsImpl.validateOIDCRequest(request, "test", "principal-domain");
        ztsImpl.validateRequest(request, "principal-domain", "test", false, true);
        ztsImpl.validateRequest(request, "principal-domain", "test", false, false);

        // oidc requests are allowed on port 443

        ztsImpl.oidcPort = 443;
        ztsImpl.validateOIDCRequest(request, "test", "principal-domain");

        // non-oidc requests are not allowed on port 443

        try {
            ztsImpl.validateRequest(request, "principal-domain", "test");
            fail();
        } catch (ResourceException ignored) {
        }

        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", false, false);
            fail();
        } catch (ResourceException ignored) {
        }
    }

    @Test
    public void testGetStatus() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        Status status = ztsImpl.getStatus(context);
        assertEquals(status.getCode(), ResourceException.OK);
    }

    @Test
    public void testGetStatusWithStatusFile() throws IOException {

        System.setProperty(ZTSConsts.ZTS_PROP_HEALTH_CHECK_PATH, "/tmp/zts-healthcheck");
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // without the file we should get failure - make sure
        // to delete it just in case left over from previous run

        File healthCheckFile = new File("/tmp/zts-healthcheck");
        healthCheckFile.delete();

        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        // create the status file

        new FileOutputStream(healthCheckFile).close();
        Status status = ztsImpl.getStatus(context);
        assertEquals(ResourceException.OK, status.getCode());

        // delete the status file

        healthCheckFile.delete();
        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_HEALTH_CHECK_PATH);
    }

    @Test
    public void testGetStatusWithStatusChecker() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // if the MockStatusCheckerNoException is set
        // the MockStatusCheckerNoException determines the server is healthy

        System.setProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS, MockStatusCheckerNoException.class.getName());
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        Status status = ztsImpl.getStatus(context);
        assertEquals(ResourceException.OK, status.getCode());

        // if the MockStatusCheckerThrowException is set
        // the MockStatusCheckerThrowException determines that there is a problem with the server

        System.setProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS,
                MockStatusCheckerThrowException.NoArguments.class.getName());
        ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            int code = com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
            String msg = com.yahoo.athenz.common.server.rest.ResourceException.symbolForCode(com.yahoo.athenz.zms.ResourceException.INTERNAL_SERVER_ERROR);
            assertEquals(new ResourceError().code(code).message(msg).toString(), ex.getData().toString());
        }

        System.setProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS,
                MockStatusCheckerThrowException.NotFound.class.getName());
        ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            int code = com.yahoo.athenz.common.server.rest.ResourceException.NOT_FOUND;
            String msg = com.yahoo.athenz.common.server.rest.ResourceException.symbolForCode(com.yahoo.athenz.zms.ResourceException.NOT_FOUND);
            assertEquals(new ResourceError().code(code).message(msg).toString(), ex.getData().toString());
        }

        System.setProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS,
                MockStatusCheckerThrowException.InternalServerErrorWithMessage.class.getName());
        ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            int code = com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
            String msg = "error message";
            assertEquals(new ResourceError().code(code).message(msg).toString(), ex.getData().toString());
        }

        System.setProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS,
                MockStatusCheckerThrowException.CauseRuntimeException.class.getName());
        ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;

        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            int code = com.yahoo.athenz.common.server.rest.ResourceException.INTERNAL_SERVER_ERROR;
            String msg = "runtime exception";
            assertEquals(new ResourceError().code(code).message(msg).toString(), ex.getData().toString());
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS);
    }

    @Test
    public void testGetStatusWithSigner() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;
        ztsImpl.statusCertSigner = true;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.getCACertificate(null)).thenReturn("ca-cert");
        ztsImpl.instanceCertManager = certManager;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        Status status = ztsImpl.getStatus(context);
        assertEquals(status.getCode(), ResourceException.OK);
    }

    @Test
    public void testGetStatusWithSignerFailure() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;
        ztsImpl.statusCertSigner = true;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.getCACertificate("aws")).thenReturn(null);
        ztsImpl.instanceCertManager = certManager;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.getStatus(context);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUserPrincipalMismatch() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(false);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Principal mismatch"));
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUser() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        Identity identity = ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
        assertNotNull(identity);
        assertNotNull(identity.getCertificate());
    }

    @Test
    public void testPostInstanceRefreshRequestByUserIdentityFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.generateX509Certificate(Mockito.anyString(), Mockito.anyString(),
                Mockito.anyString(), Mockito.anyString(), Mockito.anyInt(), Mockito.any())).thenReturn(null);
        ztsImpl.instanceCertManager = certManager;

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to generate identity"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUserCert() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("0");

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "user", "doe", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("TLS Certificates require ServiceTokens"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUserNoPublicKey() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("1");

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to retrieve public key"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUserInvalidRequest() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("1");

        String publicKeyName = "athenz.api_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "api", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid CSR - data mismatch"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUserPublicKeyMismatch() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("1");

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "ABCwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid CSR - public key mismatch"), ex.getMessage());
        }
    }

    @Test
    public void testValidateServiceX509RefreshRequest() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.1"), ServiceX509RefreshRequestStatus.SUCCESS);
    }

    @Test
    public void testValidateServiceX509RefreshRequestMismatchPublicKeys() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);
        certReq.setNormCsrPublicKey("mismatch-public-key");

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.1"), ServiceX509RefreshRequestStatus.PUBLIC_KEY_MISMATCH);
    }

    @Test
    public void testValidateServiceX509RefreshRequestNotAllowedIP() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        // our ip will not match 10.0.0.1 thus failure

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.2"), ServiceX509RefreshRequestStatus.IP_NOT_ALLOWED);
    }

    @Test
    public void testValidateServiceX509RefreshRequestMismatchDns() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/athenz.mismatch.dns.csr");
        String csr = new String(Files.readAllBytes(path));

        X509CertRequest certReq = new X509CertRequest(csr);
        assertNotNull(certReq);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.1"), ServiceX509RefreshRequestStatus.DNS_NAME_MISMATCH);
    }

    @Test
    public void testPostInstanceRefreshRequestByServiceCert() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.0.0.1");

        ResourceContext context = createResourceContext(principal, servletRequest);

        Identity identity = ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
        assertNotNull(identity);
        assertNotNull(identity.getCertificate());
    }

    @Test
    public void testPostInstanceRefreshRequestByServiceCertValidateFail() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("DNS_NAME_MISMATCH"), ex.getMessage());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByServiceCertValidateIPFail() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        path = Paths.get("src/test/resources/valid_provider_refresh.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "syncer", "v=S1,d=athenz;n=syncer;s=sig", 0, new CertificateAuthority());
        assertNotNull(principal);
        principal.setX509Certificate(cert);

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.0.0.1");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceManager.verifyCertRefreshIPAddress("10.0.0.1")).thenReturn(false);
        ztsImpl.instanceCertManager = instanceManager;

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }
    }

    @Test
    public void testPostInstanceRefreshRequestByUserInvalidCsr() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        String publicKeyName = "athenz.syncer_v0";
        final String ztsPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMp9ZHVDK2s/FyinpKpD7lSsU+d6TSRE\n"
                + "NVo6sdLrEpOaCJETsh+0Qc0knhALxBD1+B9gS5F2rAFgtug0R6savvMCAwEAAQ==\n"
                + "-----END PUBLIC KEY-----";
        ztsImpl.dataStore.getPublicKeyCache().put(publicKeyName, ztsPublicKey);

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr("csr")
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setKeyId("1");

        ZTSAuthorizer authorizer = Mockito.mock(ZTSAuthorizer.class);
        Mockito.when(authorizer.access("update", "athenz:service", principal, null)).thenReturn(true);
        ztsImpl.authorizer = authorizer;

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            ztsImpl.postInstanceRefreshRequest(context, "athenz", "syncer", req);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Unable to parse PKCS10 certificate request"), ex.getMessage());
        }
    }

    @Test
    public void testCheckRoleTokenAuthorizedServiceRequestNoAuthzService() {

        // null authorized service

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        zts.checkRoleTokenAuthorizedServiceRequest(principal, "athenz", "caller");

        // empty authorized service

        principal.setAuthorizedService("");
        zts.checkRoleTokenAuthorizedServiceRequest(principal, "athenz", "caller");
    }

    @Test
    public void testCheckRoleTokenAuthorizedServiceRequest() {

        // match authorized service - top level domain

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
        assertNotNull(principal);
        principal.setAuthorizedService("sports.api");

        zts.checkRoleTokenAuthorizedServiceRequest(principal, "sports", "caller");

        // match authorized service - subdomain

        principal.setAuthorizedService("sports.hockey.api");
        zts.checkRoleTokenAuthorizedServiceRequest(principal, "sports.hockey", "caller");

        // mismatch

        principal.setAuthorizedService("weather.api");
        try {
            zts.checkRoleTokenAuthorizedServiceRequest(principal, "sports", "caller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testIsAuthorizedServicePrincipal() {
        Principal principal = Mockito.mock(Principal.class);
        Mockito.when(principal.getAuthorizedService())
                .thenReturn(null)
                .thenReturn("")
                .thenReturn("service");

        assertFalse(zts.isAuthorizedServicePrincipal(principal));
        assertFalse(zts.isAuthorizedServicePrincipal(principal));
        assertTrue(zts.isAuthorizedServicePrincipal(principal));
    }

    @Test
    public void testReadOnlyMode() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true);
        ztsImpl.readOnlyMode = dynamicConfigBoolean;

        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "readonly",
                "v=S1;d=athenz;n=readonly;s=signature", 0, authority);

        ResourceContext ctx = createResourceContext(principal);

        try {
            ztsImpl.postRoleCertificateRequest(ctx, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.postInstanceRegisterInformation(ctx, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.postInstanceRefreshInformation(ctx, null, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.deleteInstanceIdentity(ctx, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.postInstanceRefreshRequest(ctx, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.postSSHCertRequest(ctx, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.postRoleCertificateRequestExt(ctx, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }
    }

    @Test
    public void testPostSSHRequest() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        SSHCertificates certs = new SSHCertificates();

        SSHCertRequestData data = new SSHCertRequestData();
        data.setDestinations(Arrays.asList("dest1", "dest2"));
        data.setPrincipals(Arrays.asList("user1", "user2"));
        data.setSources(Collections.singletonList("src"));
        data.setTouchPublicKey("publickey");

        SSHCertRequestMeta meta = new SSHCertRequestMeta();
        meta.setRequestor("req");
        meta.setOrigin("origin");
        meta.setClientInfo("info");
        meta.setSshClientVersion("1.2");
        meta.setCertType("user");

        SSHCertRequest certRequest = new SSHCertRequest();
        certRequest.setCertRequestData(data);
        certRequest.setCertRequestMeta(meta);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceManager.generateSSHCertificates(Mockito.any(), eq(certRequest)))
                .thenReturn(certs);

        ztsImpl.instanceCertManager = instanceManager;

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);
        Response response = ztsImpl.postSSHCertRequest(context, certRequest);
        assertEquals(response.getStatus(), 201);
    }

    @Test
    public void testPostSSHRequestException() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        SSHCertRequestData data = new SSHCertRequestData();
        data.setDestinations(Arrays.asList("dest1", "dest2"));
        data.setPrincipals(Arrays.asList("user1", "user2"));
        data.setSources(Collections.singletonList("src"));
        data.setTouchPublicKey("publickey");

        SSHCertRequestMeta meta = new SSHCertRequestMeta();
        meta.setRequestor("req");
        meta.setOrigin("origin");
        meta.setClientInfo("info");
        meta.setSshClientVersion("1.2");
        meta.setCertType("user");

        SSHCertRequest certRequest = new SSHCertRequest();
        certRequest.setCertRequestData(data);
        certRequest.setCertRequestMeta(meta);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceManager.generateSSHCertificates(Mockito.any(), eq(certRequest)))
                .thenThrow(new com.yahoo.athenz.common.server.rest.ResourceException(400, "Failed to get ssh certs"));

        ztsImpl.instanceCertManager = instanceManager;

        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        assertNotNull(principal);

        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);

        ResourceContext context = createResourceContext(principal);

        try {
            ztsImpl.postSSHCertRequest(context, certRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Failed to get ssh certs"));
        }
    }

    @Test
    public void testGetServerHostname() throws UnknownHostException {

        InetAddress localhost = java.net.InetAddress.getLocalHost();
        final String serverHostName = localhost.getCanonicalHostName();

        assertEquals(serverHostName, ZTSImpl.getServerHostName());

        System.setProperty(ZTSConsts.ZTS_PROP_HOSTNAME, "server1.athenz");
        assertEquals("server1.athenz", ZTSImpl.getServerHostName());
        System.clearProperty(ZTSConsts.ZTS_PROP_HOSTNAME);
    }

    @Test
    public void testLoadInvalidClasses() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        System.setProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS, "invalid.class");
        assertNull(ztsImpl.getChangeLogStore("/tmp/zts_server_unit_tests/zts_root"));
        System.clearProperty(ZTSConsts.ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, "invalid.class");
        try {
            ztsImpl.loadMetricObject();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid metric class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_HOSTNAME_RESOLVER_FACTORY_CLASS, "invalid.class");
        try {
            ztsImpl.loadHostnameResolver();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid HostnameResolverFactory class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_HOSTNAME_RESOLVER_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "invalid.class");
        try {
            ztsImpl.loadServicePrivateKey();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid private key store"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);

        System.setProperty(ZTSConsts.ZTS_PROP_AUDIT_LOGGER_FACTORY_CLASS, "invalid.class");
        try {
            ztsImpl.loadAuditLogger();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid audit logger class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_AUDIT_LOGGER_FACTORY_CLASS);

        assertNull(ztsImpl.getAuthority("invalid.class"));

        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES, "invalid.class");
        try {
            ztsImpl.loadAuthorities();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid authority"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES);

        System.setProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS, "invalid.class");
        try {
            ztsImpl.loadStatusChecker();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("Invalid status checker factory class"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS);
    }

    @Test
    public void testLoadMockAuthority() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES, "com.yahoo.athenz.zts.MockAuthority");
        System.setProperty(ZTSConsts.ZTS_PROP_USER_AUTHORITY_CLASS, "com.yahoo.athenz.zts.MockAuthority");

        ztsImpl.loadAuthorities();
        ztsImpl.setAuthorityKeyStore();
        assertNotNull(ztsImpl.userAuthority);
        assertEquals(ztsImpl.userAuthority, ztsImpl.authorities.getAuthorities().get(0));

        System.clearProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES);
        System.clearProperty(ZTSConsts.ZTS_PROP_USER_AUTHORITY_CLASS);
    }

    @Test
    public void testConfigurationSettings() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        System.clearProperty(ZTSConsts.ZTS_PROP_AUTHORIZED_PROXY_USERS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES);
        System.clearProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST);

        System.setProperty(ZTSConsts.ZTS_PROP_USER_DOMAIN_ALIAS, "alias");

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        assertNull(ztsImpl.authorizedProxyUsers);
        assertNull(ztsImpl.authFreeUriList);
        assertNull(ztsImpl.authFreeUriSet);
        assertNull(ztsImpl.validCertSubjectOrgValues);

        assertEquals(ztsImpl.userDomainAliasPrefix, "alias.");

        // some more config values tests

        System.clearProperty(ZTSConsts.ZTS_PROP_USER_DOMAIN_ALIAS);
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/uri1,/uri1+,/uri2");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_OU_VALUES, "Athenz|Athens");

        ztsImpl = new ZTSImpl(mockCloudStore, store);
        assertEquals(ztsImpl.authFreeUriList.size(), 1);
        assertEquals(ztsImpl.authFreeUriSet.size(), 2);
        assertEquals(ztsImpl.validCertSubjectOrgUnitValues.size(), 2);
        assertTrue(ztsImpl.validCertSubjectOrgUnitValues.contains("Athenz"));
        assertTrue(ztsImpl.validCertSubjectOrgUnitValues.contains("Athens"));

        System.clearProperty(ZTSConsts.ZTS_PROP_USER_DOMAIN_ALIAS);
        System.clearProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_OU_VALUES);
    }

    @Test
    public void testGenerateZTSServiceIdentity() {

        ServiceIdentity zmsService = new ServiceIdentity();
        zmsService.setName("athenz.api");

        com.yahoo.athenz.zts.ServiceIdentity ztsService = zts.generateZTSServiceIdentity(zmsService);
        assertEquals(ztsService.getName(), "athenz.api");
        assertNull(ztsService.getPublicKeys());
    }

    @Test
    public void testGetPolicyListEmptyValues() {

        DomainData domainData = new DomainData();
        SignedPolicies signedPolicies = new SignedPolicies();
        domainData.setPolicies(signedPolicies);

        List<com.yahoo.athenz.zts.Policy> policies = zts.getPolicyList(domainData, null);
        assertTrue(policies.isEmpty());

        DomainPolicies domainPolicies = new DomainPolicies();
        signedPolicies.setContents(domainPolicies);

        policies = zts.getPolicyList(domainData, null);
        assertTrue(policies.isEmpty());

        Policy policy = new Policy();
        policy.setName("policy1");

        List<Policy> zmsPolicies = new ArrayList<>();
        zmsPolicies.add(policy);

        domainPolicies.setPolicies(zmsPolicies);

        policies = zts.getPolicyList(domainData, null);
        assertEquals(1, policies.size());
        assertNull(policies.get(0).getAssertions());
    }

    @Test
    public void testGetAssertionEffect() {
        assertEquals(zts.getAssertionEffect(null), com.yahoo.athenz.zts.AssertionEffect.ALLOW);
        assertEquals(zts.getAssertionEffect(AssertionEffect.ALLOW), com.yahoo.athenz.zts.AssertionEffect.ALLOW);
        assertEquals(zts.getAssertionEffect(AssertionEffect.DENY), com.yahoo.athenz.zts.AssertionEffect.DENY);
    }

    @Test
    public void testGetCertRequestExpiryTime() {

        assertEquals(zts.getServiceCertRequestExpiryTime(100, null), 100);
        assertEquals(zts.getServiceCertRequestExpiryTime(100, -100), 100);
        assertEquals(zts.getServiceCertRequestExpiryTime(100, 80), 80);
        assertEquals(zts.getServiceCertRequestExpiryTime(100, 120), 100);

        assertEquals(zts.getServiceCertRequestExpiryTime(0, null), 0);
        assertEquals(zts.getServiceCertRequestExpiryTime(0, 80), 80);
        assertEquals(zts.getServiceCertRequestExpiryTime(0, 120), 120);
        assertEquals(zts.getServiceCertRequestExpiryTime(0, -110), 0);
    }

    @Test
    public void testLoadHostnameResolver() {

        System.setProperty(ZTSConsts.ZTS_PROP_HOSTNAME_RESOLVER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.TestHostnameResolverFactory");

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        assertNotNull(ztsImpl.hostnameResolver);

        System.clearProperty(ZTSConsts.ZTS_PROP_HOSTNAME_RESOLVER_FACTORY_CLASS);
    }

    @Test
    public void testPostAccessTokenRequest() throws UnsupportedEncodingException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertNotNull(claims.getBody().getId());
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals("writers", claims.getBody().get("scope"));
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));

        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context1 = createResourceContext(principal1);

        resp = ztsImpl.postAccessTokenRequest(context1,
                "grant_type=client_credentials&scope=coretech:domain&expires_in=100");
        assertNotNull(resp);
        assertEquals("coretech:role.readers coretech:role.writers", resp.getScope());

        accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);
        assertEquals(Integer.valueOf(100), resp.getExpires_in());

        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user1", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(100 * 1000, claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime());
        assertEquals("readers writers", claims.getBody().get("scope"));
    }

    @Test
    public void testPostAccessTokenRequestRoleAuthority() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
            assertEquals(403, ex.getCode());
        }

        // now add the second role as well

        principalRoles.add("coretech:role.writers");

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain&expires_in=100");
        assertNotNull(resp);
        assertEquals("coretech:role.readers coretech:role.writers", resp.getScope());
    }

    @Test
    public void testPostAccessTokenRequestmTLSBound() throws IOException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertNotNull(claims.getBody().getId());
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
        assertEquals("writers", claims.getBody().get("scope"));

        LinkedHashMap<String, Object> cnf = (LinkedHashMap<String, Object>) claims.getBody().get("cnf");
        assertEquals("A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0", cnf.get("x5t#S256"));
    }

    @Test
    public void testPostAccessTokenRequestECPrivateKey() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private_ec.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertNotNull(claims.getBody().getId());
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
        assertEquals("writers", claims.getBody().get("scope"));
    }

    @Test
    public void testPostAccessTokenRequestSingleRole() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
    public void testPostAccessTokenRequestOpenIdScope() throws UnsupportedEncodingException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech:role.writers openid", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        String idToken = resp.getId_token();
        assertNotNull(idToken);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("writers", claims.getBody().get("scope"));
        assertEquals(240 * 1000, claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime());
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOpenIDIssuer() throws UnsupportedEncodingException {

        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://openid.athenz.cloud:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER, "https://oauth.athenz.cloud:4443/zts/v1");

        testPostAccessTokenRequestOpenIdScope("https://openid.athenz.cloud:4443/zts/v1", "&openid_issuer=true");

        System.clearProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER);
        System.clearProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER);
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOAuthIssuer() throws UnsupportedEncodingException {

        System.setProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER, "https://openid.athenz.cloud:4443/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER, "https://oauth.athenz.cloud:4443/zts/v1");

        testPostAccessTokenRequestOpenIdScope("https://oauth.athenz.cloud:4443/zts/v1", "&openid_issuer=false");

        System.clearProperty(ZTSConsts.ZTS_PROP_OAUTH_ISSUER);
        System.clearProperty(ZTSConsts.ZTS_PROP_OPENID_ISSUER);
    }

    private void testPostAccessTokenRequestOpenIdScope(final String issuer, final String reqComp) {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech:role.writers openid", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals(issuer, claims.getBody().getIssuer());
        assertEquals("writers", claims.getBody().get("scope"));
        assertEquals(240 * 1000, claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime());

        String idTokenStr = resp.getId_token();
        assertNotNull(idTokenStr);

        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(idTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals(issuer, claims.getBody().getIssuer());
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeMaxTimeout() throws UnsupportedEncodingException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech:role.writers openid", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        String idToken = resp.getId_token();
        assertNotNull(idToken);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(idToken);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);

        // the value should be 12 hours - the default max

        assertEquals(12 * 60 * 60 * 1000, claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime());
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOnly() throws UnsupportedEncodingException {

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
            assertEquals(403, ex.getCode());
        }
    }

    @Test
    public void testPostAccessTokenRequestOpenIdScopeOnlyDisabled() throws UnsupportedEncodingException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        AccessTokenRequest.setSupportOpenIdScope(false);

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
            assertEquals(403, ex.getCode());
        }

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain openid coretech:service.api");
        assertNotNull(resp);
        assertEquals("coretech:role.writers", resp.getScope());

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
            assertEquals(404, ex.getCode());
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
            assertEquals(403, ex.getCode());
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
            assertEquals(400, ex.getCode());
        }

        try {
            zts.postAccessTokenRequest(context, "");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=unknown_type&scope=openid");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid grant request"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type%=client_credentials");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid grant request"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials%");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid grant request"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid grant request"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("no scope provided"));
        }

        try {
            zts.postAccessTokenRequest(context, "grant_type=client_credentials&scope=");
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("no scope provided"));
        }
    }

    @Test
    public void testPostAccessTokenRequestProxyUser() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech-proxy2:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.joe", claims.getBody().getSubject());
        assertEquals("user_domain.proxy-user1", claims.getBody().get("proxy"));
        assertEquals("coretech-proxy2", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
    }

    @Test
    public void testPostAccessTokenRequestProxyUserMismatchRolesIntersection() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        assertEquals("coretech-proxy3:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.joe", claims.getBody().getSubject());
        assertEquals("user_domain.proxy-user1", claims.getBody().get("proxy"));
        assertEquals("coretech-proxy3", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
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
    public void testPostAccessTokenRequestProxyUserOpenidScope() throws UnsupportedEncodingException {

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
    public void testPostAccessTokenRequestProxyUserSpecificRole() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.joe", claims.getBody().getSubject());
        assertEquals("user_domain.proxy-user1", claims.getBody().get("proxy"));
        assertEquals("coretech-proxy4", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
    }

    @Test
    public void testPostRoleCertificateExtRequest() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleCertificate roleCertificate = zts.postRoleCertificateRequestExt(context, req);
        assertNotNull(roleCertificate);
    }

    @Test
    public void testPostRoleCertificateExtRequestUnknownDomain() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(404, ex.getCode());
            assertTrue(ex.getMessage().contains("No such domain: coretech"));
        }
    }

    @Test
    public void testPostRoleCertificateRequestExtUnauthorizedRole() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        // user101 does not have access to role readers

        Principal principal = SimplePrincipal.create("user_domain", "user101",
                "v=U1;d=user_domain;n=user101;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
            assertTrue(ex.getMessage().contains("is not included in the requested role(s)"));
        }
    }

    @Test
    public void testPostRoleCertificateExtInvalidProxyUserRequest() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry)
                .setProxyForPrincipal("user_domain.user1");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user100",
                "v=U1;d=user_domain;n=proxy-user100;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testPostRoleCertificateExtAuthzService() {

        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        assertNotNull(principal);
        ((SimplePrincipal) principal).setAuthorizedService("sports.hockey.api");

        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorized Service Principals not allowed"));
        }
    }

    @Test
    public void testPostRoleCertificateExtInvalidCSR() {

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr("invalid-csr").setExpiryTime(3600L);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);

        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Unable to parse PKCS10 CSR"));
        }
    }

    @Test
    public void testPostRoleCertificateExtUserAccessForbidden() {

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("principal user_domain.user1 is not included in the requested role(s) in domain coretech"));
        }
    }

    @Test
    public void testPostRoleCertificateExtProxyAccessForbidden() {

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("principal user_domain.proxy-user1 is not included in the requested role(s) in domain coretech"));
        }
    }

    @Test
    public void testPostRoleCertificateExtValidateFailed() {

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user2"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user2",
                "v=U1;d=user_domain;n=proxy-user2;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Unable to validate cert request"));
        }
    }

    @Test
    public void testPostRoleCertificateExtRequestNullCertReturn() {

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.generateIdentity("aws", null, ROLE_CERT_CORETECH_REQUEST,
                "user_domain.user1", "client", 3600, Priority.Unspecified_priority)).thenReturn(null);
        zts.instanceCertManager = certManager;

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("Unable to create certificate from the cert signer"));
        }
    }

    @Test
    public void testPostRoleCertificateExtInvalidRoleDomain() {

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains("No such domain: coretech"));
        }
    }

    @Test
    public void testGetPrincipalDomain() {
        Principal principal = SimplePrincipal.create("sports", "api",
                "creds", 0, new PrincipalAuthority());

        ResourceContext ctx = createResourceContext(principal);
        assertEquals(zts.logPrincipalAndGetDomain(ctx), "sports");
    }

    @Test
    public void testGetPrincipalDomainNull() {

        ResourceContext ctx = createResourceContext(null);
        assertNull(zts.logPrincipalAndGetDomain(ctx));
    }

    @Test
    public void testValidatePrincipalNotRoleIdentity() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("sports", "api",
                "creds", 0, new PrincipalAuthority());
        assertNotNull(principal);

        // no errors with regular principal

        zts.validatePrincipalNotRoleIdentity(principal, "testCaller");

        // set roles and check for exception

        principal.setRoles(Collections.singletonList("role1"));
        try {
            zts.validatePrincipalNotRoleIdentity(principal, "testCaller");
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }
    }

    @Test
    public void testIsPrincipalRoleCertificateAccessValid() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("sports", "api",
                "creds", 0, new PrincipalAuthority());
        assertNotNull(principal);

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        roles.add("writers");

        // without any roles we should return true

        assertTrue(zts.isPrincipalRoleCertificateAccessValid(principal, "domain1", roles));
        assertTrue(zts.isPrincipalRoleCertificateAccessValid(principal, "domain2", roles));

        // with empty roles we should have same behavior

        principal.setRoles(Collections.emptyList());
        assertTrue(zts.isPrincipalRoleCertificateAccessValid(principal, "domain1", roles));
        assertTrue(zts.isPrincipalRoleCertificateAccessValid(principal, "domain2", roles));

        // set the principal with roles not matching

        List<String> principalRoles = new ArrayList<>();
        principalRoles.add("domain1:role.admin");
        principalRoles.add("domain1:role.editor");
        principal.setRoles(principalRoles);

        // we should get failure for both

        assertFalse(zts.isPrincipalRoleCertificateAccessValid(principal, "domain1", roles));
        assertFalse(zts.isPrincipalRoleCertificateAccessValid(principal, "domain2", roles));

        // set principal roles to include one of the roles

        principalRoles.add("domain1:role.readers");

        // we should get failure still

        assertFalse(zts.isPrincipalRoleCertificateAccessValid(principal, "domain1", roles));
        assertFalse(zts.isPrincipalRoleCertificateAccessValid(principal, "domain2", roles));

        // now make sure it has both roles

        principalRoles.add("domain1:role.writers");

        // should get success with correct domain name and failure with domain2

        assertTrue(zts.isPrincipalRoleCertificateAccessValid(principal, "domain1", roles));
        assertFalse(zts.isPrincipalRoleCertificateAccessValid(principal, "domain2", roles));
    }

    @Test
    public void testGetProxyForPrincipalValue() {

        // empty strings should return null

        assertNull(zts.getProxyForPrincipalValue("", "athenz.syncer", "athenz", "getToken"));

        // invalid proxy users should return exception

        try {
            zts.getProxyForPrincipalValue("invalid user", "athenz.syncer", "athenz", "getAccessToken");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // valid authorized user should return the proxy user

        assertEquals("user_domain.proxy", zts.getProxyForPrincipalValue("user_domain.proxy",
                "user_domain.proxy-user1", "user_domain", "getAccessToken"));

        // invalid authorized proxy user should return 403

        try {
            zts.getProxyForPrincipalValue("user_domain.proxy", "user_domain.proxy-unknown",
                    "user_domain", "getAccessToken");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }

    @Test
    public void testGetConfiguredRoleExpiryTimeMinsNoSettings() {

        DataCache data = new DataCache();
        Role role = new Role().setName("athenz:role.admin");
        data.processRole(role);
        data.setDomainData(new DomainData());

        Set<String> roles = new HashSet<>();
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 0);

        roles.add("readers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 0);

        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 0);
    }

    @Test
    public void testGetConfiguredRoleExpiryTimeMinsDomainSettings() {

        DataCache data = new DataCache();
        Role role = new Role().setName("athenz:role.admin");
        data.processRole(role);
        DomainData domainData = new DomainData();
        domainData.setRoleCertExpiryMins(120);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("readers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);
    }

    @Test
    public void testGetConfiguredRoleExpiryTimeMinsInvalidDomainSettings() {

        DataCache data = new DataCache();
        Role role = new Role().setName("athenz:role.admin");
        data.processRole(role);
        DomainData domainData = new DomainData();
        domainData.setRoleCertExpiryMins(-60);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 0);

        roles.add("readers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 0);

        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 0);
    }

    @Test
    public void testGetConfiguredRoleExpiryTimeMinsInvalidRoleSettings() {

        DataCache data = new DataCache();
        Role role = new Role().setName("athenz:role.admin").setCertExpiryMins(-30);
        data.processRole(role);
        DomainData domainData = new DomainData();
        domainData.setRoleCertExpiryMins(120);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("readers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);
    }

    @Test
    public void testGetConfiguredRoleExpiryTimeMinsRoleSettings() {

        DataCache data = new DataCache();
        Role role = new Role().setName("athenz:role.admin").setCertExpiryMins(180);
        data.processRole(role);
        DomainData domainData = new DomainData();
        domainData.setRoleCertExpiryMins(120);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("readers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 180);
    }

    @Test
    public void testGetConfiguredRoleExpiryTimeMinsMultipleRoleSettings() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.admin").setCertExpiryMins(60);
        data.processRole(role1);
        Role role2 = new Role().setName("athenz:role.readers").setCertExpiryMins(80);
        data.processRole(role2);
        Role role3 = new Role().setName("athenz:role.writers").setCertExpiryMins(70);
        data.processRole(role3);

        DomainData domainData = new DomainData();
        domainData.setRoleCertExpiryMins(120);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 120);

        roles.add("readers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 80);

        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 60);

        roles.add("writers");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 60);
    }


    @Test
    public void testDetermineRoleCertTimeout() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.admin").setCertExpiryMins(60);
        data.processRole(role1);

        DomainData domainData = new DomainData();
        domainData.setRoleCertExpiryMins(120);
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("admin");
        assertEquals(zts.getConfiguredRoleCertExpiryTimeMins(data, roles), 60);
        assertEquals(zts.determineRoleCertTimeout(data, roles, 120), 60);
        assertEquals(zts.determineRoleCertTimeout(data, roles, -1), 60);
        assertEquals(zts.determineRoleCertTimeout(data, roles, 30), 30);
    }

    @Test
    public void testDetermineRoleCertTimeoutNoSetting() {

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.admin").setCertExpiryMins(60);
        data.processRole(role1);

        DomainData domainData = new DomainData();
        data.setDomainData(domainData);

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        assertEquals(zts.determineRoleCertTimeout(data, roles, 120), 120);
        assertEquals(zts.determineRoleCertTimeout(data, roles, -1), 0);
        assertEquals(zts.determineRoleCertTimeout(data, roles, 60), 60);
    }

    @Test
    public void testGetConfiguredRoleListExpiryTimeMinsNoList() {

        Map<String, String[]> requestedRoleList = new HashMap<>();
        String[] roles = new String[1];
        roles[0] = "readers";
        requestedRoleList.put("athenz", roles);
        requestedRoleList.put("coretech", roles);

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.admin").setCertExpiryMins(60);
        data.processRole(role1);

        assertEquals(zts.getConfiguredRoleListExpiryTimeMins(requestedRoleList), 0);
    }

    @Test
    public void testGetConfiguredRoleListExpiryTimeMinsRoleSetting() {

        Map<String, String[]> requestedRoleList = new HashMap<>();
        String[] roles = new String[1];
        roles[0] = "readers";
        requestedRoleList.put("athenz", roles);
        requestedRoleList.put("coretech", roles);

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers").setCertExpiryMins(60);
        data.processRole(role1);

        DomainData domainData = new DomainData();
        data.setDomainData(domainData);

        zts.dataStore.getCacheStore().put("athenz", data);

        assertEquals(zts.getConfiguredRoleListExpiryTimeMins(requestedRoleList), 60);
    }

    @Test
    public void testDetermineRoleCertTimeoutRequestedRoleList() {

        Map<String, String[]> requestedRoleList = new HashMap<>();
        String[] roles = new String[1];
        roles[0] = "readers";
        requestedRoleList.put("athenz", roles);
        requestedRoleList.put("coretech", roles);

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers").setCertExpiryMins(60);
        data.processRole(role1);

        DomainData domainData = new DomainData();
        data.setDomainData(domainData);

        zts.dataStore.getCacheStore().put("athenz", data);

        assertEquals(zts.getConfiguredRoleListExpiryTimeMins(requestedRoleList), 60);
        assertEquals(zts.determineRoleCertTimeout(requestedRoleList, 30), 30);
        assertEquals(zts.determineRoleCertTimeout(requestedRoleList, 90), 60);
    }

    @Test
    public void testGetConfiguredRoleListExpiryTimeMinsDomainSetting() {

        Map<String, String[]> requestedRoleList = new HashMap<>();
        String[] roles = new String[1];
        roles[0] = "readers";
        requestedRoleList.put("athenz", roles);
        requestedRoleList.put("coretech", roles);

        DataCache data = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers");
        data.processRole(role1);

        DomainData domainData = new DomainData().setRoleCertExpiryMins(90);
        data.setDomainData(domainData);

        zts.dataStore.getCacheStore().put("athenz", data);

        assertEquals(zts.getConfiguredRoleListExpiryTimeMins(requestedRoleList), 90);
    }

    @Test
    public void testGetConfiguredRoleListExpiryTimeMinsMultipleMixedSetting() {

        Map<String, String[]> requestedRoleList = new HashMap<>();
        String[] roles = new String[1];
        roles[0] = "readers";
        requestedRoleList.put("athenz", roles);
        requestedRoleList.put("coretech", roles);

        DataCache data1 = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers").setCertExpiryMins(60);
        data1.processRole(role1);

        DomainData domainData1 = new DomainData();
        data1.setDomainData(domainData1);

        DataCache data2 = new DataCache();
        Role role2 = new Role().setName("coretech:role.readers");
        data2.processRole(role2);

        DomainData domainData2 = new DomainData().setRoleCertExpiryMins(120);
        data2.setDomainData(domainData2);

        zts.dataStore.getCacheStore().put("athenz", data1);
        zts.dataStore.getCacheStore().put("coretech", data2);

        assertEquals(zts.getConfiguredRoleListExpiryTimeMins(requestedRoleList), 60);
    }

    @Test
    public void testGetConfiguredRoleListExpiryTimeMinsMultipleDomainSetting() {

        Map<String, String[]> requestedRoleList = new HashMap<>();
        String[] roles = new String[1];
        roles[0] = "readers";
        requestedRoleList.put("athenz", roles);
        requestedRoleList.put("coretech", roles);

        DataCache data1 = new DataCache();
        Role role1 = new Role().setName("athenz:role.readers");
        data1.processRole(role1);

        DomainData domainData1 = new DomainData().setRoleCertExpiryMins(120);
        data1.setDomainData(domainData1);

        DataCache data2 = new DataCache();
        Role role2 = new Role().setName("coretech:role.readers");
        data2.processRole(role2);

        DomainData domainData2 = new DomainData().setRoleCertExpiryMins(90);
        data2.setDomainData(domainData2);

        zts.dataStore.getCacheStore().put("athenz", data1);
        zts.dataStore.getCacheStore().put("coretech", data2);

        assertEquals(zts.getConfiguredRoleListExpiryTimeMins(requestedRoleList), 90);
    }

    @Test
    public void testGetCertificateAuthorityBundle() {

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file.json");
        ztsImpl.instanceCertManager = new InstanceCertManager(null, null, null, true, null);

        CertificateAuthorityBundle bundle = ztsImpl.getCertificateAuthorityBundle(context, "athenz");
        assertNotNull(bundle);

        bundle = ztsImpl.getCertificateAuthorityBundle(context, "system");
        assertNotNull(bundle);

        bundle = ztsImpl.getCertificateAuthorityBundle(context, "ssh");
        assertNotNull(bundle);

        try {
            ztsImpl.getCertificateAuthorityBundle(context, "unknown");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        try {
            ztsImpl.getCertificateAuthorityBundle(context, "athenz test");
            fail();
        } catch (ResourceException ignored) {
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME);
    }

    @Test
    public void testLoadServerPrivateKey() {

        zts.privateOrigKey = null;
        zts.privateECKey = null;
        zts.privateRSAKey = null;

        // first we try with ec private key only

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, "src/test/resources/unit_test_zts_private_ec.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateECKey);
        assertNull(zts.privateRSAKey);
        assertNull(zts.privateOrigKey);

        assertEquals(zts.privateECKey, zts.getServerPrivateKey("EC"));
        assertEquals(zts.privateECKey, zts.getServerPrivateKey("RSA"));
        assertEquals(zts.privateECKey, zts.getServerPrivateKey("UNKNOWN"));

        List<String> algValues = zts.getSupportedSigningAlgValues();
        assertEquals(1, algValues.size());
        assertTrue(algValues.contains("ES256"));

        // now let's try the rsa key

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateRSAKey);
        assertNull(zts.privateECKey);
        assertNull(zts.privateOrigKey);

        assertEquals(zts.privateRSAKey, zts.getServerPrivateKey("EC"));
        assertEquals(zts.privateRSAKey, zts.getServerPrivateKey("RSA"));
        assertEquals(zts.privateRSAKey, zts.getServerPrivateKey("UNKNOWN"));

        algValues = zts.getSupportedSigningAlgValues();
        assertEquals(1, algValues.size());
        assertTrue(algValues.contains("RS256"));

        // now let's try both keys

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, "src/test/resources/unit_test_zts_private_ec.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateRSAKey);
        assertNotNull(zts.privateECKey);
        assertNull(zts.privateOrigKey);

        assertEquals(zts.privateECKey, zts.getServerPrivateKey("EC"));
        assertEquals(zts.privateRSAKey, zts.getServerPrivateKey("RSA"));
        assertEquals(zts.privateECKey, zts.getServerPrivateKey("UNKNOWN"));

        algValues = zts.getSupportedSigningAlgValues();
        assertEquals(2, algValues.size());
        assertTrue(algValues.contains("ES256"));
        assertTrue(algValues.contains("RS256"));

        // now back to our regular key setup

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateOrigKey);
        assertNull(zts.privateECKey);
        assertNull(zts.privateRSAKey);

        assertEquals(zts.privateOrigKey, zts.getServerPrivateKey("EC"));
        assertEquals(zts.privateOrigKey, zts.getServerPrivateKey("RSA"));
        assertEquals(zts.privateOrigKey, zts.getServerPrivateKey("UNKNOWN"));
    }

    @Test
    public void testGetInstanceRegisterQueryLog() {

        assertEquals("provider=aws&certReqInstanceId=id001&hostname=athenz.io",
                zts.getInstanceRegisterQueryLog("aws", "id001", "athenz.io"));
        assertEquals("provider=aws&certReqInstanceId=id001", zts.getInstanceRegisterQueryLog("aws", "id001", null));
        assertEquals("provider=aws&hostname=athenz.io", zts.getInstanceRegisterQueryLog("aws", null, "athenz.io"));
        assertEquals("provider=aws", zts.getInstanceRegisterQueryLog("aws", null, null));
        assertEquals("provider=aws", zts.getInstanceRegisterQueryLog("aws", null, null));

        // our max length is 1024 so we'll use the following check
        // 46 chars + hostname so we'll get create a string with
        // 978 chars and then pass some more in the api

        StringBuilder hostnameBuilder = new StringBuilder(978);
        hostnameBuilder.append("123456".repeat(163));

        final String check = "provider=aws&certReqInstanceId=id001&hostname=" + hostnameBuilder;
        assertEquals(check, zts.getInstanceRegisterQueryLog("aws", "id001", hostnameBuilder + "01234"));
    }

    @Test
    public void testGetQueryLogData() {

        String request = "data\ntest\ragain";
        assertEquals(zts.getQueryLogData(request), "data_test_again");

        // generate a string with 1024 length

        request = "0123456789012345".repeat(64);
        assertEquals(zts.getQueryLogData(request + "abcd"), request);
    }

    @Test
    public void testGenerateSSHCertRecord() {

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SSHCertRecord sshRecord = zts.generateSSHCertRecord(context, "api", "id001", "127.0.0.1");
        assertEquals(sshRecord.getPrivateIP(), "127.0.0.1");
        assertEquals(sshRecord.getClientIP(), MOCKCLIENTADDR);
        assertEquals(sshRecord.getService(), "api");
        assertEquals(sshRecord.getInstanceId(), "id001");

        sshRecord = zts.generateSSHCertRecord(context, "api", "id001", "");
        assertEquals(sshRecord.getPrivateIP(), MOCKCLIENTADDR);
        assertEquals(sshRecord.getClientIP(), MOCKCLIENTADDR);

        sshRecord = zts.generateSSHCertRecord(context, "api", "id001", null);
        assertEquals(sshRecord.getPrivateIP(), MOCKCLIENTADDR);
        assertEquals(sshRecord.getClientIP(), MOCKCLIENTADDR);
    }

    @Test
    public void testRecordMetricsUnauthenticated() {
        zts.metric = Mockito.mock(Metric.class);
        Mockito.when(mockServletRequest.getMethod()).thenReturn("GET");
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) zts.newResourceContext(mockServletContext, mockServletRequest,
                mockServletResponse, "someApiMethod");
        String testDomain = "testDomain";
        int httpStatus = 200;
        ctx.setRequestDomain(testDomain);
        zts.recordMetrics(ctx, httpStatus);
        Mockito.verify(zts.metric,
                times(1)).increment (
                eq("zts_api"),
                eq(testDomain),
                eq(null),
                eq("GET"),
                eq(httpStatus),
                eq("someapimethod"));
        Mockito.verify(zts.metric,
                times(1)).stopTiming (
                eq(ctx.getTimerMetric()),
                eq(testDomain),
                eq(null),
                eq("GET"), eq(httpStatus), eq("someapimethod_timing"));
        Mockito.verify(zts.metric,
                times(1)).startTiming (
                eq("zts_api_latency"),
                eq(null),
                eq(null),
                eq("GET"),
                eq("someapimethod"));
    }

    @Test
    public void testRecordMetricsAuthenticated() {
        zts.metric = Mockito.mock(Metric.class);
        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) createResourceContext(principal);
        String testDomain = "testDomain";
        int httpStatus = 200;
        String httpMethod = "GET";
        Mockito.when(ctx.getRequestDomain()).thenReturn(testDomain);
        Mockito.when(ctx.getApiName()).thenReturn("someapimethod");
        Mockito.when(ctx.getHttpMethod()).thenReturn(httpMethod);
        zts.recordMetrics(ctx, httpStatus);
        Mockito.verify(zts.metric,
                times(1)).increment (
                eq("zts_api"),
                eq(testDomain),
                eq("user_domain"),
                eq(httpMethod),
                eq(httpStatus),
                eq("someapimethod"));
        Mockito.verify(zts.metric,
                times(1)).stopTiming (
                eq(ctx.getTimerMetric()),
                eq(testDomain),
                eq("user_domain"),
                eq(httpMethod), eq(httpStatus), eq("someapimethod_timing"));
    }

    @Test
    public void testRecordMetricsNoCtx() {
        int httpStatus = 200;
        zts.metric = Mockito.mock(Metric.class);
        zts.recordMetrics(null, httpStatus);
        Mockito.verify(zts.metric,
                times(1)).increment (
                eq("zts_api"),
                eq(null),
                eq(null),
                eq(null),
                eq(httpStatus),
                eq(null));
        Mockito.verify(zts.metric,
                times(1)).stopTiming (
                eq(null),
                eq(null),
                eq(null),
                eq(null), eq(httpStatus), eq(null));
    }

    @Test
    public void testProcessCertRecordChange() {
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setCurrentIP("10.10.11.12");
        certRecord.setHostName("host1.localhost");
        certRecord.setSvcDataUpdateTime(null);

        zts.processCertRecordChange(certRecord, "10.10.11.12", "host1.localhost");
        assertNull(certRecord.getSvcDataUpdateTime());

        zts.processCertRecordChange(certRecord, "10.10.11.13", "host1.localhost");
        assertNotNull(certRecord.getSvcDataUpdateTime());

        certRecord.setSvcDataUpdateTime(null);
        zts.processCertRecordChange(certRecord, "10.10.11.12", "host2.localhost");
        assertNotNull(certRecord.getSvcDataUpdateTime());
    }

    @Test
    public void testCertRecordChanged() {
        assertFalse(zts.certRecordChanged(null, null));
        assertTrue(zts.certRecordChanged(null, ""));
        assertTrue(zts.certRecordChanged("", null));
        assertFalse(zts.certRecordChanged("", ""));
        assertFalse(zts.certRecordChanged("test1", "test1"));
        assertTrue(zts.certRecordChanged("test1", "test2"));
        assertTrue(zts.certRecordChanged("test1", ""));
        assertTrue(zts.certRecordChanged("", "test2"));
    }

    @Test
    public void testZTSGroupMemberFetcher() {

        // first failure case

        assertNull(zts.authorizer.groupMembersFetcher.getGroupMembers("coretech:group.unknown"));

        // now valid case

        List<Group> groups = new ArrayList<>();
        Group group = new Group().setName("coretech:group.dev-team");
        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1"));
        members.add(new GroupMember().setMemberName("user.user2"));
        group.setGroupMembers(members);
        groups.add(group);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true, groups);
        zts.dataStore.processSignedDomain(signedDomain, false);

        List<GroupMember> groupMembers = zts.authorizer.groupMembersFetcher.getGroupMembers("coretech:group.dev-team");
        assertNotNull(groupMembers);
        assertEquals(groupMembers.size(), 2);
    }

    @Test
    public void testValidateInstanceServiceIdentity() {

        DomainData domainData = new DomainData().setName("athenz");

        zts.validateInstanceServiceIdentity = new DynamicConfigBoolean(true);

        try {
            zts.validateInstanceServiceIdentity(domainData, "athenz.api", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }
        try {
            zts.validateInstanceServiceIdentity(domainData, "athenz.backend", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        List<com.yahoo.athenz.zms.ServiceIdentity> services = new ArrayList<>();
        com.yahoo.athenz.zms.ServiceIdentity serviceBackend = new com.yahoo.athenz.zms.ServiceIdentity()
                .setName("athenz.backend");
        com.yahoo.athenz.zms.ServiceIdentity serviceApi = new com.yahoo.athenz.zms.ServiceIdentity()
                .setName("athenz.api");
        services.add(serviceBackend);
        services.add(serviceApi);

        domainData.setServices(services);

        // known services should work as expected

        zts.validateInstanceServiceIdentity(domainData, "athenz.api", "unit-test");
        zts.validateInstanceServiceIdentity(domainData, "athenz.backend", "unit-test");

        // unknown services should throw an exception

        try {
            zts.validateInstanceServiceIdentity(domainData, "athenz.frontend", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        try {
            zts.validateInstanceServiceIdentity(domainData, "athenz.api2", "unit-test");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        // rbac.sre does not exists, but is accepted because rbac.* is included in skipDomains

        domainData = new DomainData().setName("rbac.sre");
        zts.validateInstanceServiceIdentity(domainData, "rbac.sre.backend", "unit-test");
        zts.validateInstanceServiceIdentity(domainData, "rbac.sre.frontend", "unit-test");

        // screwdriver services are excluded from the check since they're dynamic
        // screwdriver is configured as service skip domain

        domainData = new DomainData().setName("screwdriver");

        zts.validateInstanceServiceIdentity(domainData, "screwdriver.project1", "unit-test");
        zts.validateInstanceServiceIdentity(domainData, "screwdriver.project2", "unit-test");
        zts.validateInstanceServiceIdentity = new DynamicConfigBoolean(false);
    }

    @Test
    public void testGetRoleAccessWithDelegatedRolesWithGroupsRegularAssumeRole() {

        // we're going to try several cases with assume roles
        // first the assume role includes the full name without any wildcards

        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "role1", false, true);
        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "role1", false, false);

        // next we're going to test when the domain name is a wildcard
        // for example, resource: *:role.role1

        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "role1", true, true);
        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "role1", true, false);

        // next we're going to test when the role name is a wildcard
        // for example, resource: sports:role.*

        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "*", false, true);
        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "*", false, false);

        // finally we're going to test when the role and domain names are a wildcard
        // for example, resource: *:role.*

        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "*", true, true);
        testGetRoleAccessWithDelegatedRolesWithGroups("role1", "*", true, false);
    }

    SignedDomain createGroupNewsDomain(final String newsDomainName, final String weatherDomainName,
                                       boolean multipleUsers, Timestamp expiration) {

        // create the group domain for news

        SignedDomain newsDomain = new SignedDomain();
        List<Role> roles = new ArrayList<>();

        // create the admin role

        Role role = new Role();
        role.setName(generateRoleName(newsDomainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);

        // create our groups

        List<Group> groups = new ArrayList<>();

        Group group = new Group().setName(ResourceUtils.groupResourceName(newsDomainName, "group1"));
        List<GroupMember> groupMembers = new ArrayList<>();

        GroupMember user1GroupMember = new GroupMember().setMemberName("user_domain.user1").setGroupName(group.getName());
        if (expiration != null) {
            user1GroupMember.setExpiration(expiration);
        }
        groupMembers.add(user1GroupMember);

        if (multipleUsers) {
            groupMembers.add(new GroupMember().setMemberName("user_domain.user3").setGroupName(group.getName()));
        }
        group.setGroupMembers(groupMembers);
        groups.add(group);

        // create admin policy

        List<Policy> policies = new ArrayList<>();

        Policy policy = new com.yahoo.athenz.zms.Policy();
        Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(newsDomainName + ".*");
        assertion.setAction("*");
        assertion.setRole(generateRoleName(newsDomainName, "admin"));

        List<Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(newsDomainName, "admin"));
        policies.add(policy);

        DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(weatherDomainName);
        domainPolicies.setPolicies(policies);

        SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(newsDomainName);
        domain.setRoles(roles);
        domain.setGroups(groups);
        domain.setServices(new ArrayList<>());
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        newsDomain.setDomain(domain);

        newsDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        newsDomain.setKeyId("0");
        return newsDomain;
    }

    void testGetRoleAccessWithDelegatedRolesWithGroups(final String roleName, final String assumeRoleName,
            boolean wildCardAssumeDomain, boolean multipleUsers) {

        final String newsDomainName = "news";
        final String sportsDomainName = "sports";
        final String weatherDomainName = "weather";

        SignedDomain weatherDomain = new SignedDomain();
        List<Role> roles = new ArrayList<>();

        // create the admin role

        Role role = new Role();
        role.setName(generateRoleName(weatherDomainName, "admin"));
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);

        // create the trusted role

        roles.add(new Role().setName(generateRoleName(weatherDomainName, roleName)).setTrust(sportsDomainName));

        // no services

        List<ServiceIdentity> services = new ArrayList<>();

        // create admin policy

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(weatherDomainName + ".*");
        assertion.setAction("*");
        assertion.setRole(generateRoleName(weatherDomainName, "admin"));

        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(weatherDomainName, "admin"));
        policies.add(policy);

        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(weatherDomainName);
        domainPolicies.setPolicies(policies);

        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        DomainData domain = new DomainData();
        domain.setName(weatherDomainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        weatherDomain.setDomain(domain);

        weatherDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        weatherDomain.setKeyId("0");

        // now process the domain in ZTS

        store.processSignedDomain(weatherDomain, false);

        // now create the sports domain that includes the delegated role

        SignedDomain sportsDomain = new SignedDomain();

        roles = new ArrayList<>();
        role = new Role();
        role.setName(generateRoleName(sportsDomainName, "admin"));
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);

        role = new Role();
        role.setName(generateRoleName(sportsDomainName, roleName));
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user2"));
        members.add(new RoleMember().setMemberName(ResourceUtils.groupResourceName(newsDomainName, "group1")));
        role.setRoleMembers(members);
        roles.add(role);

        policies = new ArrayList<>();

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(sportsDomainName + ".*");
        assertion.setAction("*");
        assertion.setRole(generateRoleName(sportsDomainName, "admin"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(sportsDomainName, "admin"));
        policies.add(policy);

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        final String assumeRoleDomain = wildCardAssumeDomain ? "*" : weatherDomainName;
        assertion.setResource(generateRoleName(assumeRoleDomain, assumeRoleName));
        assertion.setAction("assume_role");
        assertion.setRole(generateRoleName(sportsDomainName, roleName));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(sportsDomainName, roleName));
        policies.add(policy);

        domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(sportsDomainName);
        domainPolicies.setPolicies(policies);

        signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        domain = new DomainData();
        domain.setName(sportsDomainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        sportsDomain.setDomain(domain);

        sportsDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        sportsDomain.setKeyId("0");

        store.processSignedDomain(sportsDomain, false);

        // create and process our new domain in ZTS

        SignedDomain newsDomain = createGroupNewsDomain(newsDomainName, weatherDomainName, multipleUsers, null);
        store.processSignedDomain(newsDomain, false);

        // now let's carry out our checks - we should get role1 for user1
        // when asked for both sports and weather domains

        Principal principal = SimplePrincipal.create("user_domain", "user", "v=U1;d=user_domain;n=user;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleAccess roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // user2 should have same access as user1

        roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // user3 should have same access as user1

        if (multipleUsers) {
            roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user3");
            assertEquals(roleAccess.getRoles().size(), 1);
            assertTrue(roleAccess.getRoles().contains(roleName));

            roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user3");
            assertEquals(roleAccess.getRoles().size(), 1);
            assertTrue(roleAccess.getRoles().contains(roleName));
        }

        // now we're going to expire our user1 group member
        // and process the domain

        newsDomain = createGroupNewsDomain(newsDomainName, weatherDomainName, multipleUsers,
                Timestamp.fromMillis(System.currentTimeMillis() - 60 * 60 * 1000L));
        store.processSignedDomain(newsDomain, false);

        // now let's verify our role access again. user1
        // should not have access in weather domain

        roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 0);

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 0);

        // user2 should still have access to both roles

        roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // user3 should still have access to both roles

        if (multipleUsers) {
            roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user3");
            assertEquals(roleAccess.getRoles().size(), 1);
            assertTrue(roleAccess.getRoles().contains(roleName));

            roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user3");
            assertEquals(roleAccess.getRoles().size(), 1);
            assertTrue(roleAccess.getRoles().contains(roleName));
        }

        // now we're going to reset our expiry for the user into the future

        newsDomain = createGroupNewsDomain(newsDomainName, weatherDomainName, multipleUsers,
                Timestamp.fromMillis(System.currentTimeMillis() + 60 * 60 * 1000L));
        store.processSignedDomain(newsDomain, false);

        // verify all previous access as expected

        roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // user2 should have same access as user1

        roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains(roleName));

        // user3 should have same access as user1

        if (multipleUsers) {
            roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user3");
            assertEquals(roleAccess.getRoles().size(), 1);
            assertTrue(roleAccess.getRoles().contains(roleName));

            roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user3");
            assertEquals(roleAccess.getRoles().size(), 1);
            assertTrue(roleAccess.getRoles().contains(roleName));
        }
    }

    @Test
    public void testPostAccessTokenRequestWithAuthorizationDetails() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
        assertEquals(authzDetails, claims.getBody().get("authorization_details"));
    }

    @Test
    public void testPostAccessTokenRequestWithSystemAuthorizationDetails() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_single_authz_details.json");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
        assertEquals(authzDetails, claims.getBody().get("authorization_details"));

        // next system based match

        authzDetails = "[{\"type\":\"proxy_access\",\"principal\":[\"spiffe://athenz/sa/api\"]}]";
        resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:role.writers&authorization_details=" + authzDetails);
        assertNotNull(resp);
        assertNull(resp.getScope());

        accessTokenStr = resp.getAccess_token();
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        assertEquals(authzDetails, claims.getBody().get("authorization_details"));

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
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        assertEquals(authzDetails, claims.getBody().get("authorization_details"));
    }

    @Test
    public void testPostAccessTokenRequestWithSystemAuthorizationDetailsFailures() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_single_authz_details.json");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        cloudStore.setHttpClient(null);
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
    public void testPostAccessTokenRequestWithProxyPrincipals() throws IOException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
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
        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));

        LinkedHashMap<String, Object> cnf = (LinkedHashMap<String, Object>) claims.getBody().get("cnf");
        assertNotNull(cnf);
        List<String> spiffeUris = (List<String>) cnf.get("proxy-principals#spiffe");
        assertNotNull(spiffeUris);
        assertEquals(spiffeUris.size(), 2);
        assertTrue(spiffeUris.contains("spiffe://athenz/sa/api"));
        assertTrue(spiffeUris.contains("spiffe://sports/sa/api"));
    }

    @Test
    public void getTransportRulesROTest() {
        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true).thenReturn(false);
        zts.readOnlyMode = dynamicConfigBoolean;
        try {
            Principal principal = SimplePrincipal.create("user_domain", "user1",
                    "v=U1;d=user_domain;n=user;s=signature", 0, null);
            ResourceContext context = createResourceContext(principal);
            zts.getTransportRules(context, "transportrules", "api");
            fail();
        } catch (ResourceException re) {
            assertEquals(ResourceException.BAD_REQUEST, re.getCode());
        }
        zts.readOnlyMode = dynamicConfigBoolean;
    }

    @Test
    public void getWorkloadsByIpROTest() {
        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true).thenReturn(false);
        zts.readOnlyMode = dynamicConfigBoolean;
        try {
            Principal principal = SimplePrincipal.create("user_domain", "user1",
                    "v=U1;d=user_domain;n=user;s=signature", 0, null);
            ResourceContext context = createResourceContext(principal);
            zts.getWorkloadsByIP(context, "10.0.0.1");
            fail();
        } catch (ResourceException re) {
            assertEquals(ResourceException.BAD_REQUEST, re.getCode());
        }
        zts.readOnlyMode = dynamicConfigBoolean;
    }

    @Test
    public void getWorkloadsByServiceROTest() {
        DynamicConfigBoolean dynamicConfigBoolean = Mockito.mock(DynamicConfigBoolean.class);
        when(dynamicConfigBoolean.get()).thenReturn(true).thenReturn(false);
        zts.readOnlyMode = dynamicConfigBoolean;
        try {
            Principal principal = SimplePrincipal.create("user_domain", "user1",
                    "v=U1;d=user_domain;n=user;s=signature", 0, null);
            ResourceContext context = createResourceContext(principal);
            zts.getWorkloadsByService(context, "transportrules", "api");
            fail();
        } catch (ResourceException re) {
            assertEquals(ResourceException.BAD_REQUEST, re.getCode());
        }
        zts.readOnlyMode = dynamicConfigBoolean;
    }

    @Test
    public void getTransportRulesTest() {
        final String domainName = "transportrules";

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = ZTSTestUtils.createRoleObject(domainName, "ACL.api.inbound-4443", "dom1.svc1", "dom2.svc2");
        Role role2 = ZTSTestUtils.createRoleObject(domainName, "ACL.api.inbound-8443", "dom3.svc3");
        Role role3 = ZTSTestUtils.createRoleObject(domainName, "ACL.api.outbound-4443", "dom1.svc1");
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);
        domainData.getRoles().add(role3);


        Policy policy1 = ZTSTestUtils.createPolicyObject(domainName, "ACL.api.inbound", domainName + ":role.ACL.api.inbound-4443",
                false, "TCP-IN:1024-65535:4443", domainName + ":api", AssertionEffect.ALLOW);
        policy1.getAssertions().add(new Assertion().setResource(domainName + ":api").setRole(domainName + ":role.ACL.api.inbound-8443")
        .setAction("TCP-IN:49152-65535:8443").setEffect(AssertionEffect.ALLOW));
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy1);

        Policy policy2 = ZTSTestUtils.createPolicyObject(domainName, "ACL.api.outbound", domainName + ":role.ACL.api.outbound-4443",
                false, "TCP-OUT:1024-65535:4443", domainName + ":api", AssertionEffect.ALLOW);
        domainData.getPolicies().getContents().getPolicies().add(policy2);

        store.getCacheStore().put(domainName, domain);

        addDomainToDataStore("dom1", "svc1");
        addDomainToDataStore("dom2", "svc2");
        addDomainToDataStore("dom3", "svc3");

        Map<String, Role> rolesMap = new HashMap<>();
        rolesMap.put(domainName + ":role.ACL.api.inbound-4443", role1);
        rolesMap.put(domainName + ":role.ACL.api.inbound-8443", role2);
        rolesMap.put(domainName + ":role.ACL.api.outbound-4443", role3);
        domain.processPolicy(domainName, policy1, rolesMap);
        domain.processPolicy(domainName, policy2, rolesMap);

        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;

        List<Workload> svc1Wl = Collections.singletonList(new Workload().setProvider("openstack").setIpAddresses(Collections.singletonList("10.0.1.1"))
        .setUuid("instance-id1"));
        Mockito.when(mockICM.getWorkloadsByService("dom1", "svc1")).thenReturn(svc1Wl);

        List<Workload> svc2Wl = Collections.singletonList(new Workload().setProvider("openstack").setIpAddresses(Collections.singletonList("10.0.2.1"))
                .setUuid("instance-id2"));
        Mockito.when(mockICM.getWorkloadsByService("dom2", "svc2")).thenReturn(svc2Wl);

        List<String> svc3Ips = Arrays.asList("10.0.3.1","10.0.3.2","10.0.3.3");
        List<Workload> svc3Wl = Collections.singletonList(new Workload().setProvider("openstack").setIpAddresses(svc3Ips)
                .setUuid("instance-id3"));
        Mockito.when(mockICM.getWorkloadsByService("dom3", "svc3")).thenReturn(svc3Wl);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        TransportRules transportRules = zts.getTransportRules(context, "transportrules", "api");
        assertNotNull(transportRules);
        assertNotNull(transportRules.getIngressRules());
        assertNotNull(transportRules.getEgressRules());
        assertEquals(transportRules.getIngressRules().size(), 5);
        TransportRule expectedIRule1 = new TransportRule().setEndPoint("10.0.1.1").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535").setDirection(TransportDirection.IN);
        TransportRule expectedIRule2 = new TransportRule().setEndPoint("10.0.2.1").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535").setDirection(TransportDirection.IN);
        TransportRule expectedIRule3 = new TransportRule().setEndPoint("10.0.3.1").setPort(8443).setProtocol("TCP").setSourcePortRange("49152-65535").setDirection(TransportDirection.IN);
        assertThat(transportRules.getIngressRules(), hasItems(expectedIRule1, expectedIRule2, expectedIRule3));

        TransportRule expectedERule1 = new TransportRule().setEndPoint("10.0.1.1").setPort(4443).setProtocol("TCP").setSourcePortRange("1024-65535").setDirection(TransportDirection.OUT);
        assertThat(transportRules.getEgressRules(), hasItems(expectedERule1));

        zts.instanceCertManager = origICM;
        store.getCacheStore().invalidate(domainName);
        store.getCacheStore().invalidate("dom1");
        store.getCacheStore().invalidate("dom2");
        store.getCacheStore().invalidate("dom3");

    }

    @Test
    public void emptyDynamicWorkloadsFromStoreTest() {

        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;
        mockICM.setWorkloadStore(null);
        addDomainToDataStore("athenz", "api");
        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);
        Workloads workloads = zts.getWorkloadsByService(context, "athenz", "api");
        assertTrue(workloads.getWorkloadList().isEmpty());
        zts.instanceCertManager = origICM;
        store.getCacheStore().invalidate("athenz");
    }

    @Test
    public void getTransportRulesEdgeCasesTest() {
        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;
        mockICM.setWorkloadStore(null);
        final String domainName = "transportrulesedge";
        addDomainToDataStore(domainName, "api");
        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);
        TransportRules transportRules = zts.getTransportRules(context, domainName, "api");
        assertTrue(transportRules.getEgressRules().isEmpty());
        assertTrue(transportRules.getIngressRules().isEmpty());

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = ZTSTestUtils.createRoleObject(domainName, "ACL.api.inbound-4443", "dom1.svc1");
        domainData.getRoles().add(role1);

        Policy policy1 = ZTSTestUtils.createPolicyObject(domainName, "ACL.api.inbound", domainName + ":role.ACL.api.inbound-4443",
                false, "TCP-IN:1024-65535:4443", domainName + ":api", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy1);

        store.getCacheStore().put(domainName, domain);

        addDomainToDataStore("dom1", "svc1");

        Map<String, Role> rolesMap = new HashMap<>();
        rolesMap.put(domainName + ":role.ACL.api.inbound-4443", role1);
        domain.processPolicy(domainName, policy1, rolesMap);

        zts.dataStore.getDataCache(domainName).getTransportRulesInfoForService("api").put("TCP-XYZ:1024-65535:4443", Collections.singletonList("dom1.svc1"));

        transportRules = zts.getTransportRules(context, domainName, "api");
        assertTrue(transportRules.getEgressRules().isEmpty());
        assertTrue(transportRules.getIngressRules().isEmpty());

        zts.instanceCertManager = origICM;
        store.getCacheStore().invalidate("athenz");
    }

    private void addDomainToDataStore(String domainName, String serviceName) {
        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domain.setDomainData(domainData);

        domainData.setServices(new ArrayList<>());
        ServiceIdentity service = new ServiceIdentity();
        service.setName(generateServiceIdentityName(domainName, serviceName));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        domainData.getServices().add(service);

        store.getCacheStore().put(domainName, domain);
    }

    @Test
    public void testGetRolesRequireRoleCert() {
        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleAccess rolesRequireRoleCert = zts.getRolesRequireRoleCert(context, "coretech.api");
        assertEquals(rolesRequireRoleCert.getRoles(), new ArrayList<>());

        rolesRequireRoleCert = zts.getRolesRequireRoleCert(context, null);
        assertEquals(rolesRequireRoleCert.getRoles(), new ArrayList<>());
    }

    @Test
    public void getWorkloadsByServiceTest() {
        final String domainName = "workloadsbyservice";
        final String serviceName = "api";

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // try with invalid domain first ( domain not in data cache )
        try {
            zts.getWorkloadsByService(context, domainName, serviceName);
            fail();
        } catch (ResourceException re) {
            assertEquals(ResourceException.BAD_REQUEST, re.getCode());
        }

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domain.setDomainData(domainData);
        domainData.setServices(new ArrayList<>());

        ServiceIdentity service = new ServiceIdentity();
        service.setName(generateServiceIdentityName(domainName, serviceName));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);

        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        service.setHosts(hosts);
        domainData.getServices().add(service);

        store.getCacheStore().put(domainName, domain);

        domain.processServiceIdentity(service);

        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;

        List<String> svcIps = Arrays.asList("10.1.1.1","2001:0db8:85a3:0000:0000:8a2e:0370:7334");

        List<Workload> dynamicWls = new ArrayList<>();
        Workload wl1 = new Workload().setProvider("openstack").setIpAddresses(svcIps)
                .setUuid("instance-id-os-1").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test1.host.yahoo.cloud");
        Workload wl2 = new Workload().setProvider("openstack").setIpAddresses(Collections.singletonList("10.1.1.2"))
                .setUuid("instance-id-os-2").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test2.host.yahoo.cloud");
        Workload wl3 = new Workload().setProvider("kubernetes").setIpAddresses(Collections.singletonList("10.2.1.1"))
                .setUuid("instance-id-k8s-1").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test3.host.yahoo.cloud");
        Workload wl4 = new Workload().setProvider("kubernetes").setIpAddresses(Collections.singletonList("10.2.1.2"))
                .setUuid("instance-id-k8s-2").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test4.host.yahoo.cloud");
        Workload wl5 = new Workload().setProvider("aws").setIpAddresses(Collections.singletonList("10.3.1.1"))
                .setUuid("instance-id-aws-1").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test5.host.yahoo.cloud");
        dynamicWls.add(wl1);
        dynamicWls.add(wl2);
        dynamicWls.add(wl3);
        dynamicWls.add(wl4);
        dynamicWls.add(wl5);


        Mockito.when(mockICM.getWorkloadsByService(domainName, serviceName)).thenReturn(dynamicWls);


        Workloads workloads = zts.getWorkloadsByService(context, domainName, serviceName);

        assertNotNull(workloads);
        assertThat(workloads.getWorkloadList(), hasItems(wl1, wl2, wl3, wl4, wl5));

        zts.instanceCertManager = origICM;
    }

    @Test
    public void getWorkloadsByIpTest() {

        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;

        List<Workload> dynamicWls = new ArrayList<>();
        Workload wl1 = new Workload().setProvider("openstack").setDomainName("dom1").setServiceName("svc1")
                .setUuid("instance-id-os-1").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test1.host.yahoo.cloud");
        Workload wl2 = new Workload().setProvider("openstack").setDomainName("dom1").setServiceName("svc2")
                .setUuid("instance-id-os-1").setUpdateTime(Timestamp.fromCurrentTime()).setHostname("test2.host.yahoo.cloud");

        dynamicWls.add(wl1);
        dynamicWls.add(wl2);

        Mockito.when(mockICM.getWorkloadsByIp("10.0.0.1")).thenReturn(dynamicWls);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);
        Workloads workloads = zts.getWorkloadsByIP(context, "10.0.0.1");

        assertNotNull(workloads);
        assertThat(workloads.getWorkloadList(), containsInAnyOrder(wl1, wl2));

        try {
            zts.getWorkloadsByIP(context, "10.0.0");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 400);
        }

        zts.instanceCertManager = origICM;
    }

    @Test
    public void insertWorkloadRecordTest() {
        Date certExpiryTime = new Date();
        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;
        Mockito.when(mockICM.insertWorkloadRecord(any())).thenReturn(true, false);
        zts.insertWorkloadRecord("athenz.api", "openstack", "123", "", "test1.host.yahoo.cloud", certExpiryTime);
        Mockito.verify(mockICM, Mockito.times(0)).insertWorkloadRecord(any(WorkloadRecord.class));
        zts.insertWorkloadRecord("athenz.api", "openstack", "123", "10.0.0.1", "test1.host.yahoo.cloud", certExpiryTime);
        Mockito.verify(mockICM, Mockito.times(1)).insertWorkloadRecord(any(WorkloadRecord.class));
        zts.insertWorkloadRecord("athenz.api", "openstack", "123", "10.0.0.1, 10.0.0.2", null, certExpiryTime);
        Mockito.verify(mockICM, Mockito.times(3)).insertWorkloadRecord(any(WorkloadRecord.class));
        zts.instanceCertManager = origICM;
    }

    @Test
    public void updateWorkloadRecordTest() {
        Date certExpiryTime = new Date();
        InstanceCertManager mockICM = Mockito.mock(InstanceCertManager.class);
        InstanceCertManager origICM = zts.instanceCertManager;
        zts.instanceCertManager = mockICM;
        Mockito.when(mockICM.updateWorkloadRecord(any())).thenReturn(true, false);
        zts.updateWorkloadRecord("athenz.api", "openstack", "123", "", "test.host-1.yahoo.cloud", certExpiryTime);
        Mockito.verify(mockICM, Mockito.times(0)).updateWorkloadRecord(any(WorkloadRecord.class));
        zts.updateWorkloadRecord("athenz.api", "openstack", "123", "10.0.0.1", "test.host-1.yahoo.cloud", certExpiryTime);
        Mockito.verify(mockICM, Mockito.times(1)).updateWorkloadRecord(any(WorkloadRecord.class));
        zts.updateWorkloadRecord("athenz.api", "openstack", "123", "10.0.0.1, 10.0.0.2", null, certExpiryTime);
        Mockito.verify(mockICM, Mockito.times(3)).updateWorkloadRecord(any(WorkloadRecord.class));
        zts.instanceCertManager = origICM;
    }

    @Test
    public void testGetInstanceRegisterToken() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("sys.auth.zts", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        // include the principal from the request object

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        InstanceRegisterToken token = new InstanceRegisterToken()
                .setProvider("sys.auth.zts").setDomain("athenz")
                .setService("production").setAttestationData("jwt");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("sys.auth.zts"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.getInstanceRegisterToken(Mockito.any())).thenReturn(token);

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        // valid request should return our token

        InstanceRegisterToken registerToken = ztsImpl.getInstanceRegisterToken(context, "sys.auth.zts",
                "athenz", "production", "id001");
        assertNotNull(registerToken);

        // other service entry will return unauthorized launch

        try {
            ztsImpl.getInstanceRegisterToken(context, "sys.auth.zts",
                    "athenz", "api", "id001");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }
    }

    @Test
    public void testGetInstanceRegisterTokenInvalidDoamin() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        // include the principal from the request object

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        InstanceRegisterToken token = new InstanceRegisterToken()
                .setProvider("athenz.provider").setDomain("athenz")
                .setService("production").setAttestationData("jwt");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.getInstanceRegisterToken(Mockito.any())).thenReturn(token);

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        try {
            ztsImpl.getInstanceRegisterToken(context, "athenz.provider",
                    "athenz", "production", "id001");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
    }

    @Test
    public void testGetInstanceRegisterTokenUnknownProvider() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);

        // include the principal from the request object

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(null);

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        try {
            ztsImpl.getInstanceRegisterToken(context, "athenz.provider",
                    "athenz", "production", "id001");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("unable to get instance for provider"));
        }
    }

    @Test
    public void testGetInstanceRegisterTokenProviderFailure() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processSignedDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processSignedDomain(tenantDomain, false);

        InstanceProviderManager instanceProviderManager = Mockito.mock(InstanceProviderManager.class);
        InstanceProvider providerClient = Mockito.mock(InstanceProvider.class);
        Mockito.when(providerClient.getProviderScheme()).thenReturn(InstanceProvider.Scheme.CLASS);

        // include the principal from the request object

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        ResourceContext context = createResourceContext(principal);

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider(eq("athenz.provider"), Mockito.any())).thenReturn(providerClient);
        Mockito.when(providerClient.getInstanceRegisterToken(Mockito.any()))
                .thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(400, "Bad Request"));

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        try {
            ztsImpl.getInstanceRegisterToken(context, "athenz.provider",
                    "athenz", "production", "id001");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("unable to get instance register token"));
        }
    }

    @Test
    public void testLoadSystemAuthorizationDetails() {

        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_invalid_authz_details.json");

        try {
            zts.loadSystemAuthorizationDetails();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid authorization details file"));
        }

        // next authz details with empty list

        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_empty_authz_details.json");

        try {
            zts.loadSystemAuthorizationDetails();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid authorization details file"));
        }

        // next unknown file

        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "invalid_authz_details.json");

        try {
            zts.loadSystemAuthorizationDetails();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid authorization details file"));
        }

        // finally a valid authz details file

        System.setProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH, "src/test/resources/system_multiple_authz_details.json");
        zts.loadSystemAuthorizationDetails();
        assertNotNull(zts.systemAuthzDetails);

        List<AuthzDetailsEntity> entities = zts.systemAuthzDetails.getEntities();
        assertNotNull(entities);
        assertEquals(entities.size(), 2);
        assertEquals(entities.get(0).getType(), "proxy_access");
        assertEquals(entities.get(1).getType(), "data_access");

        System.clearProperty(ZTSConsts.ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH);
        zts.systemAuthzDetails = null;
    }

    @Test
    public void testGetProxyPrincipalSpiffeUris() {

        List<String> uris = zts.getProxyPrincipalSpiffeUris("spiffe://data/sa/service", "athenz", "caller");
        assertEquals(uris.size(), 1);
        assertTrue(uris.contains("spiffe://data/sa/service"));

        uris = zts.getProxyPrincipalSpiffeUris(" spiffe://data/sa/service", "athenz", "caller");
        assertEquals(uris.size(), 1);
        assertTrue(uris.contains("spiffe://data/sa/service"));

        uris = zts.getProxyPrincipalSpiffeUris("spiffe://data/sa/service,spiffe://sports/sa/api", "athenz", "caller");
        assertEquals(uris.size(), 2);
        assertTrue(uris.contains("spiffe://data/sa/service"));
        assertTrue(uris.contains("spiffe://sports/sa/api"));

        uris = zts.getProxyPrincipalSpiffeUris("spiffe://data/sa/service , spiffe://sports/sa/api ", "athenz", "caller");
        assertEquals(uris.size(), 2);
        assertTrue(uris.contains("spiffe://data/sa/service"));
        assertTrue(uris.contains("spiffe://sports/sa/api"));
    }

    @Test
    public void testGetProxyPrincipalSpiffeUrisFailures() {

        // null value

        assertNull(zts.getProxyPrincipalSpiffeUris("", "athenz", "caller"));

        // uri does not start with spiffe://

        try {
            zts.getProxyPrincipalSpiffeUris("athenz://data/sa/service", "athenz", "caller");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid spiffe uri specified: athenz://data/sa/service"));
        }

        try {
            zts.getProxyPrincipalSpiffeUris("spiffe://athenz/sa/service,athenz://data/sa/service", "athenz", "caller");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid spiffe uri specified: athenz://data/sa/service"));
        }

        try {
            zts.getProxyPrincipalSpiffeUris("spiffe://\\athenz/sa/service", "athenz", "caller");
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Invalid spiffe uri specified: spiffe://\\athenz/sa/service"));
        }
    }

    @Test
    public void tesGeneratePolicyVersions() {

        Map<String, String> versions = zts.generatePolicyVersions("coretech", null);
        assertTrue(versions.isEmpty());

        SignedPolicyRequest request = new SignedPolicyRequest();
        versions = zts.generatePolicyVersions("coretech", request);
        assertTrue(versions.isEmpty());

        Map<String, String> requestVersions = new HashMap<>();
        requestVersions.put("policy1", "Prod");
        requestVersions.put("PolicyTwo", "Non-Prod");
        requestVersions.put("policy-three", "prod");
        requestVersions.put("Coretech:policy.policy4", "Four");
        requestVersions.put("coretech:policy.Policy5", "five");
        requestVersions.put("coretech:policy.test.policy", "test");
        requestVersions.put("athenz:policy.policy", "prod");
        request.setPolicyVersions(requestVersions);

        versions = zts.generatePolicyVersions("coretech", request);
        assertEquals(versions.size(), 7);
        assertEquals(versions.get("coretech:policy.policy1"), "prod");
        assertEquals(versions.get("coretech:policy.policytwo"), "non-prod");
        assertEquals(versions.get("coretech:policy.policy-three"), "prod");
        assertEquals(versions.get("coretech:policy.policy4"), "four");
        assertEquals(versions.get("coretech:policy.policy5"), "five");
        assertEquals(versions.get("coretech:policy.test.policy"), "test");
        assertEquals(versions.get("coretech:policy.athenz:policy.policy"), "prod");
    }

    @Test
    public void testPolicyVersionMatch() {
        Map<String, String> requestVersions = new HashMap<>();
        requestVersions.put("coretech:policy.policy1", "prod");
        requestVersions.put("coretech:policy.policy2", "non-prod");
        requestVersions.put("coretech:policy.policy3", "");

        Policy zmsPolicy = new Policy();

        // policy version not set

        zmsPolicy.setName("coretech:policy.policy-10");
        zmsPolicy.setVersion(null);
        assertTrue(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setActive(true);
        assertTrue(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setActive(false);
        assertFalse(zts.policyVersionMatch(zmsPolicy, requestVersions));

        // policy version set to an empty string

        zmsPolicy.setName("coretech:policy.policy3");
        zmsPolicy.setActive(null);
        assertTrue(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setActive(true);
        assertTrue(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setActive(false);
        assertFalse(zts.policyVersionMatch(zmsPolicy, requestVersions));

        // version match

        zmsPolicy.setName("coretech:policy.policy1");
        zmsPolicy.setVersion(null);
        zmsPolicy.setActive(false);
        assertFalse(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setVersion("prod");
        zmsPolicy.setActive(false);
        assertTrue(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setVersion("prod");
        zmsPolicy.setActive(true);
        assertTrue(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setVersion("non-prod");
        zmsPolicy.setActive(false);
        assertFalse(zts.policyVersionMatch(zmsPolicy, requestVersions));
        zmsPolicy.setVersion("non-prod");
        zmsPolicy.setActive(true);
        assertFalse(zts.policyVersionMatch(zmsPolicy, requestVersions));
    }

    @Test
    public void testCopyZMSPolicyObject() {

        List<AssertionCondition> conditions = new ArrayList<>();
        conditions.add(new AssertionCondition().setId(1000));
        AssertionConditions assertionConditions = new AssertionConditions().setConditionsList(conditions);
        List<Assertion> assertions = new ArrayList<>();
        assertions.add(new Assertion().setRole("role").setResource("resource").setCaseSensitive(false)
                .setAction("action").setId(1001L).setEffect(AssertionEffect.ALLOW).setConditions(assertionConditions));
        Policy zmsPolicy = new Policy().setActive(false).setVersion("0").setName("coretech:policy.policy1")
                .setCaseSensitive(false).setModified(Timestamp.fromCurrentTime()).setAssertions(assertions);

        com.yahoo.athenz.zts.Policy ztsPolicy = zts.copyZMSPolicyObject(zmsPolicy, false);
        assertNull(ztsPolicy.getActive());
        assertNull(ztsPolicy.getVersion());
        com.yahoo.athenz.zts.Assertion assertion = ztsPolicy.getAssertions().get(0);
        assertNotNull(assertion);
        assertNull(assertion.getId());
        assertNull(assertion.getCaseSensitive());

        ztsPolicy = zts.copyZMSPolicyObject(zmsPolicy, true);
        assertFalse(ztsPolicy.getActive());
        assertEquals(ztsPolicy.getVersion(), "0");
        assertion = ztsPolicy.getAssertions().get(0);
        assertNotNull(assertion);
        assertEquals(assertion.getId().longValue(), 1001L);
        assertFalse(assertion.getCaseSensitive());
    }

    @Test
    public void testPostSignedPolicyRequest() throws ParseException, JOSEException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedPolicyRequest signedPolicyRequest = new SignedPolicyRequest();
        signedPolicyRequest.setPolicyVersions(Collections.emptyMap());
        Response response = ztsImpl.postSignedPolicyRequest(context, "coretech", signedPolicyRequest, null);
        assertEquals(response.getStatus(), 200);
        JWSPolicyData jwsPolicyData = (JWSPolicyData) response.getEntity();

        JWSObject jwsObject = new JWSObject(Base64URL.from(jwsPolicyData.getProtectedHeader()),
                Base64URL.from(jwsPolicyData.getPayload()), Base64URL.from(jwsPolicyData.getSignature()));

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) Crypto.extractPublicKey(privateKey.getKey()));
        assertTrue(jwsObject.verify(verifier));

        // verify that with p1363 signature and rsa - it's the same key so validation is successful

        signedPolicyRequest.setSignatureP1363Format(true);
        response = ztsImpl.postSignedPolicyRequest(context, "coretech", signedPolicyRequest, null);
        assertEquals(response.getStatus(), 200);
        jwsPolicyData = (JWSPolicyData) response.getEntity();

        jwsObject = new JWSObject(Base64URL.from(jwsPolicyData.getProtectedHeader()),
                Base64URL.from(jwsPolicyData.getPayload()), Base64URL.from(jwsPolicyData.getSignature()));
        assertTrue(jwsObject.verify(verifier));

        // invalid domain

        try {
            ztsImpl.postSignedPolicyRequest(context, "unknowndomain", signedPolicyRequest, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }
    }

    @Test
    public void testPostSignedPolicyRequestNoChanges() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        Timestamp modified = signedDomain.getDomain().getModified();
        EntityTag eTag = new EntityTag(modified.toString());

        SignedPolicyRequest signedPolicyRequest = new SignedPolicyRequest();
        signedPolicyRequest.setPolicyVersions(Collections.emptyMap());
        Response response = ztsImpl.postSignedPolicyRequest(context, "coretech", signedPolicyRequest, eTag.toString());
        assertEquals(response.getStatus(), 304);
    }

    @Test
    public void testSignJWSPolicyDataError() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedPolicyRequest signedPolicyRequest = new SignedPolicyRequest();
        signedPolicyRequest.setPolicyVersions(Collections.emptyMap());

        // set the private key to null resulting in an exception
        ztsImpl.privateECKey = null;
        ztsImpl.privateOrigKey = null;
        Response response = ztsImpl.postSignedPolicyRequest(context, "coretech", signedPolicyRequest, null);
        assertNull(response.getEntity());
        assertEquals(response.getStatus(), 500);
    }

    @Test
    public void testSignJWSPolicyDataECKey() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, "src/test/resources/unit_test_zts_private_ec.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processSignedDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedPolicyRequest signedPolicyRequest = new SignedPolicyRequest();
        signedPolicyRequest.setPolicyVersions(Collections.emptyMap());
        signedPolicyRequest.setSignatureP1363Format(true);

        Response response = ztsImpl.postSignedPolicyRequest(context, "coretech", signedPolicyRequest, null);
        assertEquals(response.getStatus(), 200);
        JWSPolicyData jwsPolicyData = (JWSPolicyData) response.getEntity();

        // using standard DER format signature we're going to get failure

        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);
        Function<String, PublicKey> keyGetter = s -> Crypto.extractPublicKey(privateKey.getKey());
        assertFalse(Crypto.validateJWSDocument(jwsPolicyData.getProtectedHeader(), jwsPolicyData.getPayload(),
                jwsPolicyData.getSignature(), keyGetter));

        // now we need to convert to DER format

        final String derSignature = ZTSTestUtils.getDERSignature(jwsPolicyData.getProtectedHeader(),
                jwsPolicyData.getSignature());
        assertTrue(Crypto.validateJWSDocument(jwsPolicyData.getProtectedHeader(), jwsPolicyData.getPayload(),
                derSignature, keyGetter));

        // now we're going to request the jws policy data with DER signature

        signedPolicyRequest.setSignatureP1363Format(false);
        response = ztsImpl.postSignedPolicyRequest(context, "coretech", signedPolicyRequest, null);
        assertEquals(response.getStatus(), 200);
        jwsPolicyData = (JWSPolicyData) response.getEntity();

        // we should be able to validate without any conversion

        assertTrue(Crypto.validateJWSDocument(jwsPolicyData.getProtectedHeader(), jwsPolicyData.getPayload(),
                jwsPolicyData.getSignature(), keyGetter));

        // set back our private key setting
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
    }

    @Test
    public void testChangeMessage() {
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
            "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        ztsImpl.publishChangeMessage(context, 200);
    }

    @Test
    public void testGetOpenIDConfig() {

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(4443);

        RsrcCtxWrapper ctx = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(ctx.request()).thenReturn(request);

        OpenIDConfig openIDConfig = zts.getOpenIDConfig(ctx);
        assertNotNull(openIDConfig);

        assertEquals("https://athenz.cloud:4443/zts/v1", openIDConfig.getIssuer());
        assertEquals("https://athenz.cloud:4443/zts/v1/oauth2/keys?rfc=true", openIDConfig.getJwks_uri());
        assertEquals("https://athenz.cloud:4443/zts/v1/oauth2/auth", openIDConfig.getAuthorization_endpoint());

        assertEquals(Collections.singletonList("RS256"), openIDConfig.getId_token_signing_alg_values_supported());
        assertEquals(Collections.singletonList("id_token"), openIDConfig.getResponse_types_supported());
        assertEquals(Collections.singletonList("public"), openIDConfig.getSubject_types_supported());
    }

    @Test
    public void testGetOpendIDConfigOnOIDCPort() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        System.setProperty(ZTSConsts.ZTS_PROP_OIDC_PORT_ISSUER, "https://athenz.io/zts/v1");
        System.setProperty(ZTSConsts.ZTS_PROP_OIDC_PORT, "443");

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(443);

        RsrcCtxWrapper ctx = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(ctx.request()).thenReturn(request);

        OpenIDConfig openIDConfig = ztsImpl.getOpenIDConfig(ctx);
        assertNotNull(openIDConfig);

        assertEquals("https://athenz.io/zts/v1", openIDConfig.getIssuer());
        assertEquals("https://athenz.io/zts/v1/oauth2/keys?rfc=true", openIDConfig.getJwks_uri());
        assertEquals("https://athenz.io/zts/v1/oauth2/auth", openIDConfig.getAuthorization_endpoint());

        assertEquals(Collections.singletonList("RS256"), openIDConfig.getId_token_signing_alg_values_supported());
        assertEquals(Collections.singletonList("id_token"), openIDConfig.getResponse_types_supported());
        assertEquals(Collections.singletonList("public"), openIDConfig.getSubject_types_supported());

        System.clearProperty(ZTSConsts.ZTS_PROP_OIDC_PORT_ISSUER);
        System.clearProperty(ZTSConsts.ZTS_PROP_OIDC_PORT);
    }

    @Test
    public void testGetOAuthConfig() {

        ResourceContext ctx = createResourceContext(null);

        OAuthConfig oauthConfig = zts.getOAuthConfig(ctx);
        assertNotNull(oauthConfig);

        assertEquals("https://athenz.cloud:4443/zts/v1", oauthConfig.getIssuer());
        assertEquals("https://athenz.cloud:4443/zts/v1/oauth2/keys?rfc=true", oauthConfig.getJwks_uri());
        assertEquals("https://athenz.cloud:4443/zts/v1/oauth2/auth", oauthConfig.getAuthorization_endpoint());
        assertEquals("https://athenz.cloud:4443/zts/v1/oauth2/token", oauthConfig.getToken_endpoint());

        assertEquals(Collections.singletonList("RS256"), oauthConfig.getToken_endpoint_auth_signing_alg_values_supported());

        List<String> supportedTypes = oauthConfig.getResponse_types_supported();
        assertEquals(supportedTypes.size(), 2);
        assertTrue(supportedTypes.contains("token"));
        assertTrue(supportedTypes.contains("id_token token"));

        assertEquals(Collections.singletonList("client_credentials"), oauthConfig.getGrant_types_supported());
    }

    @Test
    public void testExtractServiceEndpoint() {

        // null domain data

        assertFalse(zts.validateOidcRedirectUri(null, "coretech.api", "https://api.coretech.athenz.io"));

        // null services

        DomainData domainData = new DomainData();
        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech.api", "https://api.coretech.athenz.io"));

        List<com.yahoo.athenz.zms.ServiceIdentity> services = new ArrayList<>();
        com.yahoo.athenz.zms.ServiceIdentity serviceBackend = new com.yahoo.athenz.zms.ServiceIdentity()
                .setName("coretech.backend").setProviderEndpoint("https://localhost:4443/endpoint");
        com.yahoo.athenz.zms.ServiceIdentity serviceApi = new com.yahoo.athenz.zms.ServiceIdentity()
                .setName("coretech.api");
        services.add(serviceBackend);
        services.add(serviceApi);

        domainData.setServices(services);

        // service endpoint exists - both valid and invalid cases (no redirect suffix)

        assertTrue(zts.validateOidcRedirectUri(domainData, "coretech.backend", "https://localhost:4443/endpoint"));
        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech.backend", "https://api.coretech.athenz.io"));
        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech.backend", "https://backend.coretech.athenz.io"));

        // valid service but no redirect uri suffix

        final String savedUriSuffix = zts.redirectUriSuffix;
        zts.redirectUriSuffix = null;
        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech.api", "https://api.coretech.athenz.io"));

        zts.redirectUriSuffix = ".athenz.io";

        // the service with the endpoint set now should pass with redirect suffix

        assertTrue(zts.validateOidcRedirectUri(domainData, "coretech.backend", "https://backend.coretech.athenz.io"));

        // invalid client id

        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech", "https://api.coretech.athenz.io"));

        // valid and invalid cases

        assertTrue(zts.validateOidcRedirectUri(domainData, "coretech.api", "https://api.coretech.athenz.io"));
        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech.api", "https://api-coretech.athenz.io"));

        // now verify list with subdomains

        services = new ArrayList<>();
        serviceApi = new com.yahoo.athenz.zms.ServiceIdentity().setName("coretech.sports.api");
        services.add(serviceApi);

        domainData.setServices(services);

        assertTrue(zts.validateOidcRedirectUri(domainData, "coretech.sports.api", "https://api.coretech-sports.athenz.io"));
        assertFalse(zts.validateOidcRedirectUri(domainData, "coretech.sports.api", "https://api-coretech-sports.athenz.io"));
        zts.redirectUriSuffix = savedUriSuffix;
    }

    @Test
    public void testGetOIDCResponseFailures() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // client id without domain

        try {
            zts.getOIDCResponse(context, "id_token", "coretech", "https://localhost:4443", "openid",
                    null, "nonce", "RSA", null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("Invalid client id"));
        }

        // unknown domain

        try {
            zts.getOIDCResponse(context, "id_token", "unknown-domain.api", "https://localhost:4443",
                    "openid", null, "nonce", "EC", null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("No such domain: unknown-domain"));
        }

        // no service endpoint - during the domain setup
        // service backup has no endpoint while service api is
        // registered with https://localhost:4443/zts

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true);
        store.processSignedDomain(signedDomain, false);

        try {
            zts.getOIDCResponse(context, "id_token", "coretech.backup", "https://localhost:4443/zts",
                    "openid", null, "nonce", "RSA", null, null, null, Boolean.FALSE);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        // mismatch service endpoint

        try {
            zts.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443",
                    "openid", "state", "nonce", null, null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        // invalid response type

        try {
            zts.getOIDCResponse(context, "token", "coretech.api", "https://localhost:4443/zts",
                    "openid", null, "nonce", "", null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("invalid response type"));
        }

        // empty scope

        try {
            zts.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "", null, "nonce", "rsa", null, null, null, Boolean.TRUE);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("no scope provided"));
        }

        try {
            zts.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    null, null, "nonce", "unknown", Boolean.FALSE, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("no scope provided"));
        }
    }

    @Test
    public void testGetOIDCResponseNoRulesGroups() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ztsImpl.oidcPort = 443;
        ztsImpl.ztsOIDCPortIssuer = "https://athenz.io";

        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);
        Mockito.when(context.request().getLocalPort()).thenReturn(443);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true);
        store.processSignedDomain(signedDomain, false);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid", null, "nonce", "RSA", Boolean.FALSE, null, null, Boolean.TRUE);
        Jws<Claims> claims = getClaimsFromResponse(response, privateKey.getKey(), null);
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals("https://athenz.io", claims.getBody().getIssuer());
        List<String> groups = (List<String>) claims.getBody().get("groups");
        assertNull(groups);
    }

    @Test
    public void testGetOIDCResponseGroups() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        Group groupDev = createTestGroup("coretech", "dev-team", "user_domain.user", "user_domain.user1");
        Group groupPe = createTestGroup("coretech", "pe-team", "user_domain.user", "user_domain.user1");

        List<Group> groups = new ArrayList<>();
        groups.add(groupDev);
        groups.add(groupPe);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true, groups);
        store.processSignedDomain(signedDomain, false);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        // get all the groups

        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid groups", null, "nonce", "EC", null, null, null, null);
        Jws<Claims> claims = getClaimsFromResponse(response, privateKey.getKey(), null);
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals("nonce", claims.getBody().get("nonce", String.class));
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        List<String> userGroups = (List<String>) claims.getBody().get("groups");
        assertNotNull(userGroups);
        assertEquals(userGroups.size(), 2);
        assertTrue(userGroups.contains("coretech:group.dev-team"));
        assertTrue(userGroups.contains("coretech:group.pe-team"));

        // get only one of the groups and include state

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid coretech:group.dev-team", "valid-state", "nonce", "RSA", null, null, null, null);
        assertEquals(response.getStatus(), ResourceException.FOUND);
        String location = response.getHeaderString("Location");
        final String stateComp = "&state=valid-state";
        assertTrue(location.endsWith(stateComp));

        int idx = location.indexOf("#id_token=");
        String idToken = location.substring(idx + 10, location.length() - stateComp.length());

        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey()))
                    .build().parseClaimsJws(idToken);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        userGroups = (List<String>) claims.getBody().get("groups");
        assertNotNull(userGroups);
        assertEquals(userGroups.size(), 1);
        assertTrue(userGroups.contains("coretech:group.dev-team"));

        // requesting a group that the user is not part of

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid coretech:group.eng-team", null, "nonce", null, Boolean.FALSE, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("principal not included in requested groups"));
        }
    }

    @Test
    public void testGetOIDCResponseGroupsDifferentDomain() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true, null);
        store.processSignedDomain(signedDomain, false);

        Group groupDev = createTestGroup("weather", "dev-team", "user_domain.user", "user_domain.user1");
        Group groupPe = createTestGroup("weather", "pe-team", "user_domain.user", "user_domain.user1");

        List<Group> groups = new ArrayList<>();
        groups.add(groupDev);
        groups.add(groupPe);

        signedDomain = createSignedDomain("weather", "sports", "api", true, groups);
        store.processSignedDomain(signedDomain, false);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        // get all the groups from the coretech domain

        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid groups weather:domain", null, "nonce", "EC", null, null, null, null);
        Jws<Claims> claims = getClaimsFromResponse(response, privateKey.getKey(), null);
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals("nonce", claims.getBody().get("nonce", String.class));
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        List<String> userGroups = (List<String>) claims.getBody().get("groups");
        assertNotNull(userGroups);
        assertEquals(userGroups.size(), 2);
        assertTrue(userGroups.contains("weather:group.dev-team"));
        assertTrue(userGroups.contains("weather:group.pe-team"));

        // try with unknown domain

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid groups unknown-domain:domain", null, "nonce", "EC", null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
    }

    private Group createTestGroup(final String domainName, final String groupName, final String... members) {
        Group group = new Group();
        final String groupDevName = generateGroupName(domainName, groupName);
        group.setName(groupDevName);
        List<GroupMember> groupMembers = new ArrayList<>();
        for (String member : members) {
            groupMembers.add(new GroupMember().setMemberName(member).setGroupName(groupDevName));
        }
        group.setGroupMembers(groupMembers);
        return group;
    }

    @Test
    public void testGetOIDCResponseGroupsMultipleDomains() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        IdTokenRequest.setMaxDomains(10);

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // first create the coretech domain groups

        Group groupDev = createTestGroup("coretech", "dev-team", "user_domain.user", "user_domain.user1");
        Group groupPe = createTestGroup("coretech", "pe-team", "user_domain.user", "user_domain.user1");

        List<Group> groups = new ArrayList<>();
        groups.add(groupDev);
        groups.add(groupPe);

        SignedDomain signedDomain1 = createSignedDomain("coretech", "sports", "api", true, groups);
        store.processSignedDomain(signedDomain1, false);

        // now create the weather domain groups

        groupDev = createTestGroup("weather", "dev-team", "user_domain.user", "user_domain.user1");
        groupPe = createTestGroup("weather", "pe-team", "user_domain.user", "user_domain.user1");

        groups = new ArrayList<>();
        groups.add(groupDev);
        groups.add(groupPe);

        SignedDomain signedDomain2 = createSignedDomain("weather", "sports", "api", true, groups);
        store.processSignedDomain(signedDomain2, false);

        // domains with no groups

        SignedDomain signedDomain3 = createSignedDomain("homepage", "sports", "api", true, null);
        store.processSignedDomain(signedDomain3, false);

        SignedDomain signedDomain4 = createSignedDomain("fantasy", "sports", "api", true, null);
        store.processSignedDomain(signedDomain4, false);

        // get all the groups

        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api",
                "https://localhost:4443/zts", "openid groups coretech:domain weather:domain homepage:domain",
                null, "nonce", "EC", null, null, null, null);
        assertEquals(response.getStatus(), ResourceException.FOUND);
        String location = response.getHeaderString("Location");

        int idx = location.indexOf("#id_token=");
        String idToken = location.substring(idx + 10);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey()))
                    .build().parseClaimsJws(idToken);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals("nonce", claims.getBody().get("nonce", String.class));
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        List<String> userGroups = (List<String>) claims.getBody().get("groups");
        assertNotNull(userGroups);
        assertEquals(userGroups.size(), 4);
        assertTrue(userGroups.contains("coretech:group.dev-team"));
        assertTrue(userGroups.contains("coretech:group.pe-team"));
        assertTrue(userGroups.contains("weather:group.dev-team"));
        assertTrue(userGroups.contains("weather:group.pe-team"));

        // get only one of the groups and include state

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api",
                "https://localhost:4443/zts", "openid coretech:group.dev-team weather:group.pe-team",
                "valid-state", "nonce", "RSA", null, null, null, Boolean.FALSE);
        assertEquals(response.getStatus(), ResourceException.FOUND);
        location = response.getHeaderString("Location");
        String stateComp = "&state=valid-state";
        assertTrue(location.endsWith(stateComp));

        idx = location.indexOf("#id_token=");
        idToken = location.substring(idx + 10, location.length() - stateComp.length());

        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey()))
                    .build().parseClaimsJws(idToken);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        userGroups = (List<String>) claims.getBody().get("groups");
        assertNotNull(userGroups);
        assertEquals(userGroups.size(), 2);
        assertTrue(userGroups.contains("coretech:group.dev-team"));
        assertTrue(userGroups.contains("weather:group.pe-team"));

        // requesting a group that the user is not part of

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid coretech:group.eng-team weather:group.eng-team", null, "nonce", null,
                    Boolean.FALSE, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("principal not included in requested groups"));
        }

        // specify a domain that doesn't exist

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid coretech:group.eng finance:group.eng", null, "nonce", "EC", Boolean.FALSE,
                    null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("No such domain: finance"));
        }

        // requests from domains where the user is not part of any groups

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid groups homepage:domain fantasy:domain", "valid-state", "nonce", "RSA", null,
                null, null, null);
        assertEquals(response.getStatus(), ResourceException.FOUND);
        location = response.getHeaderString("Location");
        stateComp = "&state=valid-state";
        assertTrue(location.endsWith(stateComp));

        idx = location.indexOf("#id_token=");
        idToken = location.substring(idx + 10, location.length() - stateComp.length());

        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey.getKey()))
                    .build().parseClaimsJws(idToken);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        userGroups = (List<String>) claims.getBody().get("groups");
        assertNull(userGroups);
    }

    @Test
    public void testGetOIDCResponseRolesWithJson() {
        testGetOIDCResponseRoles("json", null, Boolean.TRUE);
        testGetOIDCResponseRoles("json", Boolean.FALSE, Boolean.TRUE);
        testGetOIDCResponseRoles("json", Boolean.TRUE, Boolean.TRUE);
        testGetOIDCResponseRoles("json", Boolean.TRUE, Boolean.FALSE);
    }

    @Test
    public void testGetOIDCResponseRolesRFC() {
        testGetOIDCResponseRoles(null, null, Boolean.TRUE);
        testGetOIDCResponseRoles(null, Boolean.FALSE, Boolean.TRUE);
        testGetOIDCResponseRoles(null, Boolean.TRUE, Boolean.TRUE);
    }

    private void testGetOIDCResponseRoles(final String output, Boolean roleInAudClaim, Boolean includeRedirectUri) {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ztsImpl.userDomain = "user_domain";

        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true, null);
        store.processSignedDomain(signedDomain, false);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        // get all the roles

        final String redirectUri = includeRedirectUri ? "https://localhost:4443/zts" : null;
        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", redirectUri,
                "openid roles", null, "nonce", "", null, null, output, roleInAudClaim);
        Jws<Claims> claims = getClaimsFromResponse(response, privateKey.getKey(), output);
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals((roleInAudClaim == Boolean.TRUE) ? "coretech.api:writers" : "coretech.api", claims.getBody().getAudience());
        assertEquals("nonce", claims.getBody().get("nonce", String.class));
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        List<String> userRoles = (List<String>) claims.getBody().get("groups");
        assertNotNull(userRoles);
        assertEquals(userRoles.size(), 1);
        assertTrue(userRoles.contains("writers"));

        // get only one of the roles with a 30-min timeout
        // which should be honored

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", redirectUri,
                "openid coretech:role.writers", null, "nonce", "RSA", Boolean.FALSE, 30 * 60, output, roleInAudClaim);
        claims = getClaimsFromResponse(response, privateKey.getKey(), output);
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals((roleInAudClaim == Boolean.TRUE) ? "coretech.api:writers" : "coretech.api", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        userRoles = (List<String>) claims.getBody().get("groups");
        assertNotNull(userRoles);
        assertEquals(userRoles.size(), 1);
        assertTrue(userRoles.contains("writers"));
        assertEquals(claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime(), 30 * 60 * 1000);

        // repeat the same request with 120 minutes and make sure the
        // expiry is still set to 1 hour

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", redirectUri,
                "openid coretech:role.writers", null, "nonce", "RSA", Boolean.FALSE, 120 * 60, output, roleInAudClaim);
        claims = getClaimsFromResponse(response, privateKey.getKey(), output);
        assertNotNull(claims);
        assertEquals(claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime(), 60 * 60 * 1000);

        // let's set the user domain to a different value so the
        // principal will be treated as a service thus the 120-min
        // value will be allowed

        ztsImpl.userDomain = "user-other-domain";

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", redirectUri,
                "openid coretech:role.writers", null, "nonce", "RSA", Boolean.FALSE, 120 * 60, output, roleInAudClaim);
        claims = getClaimsFromResponse(response, privateKey.getKey(), output);
        assertNotNull(claims);
        assertEquals(claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime(), 120 * 60 * 1000);

        // reset the domain value

        ztsImpl.userDomain = "user_domain";

        // requesting a role that the user is not part of

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", redirectUri,
                "openid coretech:role.eng-team", null, "nonce", "EC", Boolean.FALSE, null, output, roleInAudClaim);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("principal not included in requested roles"));
        }
    }

    private Jws<Claims> getClaimsFromResponse(Response response, PrivateKey privateKey, final String output) {

        String idToken;
        if ("json".equalsIgnoreCase(output)) {
            assertEquals(response.getStatus(), ResourceException.OK);
            OIDCResponse oidcResponse = (OIDCResponse) response.getEntity();
            idToken = oidcResponse.getId_token();
        } else {
            assertEquals(response.getStatus(), ResourceException.FOUND);
            String location = response.getHeaderString("Location");

            int idx = location.indexOf("#id_token=");
            idToken = location.substring(idx + 10);
        }

        try {
            return Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(privateKey))
                    .build().parseClaimsJws(idToken);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
    }

    @Test
    public void testGetOIDCResponseRolesDifferentDomain() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true, null);
        store.processSignedDomain(signedDomain, false);

        signedDomain = createSignedDomain("weather", "sports", "api", true, null);
        store.processSignedDomain(signedDomain, false);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        // get all the roles

        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid roles weather:domain", null, "nonce", "", null, null, null, Boolean.FALSE);
        Jws<Claims> claims = getClaimsFromResponse(response, privateKey.getKey(), null);

        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals("nonce", claims.getBody().get("nonce", String.class));
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        List<String> userRoles = (List<String>) claims.getBody().get("groups");
        assertNotNull(userRoles);
        assertEquals(userRoles.size(), 1);
        assertTrue(userRoles.contains("weather:role.writers"));

        // try with unknown domain

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid roles unknown-domain:domain", null, "nonce", "EC", null, null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }
    }

    @Test
    public void testGetOIDCResponseRolesMultipleDomains() {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        IdTokenRequest.setMaxDomains(10);

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedDomain signedDomain1 = createSignedDomain("coretech", "sports", "api", true, null);
        store.processSignedDomain(signedDomain1, false);

        SignedDomain signedDomain2 = createSignedDomain("weather", "sports", "api", true, null);
        store.processSignedDomain(signedDomain2, false);

        SignedDomain signedDomain3 = createSignedDomainExpiration("homepage", "api");
        store.processSignedDomain(signedDomain3, false);

        SignedDomain signedDomain4 = createSignedDomainExpiration("fantasy", "api");
        store.processSignedDomain(signedDomain4, false);
        ServerPrivateKey privateKey = getServerPrivateKey(ztsImpl, ztsImpl.keyAlgoForJsonWebObjects);

        // get all the roles

        Response response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api",
                "https://localhost:4443/zts", "openid roles coretech:domain weather:domain homepage:domain",
                null, "nonce", "", null, null, null, null);
        Jws<Claims> claims = getClaimsFromResponse(response, privateKey.getKey(), null);

        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals("nonce", claims.getBody().get("nonce", String.class));
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        List<String> userRoles = (List<String>) claims.getBody().get("groups");
        assertNotNull(userRoles);
        assertEquals(userRoles.size(), 2);
        assertTrue(userRoles.contains("coretech:role.writers"));
        assertTrue(userRoles.contains("weather:role.writers"));

        // specific the roles explicitly

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid coretech:role.writers weather:role.writers", null, "nonce", "RSA", Boolean.FALSE,
                null, null, null);
        assertEquals(response.getStatus(), ResourceException.FOUND);
        claims = getClaimsFromResponse(response, privateKey.getKey(), null);

        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        userRoles = (List<String>) claims.getBody().get("groups");
        assertNotNull(userRoles);
        assertEquals(userRoles.size(), 2);
        assertTrue(userRoles.contains("coretech:role.writers"));
        assertTrue(userRoles.contains("weather:role.writers"));

        // requesting a role that the user is not part of

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid coretech:role.eng weather:role.eng", null, "nonce", "EC", Boolean.FALSE,
                    null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("principal not included in requested roles"));
        }

        // specify a domain that doesn't exist

        try {
            ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                    "openid coretech:role.eng finance:role.eng", null, "nonce", "EC", Boolean.FALSE,
                    null, null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
            assertTrue(ex.getMessage().contains("No such domain: finance"));
        }

        // requests from domains where the user is not part of any role

        response = ztsImpl.getOIDCResponse(context, "id_token", "coretech.api", "https://localhost:4443/zts",
                "openid roles homepage:domain fantasy:domain", null, "nonce", "RSA", null, null, null, null);
        claims = getClaimsFromResponse(response, privateKey.getKey(), null);

        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech.api", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOpenIDIssuer, claims.getBody().getIssuer());
        userRoles = (List<String>) claims.getBody().get("groups");
        assertNull(userRoles);
    }

    @Test
    public void testGeSignPrivateKey() {

        // by default, we specify the original key and not rsa/ec keys

        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey(null));
        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey(""));
        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey("unknown"));

        List<String> algValues = zts.getSupportedSigningAlgValues();
        assertEquals(1, algValues.size());
        assertTrue(algValues.contains("RS256"));

        // load our ec and rsa private keys

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, "src/test/resources/unit_test_zts_private_ec.pem");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        zts.loadServicePrivateKey();

        algValues = zts.getSupportedSigningAlgValues();
        assertEquals(2, algValues.size());
        assertTrue(algValues.contains("RS256"));
        assertTrue(algValues.contains("ES256"));

        assertEquals(zts.privateECKey, zts.getSignPrivateKey("EC"));
        assertEquals(zts.privateECKey, zts.getSignPrivateKey("ec"));

        assertEquals(zts.privateRSAKey, zts.getSignPrivateKey("RSA"));
        assertEquals(zts.privateRSAKey, zts.getSignPrivateKey("rsa"));

        // now back to our regular key setup - we only have a single key
        // so we have a match always

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);

        zts.loadServicePrivateKey();

        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey("RSA"));
        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey("rsa"));
        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey("EC"));
        assertEquals(zts.privateOrigKey, zts.getSignPrivateKey("ec"));
    }

    @Test
    public void testGenerateInstanceConfirmObjectWithCtxCert() throws IOException {
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);
        Mockito.when(mockCloudStore.getAzureSubscription("athenz")).thenReturn("12345");
        Mockito.when(mockCloudStore.getGCPProjectId("athenz")).thenReturn(null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        Path path = Paths.get("src/test/resources//athenz.instanceid.hostname.pem");
        X509Certificate cert = Crypto.loadX509Certificate(path.toFile());
        X509Certificate[] certs = new X509Certificate[]{cert};

        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getAttribute(Http.JAVAX_CERT_ATTR)).thenReturn(certs).thenReturn(null);

        ResourceContext context = createResourceContext(null, servletRequest);

        path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));
        X509CertRequest certRequest = new X509ServiceCertRequest(certCsr);

        InstanceConfirmation confirmation = ztsImpl.newInstanceConfirmationForRegister(context,
                "secureboot.provider",
                "athenz",
                "production",
                "attestationData",
                "1001",
                "athenz-example1.host.com",
                certRequest,
                InstanceProvider.Scheme.CLASS,
                "aws"
        );

        assertNotNull(confirmation);
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN), "CN=self.signer.root");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN), "CN=athenz.production,OU=Testing Domain,O=Athenz,L=LA,ST=CA,C=US");
        assertEquals(confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_CERT_RSA_MOD_HASH), "72332cafbe1f874b4d89f6277508d03494c0dd4258e32a6999a7b8328eaa0e07");

        // Ensure the cert issuer/key modulus/subject attributes are empty, when the context doesn't have certificates
        // Mocking is set up to return null for certs on a second call
        confirmation = ztsImpl.newInstanceConfirmationForRegister(context,
                "secureboot.provider",
                "athenz",
                "production",
                "attestationData",
                "1001",
                "athenz-example1.host.com",
                certRequest,
                InstanceProvider.Scheme.CLASS,
                "aws"
        );
        assertNotNull(confirmation);
        assertNull(confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN));
        assertNull(confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN));
        assertNull(confirmation.getAttributes().get(InstanceProvider.ZTS_INSTANCE_CERT_RSA_MOD_HASH));
    }

    @Test
    public void testGetInfo() throws URISyntaxException, FileNotFoundException {

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ztsImpl.serverInfo = null;

        RsrcCtxWrapper mockContext = Mockito.mock(RsrcCtxWrapper.class);
        HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
        when(mockRequest.isSecure()).thenReturn(true);
        when(mockContext.request()).thenReturn(mockRequest);
        ServletContext mockServletContext = Mockito.mock(ServletContext.class);
        when(mockContext.servletContext()).thenReturn(mockServletContext);

        FileInputStream inputStream = new FileInputStream(
                new File(getClass().getClassLoader().getResource("manifest.mf").toURI()));
        when(mockServletContext.getResourceAsStream("/META-INF/MANIFEST.MF")).thenReturn(inputStream);

        Info info = ztsImpl.getInfo(mockContext);
        assertNotNull(info);
        assertEquals(info.getImplementationVersion(), "1.11.0");
        assertEquals(info.getBuildJdkSpec(), "17");
        assertEquals(info.getImplementationTitle(), "zts");
        assertEquals(info.getImplementationVendor(), "athenz");

        // this should be no-op since we already have an info object

        ztsImpl.fetchInfoFromManifest(mockServletContext);

        // this should just return our previously generated info object

        info = ztsImpl.getInfo(mockContext);
        assertNotNull(info);
        assertEquals(info.getImplementationVersion(), "1.11.0");
        assertEquals(info.getBuildJdkSpec(), "17");
        assertEquals(info.getImplementationTitle(), "zts");
        assertEquals(info.getImplementationVendor(), "athenz");
    }

    @Test
    public void testGetInfoException() throws URISyntaxException, FileNotFoundException {

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ztsImpl.serverInfo = null;

        RsrcCtxWrapper mockContext = Mockito.mock(RsrcCtxWrapper.class);
        HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
        when(mockRequest.isSecure()).thenReturn(true);
        when(mockContext.request()).thenReturn(mockRequest);
        ServletContext mockServletContext = Mockito.mock(ServletContext.class);
        when(mockContext.servletContext()).thenReturn(mockServletContext);
        when(mockServletContext.getResourceAsStream("/META-INF/MANIFEST.MF")).thenThrow(new IllegalArgumentException());

        Info info = ztsImpl.getInfo(mockContext);
        assertNotNull(info);
        assertNull(info.getImplementationVersion());
        assertNull(info.getBuildJdkSpec());
        assertNull(info.getImplementationTitle());
        assertNull(info.getImplementationVendor());
    }

    @Test
    public void testGetIdTokenGroupsFromGroups() {

        assertNull(zts.getIdTokenGroupsFromGroups(null, "coretech", Boolean.TRUE));
        assertNull(zts.getIdTokenGroupsFromGroups(null, "coretech", Boolean.FALSE));
        assertNull(zts.getIdTokenGroupsFromGroups(null, "coretech", null));

        List<String> groups = Collections.singletonList("admin");
        assertEquals(zts.getIdTokenGroupsFromGroups(groups, "coretech", Boolean.FALSE), groups);
        assertEquals(zts.getIdTokenGroupsFromGroups(groups, "coretech", null), groups);

        List<String> resGroups = zts.getIdTokenGroupsFromGroups(groups, "coretech", Boolean.TRUE);
        assertEquals(resGroups.size(), 1);
        assertEquals(resGroups.get(0), "coretech:group.admin");

        groups = new ArrayList<>();
        groups.add("reader");
        groups.add("writer");
        resGroups = zts.getIdTokenGroupsFromGroups(groups, "coretech", Boolean.TRUE);
        assertEquals(resGroups.size(), 2);
        assertEquals(resGroups.get(0), "coretech:group.reader");
        assertEquals(resGroups.get(1), "coretech:group.writer");
    }

    @Test
    public void testGetIdTokenGroupsFromRoles() {

        assertNull(zts.getIdTokenGroupsFromRoles(Collections.emptySet(), "coretech", Boolean.FALSE));
        assertNull(zts.getIdTokenGroupsFromRoles(Collections.emptySet(), "coretech", Boolean.TRUE));
        assertNull(zts.getIdTokenGroupsFromRoles(Collections.emptySet(), "coretech", null));

        Set<String> groups = new HashSet<>();
        groups.add("reader");
        groups.add("writer");
        List<String> resGroups = zts.getIdTokenGroupsFromRoles(groups, "coretech", Boolean.TRUE);

        assertEquals(resGroups.size(), 2);
        assertTrue(resGroups.contains("coretech:role.reader"));
        assertTrue(resGroups.contains("coretech:role.writer"));
    }

    @Test
    public void testIsOidcPortRequest() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null, ztsMetric);

        HttpServletRequest servletRequest443 = Mockito.mock(HttpServletRequest.class);
        when(servletRequest443.getLocalPort()).thenReturn(443);

        HttpServletRequest servletRequest4443 = Mockito.mock(HttpServletRequest.class);
        when(servletRequest4443.getLocalPort()).thenReturn(4443);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.oidcPort = 0;
        ztsImpl.httpsPort = 4443;

        assertFalse(ztsImpl.isOidcPortRequest(servletRequest443, null));
        assertFalse(ztsImpl.isOidcPortRequest(servletRequest4443, null));

        ztsImpl.oidcPort = 443;
        ztsImpl.httpsPort = 4443;

        assertTrue(ztsImpl.isOidcPortRequest(servletRequest443, null));
        assertFalse(ztsImpl.isOidcPortRequest(servletRequest4443, null));

        ztsImpl.oidcPort = 4443;
        ztsImpl.httpsPort = 4443;

        assertFalse(ztsImpl.isOidcPortRequest(servletRequest443, null));
        assertFalse(ztsImpl.isOidcPortRequest(servletRequest4443, null));

        // with a null request object we get true always

        assertTrue(ztsImpl.isOidcPortRequest(null, null));

        // with the issuer option specified we get the requested value

        assertTrue(ztsImpl.isOidcPortRequest(null, "oidc_port"));
        assertFalse(ztsImpl.isOidcPortRequest(null, "openid"));
        assertTrue(ztsImpl.isOidcPortRequest(null, ""));
        assertTrue(ztsImpl.isOidcPortRequest(null, "unknown_option"));
    }

    @Test
    public void testGetIdTokenAudience() {
        assertEquals(zts.getIdTokenAudience("id", null, null), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.FALSE, null), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.TRUE, null), "id");

        List<String> idTokenGroups = new ArrayList<>();
        assertEquals(zts.getIdTokenAudience("id", null, idTokenGroups), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.FALSE, idTokenGroups), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.TRUE, idTokenGroups), "id");

        idTokenGroups.add("athenz:role.oidc");
        assertEquals(zts.getIdTokenAudience("id", null, idTokenGroups), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.FALSE, idTokenGroups), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.TRUE, idTokenGroups), "id:athenz:role.oidc");

        idTokenGroups.add("athenz:role.oidc2");
        assertEquals(zts.getIdTokenAudience("id", null, idTokenGroups), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.FALSE, idTokenGroups), "id");
        assertEquals(zts.getIdTokenAudience("id", Boolean.TRUE, idTokenGroups), "id");
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

    @Test
    public void testPostExternalCredentials() throws IOException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ztsImpl.userDomain = "user_domain";

        // set back to our zts rsa private key
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true, null);
        store.processSignedDomain(signedDomain, false);

        GcpAccessTokenProvider provider = new GcpAccessTokenProvider();
        ztsImpl.externalCredentialsManager.setProvider("gcp", provider);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        HttpDriverResponse exchangeTokenResponse = new HttpDriverResponse(200,
                GcpAccessTokenProviderTest.EXCHANGE_TOKEN_RESPONSE_STR, null);
        HttpDriverResponse accessTokenResponse = new HttpDriverResponse(200,
                GcpAccessTokenProviderTest.ACCESS_TOKEN_RESPONSE_STR, null);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(exchangeTokenResponse, accessTokenResponse);

        provider.setHttpDriver(httpDriver);
        Mockito.when(authorizer.access(any(), any(), any(), any())).thenReturn(true);

        // get exchange credentials

        ExternalCredentialsRequest extCredsRequest = new ExternalCredentialsRequest();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("athenzRoleName", "writers");
        attributes.put("gcpServiceAccount", "gcp-svc-writer");
        extCredsRequest.setAttributes(attributes);

        extCredsRequest.setClientId("coretech.api");
        ExternalCredentialsResponse extCredsResponse = ztsImpl.postExternalCredentialsRequest(context,
                "gcp", "coretech", extCredsRequest);
        assertNotNull(extCredsResponse);

        // now let's test the same api through our instance provider

        InstanceExternalCredentialsProvider extCredsProvider = new InstanceExternalCredentialsProvider("user_domain.user", ztsImpl);
        extCredsResponse = extCredsProvider.getExternalCredentials("gcp", "coretech", extCredsRequest);
        assertNotNull(extCredsResponse);

        // let's temporarily disable gcp provider

        ztsImpl.externalCredentialsManager.disableProvider("gcp");
        try {
            ztsImpl.postExternalCredentialsRequest(context, "gcp", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid external credentials provider"));
        }
        ztsImpl.externalCredentialsManager.enableProvider("gcp");

        // now let's configure our http driver to return failure

        exchangeTokenResponse = new HttpDriverResponse(403, GcpAccessTokenProviderTest.EXCHANGE_TOKEN_ERROR_STR, null);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(exchangeTokenResponse);
        attributes.put("athenzScope", "openid coretech:role.writers");

        try {
            ztsImpl.postExternalCredentialsRequest(context, "gcp", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
            assertTrue(ex.getMessage().contains("gcp exchange token error"));
        }
    }

    @Test
    public void testPostExternalCredentialsFailures() throws IOException {

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_at_private.pem");

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ztsImpl.userDomain = "user_domain";

        // set back to our zts rsa private key

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        SignedDomain signedDomain = createSignedDomain("coretech", "sports", "api", true, null);
        store.processSignedDomain(signedDomain, false);

        GcpAccessTokenProvider provider = new GcpAccessTokenProvider();
        ztsImpl.externalCredentialsManager.setProvider("gcp", provider);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        Mockito.when(httpDriver.doPost(any())).thenReturn(GcpAccessTokenProviderTest.EXCHANGE_TOKEN_RESPONSE_STR,
                GcpAccessTokenProviderTest.ACCESS_TOKEN_RESPONSE_STR);

        provider.setHttpDriver(httpDriver);
        Mockito.when(authorizer.access(any(), any(), any(), any())).thenReturn(true);

        // request with unknown provider

        ExternalCredentialsRequest extCredsRequest = new ExternalCredentialsRequest();
        extCredsRequest.setClientId("coretech");

        try {
            ztsImpl.postExternalCredentialsRequest(context, "aws", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.BAD_REQUEST, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid external credentials provider"));
        }

        // gcp provider is valid but no attributes in the request

        try {
            ztsImpl.postExternalCredentialsRequest(context, "gcp", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.BAD_REQUEST, ex.getCode());
            assertTrue(ex.getMessage().contains("Missing credentials attributes"));
        }

        Map<String, String> attributes = new HashMap<>();
        extCredsRequest.setAttributes(attributes);

        // valid attribute map but no role or scope attributes

        try {
            ztsImpl.postExternalCredentialsRequest(context, "gcp", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.BAD_REQUEST, ex.getCode());
            assertTrue(ex.getMessage().contains("Either athenzRoleName or athenzScope must be specified"));
        }

        attributes.put("athenzScope", "openid coretech:role.writers");
        attributes.put("athenzFullArn", "true");
        attributes.put("gcpServiceAccount", "gcp-svc-writer");

        // invalid client id (without service component)

        try {
            ztsImpl.postExternalCredentialsRequest(context, "gcp", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.BAD_REQUEST, ex.getCode());
            assertTrue(ex.getMessage().contains("Invalid client id"));
        }

        // invalid client id (unknown domain) but let's use role name
        // instead of scope for our request

        attributes.remove("athenzScope");
        attributes.put("athenzRoleName", "writers");
        extCredsRequest.setClientId("coretech-unknown.api");

        try {
            ztsImpl.postExternalCredentialsRequest(context, "gcp", "coretech", extCredsRequest);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.NOT_FOUND, ex.getCode());
            assertTrue(ex.getMessage().contains("No such domain"));
        }
    }

    @Test
    public void testCreateSsshPrincipalsSet() {

        assertTrue(zts.createSshPrincipalsSet(null, null, null).isEmpty());
        assertTrue(zts.createSshPrincipalsSet("", null, null).isEmpty());
        assertTrue(zts.createSshPrincipalsSet(null, "", null).isEmpty());
        assertTrue(zts.createSshPrincipalsSet(null, null, "").isEmpty());

        Set<String> principals = zts.createSshPrincipalsSet(null, "127.0.0.1", "");
        assertEquals(principals.size(), 1);
        assertTrue(principals.contains("127.0.0.1"));

        principals = zts.createSshPrincipalsSet(null, "", "127.0.0.2");
        assertEquals(principals.size(), 1);
        assertTrue(principals.contains("127.0.0.2"));

        principals = zts.createSshPrincipalsSet("127.0.0.3", "", "");
        assertEquals(principals.size(), 1);
        assertTrue(principals.contains("127.0.0.3"));

        principals = zts.createSshPrincipalsSet("127.0.0.3,127.0.0.4", null, "");
        assertEquals(principals.size(), 2);
        assertTrue(principals.contains("127.0.0.3"));
        assertTrue(principals.contains("127.0.0.4"));

        principals = zts.createSshPrincipalsSet("127.0.0.3,127.0.0.4", "127.0.0.5", "127.0.0.6");
        assertEquals(principals.size(), 4);
        assertTrue(principals.contains("127.0.0.3"));
        assertTrue(principals.contains("127.0.0.4"));
        assertTrue(principals.contains("127.0.0.5"));
        assertTrue(principals.contains("127.0.0.6"));
    }
}
