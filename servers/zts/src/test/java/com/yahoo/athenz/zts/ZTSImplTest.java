/*
 * Copyright 2016 Yahoo Inc.
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.Response;

import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.store.impl.ZMSFileChangeLogStore;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zts.status.MockStatusCheckerThrowException;
import com.yahoo.athenz.zts.status.MockStatusCheckerNoException;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.MockCloudStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.CertificateAuthority;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.impl.UserAuthority;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.ZTSImpl.AthenzObject;
import com.yahoo.athenz.zts.ZTSImpl.ServiceX509RefreshRequestStatus;
import com.yahoo.athenz.zts.ZTSAuthorizer.AccessStatus;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cert.*;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.testng.Assert.*;

public class ZTSImplTest {

    private int roleTokenDefaultTimeout = 2400;
    private int roleTokenMaxTimeout = 96000;

    private ZTSImpl zts = null;
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
    
    @BeforeClass
    public void setupClass() {
        MockitoAnnotations.initMocks(this);
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
        System.setProperty(ZTSConsts.ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS, "screwdriver");
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

        // enable ip validation for cert requests

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REQUEST_VERIFY_IP, "true");

        store = new DataStore(structStore, cloudStore);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        authorizer = new ZTSAuthorizer(store);

        // enable openid scope

        AccessTokenRequest.setSupportOpenidScope(true);
    }
    
    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
    }
    
    static class ZtsMetricTester extends com.yahoo.athenz.common.metrics.impl.NoOpMetric {
        final Map<String, Integer> metrixMap = new HashMap<>();

        Map<String, Integer> getMap() { return metrixMap; }

        public void  increment(String metric, String domainName, String principalDomain, int count) {
            String key = metric + domainName;
            metrixMap.put(key, count);
        }
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
            
            service = new ServiceIdentity();
            service.setName(generateServiceIdentityName(domainName, "backup"));
            setServicePublicKey(service, "0", ZTS_Y64_CERT0);
            
            hosts = new ArrayList<>();
            hosts.add("host2");
            hosts.add("host3");
            service.setHosts(hosts);
            services.add(service);
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
        domain.setModified(Timestamp.fromCurrentTime());
        
        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");
        
        return signedDomain;
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        
        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain);
        assertEquals(policyList.size(), 2);
        assertEquals(policyList.get(0).getName(), "coretech:policy.reader");
        assertEquals(policyList.get(1).getName(), "coretech:policy.writer");
    }
    
    @Test
    public void testGetPolicyListPoliciesNull() {
        
        DomainData domain = new DomainData();
        domain.setName("coretech");
        domain.setPolicies(null);
        domain.setModified(Timestamp.fromCurrentTime());

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain);
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

        List<com.yahoo.athenz.zts.Policy> policyList = zts.getPolicyList(domain);
        assertEquals(policyList.size(), 0);
    }
    
    
    @Test
    public void testGetRoleTokenAuthorizedService() {
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        signedDomain.domain.setApplicationId("application_id");
        store.processDomain(signedDomain, false);
        
        //success
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, new CertificateAuthority());
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomainWildCard("netops");
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomainWildCard("netops");
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
    public void testGetServiceIdentityInvalid() {
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
    public void testDetermineIdTokenTimeout() {
        assertEquals(zts.determineIdTokenTimeout(3600), 3600);
        assertEquals(zts.determineIdTokenTimeout(360000), zts.idTokenMaxTimeout);
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

        DataStore store = new DataStore(structStore, null);
        
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
        assertEquals("coretech", zts.retrieveTenantDomainName("storage.tenant.coretech.resource_group.admin", "storage"));
        assertEquals("coretech", zts.retrieveTenantDomainName("storage.tenant.coretech.resource_group.admin", null));
        
        signedDomain = createSignedDomain("coretech.office.burbank", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.resource_group.admin", "storage"));
        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.resource_group.admin", null));
    }
    
    @Test
    public void testRetrieveTenantDomainName4PlusCompsValidDomainWithOutResourceGroup() {
        
        SignedDomain signedDomain = createSignedDomain("coretech.office.burbank", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.admin", "storage"));
        assertEquals("coretech.office.burbank", zts.retrieveTenantDomainName("storage.tenant.coretech.office.burbank.admin", null));
    }
    
    @Test
    public void testRetrieveTenantDomainName4PlusCompsInvalidDomain() {
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        assertNull(zts.retrieveTenantDomainName("storage.tenant.coretech.office.glendale.admin", "storage"));
        assertNull(zts.retrieveTenantDomainName("storage.tenant.coretech.office.glendale.resource_group.admin", null));
    }
    
    @Test
    public void testGetTenantDomainsSingleDomain() {

        SignedDomain signedDomain = createSignedDomain("athenz.product", "weather.frontpage", "storage", true);
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);

        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomain("hockey.kings", "athenz.multiple", "storage");
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomain("hockey.stars", "athenz.multiple", "storage");
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomain("weather.frontpage", "athenz.product", "storage");
        store.processDomain(signedDomain, false);
        
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
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) zts.newResourceContext(mockServletRequest, mockServletResponse, "apiName");
        assertNotNull(ctx);
        assertNotNull(ctx.context());
        assertNull(ctx.principal());
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
        store.processDomain(signedDomain, false);
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "role", "user_domain.user200"));
    }
    
    @Test
    public void testVerifyAWSAssumeRole() {
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processDomain(signedDomain, false);
        
        // our group includes user100 and user101
        assertTrue(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws_role_name", "user_domain.user100"));
        assertTrue(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws_role_name", "user_domain.user101"));
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws_role_name", "user_domain.user102"));
    }
    
    @Test
    public void testVerifyAWSAssumeRoleNoResourceMatch() {
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processDomain(signedDomain, false);
        
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws2_role_name", "user_domain.user100"));
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws2_role_name", "user_domain.user101"));
        assertFalse(zts.verifyAWSAssumeRole("athenz.product", "athenz.product:aws2_role_name", "user_domain.user102"));
    }
    
    @Test
    public void testGetAWSTemporaryCredentialsNoCloudStore() {
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
        principal.setAuthorizedService("athenz.service");
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.setMockFields("1234", "aws_role_name", "user_domain.user101");
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processDomain(signedDomain, false);

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
    public void testPostInstanceRefreshRequestMismatchIP() throws IOException {

        Path path = Paths.get("src/test/resources/athenz.single_ip.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz",
                "production", "v=S1,d=athenz;n=production;s=sig", 0, new PrincipalAuthority());
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

        access = zts.getResourceAccess(ctx, "update", domainName + ":table1", null, "user.user3");
        assertTrue(access.getGranted());
        
        access = zts.getResourceAccess(ctx, "update", domainName + ":table2", null, "user.user3");
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
    public void testGetAccess() {
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
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
        store.processDomain(signedDomain, false);
        
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
    public void testPostDomainMetrics() {
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", false);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // create zts with a metric we can verify
        
        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZtsMetricTester metric = new ZtsMetricTester();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";
        ztsImpl.metric = metric;
        
        String testDomain = "coretech";

        // create some metrics
        
        List<DomainMetric> metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(99));
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED).
                setMetricVal(27));
        DomainMetrics req = new DomainMetrics().
            setDomainName(testDomain).
            setMetricList(metricList);

        // send the metrics
        
        ztsImpl.postDomainMetrics(context, testDomain, req);

        // verify metrics were recorded
        
        Map<String, Integer> metrixMap = metric.getMap();
        String key = "dom_metric_" + 
            DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH.toString().toLowerCase() +
            testDomain;
        Integer val = metrixMap.get(key);
        assertNotNull(val);
        assertEquals(val.intValue(), 99);
        key = "dom_metric_" +
            DomainMetricType.ACCESS_ALLOWED.toString().toLowerCase() +
            testDomain;
        val = metrixMap.get(key);
        assertNotNull(val);
        assertEquals(val.intValue(), 27);

        // test - failure case - invalid domain
        
        testDomain = "not_coretech";
        
        // create some metrics
        
        metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(999));
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED).
                setMetricVal(277));
        req = new DomainMetrics().
            setDomainName(testDomain).
            setMetricList(metricList);

        // send the metrics
        
        metrixMap.clear();
        String errMsg = "No such domain";
        try {
            ztsImpl.postDomainMetrics(context, testDomain, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains(errMsg));
        }

        // verify no metrics were recorded
        
        assertEquals(metrixMap.size(), 0);

        // test - failure case - missing domain name in metric data
        
        testDomain = "coretech";
        
        // create some metrics
        
        metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(999));
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED).
                setMetricVal(277));
        req = new DomainMetrics().
            setMetricList(metricList);

        errMsg = "Missing required field: domainName";
        
        // send the metrics
        
        metrixMap.clear();
        try {
            ztsImpl.postDomainMetrics(context, testDomain, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errMsg), ex.getMessage());
        }
        
        // verify no metrics were recorded
        
        assertEquals(metrixMap.size(), 0);

        // test - failure case - mismatch domain in uri and metric data
        
        testDomain = "coretech";
        
        // create some metrics
        
        metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(999));
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED).
                setMetricVal(277));
        req = new DomainMetrics().
            setDomainName("not_coretech").
            setMetricList(metricList);

        errMsg = "mismatched domain names";
        
        // send the metrics
        
        metrixMap.clear();
        try {
            ztsImpl.postDomainMetrics(context, testDomain, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errMsg), ex.getMessage());
        }
        // verify no metrics were recorded
        
        assertEquals(metrixMap.size(), 0);

        // test - failure case - empty metric list

        testDomain = "coretech";
        
        // create some metrics
        
        metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(999));
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED).
                setMetricVal(277));
        req = new DomainMetrics().
            setDomainName(testDomain);
 
        errMsg = "Missing required field: metricList";
        
        // send the metrics
        
        metrixMap.clear();
        try {
            ztsImpl.postDomainMetrics(context, testDomain, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errMsg), ex.getMessage());
        }
        
        // verify no metrics were recorded
        
        assertEquals(metrixMap.size(), 0);

        // test - failure case - metric count is missing
        
        testDomain = "coretech";
        
        // create a single metric without a count
        
        metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(-1));
        req = new DomainMetrics().
            setDomainName(testDomain).
            setMetricList(metricList);
        
        // verify no metrics were recorded
        
        metrixMap.clear();
        ztsImpl.postDomainMetrics(context, testDomain, req);
        assertEquals(metrixMap.size(), 0);
    }

    @Test
    public void testPostDomainMetricsNoMetrics() {
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", false);
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // create zts with a metric we can verify

        CloudStore cloudStore = new CloudStore();
        cloudStore.setHttpClient(null);
        ZtsMetricTester metric = new ZtsMetricTester();
        ZTSImpl ztsImpl = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";
        ztsImpl.metric = metric;

        String testDomain = "coretech";

        // create some metrics

        List<DomainMetric> metricList = new ArrayList<>();
        DomainMetrics req = new DomainMetrics().
                setDomainName(testDomain).
                setMetricList(metricList);

        // send the metrics

        try {
            ztsImpl.postDomainMetrics(context, testDomain, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        // metrics with invalid null type

        metricList.add(new DomainMetric().setMetricType(null).setMetricVal(-1));
        try {
            ztsImpl.postDomainMetrics(context, testDomain, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
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
    public void testValidateRoleCertificateRequestMismatchRole() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("writer");
        zts.validCertSubjectOrgValues = null;
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, null, "10.0.0.1"));
    }
    
    @Test
    public void testValidateRoleCertificateRequestMismatchEmail() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        zts.validCertSubjectOrgValues = null;
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.standings",
                null, null, "10.0.0.1"));
    }
    
    @Test
    public void testValidateRoleCertificateRequestNoEmail() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_noemail.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        zts.validCertSubjectOrgValues = null;
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "no-email", null,
                null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestInvalidOField() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        Set<String> validOValues = new HashSet<>();
        validOValues.add("InvalidCompany");
        zts.validCertSubjectOrgValues = validOValues;
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequest() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        zts.validCertSubjectOrgValues = null;
        assertTrue(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, null, "10.0.0.1"));

        Set<String> validOValues = new HashSet<>();
        validOValues.add("Athenz");
        zts.validCertSubjectOrgValues = validOValues;
        assertTrue(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores", null,
                null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestOU() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        zts.validCertSubjectOrgValues = null;

        Set<String> ouValues = new HashSet<>();
        ouValues.add("Testing Domain1");
        zts.validCertSubjectOrgUnitValues = ouValues;
        zts.verifyCertSubjectOU = true;

        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, null, "10.0.0.1"));

        ouValues.add("Testing Domain");
        assertTrue(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, null, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestWithUriHostname() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.examples.role-uri-hostname-only.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/athenz.examples.no-uri.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        // if the CSR has hostname, but the cert doesn't have hostname, it should result in false
        assertFalse(zts.validateRoleCertificateRequest(csr, "athenz.examples", roles, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));

        path = Paths.get("src/test/resources/athenz.examples.uri-hostname-only.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateRoleCertificateRequest(csr, "athenz.examples", roles, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));

        path = Paths.get("src/test/resources/athenz.examples.role-uri-instanceid-hostname.csr");
        csr = new String(Files.readAllBytes(path));

        // if CSR has hostname+instanceid, and cert has only hostname, it should result in false
        // Todo: ignoring instanceid mismatches. in later iterations, this will be a failure
        assertTrue(zts.validateRoleCertificateRequest(csr, "athenz.examples", roles, "athenz.examples.httpd",
                null, cert, "10.0.0.1"));

        path = Paths.get("src/test/resources/athenz.examples.uri-instanceid-hostname.pem");
        pem = new String(Files.readAllBytes(path));
        cert = Crypto.loadX509Certificate(pem);

        assertTrue(zts.validateRoleCertificateRequest(csr, "athenz.examples", roles, "athenz.examples.httpd",
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

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        zts.validCertSubjectOrgValues = null;

        Set<String> ouValues = new HashSet<>();
        ouValues.add("Athenz");
        zts.validCertSubjectOrgUnitValues = ouValues;
        zts.verifyCertSubjectOU = true;

        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, invalidCert, "10.0.0.1"));

        assertTrue(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores",
                null, validCert, "10.0.0.1"));
    }

    @Test
    public void testValidateRoleCertificateRequestMismatchIP() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);

        Set<String> roles = new HashSet<>();
        roles.add("writers");

        // disable IP validation and we should get success

        zts.verifyCertRequestIP = false;
        zts.validCertSubjectOrgValues = null;
        assertTrue(zts.validateRoleCertificateRequest(csr, "athenz", roles, "athenz.production",
                null, cert, "10.11.12.13"));
        assertTrue(zts.validateRoleCertificateRequest(csr, "athenz", roles, "athenz.production",
                null, cert, "10.11.12.14"));

        // enable validation and the mismatch one should fail

        zts.verifyCertRequestIP = true;
        assertTrue(zts.validateRoleCertificateRequest(csr, "athenz", roles, "athenz.production",
                null, cert, "10.11.12.13"));
        assertFalse(zts.validateRoleCertificateRequest(csr, "athenz", roles, "athenz.production",
                null, cert, "10.11.12.14"));
    }

    @Test
    public void testPostRoleCertificateRequest() {

        // this csr is for sports:role.readers role
        long expiry = 3600;
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(expiry);
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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

        store.processDomain(signedDomain, false);

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

        store.processDomain(signedDomain, false);

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
            assertTrue(ex.getMessage().contains("No access to any roles by User and Proxy Principals"));
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

        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.generateIdentity(ROLE_CERT_CORETECH_REQUEST, "coretech.weathers",
                "client", 3600)).thenReturn(null);
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

        // this csr is for sports:role.readers role

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(3600L);
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // this time we're passing an invalid role name so we should
        // get no access - 403
        
        try {
            zts.postRoleCertificateRequest(context, "coretech", "unknownrole", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
        
        // this time we're passing an role name that the user has access to
        // but it's not the readers role as in the csr
        
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
            assertEquals(ex.getCode(), 404);
        }
    }
    
    @Test
    public void testPostRoleCertificateRequestMismatchDomain() {

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_DB_REQUEST).setExpiryTime(3600L);
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        principal.setAuthorizedService("athenz.api");
        ResourceContext context = createResourceContext(principal);

        // this time we're passing an invalid role name

        try {
            zts.postRoleCertificateRequest(context, "coretech", "readers", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Authorized Service Principals not allowed"));
        }
    }

    @Test
    public void testLogPrincipalEmpty() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResourceContext ctx = zts.newResourceContext(request, null, "apiName");
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
                Mockito.any(), Mockito.any(), Mockito.anyInt());
        
        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        
        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(true);

        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        InstanceIdentity resIdentity = (InstanceIdentity) response.getEntity();
        assertNotNull(resIdentity.getX509Certificate());
    }

    @Test
    public void testPostInstanceRegisterInformationInvalidDomain() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

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
    }

    @Test
    public void testPostInstanceRegisterInformationWithHostnameCnames() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                        Mockito.any(), Mockito.any());

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem)
                .setSshCertificate("test ssh host certificate");
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
                Mockito.any(), Mockito.any(), Mockito.anyInt());
        
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
                Mockito.any(), Mockito.any(), Mockito.anyInt());
        
        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        
        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("attestationData").setCsr(certCsr)
                .setDomain("athenz").setService("production")
                .setProvider("athenz.provider").setToken(false);
        
        Mockito.doReturn(false).when(instanceManager).generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.any());
        
        ResourceContext context = createResourceContext(null);

        Response response = ztsImpl.postInstanceRegisterInformation(context, info);
        assertEquals(response.getStatus(), 201);
        assertNull(info.getSsh());
    }
    
    @Test
    public void testPostInstanceRegisterInformationCertRecordFailure() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);
        
        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);
        
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
                Mockito.any(), Mockito.any(), Mockito.anyInt());
        
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyInt());

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(true);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem)
                .setSshCertificate("test ssh host certificate");
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true)
                .setHostname("host1.athenz.cloud")
                .setSsh(sshCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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
    }

    @Test
    public void testPostInstanceRefreshInformationWithHostnameCnames() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true)
                .setHostname("host1.athenz.cloud")
                .setHostCnames(cnames);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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
        testPostInstanceRefreshInformation("src/test/resources/athenz.instance.prod.uri.csr", "test.hostname.athenz.cloud");
    }

    @Test
    public void testGetValidatedX509CertRecordForbidden() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        ztsImpl.x509CertRefreshResetTime = cert.getNotBefore().getTime() + 1;

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        ztsImpl.x509CertRefreshResetTime = cert.getNotBefore().getTime() + 1;

        X509CertRecord certRecord =  ztsImpl.getValidatedX509CertRecord(context, "athenz.provider",
                "1001", "athenz.production", cert, "caller", "athenz", "athenz",
                "localhost");
        assertNotNull(certRecord);
    }

    @Test
    public void testPostInstanceRefreshInformationNoCertRefeshCheck() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), eq("user"))).thenReturn(false);

        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production")
                .setX509Certificate(pem);
        Mockito.doReturn(identity).when(instanceManager).generateIdentity(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr).setSsh("ssh-csr").setToken(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;
        ztsImpl.x509CertRefreshResetTime = System.currentTimeMillis();

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

        tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz2", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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
                Mockito.any(), Mockito.any(), Mockito.anyInt());

        ztsImpl.instanceProviderManager = instanceProviderManager;
        ztsImpl.instanceCertManager = instanceManager;

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, null, "ssh-csr", null, "user")).thenReturn(true);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, null, "ssh-csr", null, "user")).thenReturn(true);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, null, "ssh-csr", null, "user")).thenReturn(false);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        InstanceCertManager instanceManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(instanceManager.deleteX509CertRecord("athenz.provider", "1001", "athenz.production")).thenReturn(true);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        ztsImpl.instanceCertManager = instanceManager;

        ResourceContext context = createResourceContext(null);

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

        DataStore store = new DataStore(structStore, null);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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

        DataStore store = new DataStore(structStore, null);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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

        DataStore store = new DataStore(structStore, null);
        
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = false;
        ztsImpl.statusPort = 0;
        
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        
        // if secure requests is false, no check is done
        
        ztsImpl.validateRequest(request, "principal-domain", "test");
        ztsImpl.validateRequest(request, "principal-domain", "test", false);
        ztsImpl.validateRequest(request, "principal-domain", "test", true);
        
        // should complete successfully since our request is true
        
        ztsImpl.secureRequestsOnly = true;
        ztsImpl.validateRequest(request, "principal-domain", "test");
        ztsImpl.validateRequest(request, "principal-domain", "test", false);
        ztsImpl.validateRequest(request, "principal-domain", "test", true);
    }
    
    @Test
    public void testValidateRequestNonSecureRequests() {
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        
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
            ztsImpl.validateRequest(request, "principal-domain", "test", false);
            fail();
        } catch (ResourceException ignored) {
        }
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", true);
            fail();
        } catch (ResourceException ignored) {
        }
    }
    
    @Test
    public void testValidateRequestStatusRequestPort() {
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = true;
        ztsImpl.statusPort = 8443;
        
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(4443);
        
        // non-status requests are allowed on port 4443
        
        ztsImpl.validateRequest(request, "principal-domain", "test");
        ztsImpl.validateRequest(request, "principal-domain", "test", false);

        // status requests are not allowed on port 4443
        
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", true);
            fail();
        } catch (ResourceException ignored) {
        }
    }
    
    @Test
    public void testValidateRequestRegularRequestPort() {
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.secureRequestsOnly = true;
        ztsImpl.statusPort = 8443;
        
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.isSecure()).thenReturn(true);
        Mockito.when(request.getLocalPort()).thenReturn(8443);
        
        // status requests are allowed on port 8443
        
        ztsImpl.validateRequest(request, "test", "principal-domain", true);

        // non-status requests are not allowed on port 8443
        
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test");
            fail();
        } catch (ResourceException ignored) {
        }
        
        try {
            ztsImpl.validateRequest(request, "principal-domain", "test", false);
            fail();
        } catch (ResourceException ignored) {
        }
    }
    
    @Test
    public void testGetStatus() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        
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

        DataStore store = new DataStore(structStore, null);

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

        DataStore store = new DataStore(structStore, null);

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

        DataStore store = new DataStore(structStore, null);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;
        ztsImpl.statusCertSigner = true;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.getCACertificate()).thenReturn("ca-cert");
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

        DataStore store = new DataStore(structStore, null);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.statusPort = 0;
        ztsImpl.statusCertSigner = true;

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.getCACertificate()).thenReturn(null);
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
                Mockito.anyInt())).thenReturn(null);
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid_provider_refresh.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceRefreshRequest req = new InstanceRefreshRequest().setCsr(certCsr)
                .setKeyId("v0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user",
                "doe", "v=U1,d=user;n=doe;s=sig", 0, new PrincipalAuthority());
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
        
        DataStore store = new DataStore(structStore, null);
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
        principal.setX509Certificate(cert);

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.1"), ServiceX509RefreshRequestStatus.SUCCESS);
    }
    
    @Test
    public void testValidateServiceX509RefreshRequestMismatchPublicKeys() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        DataStore store = new DataStore(structStore, null);
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
        principal.setX509Certificate(cert);

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.1"), ServiceX509RefreshRequestStatus.PUBLIC_KEY_MISMATCH);
    }
    
    @Test
    public void testValidateServiceX509RefreshRequestNotAllowedIP() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        DataStore store = new DataStore(structStore, null);
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
        principal.setX509Certificate(cert);
        
        // our ip will not match 10.0.0.1 thus failure

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.2"), ServiceX509RefreshRequestStatus.IP_NOT_ALLOWED);
    }
    
    @Test
    public void testValidateServiceX509RefreshRequestMismatchDns() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        DataStore store = new DataStore(structStore, null);
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
        principal.setX509Certificate(cert);

        assertSame(ztsImpl.validateServiceX509RefreshRequest(principal, certReq, "10.0.0.1"), ServiceX509RefreshRequestStatus.DNS_NAME_MISMATCH);
    }
    
    @Test
    public void testPostInstanceRefreshRequestByServiceCert() throws IOException {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        DataStore store = new DataStore(structStore, null);
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
        
        DataStore store = new DataStore(structStore, null);
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

        DataStore store = new DataStore(structStore, null);
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
        
        DataStore store = new DataStore(structStore, null);
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

        DataStore store = new DataStore(structStore, null);

        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        ztsImpl.readOnlyMode = true;

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
            ztsImpl.postDomainMetrics(ctx, null, null);
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        SignedDomain providerDomain = signedAuthorizedProviderDomain();
        store.processDomain(providerDomain, false);

        SignedDomain tenantDomain = signedBootstrapTenantDomain("athenz.provider", "athenz", "production");
        store.processDomain(tenantDomain, false);

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

        DataStore store = new DataStore(structStore, null);
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        System.setProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES, "com.yahoo.athenz.zts.MockAuthority");
        ztsImpl.loadAuthorities();
        ztsImpl.setAuthorityKeyStore();
        System.clearProperty(ZTSConsts.ZTS_PROP_AUTHORITY_CLASSES);
    }

    @Test
    public void testValidateRoleCertificateRequestInvalidCSR() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        ztsImpl.validCertSubjectOrgValues = null;
        assertFalse((ztsImpl.validateRoleCertificateRequest("invalid-csr", null,
                null, null, null, null, "10.0.0.1")));
    }

    @Test
    public void testGetAuditLogMsgBuilderUnsignedCreds() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, null);
        principal.setUnsignedCreds("unsigned-creds");

        ResourceContext context = createResourceContext(principal);

        AuditLogMsgBuilder msgBuilder = zts.getAuditLogMsgBuilder(context, "athenz", "test", "test");
        assertEquals(msgBuilder.who(), "unsigned-creds");
    }

    @Test
    public void testGetAuditLogMsgBuilderPrincipalName() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, null);
        principal.setUnsignedCreds(null);

        ResourceContext context = createResourceContext(principal);

        AuditLogMsgBuilder msgBuilder = zts.getAuditLogMsgBuilder(context, "athenz", "test", "test");
        assertEquals(msgBuilder.who(), "athenz.production");
    }

    @Test
    public void testGetAuditLogMsgBuilderNoPrincipal() {

        ResourceContext context = createResourceContext(null);

        AuditLogMsgBuilder msgBuilder = zts.getAuditLogMsgBuilder(context, "athenz", "test", "test");
        assertEquals(msgBuilder.who(), "null");
    }

    @Test
    public void testGetAuditLogMsgBuilderBuild() {

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, null);
        principal.setUnsignedCreds(null);

        ResourceContext context = createResourceContext(principal);

        AuditLogMsgBuilder msgBuilder = zts.getAuditLogMsgBuilder(context, "athenz", "test", "test");
        String auditLog = msgBuilder.build();
        assertEquals(msgBuilder.whoFullName(), "athenz.production");
        assertTrue(auditLog.contains("UUID="), "Test string=" + auditLog);
        assertTrue(auditLog.contains("WHEN-epoch="), "Test string=" + auditLog);
    }

    @Test
    public void testConfigurationSettings() {

        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        DataStore store = new DataStore(structStore, null);

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

        List<com.yahoo.athenz.zts.Policy> policies = zts.getPolicyList(domainData);
        assertTrue(policies.isEmpty());

        DomainPolicies domainPolicies = new DomainPolicies();
        signedPolicies.setContents(domainPolicies);

        policies = zts.getPolicyList(domainData);
        assertTrue(policies.isEmpty());

        Policy policy = new Policy();
        policy.setName("policy1");

        List<Policy> zmsPolicies = new ArrayList<>();
        zmsPolicies.add(policy);

        domainPolicies.setPolicies(zmsPolicies);

        policies = zts.getPolicyList(domainData);
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

        DataStore store = new DataStore(structStore, null);
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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String scope = URLEncoder.encode("coretech:domain", "UTF-8");
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope);
        assertNotNull(resp);
        assertEquals("coretech:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
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
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user1", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(100 * 1000, claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime());
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
        store.processDomain(signedDomain, false);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, new CertificateAuthority());
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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "x509-certificate-details", 0, new CertificateAuthority());

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

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));

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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech:domain");
        assertNotNull(resp);
        assertEquals("coretech:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);
        assertEquals("user_domain.user", claims.getBody().getSubject());
        assertEquals("coretech", claims.getBody().getAudience());
        assertEquals(ztsImpl.ztsOAuthIssuer, claims.getBody().getIssuer());
        List<String> scopes = (List<String>) claims.getBody().get("scp");
        assertNotNull(scopes);
        assertEquals(1, scopes.size());
        assertEquals("writers", scopes.get(0));
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        final String scope = URLEncoder.encode("coretech:domain openid coretech:service.api", "UTF-8");
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope + "&expires_in=240");
        assertNotNull(resp);
        assertEquals("coretech:role.writers openid", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        String idToken = resp.getId_token();
        assertNotNull(idToken);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
        } catch (SignatureException e) {
            throw new ResourceException(ResourceException.UNAUTHORIZED);
        }
        assertNotNull(claims);

        assertEquals(240 * 1000, claims.getBody().getExpiration().getTime() - claims.getBody().getIssuedAt().getTime());
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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // default max timeout is 12 hours so we'll pick a value
        // bigger than that

        final String scope = URLEncoder.encode("coretech:domain openid coretech:service.api", "UTF-8");
        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=" + scope + "&expires_in=57600");
        assertNotNull(resp);
        assertEquals("coretech:role.writers openid", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        String idToken = resp.getId_token();
        assertNotNull(idToken);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(idToken);
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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // we should only get back openid scope

        try {
            final String scope = URLEncoder.encode("coretech:role.role999 openid coretech:service.api", "UTF-8");
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

        AccessTokenRequest.setSupportOpenidScope(false);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // no role access and no openid - we should get back 403
        try {
            final String scope = URLEncoder.encode("coretech:role.role999 openid coretech:service.api", "UTF-8");
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech-proxy2:domain&proxy_for_principal=user_domain.joe");
        assertNotNull(resp);
        assertEquals("coretech-proxy2:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech-proxy3:domain&proxy_for_principal=user_domain.joe");
        assertNotNull(resp);
        assertEquals("coretech-proxy3:role.writers", resp.getScope());

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
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
        store.processDomain(signedDomain, false);

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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            final String scope = URLEncoder.encode("openid coretech-proxy4:domain coretech-proxy4:service.api", "UTF-8");
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
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        AccessTokenResponse resp = ztsImpl.postAccessTokenRequest(context,
                "grant_type=client_credentials&scope=coretech-proxy4:role.writers&proxy_for_principal=user_domain.joe");
        assertNotNull(resp);

        String accessTokenStr = resp.getAccess_token();
        assertNotNull(accessTokenStr);

        Jws<Claims> claims;
        try {
            claims = Jwts.parserBuilder().setSigningKey(Crypto.extractPublicKey(ztsImpl.privateKey.getKey())).build().parseClaimsJws(accessTokenStr);
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
    public void testPostRoleCertificateExtRequest() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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
    public void testPostRoleCertificateExtProxyUserRequest() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

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

        store.processDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "proxy-user1",
                "v=U1;d=user_domain;n=proxy-user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleCertificate roleCertificate = zts.postRoleCertificateRequestExt(context, req);
        assertNotNull(roleCertificate);
    }

    @Test
    public void testPostRoleCertificateExtInvalidProxyUserRequest() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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
    public void testPostRoleCertificateExtAuthzService() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
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

        // this csr is for coretech:role.readers and coretech:role.writers roles

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
    public void testPostRoleCertificateExtNoRoleURI() throws IOException {

        Path path = Paths.get("src/test/resources/role_single_ip.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

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
            assertTrue(ex.getMessage().contains("No roles requested in CSR"));
        }
    }

    @Test
    public void testPostRoleCertificateExtSingleRoleOnly() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        zts.singleDomainInRoleCert = true;
        try {
            zts.postRoleCertificateRequestExt(context, req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("cannot contain roles from multiple domains"));
        }
    }

    @Test
    public void testPostRoleCertificateExtUserAccessForbidden() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        readers.add(new RoleMember().setMemberName("user_domain.user4"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processDomain(signedDomain, false);

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
            assertTrue(ex.getMessage().contains("Not authorized to assume all requested roles by proxy principal"));
        }
    }

    @Test
    public void testPostRoleCertificateExtProxyAccessForbidden() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
                .setProxyForPrincipal("user_domain.user1");

        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.proxy-user1"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));

        List<RoleMember> readers = new ArrayList<>();
        readers.add(new RoleMember().setMemberName("user_domain.user4"));
        readers.add(new RoleMember().setMemberName("user_domain.user1"));

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", writers,
                readers, true);

        store.processDomain(signedDomain, false);

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
            assertTrue(ex.getMessage().contains("Not authorized to assume all requested roles by user principal"));
        }
    }

    @Test
    public void testPostRoleCertificateExtValidateFailed() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_proxy_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L)
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

        store.processDomain(signedDomain, false);

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
    public void testPostRoleCertificateExtRequestNullCertReturn() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        InstanceCertManager certManager = Mockito.mock(InstanceCertManager.class);
        Mockito.when(certManager.generateIdentity(csr, "user_domain.user1",
                "client", 3600)).thenReturn(null);
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
    public void testPostRoleCertificateExtInvalidRoleDomain() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));

        // this csr is for coretech:role.readers and coretech:role.writers roles

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(csr).setExpiryTime(3600L);

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
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Not authorized to assume all requested roles by user principal"));
        }
    }

    @Test
    public void testValidateRoleCertificateExtRequest() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_role_uri_ip.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        assertTrue(zts.validateRoleCertificateExtRequest(certReq, "user_domain.user1", null, null, "10.11.12.13"));
    }

    @Test
    public void testValidateRoleCertificateExtRequestInvalidOU() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_role_uri.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        zts.verifyCertSubjectOU = true;
        assertFalse(zts.validateRoleCertificateExtRequest(certReq, "user_domain.user1", null, null, null));
    }

    @Test
    public void testValidateRoleCertificateExtRequestInvalidIP() throws IOException {

        Path path = Paths.get("src/test/resources/athenz_coretech_role_uri_ip.csr");
        String csr = new String(Files.readAllBytes(path));
        X509RoleCertRequest certReq = new X509RoleCertRequest(csr);

        assertFalse(zts.validateRoleCertificateExtRequest(certReq, "user_domain.user1", null, null, "10.20.20.20"));

        // with disabled ip check, we should get success

        zts.verifyCertRequestIP = false;
        assertTrue(zts.validateRoleCertificateExtRequest(certReq, "user_domain.user1", null, null, "10.20.20.20"));
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

        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_BUNDLES_FNAME, "src/test/resources/ca-bundle-file.json");
        ztsImpl.instanceCertManager = new InstanceCertManager(null, null, null, true);

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

        // first we try with ec private key only

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY, "src/test/resources/unit_test_zts_private_ec.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateECKey);
        assertEquals(zts.privateKey, zts.privateECKey);
        assertNull(zts.privateRSAKey);

        // now let's try the rsa key

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateRSAKey);
        assertEquals(zts.privateKey, zts.privateRSAKey);
        assertNull(zts.privateECKey);

        // now back to our regular key setup

        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY, "src/test/resources/unit_test_zts_private.pem");
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_EC_KEY);
        System.clearProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_RSA_KEY);

        zts.loadServicePrivateKey();
        assertNotNull(zts.privateKey);
        assertNull(zts.privateECKey);
        assertNull(zts.privateRSAKey);
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
        for (int i = 0; i < 163; i++) {
            hostnameBuilder.append("123456");
        }

        final String check = "provider=aws&certReqInstanceId=id001&hostname=" + hostnameBuilder.toString();
        assertEquals(check, zts.getInstanceRegisterQueryLog("aws", "id001", hostnameBuilder.toString() + "01234"));
    }

    @Test
    public void testGetQueryLogData() {

        String request = "data\ntest\ragain";
        assertEquals(zts.getQueryLogData(request), "data_test_again");

        // generate a string with 1024 length

        StringBuilder longRequest = new StringBuilder(1024);
        for (int i = 0; i < 64; i++) {
            longRequest.append("0123456789012345");
        }
        request = longRequest.toString();

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
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) zts.newResourceContext(mockServletRequest, mockServletResponse, "someApiMethod");
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
        zts.dataStore.processDomain(signedDomain, false);

        List<GroupMember> groupMembers = zts.authorizer.groupMembersFetcher.getGroupMembers("coretech:group.dev-team");
        assertNotNull(groupMembers);
        assertEquals(groupMembers.size(), 2);
    }

    @Test
    public void testValidateInstanceServiceIdentity() {

        DomainData domainData = new DomainData();

        // TODO once enabled a domain data with null services should throw an exception

        zts.validateInstanceServiceIdentity(domainData, "athenz.api", "unit-test");
        zts.validateInstanceServiceIdentity(domainData, "athenz.backend", "unit-test");

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

        // TODO unknown services should throw an exception once enabled

        zts.validateInstanceServiceIdentity(domainData, "athenz.frontend", "unit-test");
        zts.validateInstanceServiceIdentity(domainData, "athenz.api2", "unit-test");

        // screwdriver services are excluded from the check since they're dynamic
        // screwdriver is configured as service skip domain

        domainData = new DomainData().setName("screwdriver");

        zts.validateInstanceServiceIdentity(domainData, "screwdriver.project1", "unit-test");
        zts.validateInstanceServiceIdentity(domainData, "screwdriver.project2", "unit-test");
    }

    @Test
    public void testGetRoleAccessWithDelegatedRolesWithGroups() {

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

        roles.add(new Role().setName(generateRoleName(weatherDomainName, "role1")).setTrust(sportsDomainName));

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

        store.processDomain(weatherDomain, false);

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
        role.setName(generateRoleName(sportsDomainName, "role1"));
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
        assertion.setResource(generateRoleName(weatherDomainName, "role1"));
        assertion.setAction("assume_role");
        assertion.setRole(generateRoleName(sportsDomainName, "role1"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(sportsDomainName, "role1"));
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

        store.processDomain(sportsDomain, false);

        // create the group domain for news

        SignedDomain newsDomain = new SignedDomain();
        roles = new ArrayList<>();

        // create the admin role

        role = new Role();
        role.setName(generateRoleName(newsDomainName, "admin"));
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);

        // create our groups

        List<Group> groups = new ArrayList<>();

        Group group = new Group().setName(ResourceUtils.groupResourceName(newsDomainName, "group1"));
        List<GroupMember> groupMembers = new ArrayList<>();
        groupMembers.add(new GroupMember().setMemberName("user_domain.user1").setGroupName(group.getName()));
        group.setGroupMembers(groupMembers);
        groups.add(group);

        // create admin policy

        policies = new ArrayList<>();

        policy = new com.yahoo.athenz.zms.Policy();
        assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(newsDomainName + ".*");
        assertion.setAction("*");
        assertion.setRole(generateRoleName(newsDomainName, "admin"));

        assertions = new ArrayList<>();
        assertions.add(assertion);

        policy.setAssertions(assertions);
        policy.setName(generatePolicyName(newsDomainName, "admin"));
        policies.add(policy);

        domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(weatherDomainName);
        domainPolicies.setPolicies(policies);

        signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), privateKey));
        signedPolicies.setKeyId("0");

        domain = new DomainData();
        domain.setName(newsDomainName);
        domain.setRoles(roles);
        domain.setGroups(groups);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());

        newsDomain.setDomain(domain);

        newsDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        newsDomain.setKeyId("0");

        // now process the domain in ZTS

        store.processDomain(newsDomain, false);

        // now let's carry out our checks - we should get role1 for user1
        // when asked for both sports and weather domains

        Principal principal = SimplePrincipal.create("user_domain", "user", "v=U1;d=user_domain;n=user;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleAccess roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user1");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        // user2 should have same access as user1

        roleAccess = zts.getRoleAccess(context, weatherDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));

        roleAccess = zts.getRoleAccess(context, sportsDomainName, "user_domain.user2");
        assertEquals(roleAccess.getRoles().size(), 1);
        assertTrue(roleAccess.getRoles().contains("role1"));
    }
}
