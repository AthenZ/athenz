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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
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
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.log.impl.DefaultAuditLogger;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.ZTSImpl.AthenzObject;
import com.yahoo.athenz.zts.ZTSImpl.ServiceX509RefreshRequestStatus;
import com.yahoo.athenz.zts.ZTSAuthorizer.AccessStatus;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cert.CertRecordStore;
import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;
import com.yahoo.athenz.zts.cert.InstanceCertManager;
import com.yahoo.athenz.zts.cert.X509CertRecord;
import com.yahoo.athenz.zts.cert.X509CertRequest;
import com.yahoo.athenz.zts.cert.impl.SelfCertSigner;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockCloudStore;
import com.yahoo.athenz.zts.store.impl.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStore;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;

import static org.testng.Assert.*;

public class ZTSImplTest {

    private int roleTokenDefaultTimeout = 2400;
    private int roleTokenMaxTimeout = 96000;

    private ZTSImpl zts = null;
    private ZTSAuthorizer authorizer = null;
    private DataStore store = null;
    private PrivateKey privateKey = null;
    PublicKey publicKey = null;
    private AuditLogger auditLogger = null;
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
        
        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, ZTSConsts.ZTS_METRIC_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_SIGNER_FACTORY_CLASS,
                "com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zts_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTSConsts.ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
        System.setProperty(ZTSConsts.ZTS_PROP_NOAUTH_URI_LIST, "/zts/v1/schema,/zts/v1/status");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_REFRESH_IP_FNAME,
                "src/test/resources/cert_refresh_ipblocks.txt");
        System.setProperty(ZTSConsts.ZTS_PROP_OSTK_HOST_SIGNER_SERVICE, "sys.auth.hostsignd");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_ALLOWED_O_VALUES, "Athenz, Inc.|My Test Company|Athenz|Yahoo");

        auditLogger = new DefaultAuditLogger();
    }
    
    @BeforeMethod
    public void setup() {

        // we want to make sure we start we clean dir structure

        ZMSFileChangeLogStore.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);
        
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
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
        
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        
        ZMSFileChangeLogStore.deleteDirectory(new File("/tmp/zts_server_cert_store"));
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_FILE_STORE_PATH, "/tmp/zts_server_cert_store");
        
        store = new DataStore(structStore, cloudStore);
        zts = new ZTSImpl(cloudStore, store);
        ZTSImpl.serverHostName = "localhost";

        authorizer = new ZTSAuthorizer(store);
    }
    
    @AfterMethod
    public void shutdown() {
        cloudStore.close();
        ZMSFileChangeLogStore.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);
    }
    
    static class ZtsMetricTester extends com.yahoo.athenz.common.metrics.impl.NoOpMetric {
        final Map<String, Integer> metrixMap = new HashMap<>();

        Map<String, Integer> getMap() { return metrixMap; }

        public void  increment(String metric, String domainName, int count) {
            String key = metric + domainName;
            metrixMap.put(key, count);
        }
    }
    
    private ResourceContext createResourceContext(Principal principal) {
        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);
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

    Object getWebAppExcEntity(javax.ws.rs.WebApplicationException wex) {
        javax.ws.rs.core.Response resp = wex.getResponse();
        return resp.getEntity();
    }

    Object getWebAppExcMapValue(javax.ws.rs.WebApplicationException wex, String header) {
        javax.ws.rs.core.MultivaluedMap<String, Object> mvmap = wex.getResponse().getMetadata();
        return mvmap.getFirst(header);
    }
    
    private static Role createRoleObject(String domainName, String roleName,
                                         String trust) {
        Role role = new Role();
        role.setName(domainName + ":role." + roleName);
        role.setTrust(trust);
        return role;
    }
    
    private static Role createRoleObject(String domainName, String roleName,
                                         String trust, String member1, String member2) {

        List<RoleMember> members = new ArrayList<>();
        if (member1 != null) {
            members.add(new RoleMember().setMemberName(member1));
        }
        if (member2 != null) {
            members.add(new RoleMember().setMemberName(member2));
        }
        return createRoleObject(domainName, roleName, trust, members);
    }

    private static Role createRoleObject(String domainName, String roleName,
                                         String trust, List<RoleMember> members) {
        
        Role role = new Role();
        role.setName(domainName + ":role." + roleName);
        role.setRoleMembers(members);
        if (trust != null) {
            role.setTrust(trust);
        }
        
        return role;
    }
    
    private Policy createPolicyObject(String domainName, String policyName,
            String roleName, boolean generateRoleName, String action,
            String resource, AssertionEffect effect) {

        Policy policy = new Policy();
        policy.setName(domainName + ":policy." + policyName);

        Assertion assertion = new Assertion();
        assertion.setAction(action);
        assertion.setEffect(effect);
        assertion.setResource(resource);
        if (generateRoleName) {
            assertion.setRole(domainName + ":role." + roleName);
        } else {
            assertion.setRole(roleName);
        }

        List<Assertion> assertList = new ArrayList<>();
        assertList.add(assertion);

        policy.setAssertions(assertList);
        return policy;
    }
    
    private Metric getMetric(){
        com.yahoo.athenz.common.metrics.MetricFactory metricFactory;
        com.yahoo.athenz.common.metrics.Metric metric;
        try {
            metricFactory = (com.yahoo.athenz.common.metrics.MetricFactory) 
                Class.forName(System.getProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS)).newInstance();
            metric = metricFactory.create();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException exc) {
            System.out.println("Invalid MetricFactory class: " + ZTSConsts.ZTS_METRIC_FACTORY_CLASS
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
        
        List<RoleMember> writers = new ArrayList<>();
        writers.add(new RoleMember().setMemberName("user_domain.user"));
        writers.add(new RoleMember().setMemberName("user_domain.user1"));
        
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
    public void testShouldRunDelegatedTrustCheckNullTrust() {
        assertFalse(authorizer.shouldRunDelegatedTrustCheck(null, "TrustDomain"));
    }
    
    @Test
    public void testShouldRunDelegatedTrustCheckNullTrustDomain() {
        assertTrue(authorizer.shouldRunDelegatedTrustCheck("TrustDomain", null));
    }
    
    @Test
    public void testShouldRunDelegatedTrustCheckMatch() {
        assertTrue(authorizer.shouldRunDelegatedTrustCheck("TrustDomain", "TrustDomain"));
    }
    
    @Test
    public void testShouldRunDelegatedTrustCheckNoMatch() {
        assertFalse(authorizer.shouldRunDelegatedTrustCheck("TrustDomain1", "TrustDomain"));
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
        Role role = createRoleObject("coretech", "role1", null, "user_domain.user1", null);
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
    public void testEvaluateAccessAssertionAllow() {
        
        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role = createRoleObject("coretech", "role1", null, "user_domain.user1", null);
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
            @SuppressWarnings("unused")
            com.yahoo.athenz.zts.ServiceIdentity svc = zts.getServiceIdentity(context, "coretech", "storage2");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
        
        try {
            @SuppressWarnings("unused")
            com.yahoo.athenz.zts.ServiceIdentity svc = zts.getServiceIdentity(context, "testDomain2", "storage");
            fail();
        } catch (ResourceException ex) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testAddServiceNameToListValid() {
        
        List<String> names = new ArrayList<>();
        zts.addServiceNameToList("coretech.storage", "coretech.", names);
        
        assertEquals(names.size(), 1);
        assertTrue(names.contains("storage"));
    }
    
    @Test
    public void testAddServiceNameToListInValid() {
        
        List<String> names = new ArrayList<>();
        zts.addServiceNameToList("coretech.storage", "weather.", names);
        
        assertEquals(names.size(), 0);
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
            @SuppressWarnings("unused")
            com.yahoo.athenz.zts.ServiceIdentityList svcList = zts.getServiceIdentityList(context, "testDomain2");
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
    public void testValidate() {
        com.yahoo.athenz.zts.ServiceIdentity service = new com.yahoo.athenz.zts.ServiceIdentity();
        service.setName(generateServiceIdentityName("coretech", "storage"));
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        zts.validate(service, "ServiceIdentity", "testValidate");
        assertTrue(true);
    }
    
    @Test
    public void testValidateObjNull() {
        try {
            zts.validate(null, "SignedDomain", "testValidate");
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
            zts.validate(service, "Policy", "testValidate");
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
        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, null, ZTSConsts.ZTS_UNKNOWN_DOMAIN, metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, "", ZTSConsts.ZTS_UNKNOWN_DOMAIN, metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, "", null, metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(0, caller, null, metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(-100, caller, null, metric);
        assertFalse(isEmitMonmetricError);

        // positive tests
        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, caller, null, metric);
        assertTrue(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, " " + caller + " ", null, metric);
        assertTrue(isEmitMonmetricError);
    }
    
    @Test
    public void testDetermineTokenTimeoutBothNull() {
        assertEquals(zts.determineTokenTimeout(null, null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutMinNull() {
        assertEquals(zts.determineTokenTimeout(null, 100), 100);
    }
    
    @Test
    public void testDetermineTokenTimeoutMaxNull() {
        assertEquals(zts.determineTokenTimeout(100, null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutMinInvalid() {
        assertEquals(zts.determineTokenTimeout(-10, null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutMaxInvalid() {
        assertEquals(zts.determineTokenTimeout(null, -10), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutDefaultBigger() {
        assertEquals(zts.determineTokenTimeout(3200, null), 3200);
    }
    
    @Test
    public void testDetermineTokeTimeoutDefaultSmaller() {
        assertEquals(zts.determineTokenTimeout(1200, null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokeTimeoutMaxValueMaxExceeded() {
        assertEquals(zts.determineTokenTimeout(null, 120000), roleTokenMaxTimeout);
    }

    @Test
    public void testDetermineTokeTimeoutMinValueMaxExceeded() {
        assertEquals(zts.determineTokenTimeout(120000, null), roleTokenMaxTimeout);
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
        
        TenantDomains tenantDomains = zts.getTenantDomains(context, "athenz.multiple", "user_domain.user100", null, null);
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
        
        RsrcCtxWrapper ctx = (RsrcCtxWrapper) zts.newResourceContext(mockServletRequest, mockServletResponse);
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
    public void testRetrieveResourceDomainAssumeRoleWithTrust() {
        assertEquals("trustdomain", authorizer.retrieveResourceDomain("resource", "assume_role", "trustdomain"));
    }
    
    @Test
    public void testRetrieveResourceDomainAssumeRoleWithOutTrust() {
        assertEquals("domain1", authorizer.retrieveResourceDomain("domain1:resource", "assume_role", null));
    }
    
    @Test
    public void testRetrieveResourceDomainValidDomain() {
        assertEquals("domain1", authorizer.retrieveResourceDomain("domain1:resource", "read", null));
        assertEquals("domain1", authorizer.retrieveResourceDomain("domain1:resource", "read", "trustdomain"));
        assertEquals("domain1", authorizer.retrieveResourceDomain("domain1:resource:invalid", "read", null));
    }
    
    @Test
    public void testRetrieveResourceDomainInvalidResource() {
        assertNull(authorizer.retrieveResourceDomain("domain1", "read", "trustdomain"));
    }


    @Test
    public void testCheckKerberosAuthorityAuthorization() {
        Authority authority = new com.yahoo.athenz.auth.impl.KerberosAuthority();
        Principal principal = SimplePrincipal.create("krb", "user1", "v=U1;d=krb;n=user1;s=signature",
                0, authority);
        assertTrue(authorizer.authorityAuthorizationAllowed(principal));
    }
    
    @Test
    public void testCheckNullAuthorityAuthorization() {
        Principal principal = SimplePrincipal.create("user", "joe", "v=U1;d=user;n=joe;s=signature",
                0, null);
        assertTrue(authorizer.authorityAuthorizationAllowed(principal));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionInvalidAction() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("READ");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain:*");
        assertion.setRole("domain:role.Role");

        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, null, null, null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoResPatternMatchWithOutPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("domain:role.Role");
        assertion.setRole("domain:role.Role");

        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "domain:role.Role2", null, null));
        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoResPatternMatchWithPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("domain:role.Role");

        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "domain:role.Role2", null, null));
        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "coretech:role.Role2", null, null));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoRoleMatchWithPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");
        
        Role role;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("coretech",  "readers", null);
        roles.add(role);

        role = createRoleObject("coretech",  "writers", null);
        roles.add(role);

        role = createRoleObject("coretech",  "updaters", null);
        roles.add(role);
        
        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoRoleMatchWithOutPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");
        
        Role role;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("coretech",  "Role1", null);
        roles.add(role);

        role = createRoleObject("coretech",  "Role2", null);
        roles.add(role);
        
        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "weather:role.Role1", null, roles));
        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "coretech:role.Role", null, roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionNoMemberMatch() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");
        
        Role role;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("weather",  "Role1", null, "user_domain.user1", null);
        roles.add(role);

        role = createRoleObject("weather",  "Role", null, "user_domain.user2", null);
        roles.add(role);
        
        assertFalse(authorizer.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user_domain.user1", roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionValidWithPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.*");
        
        Role role;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("weather",  "Role1", null, "user_domain.user1", null);
        roles.add(role);

        role = createRoleObject("weather",  "Role", null, "user_domain.user2", null);
        roles.add(role);
        
        assertTrue(authorizer.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user_domain.user2", roles));
    }
    
    @Test
    public void testMatchDelegatedTrustAssertionValidWithOutPattern() {
        
        Assertion assertion = new Assertion();
        assertion.setAction("ASSUME_ROLE");
        assertion.setEffect(AssertionEffect.ALLOW);
        assertion.setResource("*:role.Role");
        assertion.setRole("weather:role.Role");
        
        Role role;
        List<Role> roles = new ArrayList<>();
        
        role = createRoleObject("weather",  "Role1", null, "user_domain.user1", null);
        roles.add(role);

        role = createRoleObject("weather",  "Role", null, "user_domain.user2", null);
        roles.add(role);
        
        assertTrue(authorizer.matchDelegatedTrustAssertion(assertion, "weather:role.Role", "user_domain.user2", roles));
    }
    
    @Test
    public void testMatchDelegatedTrustPolicyNoAssertions() {
        Policy policy = new Policy();
        assertFalse(authorizer.matchDelegatedTrustPolicy(policy, "roleName", "user_domain.user1", null));
    }
    
    @Test
    public void testMatchPrincipalInRoleStdMemberMatch() {
        
        Role role = createRoleObject("weather",  "Role", null, "user_domain.user2", null);
        assertTrue(authorizer.matchPrincipalInRole(role, null, "user_domain.user2", null));
    }
    
    @Test
    public void testMatchPrincipalInRoleStdMemberNoMatch() {
        
        Role role = createRoleObject("weather",  "Role", null, "user_domain.user2", null);
        assertFalse(authorizer.matchPrincipalInRole(role, null, "user_domain.user23", null));
    }
    
    @Test
    public void testMatchPrincipalInRoleNoDelegatedTrust() {
        Role role = createRoleObject("weather",  "Role", null);
        assertFalse(authorizer.matchPrincipalInRole(role, null, null, null));
        assertFalse(authorizer.matchPrincipalInRole(role, null, null, "weather"));
    }
    
    @Test
    public void testMatchPrincipalInRoleDelegatedTrustNoMatch() {
        Role role = createRoleObject("weather",  "Role", "coretech_not_present");
        assertFalse(authorizer.matchPrincipalInRole(role, "Role", "user_domain.user1", "coretech_not_present"));
    }

    @Test
    public void testMatchPrincipalInRoleDelegatedTrustMatch() {

        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretechtrust");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<>());
        Role role1 = createRoleObject("coretechtrust",  "role1", null, "user_domain.user1", null);
        Role role2 = createRoleObject("coretechtrust",  "role2", null, "user_domain.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject("coretechtrust", "trust", "coretechtrust:role.role1",
                false, "ASSUME_ROLE", "weather:role.role1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        
        store.getCacheStore().put("coretechtrust", domain);
        Role role = createRoleObject("weather", "role1", "coretechtrust");
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
        Role role1 = createRoleObject("coretechtrust",  "role1", null, "user_domain.user1", null);
        Role role2 = createRoleObject("coretechtrust",  "role2", null, "user_domain.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject("coretechtrust", "trust", "coretechtrust:role.role1",
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
        role1 = createRoleObject("weather", "role1", "coretechtrust");
        domainData.getRoles().add(role1);

        policy = createPolicyObject("weather", "access", "weather:role.role1",
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
        Role role1 = createRoleObject("coretechtrust",  "role1", null, "user_domain.user1", null);
        Role role2 = createRoleObject("coretechtrust",  "role2", null, "user_domain.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject("coretechtrust", "access", "coretechtrust:role.role1",
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
    public void testIsMemberOfRoleNoMembers() {
        Role role1 = new Role();
        assertFalse(authorizer.isMemberOfRole(role1, "user_domain.user1"));
    }
    
    @Test
    public void testPostOSTKInstanceInformationInvalidCsr() {
        OSTKInstanceInformation info = new OSTKInstanceInformation()
                .setCsr("invalid-csr")
                .setDocument("Test Document")
                .setSignature("Test Signature")
                .setDomain("iaas.athenz")
                .setService("syncer");
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        
        ResourceContext context = createResourceContext(null, servletRequest);
        
        try {
            zts.postOSTKInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostOSTKInstanceRefreshRequest() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        OSTKInstanceRefreshRequest req = new OSTKInstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(
                "athenz",
                "production",
                "v=S1,d=athenz;n=production;s=sig",
                0,
                new CertificateAuthority()
        );
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);
        
        ResourceContext context = createResourceContext(principal, servletRequest);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setService("athenz.production");
        certRecord.setInstanceId("1001");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(certRecord);
        Mockito.when(certConnection.updateX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        zts.instanceCertManager.setCertStore(certStore);
        
        Identity identity = zts.postOSTKInstanceRefreshRequest(context, "athenz", "production", req);
        assertNotNull(identity);

        X509Certificate x509Cert = Crypto.loadX509Certificate(identity.getCertificate());
        assertNotNull(x509Cert);
    }

    @Test
    public void testPostOSTKInstanceRefreshRequestPreviousSerialMatch() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        OSTKInstanceRefreshRequest req = new OSTKInstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(
                "athenz",
                "production",
                "v=S1,d=athenz;n=production;s=sig",
                0,
                new CertificateAuthority()
        );
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);
        
        ResourceContext context = createResourceContext(principal, servletRequest);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setService("athenz.production");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("1001");
        certRecord.setCurrentSerial("12341324334");
        certRecord.setPrevSerial("16503746516960996918");
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(certRecord);
        Mockito.when(certConnection.updateX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        zts.instanceCertManager.setCertStore(certStore);
        
        Identity identity = zts.postOSTKInstanceRefreshRequest(context, "athenz", "production", req);
        assertNotNull(identity);

        X509Certificate x509Cert = Crypto.loadX509Certificate(identity.getCertificate());
        assertNotNull(x509Cert);
    }
    
    @Test
    public void testPostOSTKInstanceRefreshRequestSerialMisMatch() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        OSTKInstanceRefreshRequest req = new OSTKInstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(
                "athenz",
                "production",
                "v=S1,d=athenz;n=production;s=sig",
                0,
                new CertificateAuthority()
        );
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);
        
        ResourceContext context = createResourceContext(principal, servletRequest);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setService("athenz.production");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("1001");
        certRecord.setCurrentSerial("12341324334");
        certRecord.setPrevSerial("2342134323");
        
        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(certRecord);
        Mockito.when(certConnection.updateX509CertRecord(ArgumentMatchers.isA(X509CertRecord.class))).thenReturn(true);
        zts.instanceCertManager.setCertStore(certStore);
        
        try {
            zts.postOSTKInstanceRefreshRequest(context, "athenz", "production", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("Certificate revoked"));
        }
    }
    
    @Test
    public void testPostOSTKInstanceRefreshRequestCertRecordCnMismatch() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        OSTKInstanceRefreshRequest req = new OSTKInstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(
                "athenz",
                "production",
                "v=S1,d=athenz;n=production;s=sig",
                0,
                new CertificateAuthority()
        );
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);
        
        path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        principal.setX509Certificate(cert);
        
        ResourceContext context = createResourceContext(principal, servletRequest);

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setService("athenz2.production");
        certRecord.setProvider("ostk");

        CertRecordStore certStore = Mockito.mock(CertRecordStore.class);
        CertRecordStoreConnection certConnection = Mockito.mock(CertRecordStoreConnection.class);
        Mockito.when(certStore.getConnection()).thenReturn(certConnection);
        Mockito.when(certConnection.getX509CertRecord("ostk", "1001")).thenReturn(certRecord);
        zts.instanceCertManager.setCertStore(certStore);
        
        // we'll get back 400 mismatch cn error message
        
        try {
            zts.postOSTKInstanceRefreshRequest(context, "athenz", "production", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("cn mismatch"));
        }
    }
    
    @Test
    public void testPostOSTKInstanceRefreshRequestPrincipalMismatch() throws IOException {
        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        OSTKInstanceRefreshRequest req = new OSTKInstanceRefreshRequest().setCsr(certCsr);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create(
                "athenz2",
                "production",
                "v=S1,d=athenz2;n=production;s=sig",
                0,
                new CertificateAuthority()
        );
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.isSecure()).thenReturn(true);

        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postOSTKInstanceRefreshRequest(context, "athenz", "production", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
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
        Role role1 = createRoleObject(domainName,  "role1", null, "user.user1", "user.user3");
        Role role2 = createRoleObject(domainName,  "role2", null, "user.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject(domainName, "access", domainName + ":role.role1",
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
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores", null));
    }
    
    @Test
    public void testValidateRoleCertificateRequestMismatchEmail() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.standings", null));
    }
    
    @Test
    public void testValidateRoleCertificateRequestNoEmail() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_noemail.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "no-email", null));
    }

    @Test
    public void testValidateRoleCertificateRequestInvalidOField() throws IOException {

        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");

        Set<String> validOValues = new HashSet<>();
        validOValues.add("InvalidCompany");
        assertFalse(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores", validOValues));
    }

    @Test
    public void testValidateRoleCertificateRequest() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));

        Set<String> roles = new HashSet<>();
        roles.add("readers");
        assertTrue(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores", null));

        Set<String> validOValues = new HashSet<>();
        validOValues.add("Athenz");
        assertTrue(zts.validateRoleCertificateRequest(csr, "sports", roles, "sports.scores", validOValues));
    }
    
    @Test
    public void testGetRoleTokenCert() {

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

        RoleToken roleToken = zts.postRoleCertificateRequest(context, "coretech",
                "readers", req);
        assertNotNull(roleToken);
        assertEquals(roleToken.getExpiryTime(), TimeUnit.SECONDS.convert(30, TimeUnit.DAYS));
    }
    
    @Test
    public void testGetRoleTokenCertInvalidRequests() {

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
    public void testGetRoleTokenCertMismatchDomain() {

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
    public void testLogPrincipalEmpty() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResourceContext ctx = zts.newResourceContext(request, null);
        zts.logPrincipal(ctx);
        assertTrue(request.attributes.isEmpty());
    }
    
    @Test
    public void testMemberNameMatch() {
        assertTrue(authorizer.memberNameMatch("*", "user.joe"));
        assertTrue(authorizer.memberNameMatch("*", "athenz.service.storage"));
        assertTrue(authorizer.memberNameMatch("user.*", "user.joe"));
        assertTrue(authorizer.memberNameMatch("athenz.*", "athenz.service.storage"));
        assertTrue(authorizer.memberNameMatch("athenz.service*", "athenz.service.storage"));
        assertTrue(authorizer.memberNameMatch("athenz.service*", "athenz.service-storage"));
        assertTrue(authorizer.memberNameMatch("athenz.service*", "athenz.service"));
        assertTrue(authorizer.memberNameMatch("user.joe", "user.joe"));
        
        assertFalse(authorizer.memberNameMatch("user.*", "athenz.joe"));
        assertFalse(authorizer.memberNameMatch("athenz.*", "athenztest.joe"));
        assertFalse(authorizer.memberNameMatch("athenz.service*", "athenz.servic"));
        assertFalse(authorizer.memberNameMatch("athenz.service*", "athenz.servictag"));
        assertFalse(authorizer.memberNameMatch("user.joe", "user.joel"));
    }
    
    @Test
    public void testConverToLowerCaseInstanceRegisterInformation() {
        
        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setDomain("Domain").setService("Service").setProvider("Provider.Service");
        
        AthenzObject.INSTANCE_REGISTER_INFO.convertToLowerCase(info);
        assertEquals(info.getService(), "service");
        assertEquals(info.getDomain(), "domain");
        assertEquals(info.getProvider(), "provider.service");
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
        
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion1);
        assertions.add(assertion2);
        
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
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setDomain("athenz").setService("production").setProvider("athenz.provider");

        InstanceCertManager instanceManager = Mockito.spy(ztsImpl.instanceCertManager);
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.confirmInstance(Mockito.any())).thenReturn(confirmation);
        Mockito.when(instanceManager.insertX509CertRecord(Mockito.any())).thenReturn(true);
        
        Mockito.when(mockCloudStore.getCloudAccount("athenz")).thenReturn("1234");
        
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(null);
        
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
        
        Mockito.doReturn(false).when(instanceManager).generateSSHIdentity(Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any());
        
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
    
    @Test
    public void testPostInstanceRefreshInformation() throws IOException {

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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        certRecord.setClientCert(true);
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(403, "Forbidden"));
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
            ztsImpl.postInstanceRefreshInformation(context,
                "athenz.provider", "athenz", "production", "1001", info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403, ex.getMessage());
            assertTrue(ex.getMessage().contains("unable to verify attestation data"), ex.getMessage());
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenThrow(new com.yahoo.athenz.instance.provider.ResourceException(404, "Not Found"));
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);
        Mockito.when(instanceManager.generateSSHIdentity(Mockito.any(), Mockito.any(), Mockito.eq("ssh-csr"),
                Mockito.eq("user"))).thenReturn(false);

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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("101");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        
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
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
    public void testPostInstanceRefreshInformationCertDNSMismatch() throws IOException {

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
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
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
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("dnsName attribute mismatch in CSR"));
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(null);
        
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz2.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("101");
        certRecord.setPrevSerial("101");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(providerClient);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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

        Path path = Paths.get("src/test/resources/athenz.instanceid.csr");
        String certCsr = new String(Files.readAllBytes(path));
        
        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(certCsr);
        
        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenzn=production;s=signature", 0, authority);
        
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
    public void testPostInstanceRefreshInformationNullCSRs() {
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        DataStore store = new DataStore(structStore, null);
        ZTSImpl ztsImpl = new ZTSImpl(mockCloudStore, store);
        
        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr(null).setSsh("");
        
        PrincipalAuthority authority = new PrincipalAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenzn=production;s=signature", 0, authority);
        
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
        
        Mockito.when(instanceProviderManager.getProvider("athenz.provider")).thenReturn(null);
        Mockito.when(providerClient.refreshInstance(Mockito.any())).thenReturn(confirmation);
        
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setInstanceId("1001");
        certRecord.setProvider("athenz.provider");
        certRecord.setService("athenz.production");
        certRecord.setCurrentSerial("16503746516960996918");
        certRecord.setPrevSerial("16503746516960996918");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
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
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, "ssh-csr", "user")).thenReturn(true);
        
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
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, "ssh-csr", "user")).thenReturn(true);
        
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
    public void testPostInstanceRefreshInformationSSHMismatchSerial() throws IOException {

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
        certRecord.setPrevSerial("123413");
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);
        
        ztsImpl.instanceCertManager = instanceManager;
        
        InstanceRefreshInformation info = new InstanceRefreshInformation().setSsh("ssh-csr");
        
        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);
        
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
            assertEquals(ex.getCode(), 403);
        }
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
        Mockito.when(instanceManager.getX509CertRecord("athenz.provider", "1001")).thenReturn(certRecord);
        Mockito.when(instanceManager.updateX509CertRecord(Mockito.any())).thenReturn(true);

        CertificateAuthority certAuthority = new CertificateAuthority();
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("athenz", "production",
                "v=S1;d=athenz;n=production;s=signature", 0, certAuthority);

        InstanceIdentity identity = new InstanceIdentity().setName("athenz.production");
        Mockito.when(instanceManager.generateSSHIdentity(principal, identity, "ssh-csr", "user")).thenReturn(false);
        
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
        Mockito.when(instanceManager.deleteX509CertRecord("athenz.provider", "1001")).thenReturn(true);
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
    public void testCreatePrincpalForName() {
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
        
        ztsImpl.validateRequest(request, "test");
        ztsImpl.validateRequest(request, "test", false);
        ztsImpl.validateRequest(request, "test", true);
        
        // should complete successfully since our request is true
        
        ztsImpl.secureRequestsOnly = true;
        ztsImpl.validateRequest(request, "test");
        ztsImpl.validateRequest(request, "test", false);
        ztsImpl.validateRequest(request, "test", true);
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
            ztsImpl.validateRequest(request, "test");
            fail();
        } catch (ResourceException ignored) {
        }
        try {
            ztsImpl.validateRequest(request, "test", false);
            fail();
        } catch (ResourceException ignored) {
        }
        try {
            ztsImpl.validateRequest(request, "test", true);
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
        
        ztsImpl.validateRequest(request, "test");
        ztsImpl.validateRequest(request, "test", false);

        // status requests are not allowed on port 4443
        
        try {
            ztsImpl.validateRequest(request, "test", true);
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
        
        ztsImpl.validateRequest(request, "test", true);

        // non-status requests are not allowed on port 8443
        
        try {
            ztsImpl.validateRequest(request, "test");
            fail();
        } catch (ResourceException ignored) {
        }
        
        try {
            ztsImpl.validateRequest(request, "test", false);
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

        //noinspection CatchMayIgnoreException
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

        //noinspection CatchMayIgnoreException
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

        //noinspection CatchMayIgnoreException
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

        //noinspection CatchMayIgnoreException
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

        //noinspection CatchMayIgnoreException
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

        //noinspection CatchMayIgnoreException
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

        //noinspection CatchMayIgnoreException
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
            ztsImpl.postOSTKInstanceInformation(ctx, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains("Read-Only mode"));
        }

        try {
            ztsImpl.postOSTKInstanceRefreshRequest(ctx, null, null, null);
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
        Mockito.when(instanceManager.generateSSHCertificates(Mockito.any(), Mockito.eq(certRequest)))
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
        Mockito.when(instanceManager.generateSSHCertificates(Mockito.any(), Mockito.eq(certRequest)))
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
}
