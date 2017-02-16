/**
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.impl.UserAuthority;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.log.AthenzRequestLog;
import com.yahoo.athenz.common.server.log.AuditLogFactory;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.ZTSAuthorizer.AccessStatus;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.cert.impl.SelfCertSigner;
import com.yahoo.athenz.zts.cert.impl.SelfCertSignerFactory;
import com.yahoo.athenz.zts.cert.InstanceIdentityStore;
import com.yahoo.athenz.zts.cert.impl.LocalInstanceIdentityStore;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.CloudStore;
import com.yahoo.athenz.zts.store.CloudStoreTest;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.MockCloudStore;
import com.yahoo.athenz.zts.store.file.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.store.file.ZMSFileChangeLogStore;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.Schema;
import com.yahoo.rdl.Timestamp;

public class ZTSImplTest {

    int roleTokenDefaultTimeout = 2400;
    int roleTokenMaxTimeout = 96000;

    ZTSImpl zts = null;
    ZTSAuthorizer authorizer = null;
    DataStore store = null;
    PrivateKey privateKey = null;
    PublicKey publicKey = null;

    static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    static final String ZTS_Y64_CERT0 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84a"
            + "EtFVWZTU2dwWHIzQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbE"
            + "dVT0VnMmpzbWRha1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY"
            + "0cmJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    static final String ZTS_PEM_CERT0 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1tGSVCA8wl5ew5Y76Wj2rJAUD\n"
            + "YanEJfKmAlx5cQ/8hKEUfSSgpXr3Czdh1a26dlb7mmK29qmXJXh6umW9AyfTOKVo\n"
            + "+6ASloVU3avvuflGUOEg2jsmdakR24KcLjAu6QrUe417lG3t8qSPIGjS5C+CsJUw\n"
            + "h04hHx5f+PEwxV4rbQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    final static String AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_BEGIN = "{\n"
            + "  \"devpayProductCodes\" : null,\n"
            + "  \"availabilityZone\" : \"us-west-2a\",\n"
            + "  \"privateIp\" : \"10.10.10.10\",\n"
            + "  \"version\" : \"2010-08-31\",\n"
            + "  \"instanceId\" : \"i-056921225f1fbb47a\",\n"
            + "  \"billingProducts\" : null,\n"
            + "  \"instanceType\" : \"t2.micro\",\n"
            + "  \"accountId\" : \"111111111111\",\n"
            + "  \"pendingTime\" : \"";
    final static String AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_END = "\",\n"
            + "  \"imageId\" : \"ami-c229c0a2\",\n"
            + "  \"architecture\" : \"x86_64\",\n"
            + "  \"kernelId\" : null,\n"
            + "  \"ramdiskId\" : null,\n"
            + "  \"region\" : \"us-west-2\"\n"
            + "}";
    final static String ROLE_CERT_DB_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIBujCCASMCAQAwOzELMAkGA1UEBhMCVVMxDjAMBgNVBAoTBVlhaG9vMRwwGgYD\n"
            + "VQQDExNzcG9ydHM6cm9sZS5yZWFkZXJzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
            + "iQKBgQCu0nOEra8WmmU91u2KrDdcKRDcZn3oSwsZD/55d0bkMwEiMzfQ+xHVRFI1\n"
            + "PPGjhG167oRhTRKE3a3uakMGmMDM5WWcDLbLo+PHZGqUyhJrvq5BF4VWrUWpY+rp\n"
            + "paklBTUPY0asmlObVpFBVoujkSyxMIXmOi9qK/O+Bs0BI4jo6QIDAQABoD8wPQYJ\n"
            + "KoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjgiFhcGkuY29yZXRlY2gtdGVzdC5hd3Mu\n"
            + "eWFob28uY2xvdWQwDQYJKoZIhvcNAQELBQADgYEAQSEWI7eRM5Xv0oENQ+zzdoQI\n"
            + "MgzgsXRKGxlZFBpHNvT1R/4pkrU2XdpU1sQP8nrs3Xl+jUd70Ke7K1b2qL6D9op8\n"
            + "eE/qKXv+mcEBGlSCaJtK9MBUnOh4TVZ3EePxbc41Ha2/zWn+J3RFBMz9i1Nxy+Nq\n"
            + "s1K+2Aj6SbErxrEunNI=\n-----END CERTIFICATE REQUEST-----\n";
    final static String ROLE_CERT_CORETECH_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIIBuDCCASECAQAwPTELMAkGA1UEBhMCVVMxDjAMBgNVBAoTBVlhaG9vMR4wHAYD\n"
            + "VQQDExVjb3JldGVjaDpyb2xlLnJlYWRlcnMwgZ8wDQYJKoZIhvcNAQEBBQADgY0A\n"
            + "MIGJAoGBAK7Sc4StrxaaZT3W7YqsN1wpENxmfehLCxkP/nl3RuQzASIzN9D7EdVE\n"
            + "UjU88aOEbXruhGFNEoTdre5qQwaYwMzlZZwMtsuj48dkapTKEmu+rkEXhVatRalj\n"
            + "6umlqSUFNQ9jRqyaU5tWkUFWi6ORLLEwheY6L2or874GzQEjiOjpAgMBAAGgOzA5\n"
            + "BgkqhkiG9w0BCQ4xLDAqMCgGA1UdEQQhMB+CHWFwaS55YnktdXNlcjEuYXdzLnlh\n"
            + "aG9vLmNsb3VkMA0GCSqGSIb3DQEBCwUAA4GBAKvuws3Ls+kCvRbriP3Abb2ApTuK\n"
            + "747eax54gzyhGYdVqOKcGATy9S3RoEQaLeB1wMp+aHRHdcZXlEiNIqqzKWTIlr6l\n"
            + "NUAnfloQjAe8SN4EaZUaUVep76zhpkoXAytfxM/rKWUFzPKPIZ0tv7p1rJsj5USc\n"
            + "KxZ+SxVr4KD8nM/v\n-----END CERTIFICATE REQUEST-----\n";
    
    private static final String MOCKCLIENTADDR = "10.11.12.13";
    @Mock HttpServletRequest  mockServletRequest;
    @Mock HttpServletResponse mockServletResponse;

    static class ZtsMetricTester extends com.yahoo.athenz.common.metrics.impl.NoOpMetric {
        Map<String, Integer> metrixMap = new HashMap<>();

        public Map<String, Integer> getMap() { return metrixMap; }

        public void  increment(String metric, String domainName, int count) {
            String key = metric + domainName;
            metrixMap.put(key, count);
        }
    }
    
    ResourceContext createResourceContext(Principal principal) {
        com.yahoo.athenz.common.server.rest.ResourceContext rsrcCtx = Mockito.mock(com.yahoo.athenz.common.server.rest.ResourceContext.class);
        Mockito.when(rsrcCtx.principal()).thenReturn(principal);
        Mockito.when(rsrcCtx.request()).thenReturn(mockServletRequest);

        RsrcCtxWrapper rsrcCtxWrapper = Mockito.mock(RsrcCtxWrapper.class);
        Mockito.when(rsrcCtxWrapper.context()).thenReturn(rsrcCtx);
        Mockito.when(rsrcCtxWrapper.principal()).thenReturn(principal);
        Mockito.when(rsrcCtxWrapper.request()).thenReturn(mockServletRequest);
        Mockito.when(rsrcCtxWrapper.response()).thenReturn(mockServletResponse);
        return rsrcCtxWrapper;
    }
    
    ResourceContext createResourceContext(Principal principal, HttpServletRequest request) {
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
        Object obj = mvmap.getFirst(header);
        return obj;
    }
    
    public static Role createRoleObject(String domainName, String roleName,
            String trust) {
        Role role = new Role();
        role.setName(domainName + ":role." + roleName);
        role.setTrust(trust);
        return role;
    }
    
    public static Role createRoleObject(String domainName, String roleName,
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

    public static Role createRoleObject(String domainName, String roleName,
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

        List<Assertion> assertList = new ArrayList<Assertion>();
        assertList.add(assertion);

        policy.setAssertions(assertList);
        return policy;
    }
    
    @BeforeClass
    public void setUpClass() throws Exception {
        MockitoAnnotations.initMocks(this);
        Mockito.when(mockServletRequest.getRemoteAddr()).thenReturn(MOCKCLIENTADDR);
        
        System.setProperty(ZTSConsts.ZTS_PROP_METRIC_FACTORY_CLASS, ZTSConsts.ZTS_METRIC_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_STATS_ENABLED, "true");
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/zts_private.pem");
        System.setProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF,  "src/test/resources/athenz.conf");
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

        CloudStore cloudStore = new CloudStore(null);
        cloudStore.setHttpClient(null);
        
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME,
                "src/test/resources/private_encrypted.key");
        System.setProperty(ZTSConsts.ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD, "athenz");
        CertSigner certSigner = new SelfCertSignerFactory().create();
        InstanceIdentityStore instanceIdentityStore = new LocalInstanceIdentityStore(certSigner);

        store = new DataStore(structStore, cloudStore);

        com.yahoo.athenz.common.metrics.Metric metric = getMetric();
        zts = new ZTSImpl("localhost", store, cloudStore, instanceIdentityStore, metric,
                privateKey, "0", AuditLogFactory.getLogger(), null);
        authorizer = (ZTSAuthorizer) zts.getAuthorizer();
    }
    
    private Metric getMetric(){
        com.yahoo.athenz.common.metrics.MetricFactory metricFactory = null;
        com.yahoo.athenz.common.metrics.Metric metric = null;
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
    
    @AfterMethod
    public void shutdown() {
        ZMSFileChangeLogStore.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT);
        System.clearProperty(ZTSConsts.ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT);

    }
    
    private String generateRoleName(String domain, String role) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(":role.");
        str.append(role);
        return str.toString();
    }

    private String generatePolicyName(String domain, String policy) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(":policy.");
        str.append(policy);
        return str.toString();
    }

    private String generateServiceIdentityName(String domain, String service) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(".");
        str.append(service);
        return str.toString();
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
        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();
        String memberName = "user_domain.user1";
        Role role = new Role();
        role.setName(generateRoleName(domainName, "admin"));
        List<RoleMember> members = new ArrayList<RoleMember>();
        RoleMember roleMember = new RoleMember();
        roleMember.setMemberName("user_domain.adminuser");
        members.add(roleMember);
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(generateRoleName(domainName, "role1"));
        members = new ArrayList<RoleMember>();
        roleMember = new RoleMember();
        roleMember.setMemberName(memberName);
        roleMember.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 100));
        members.add(roleMember);
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(generateRoleName(domainName, "role2"));
        members = new ArrayList<RoleMember>();
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
    
    private SignedDomain createTenantSignedDomainWildCard(String domainName, String providerDomain) {
        
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
        domainData.setRoles(new ArrayList<Role>());
        Role role = new Role().setName("coretech:role.role1");
        domainData.getRoles().add(role);
        Policy policy = new Policy().setName("coretech:policy.policy1");
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        assertEquals(authorizer.evaluateAccess(domain, null, null, null, null), AccessStatus.DENIED);
    }
    
    @Test
    public void testEvaluateAccessAssertionDeny() {
        
        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<Role>());
        Role role = createRoleObject("coretech", "role1", null, "user_domain.user1", null);
        domainData.getRoles().add(role);

        Policy policy = new Policy().setName("coretech:policy.policy1");
        Assertion assertion = new Assertion();
        assertion.setAction("read");
        assertion.setEffect(AssertionEffect.DENY);
        assertion.setResource("coretech:*");
        assertion.setRole("coretech:role.role1");
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        
        assertEquals(authorizer.evaluateAccess(domain, "user_domain.user1", "read", "coretech:resource1", null), AccessStatus.DENIED);
    }
    
    @Test
    public void testEvaluateAccessAssertionAllow() {
        
        DataCache domain = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<Role>());
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
        policy.setAssertions(new ArrayList<Assertion>());
        policy.getAssertions().add(assertion1);
        policy.getAssertions().add(assertion2);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
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
        assertTrue(hosts.getNames().size() == 1);
        assertTrue(hosts.getNames().contains("coretech.storage"));
        
        hosts = zts.getHostServices(context, "host2");
        assertTrue(hosts.getNames().size() == 2);
        assertTrue(hosts.getNames().contains("coretech.storage"));
        assertTrue(hosts.getNames().contains("coretech.backup"));
        
        hosts = zts.getHostServices(context, "host3");
        assertTrue(hosts.getNames().size() == 1);
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
    public void testGetRoleToken() {
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);
        
        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                Integer.valueOf(1200), null);
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
        
        roleToken = zts.getRoleToken(context1, "coretech", null, null, Integer.valueOf(1200), null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 2);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(token.getRoles().contains("writers"));
        
        Principal principal4 = SimplePrincipal.create("user_domain", "user4",
                "v=U1;d=user_domain;n=user4;s=signature", 0, null);
        ResourceContext context4 = createResourceContext(principal4);
        
        roleToken = zts.getRoleToken(context4, "coretech", null, Integer.valueOf(600),
                null, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.user4;"));
    }
    
    @Test
    public void testGetRoleTokenExpire() {
        
        SignedDomain signedDomain = createSignedDomainExpiration("coretech-expire", "weather");
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        RoleToken roleToken = zts.getRoleToken(context, "coretech-expire",
                null, Integer.valueOf(600), Integer.valueOf(1200), null);
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
            zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                    Integer.valueOf(1200), null);
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
            zts.getRoleToken(context, "invalidDomain", null, Integer.valueOf(600),
                    Integer.valueOf(1200), null);
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
        
        RoleToken roleToken = zts.getRoleToken(context, "coretech", "writers", Integer.valueOf(600),
                Integer.valueOf(1200), null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
        
        Principal principal1 = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user1;s=signature", 0, null);
        ResourceContext context1 = createResourceContext(principal1);
        
        roleToken = zts.getRoleToken(context1, "coretech", "writers", null, Integer.valueOf(1200), null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
        
        Principal principal4 = SimplePrincipal.create("user_domain", "user4",
                "v=U1;d=user_domain;n=user4;s=signature", 0, null);
        ResourceContext context4 = createResourceContext(principal4);
        
        roleToken = zts.getRoleToken(context4, "coretech", "readers", Integer.valueOf(600), null, null);
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
    }
    
    @Test
    public void testGetRoleTokenSpecifiedRoleInValid() {
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.getRoleToken(context, "coretech", "coretech:role.readers", Integer.valueOf(600),
                    Integer.valueOf(1200), null);
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
            zts.getRoleToken(context, "coretech", "updaters", Integer.valueOf(600),
                    Integer.valueOf(1200), null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
    
    @Test
    public void testGetRoleTokenTrustDomainWildCard() {

        SignedDomain signedDomain = createSignedDomainWildCard("weather", "netops");
        store.processDomain(signedDomain, false);
        
        signedDomain = createTenantSignedDomainWildCard("netops", "weather");
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
        
        signedDomain = createTenantSignedDomainWildCard("netops", "weather");
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
    }
    
    @Test
    public void testGetRoleTokenUnauthorizedProxy() {
        SignedDomain signedDomain = createSignedDomain("coretech-proxy1", "weather-proxy1", "storage", true);
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user", "v=U1;d=user_domain;n=user;s=sig", 0, null);
        ResourceContext context = createResourceContext(principal);

        try {
            zts.getRoleToken(context, "coretech-proxy1", null, Integer.valueOf(600),
                Integer.valueOf(1200), "user_domain.unknown-proxy-user");
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

        RoleToken roleToken = zts.getRoleToken(context, "coretech-proxy2", null, Integer.valueOf(600),
                Integer.valueOf(1200), "user_domain.joe");
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("writers"));
        assertTrue(roleToken.getToken().contains(";h=localhost;"));
        assertTrue(roleToken.getToken().contains(";i=10.11.12.13"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.joe;"));
        assertTrue(roleToken.getToken().contains(";proxy=user_domain.proxy-user1;"));
        assertTrue(roleToken.getToken().contains(";c=1;"));
        assertEquals(roleToken.getExpiryTime(), token.getExpiryTime());

        principal = SimplePrincipal.create("user_domain", "proxy-user2",
                "v=U1;d=user_domain;n=proxy-user2;s=sig", 0, null);
        context = createResourceContext(principal);
        
        roleToken = zts.getRoleToken(context, "coretech-proxy2", null, Integer.valueOf(600),
                Integer.valueOf(1200), "user_domain.jane");
        token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("readers"));
        assertTrue(roleToken.getToken().contains(";h=localhost;"));
        assertTrue(roleToken.getToken().contains(";i=10.11.12.13"));
        assertTrue(roleToken.getToken().contains(";p=user_domain.jane;"));
        assertTrue(roleToken.getToken().contains(";proxy=user_domain.proxy-user2;"));
        assertTrue(roleToken.getToken().contains(";c=1;"));
        assertEquals(roleToken.getExpiryTime(), token.getExpiryTime());
    }
    
    @Test
    public void testGetRoleTokenProxyUserMismatchRoles() {
        
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

        try {
            zts.getRoleToken(context, "coretech-proxy3", null, Integer.valueOf(600),
                    Integer.valueOf(1200), "user_domain.joe");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("does not have access to the same set of roles as proxy"));
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

        RoleToken roleToken = zts.getRoleToken(context, "coretech-proxy4", "writers", Integer.valueOf(600),
                Integer.valueOf(1200), "user_domain.joe");
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

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, new String(), null, metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, "invalidcharacterslike...$!?", null, metric);
        assertFalse(isEmitMonmetricError);

        isEmitMonmetricError = ZTSUtils.emitMonmetricError(errorCode, "spaces are not allowed", ZTSConsts.ZTS_UNKNOWN_DOMAIN, metric);
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
        assertEquals(zts.determineTokenTimeout(null, Integer.valueOf(100)), 100);
    }
    
    @Test
    public void testDetermineTokenTimeoutMaxNull() {
        assertEquals(zts.determineTokenTimeout(Integer.valueOf(100), null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutMinInvalid() {
        assertEquals(zts.determineTokenTimeout(Integer.valueOf(-10), null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutMaxInvalid() {
        assertEquals(zts.determineTokenTimeout(null, Integer.valueOf(-10)), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokenTimeoutDefaultBigger() {
        assertEquals(zts.determineTokenTimeout(Integer.valueOf(3200), null), 3200);
    }
    
    @Test
    public void testDetermineTokeTimeoutDefaultSmaller() {
        assertEquals(zts.determineTokenTimeout(Integer.valueOf(1200), null), roleTokenDefaultTimeout);
    }
    
    @Test
    public void testDetermineTokeTimeoutMaxValueMaxExceeded() {
        assertEquals(zts.determineTokenTimeout(null, Integer.valueOf(120000)), roleTokenMaxTimeout);
    }

    @Test
    public void testDetermineTokeTimeoutMinValueMaxExceeded() {
        assertEquals(zts.determineTokenTimeout(Integer.valueOf(120000), null), roleTokenMaxTimeout);
    }
    
    @Test
    public void testRoleTokenAddrNoLoopbackAuditLog() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("10.10.10.11");

        final java.util.Set<String> aLogMsgs = new java.util.HashSet<String>();
        AuditLogger alogger = new AuditLogger() {
            public void log(String logMsg, String msgVersionTag) {
                aLogMsgs.add(logMsg);
            }
            public void log(AuditLogMsgBuilder msgBldr) {
                String msg = msgBldr.build();
                aLogMsgs.add(msg);
            }
        };
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");

        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        DataStore store = new DataStore(structStore, null);
        zts = new ZTSImpl("localhost", store, null, null, debugMetric, privateKey, "0", alogger, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        
        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                Integer.valueOf(1200), null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
        String unsignToken = token.getUnsignedToken();
        for (String msg: aLogMsgs) {
            assertTrue(msg.contains("SUCCESS ROLETOKEN=(" + unsignToken));
            assertTrue(msg.contains("CLIENT-IP=(10.10.10.11)"));
            break;
        }
    }

    @Test
    public void testGetRoleTokenAddrLoopbackNoXFFAuditLog() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        
        final java.util.Set<String> aLogMsgs = new java.util.HashSet<String>();
        AuditLogger alogger = new AuditLogger() {
            public void log(String logMsg, String msgVersionTag) {
                aLogMsgs.add(logMsg);
            }
            public void log(AuditLogMsgBuilder msgBldr) {
                String msg = msgBldr.build();
                aLogMsgs.add(msg);
            }
        };
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        DataStore store = new DataStore(structStore, null);
        zts = new ZTSImpl("localhost", store, null, null, debugMetric, privateKey, "0", alogger, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        
        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                Integer.valueOf(1200), null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
        String unsignToken = token.getUnsignedToken();
        for (String msg: aLogMsgs) {
            assertTrue(msg.contains("SUCCESS ROLETOKEN=(" + unsignToken));
            assertTrue(msg.contains("i=127.0.0.1"));
            assertTrue(msg.contains("CLIENT-IP=(127.0.0.1)"));
            break;
        }
    }
 
    @Test
    public void testGetRoleTokenAddrLoopbackXFFSingeValueAuditLog() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.getHeader("X-Forwarded-For")).thenReturn("10.10.10.12");
        
        final java.util.Set<String> aLogMsgs = new java.util.HashSet<String>();
        AuditLogger alogger = new AuditLogger() {
            public void log(String logMsg, String msgVersionTag) {
                aLogMsgs.add(logMsg);
            }
            public void log(AuditLogMsgBuilder msgBldr) {
                String msg = msgBldr.build();
                aLogMsgs.add(msg);
            }
        };
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        DataStore store = new DataStore(structStore, null);
        zts = new ZTSImpl("localhost", store, null, null, debugMetric, privateKey, "0", alogger, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        
        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                Integer.valueOf(1200), null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
        String unsignToken = token.getUnsignedToken();
        for (String msg: aLogMsgs) {
            assertTrue(msg.contains("SUCCESS ROLETOKEN=(" + unsignToken));
            assertTrue(msg.contains("CLIENT-IP=(10.10.10.12)"));
            break;
        }
    }
    
    @Test
    public void testGetRoleTokenAddrLoopbackXFFMultipleValuesAuditLog() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        Mockito.when(servletRequest.getHeader("X-Forwarded-For")).thenReturn("10.10.10.11, 10.11.11.11, 10.12.12.12");
        
        final java.util.Set<String> aLogMsgs = new java.util.HashSet<String>();
        AuditLogger alogger = new AuditLogger() {
            public void log(String logMsg, String msgVersionTag) {
                aLogMsgs.add(logMsg);
            }
            public void log(AuditLogMsgBuilder msgBldr) {
                String msg = msgBldr.build();
                aLogMsgs.add(msg);
            }
        };
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        DataStore store = new DataStore(structStore, null);
        zts = new ZTSImpl("localhost", store, null, null, debugMetric, privateKey, "0", alogger, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        
        RoleToken roleToken = zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                Integer.valueOf(1200), null);
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertNotNull(token);
        String unsignToken = token.getUnsignedToken();
        for (String msg: aLogMsgs) {
            assertTrue(msg.contains("SUCCESS ROLETOKEN=(" + unsignToken));
            assertTrue(msg.contains("CLIENT-IP=(10.12.12.12)"));
            break;
        }
    }

    @Test
    public void testGetRoleTokenNoRoleMatchAuditLog() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("99.88.77.66");
        
        final java.util.Set<String> aLogMsgs = new java.util.HashSet<String>();
        AuditLogger alogger = new AuditLogger() {
            public void log(String logMsg, String msgVersionTag) {
                aLogMsgs.add(logMsg);
            }
            public void log(AuditLogMsgBuilder msgBldr) {
                String msg = msgBldr.build();
                aLogMsgs.add(msg);
            }
        };
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        DataStore store = new DataStore(structStore, null);
        zts = new ZTSImpl("localhost", store, null, null, debugMetric, privateKey, "0", alogger, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "invalidUser",
                "v=U1;d=user_domain;n=invalidUser;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        
        try {
            zts.getRoleToken(context, "coretech", null, Integer.valueOf(600),
                    Integer.valueOf(1200), null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }

        for (String msg: aLogMsgs) {
            assertTrue(msg.contains("ERROR=(Principal Has No Access to Domain)"));
            assertTrue(msg.contains("CLIENT-IP=(99.88.77.66)"));
            assertTrue(msg.contains("WHO=(who-name=invalidUser,who-domain=user_domain,who-fullname=user_domain.invalidUser)"));
            break;
        }
    }

    @Test
    public void testGetRoleTokenInvalidDomainAuditLog() {
        HttpServletRequest servletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(servletRequest.getRemoteAddr()).thenReturn("55.88.77.66");
        
        final java.util.Set<String> aLogMsgs = new java.util.HashSet<String>();
        AuditLogger alogger = new AuditLogger() {
            public void log(String logMsg, String msgVersionTag) {
                aLogMsgs.add(logMsg);
            }
            public void log(AuditLogMsgBuilder msgBldr) {
                String msg = msgBldr.build();
                aLogMsgs.add(msg);
            }
        };
        
        ChangeLogStore structStore = new ZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        Metric debugMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
        DataStore store = new DataStore(structStore, null);
        zts = new ZTSImpl("localhost", store, null, null, debugMetric, privateKey, "0", alogger, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal, servletRequest);
        
        try {
            zts.getRoleToken(context, "invalidDomain", null, Integer.valueOf(600),
                    Integer.valueOf(1200), null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        for (String msg: aLogMsgs) {
            assertTrue(msg.contains("ERROR=(No Such Domain)"));
            assertTrue(msg.contains("CLIENT-IP=(55.88.77.66)"));
            assertTrue(msg.contains("WHO=(who-name=user,who-domain=user_domain,who-fullname=user_domain.user)"));
            break;
        }
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
    public void testGetTenantDomainsSingleDomainWithUserDomain() {

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
            assertEquals( ((ResourceError) ex.data).message, "failed message");
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
            zts.getAWSTemporaryCredentials(context, "athenz.product", "aws_role_name");
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
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name");
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
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testGetAWSTemporaryCredentials() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user101",
                "v=U1;d=user_domain;n=user101;s=signature", 0, null);
        CloudStore cloudStore = new MockCloudStore();
        ((MockCloudStore) cloudStore).setMockFields("1234", "aws_role_name", "user_domain.user101");
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "1234");
        store.processDomain(signedDomain, false);
        
        AWSTemporaryCredentials creds = zts.getAWSTemporaryCredentials(
                createResourceContext(principal), "athenz.product", "aws_role_name");
        assertNotNull(creds);
        
        // now try a failure case
        
        try {
            ((MockCloudStore) cloudStore).setMockFields("1234", "aws_role2_name", "user_domain.user101");
            zts.getAWSTemporaryCredentials(createResourceContext(principal), "athenz.product", "aws_role_name");
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
        assertEquals(null, authorizer.retrieveResourceDomain("domain1", "read", "trustdomain"));
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
        
        Role role = null;
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
        
        Role role = null;
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
        
        Role role = null;
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
        
        Role role = null;
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
        
        Role role = null;
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
        domainData.setRoles(new ArrayList<Role>());
        Role role1 = createRoleObject("coretechtrust",  "role1", null, "user_domain.user1", null);
        Role role2 = createRoleObject("coretechtrust",  "role2", null, "user_domain.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject("coretechtrust", "trust", "coretechtrust:role.role1",
                false, "ASSUME_ROLE", "weather:role.role1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
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
        domainData.setRoles(new ArrayList<Role>());
        Role role1 = createRoleObject("coretechtrust",  "role1", null, "user_domain.user1", null);
        Role role2 = createRoleObject("coretechtrust",  "role2", null, "user_domain.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject("coretechtrust", "trust", "coretechtrust:role.role1",
                false, "ASSUME_ROLE", "weather:role.role1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
        domainData.getPolicies().getContents().getPolicies().add(policy);
        store.getCacheStore().put("coretechtrust", domain);
        
        domain = new DataCache();
        domainData = new DomainData();
        domainData.setName("weather");
        domain.setDomainData(domainData);
        domainData.setRoles(new ArrayList<Role>());
        role1 = createRoleObject("weather", "role1", "coretechtrust");
        domainData.getRoles().add(role1);

        policy = createPolicyObject("weather", "access", "weather:role.role1",
                false, "update", "weather:table1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
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
        domainData.setRoles(new ArrayList<Role>());
        Role role1 = createRoleObject("coretechtrust",  "role1", null, "user_domain.user1", null);
        Role role2 = createRoleObject("coretechtrust",  "role2", null, "user_domain.user2", null);
        domainData.getRoles().add(role1);
        domainData.getRoles().add(role2);

        Policy policy = createPolicyObject("coretechtrust", "access", "coretechtrust:role.role1",
                false, "update", "coretechtrust:table1", AssertionEffect.ALLOW);
        domainData.setPolicies(new com.yahoo.athenz.zms.SignedPolicies());
        domainData.getPolicies().setContents(new com.yahoo.athenz.zms.DomainPolicies());
        domainData.getPolicies().getContents().setPolicies(new ArrayList<Policy>());
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
        } catch (com.yahoo.athenz.zts.ResourceException ex) {
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
        } catch (com.yahoo.athenz.zts.ResourceException ex) {
            assertEquals(404, ex.getCode());
        }
    }
    
    @Test
    public void testIsMemberOfRoleNoMembers() {
        Role role1 = new Role();
        assertFalse(authorizer.isMemberOfRole(role1, "user_domain.user1"));
    }
    
    @Test
    public void testPostAWSCertificateRequestNoAwsAccount() {
        
        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processDomain(signedDomain, false);
        AWSCertificateRequest req = new AWSCertificateRequest();
        req.setCsr("csr");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature",
                0, new com.yahoo.athenz.auth.impl.CertificateAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSCertificateRequest(context, "athenz.product", "zts", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSCertificateRequestNoCloudStore() {
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processDomain(signedDomain, false);
        AWSCertificateRequest req = new AWSCertificateRequest();
        req.setCsr("csr");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature",
                0, new com.yahoo.athenz.auth.impl.CertificateAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSCertificateRequest(context, "athenz.product", "zts", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSCertificateRequestInvalidAuthority() {
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processDomain(signedDomain, false);
        AWSCertificateRequest req = new AWSCertificateRequest();
        req.setCsr("csr");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature",
                0, new com.yahoo.athenz.auth.impl.KerberosAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSCertificateRequest(context, "athenz.product", "zts", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
    
    @Test
    public void testPostAWSCertificateRequestNullAuthority() {
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processDomain(signedDomain, false);
        AWSCertificateRequest req = new AWSCertificateRequest();
        req.setCsr("csr");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);

        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSCertificateRequest(context, "athenz.product", "zts", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
    
    @Test
    public void testPostAWSCertificateRequest() throws IOException {
        
        File caCert = new File("src/test/resources/valid_cn_x509.cert");
        X509Certificate caCertificate = Crypto.loadX509Certificate(caCert);
        
        File caKey = new File("src/test/resources/private_encrypted.key");
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(caKey, "athenz");
        CertSigner certSigner = new SelfCertSigner(caPrivateKey, caCertificate);

        CloudStore cloudStore = new MockCloudStore(certSigner);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz", "012345");
        store.processDomain(signedDomain, false);
        
        AWSCertificateRequest req = new AWSCertificateRequest();
        Path path = Paths.get("src/test/resources/valid.csr");
        String certStr = new String(Files.readAllBytes(path));
        req.setCsr(certStr);
        
        Principal principal = SimplePrincipal.create("athenz", "syncer", "user-credentials",
                0, new com.yahoo.athenz.auth.impl.CertificateAuthority());
        ResourceContext context = createResourceContext(principal);
        
        Identity identity = zts.postAWSCertificateRequest(context, "athenz", "syncer", req);
        assertNotNull(identity);
    }
    
    @Test
    public void testPostAWSCertificateRequestInvalidCSR() throws IOException {
        
        File caCert = new File("src/test/resources/valid_cn_x509.cert");
        X509Certificate caCertificate = Crypto.loadX509Certificate(caCert);
        
        File caKey = new File("src/test/resources/private_encrypted.key");
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(caKey, "athenz");
        CertSigner certSigner = new SelfCertSigner(caPrivateKey, caCertificate);

        CloudStore cloudStore = new MockCloudStore(certSigner);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz", "012345");
        store.processDomain(signedDomain, false);
        
        AWSCertificateRequest req = new AWSCertificateRequest();
        req.setCsr("invalid-csr");
        
        Principal principal = SimplePrincipal.create("athenz", "syncer",
                "v=U1;d=athenz;n=syncer;s=signature",
                0, new com.yahoo.athenz.auth.impl.CertificateAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSCertificateRequest(context, "athenz", "syncer", req);
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }
    
    @Test
    public void testPostAWSCertificateRequestMismatchPrincipal() throws IOException {
        
        File caCert = new File("src/test/resources/valid_cn_x509.cert");
        X509Certificate caCertificate = Crypto.loadX509Certificate(caCert);
        
        File caKey = new File("src/test/resources/private_encrypted.key");
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(caKey, "athenz");
        CertSigner certSigner = new SelfCertSigner(caPrivateKey, caCertificate);

        CloudStore cloudStore = new MockCloudStore(certSigner);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz", "012345");
        store.processDomain(signedDomain, false);
        
        AWSCertificateRequest req = new AWSCertificateRequest();
        req.setCsr("invalid-csr");
        
        Principal principal = SimplePrincipal.create("athenz", "zts",
                "v=U1;d=athenz;n=zts;s=signature",
                0, new com.yahoo.athenz.auth.impl.CertificateAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSCertificateRequest(context, "athenz", "zts", req);
        } catch (ResourceException ex) {
            assertEquals(400, ex.getCode());
        }
    }
    
    private AWSInstanceInformation generateAWSInstanceInformation(String domain, String account,
            String document, String signature) {
        
        AWSInstanceInformation info = new AWSInstanceInformation();
        if (document == null) {
            info.setDocument(CloudStoreTest.AWS_INSTANCE_DOCUMENT);
        } else {
            info.setDocument(document);
        }
        info.setSignature(signature);

        info.setName(domain + ".syncer");
        info.setDomain(domain);
        info.setAccount(account);
        info.setCloud("athenz");
        info.setService("syncer");
        info.setSubnet("subnet");
        info.setAccess("access");
        info.setSecret("secret");
        info.setToken("token");
        info.setExpires(Timestamp.fromCurrentTime());
        info.setModified(Timestamp.fromCurrentTime());
        info.setFlavor("AWS-HMAC");
        
        Path path = Paths.get("src/test/resources/valid.csr");
        try {
            String certCsr = new String(Files.readAllBytes(path));
            info.setCsr(certCsr);
        } catch (IOException e) {
        }

        return info;
    }

    @Test
    public void testPostInstanceInformation() throws IOException  {
        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        InstanceInformation info = new InstanceInformation()
                .setCsr(certCsr)
                .setDocument("Test Document")
                .setSignature("Test Signature")
                .setDomain("athenz")
                .setService("syncer")
                .setKeyId("0");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        Identity identity = zts.postInstanceInformation(context, info);

        assertNotNull(identity);

        X509Certificate cert = Crypto.loadX509Certificate(identity.getCertificate());
        assertNotNull(cert);
    }

    @Test
    public void testPostInstanceInformationInvalidCsr() throws IOException  {
        InstanceInformation info = new InstanceInformation()
                .setCsr("invalid-csr")
                .setDocument("Test Document")
                .setSignature("Test Signature")
                .setDomain("iaas.athenz")
                .setService("syncer");

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }

    @Test
    public void testPostAWSInstanceInformationNoAwsAccount() {

        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;

        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processDomain(signedDomain, false);

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", null, null);

        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationInfoAwsAccountMismatch() {
        
        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "12345");
        store.processDomain(signedDomain, false);

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", null, null);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationNoCloudStore() {
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", null);
        store.processDomain(signedDomain, false);

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", null, null);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationInvalidSignature() {
        
        CloudStore cloudStore = new MockCloudStore();
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "111111111111");
        store.processDomain(signedDomain, false);

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", null, "invalid-signature");
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationInvalidDocument() {
        
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.skipDocumentSignatureCheck(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "111111111111");
        store.processDomain(signedDomain, false);

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", "invalid-document", null);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationAccountMismatch() {
        
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.skipDocumentSignatureCheck(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "12345");
        store.processDomain(signedDomain, false);

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "12345", null, null);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationInvalidBootTime() {
        
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.setIdentityCheckResult(1);
        cloudStore.skipDocumentSignatureCheck(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "111111111111");
        store.processDomain(signedDomain, false);

        // our default limit is 300 seconds so we're going to set
        // the pending time to before 301 seconds to fail
        
        long pendingTime = System.currentTimeMillis() - 301 * 1000;
        String instanceDocument = AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_BEGIN
                + Timestamp.fromMillis(pendingTime).toString()
                + AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_END;
        
        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", instanceDocument, "signature");
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationIdentityCheckFailure() {
        
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.setIdentityCheckResult(-1);
        cloudStore.skipDocumentSignatureCheck(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "111111111111");
        store.processDomain(signedDomain, false);

        long pendingTime = System.currentTimeMillis();
        String instanceDocument = AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_BEGIN
                + Timestamp.fromMillis(pendingTime).toString()
                + AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_END;
        
        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", instanceDocument, null);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformationInvalidCSR() {
        
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.setIdentityCheckResult(1);
        cloudStore.skipDocumentSignatureCheck(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz.product", "111111111111");
        store.processDomain(signedDomain, false);

        long pendingTime = System.currentTimeMillis();
        String instanceDocument = AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_BEGIN
                + Timestamp.fromMillis(pendingTime).toString()
                + AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_END;
        
        AWSInstanceInformation info = generateAWSInstanceInformation("athenz.product",
                "111111111111", instanceDocument, null);
        info.setCsr("invalid-csr");
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        try {
            zts.postAWSInstanceInformation(context, info);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
    }
    
    @Test
    public void testPostAWSInstanceInformation() throws IOException {
        
        File caCert = new File("src/test/resources/valid_cn_x509.cert");
        X509Certificate caCertificate = Crypto.loadX509Certificate(caCert);
        
        File caKey = new File("src/test/resources/private_encrypted.key");
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(caKey, "athenz");
        CertSigner certSigner = new SelfCertSigner(caPrivateKey, caCertificate);

        MockCloudStore cloudStore = new MockCloudStore(certSigner);
        cloudStore.setIdentityCheckResult(1);
        cloudStore.skipDocumentSignatureCheck(true);
        store.setCloudStore(cloudStore);
        zts.cloudStore = cloudStore;
        
        SignedDomain signedDomain = createAwsSignedDomain("athenz", "111111111111");
        store.processDomain(signedDomain, false);

        long pendingTime = System.currentTimeMillis();
        String instanceDocument = AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_BEGIN
                + Timestamp.fromMillis(pendingTime).toString()
                + AWS_INSTANCE_DOCUMENT_WOUT_TIMESTAMP_END;

        Path path = Paths.get("src/test/resources/valid.csr");
        String certCsr = new String(Files.readAllBytes(path));

        AWSInstanceInformation info = generateAWSInstanceInformation("athenz",
                "111111111111", instanceDocument, "signature");
        info.setCsr(certCsr);
        
        SimplePrincipal principal = (SimplePrincipal) SimplePrincipal.create("hockey", "kings",
                "v=S1,d=hockey;n=kings;s=sig", 0, new PrincipalAuthority());
        ResourceContext context = createResourceContext(principal);
        
        Identity identity = zts.postAWSInstanceInformation(context, info);
        assertNotNull(identity);
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
            assertTrue(ex.getMessage().contains("Unsupported authority"), ex.getMessage());
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
        ResourceContext context = createResourceContext(principal, servletRequest);

        try {
            zts.postInstanceRefreshRequest(context, "iaas.athenz", "syncer", req);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
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
        CloudStore cloudStore = new CloudStore(null);
        cloudStore.setHttpClient(null);
        CertSigner certSigner = new SelfCertSignerFactory().create();
        InstanceIdentityStore instanceIdentityStore = new LocalInstanceIdentityStore(certSigner);
        ZtsMetricTester metric = new ZtsMetricTester();
        ZTSImpl ztsImpl = new ZTSImpl("localhost", store, cloudStore, instanceIdentityStore, metric,
                privateKey, "0", AuditLogFactory.getLogger(), null);

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
        //
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
            assertTrue(ex.getMessage().contains(errMsg));
        }

        // verify no metrics were recorded
        assertEquals(metrixMap.size(), 0);

        // test - failure case - missing domain name in metric data
        //
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errMsg), ex.getMessage());
        }
        // verify no metrics were recorded
        assertEquals(metrixMap.size(), 0);

        // test - failure case - mismatch domain in uri and metric data
        //
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errMsg), ex.getMessage());
        }
        // verify no metrics were recorded
        assertEquals(metrixMap.size(), 0);

        // test - failure case - empty metric list
        //
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
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
            assertTrue(ex.getMessage().contains(errMsg), ex.getMessage());
        }
        // verify no metrics were recorded
        assertEquals(metrixMap.size(), 0);

        // test - failure case - metric count is missing
        //
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
    public void testCompareRoleLists() {
        List<String> list1 = new ArrayList<>();
        List<String> list2 = new ArrayList<>();

        // emtpy sets should match
        
        assertTrue(zts.compareRoleLists(list1, list2));
        
        // not the same size so mismatch
        
        list1.add("role1");
        list1.add("role2");
        
        list2.add("role1");
        
        assertFalse(zts.compareRoleLists(list1, list2));
        
        // same size different values
        
        list2.add("role3");
        
        assertFalse(zts.compareRoleLists(list1, list2));

        // same values in both
        
        list1.add("role3");
        list2.add("role2");
        
        assertTrue(zts.compareRoleLists(list1, list2));
    }
    
    @Test
    public void testValidateRoleCertificateRequestMismatchRole() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        
        List<String> roles = Arrays.asList("writer");
        assertFalse(zts.validateRoleCertificateRequest(certReq, "sports", roles, "sports.scores"));
    }
    
    @Test
    public void testValidateRoleCertificateRequestMismatchEmail() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        
        List<String> roles = Arrays.asList("readers");
        assertFalse(zts.validateRoleCertificateRequest(certReq, "sports", roles, "sports.standings"));
    }
    
    @Test
    public void testValidateRoleCertificateRequestNoEmail() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_noemail.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        
        List<String> roles = Arrays.asList("readers");
        assertTrue(zts.validateRoleCertificateRequest(certReq, "sports", roles, "no-email"));
    }
    
    @Test
    public void testValidateRoleCertificateRequest() throws IOException {
        
        Path path = Paths.get("src/test/resources/valid_email.csr");
        String csr = new String(Files.readAllBytes(path));
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(csr);
        
        List<String> roles = Arrays.asList("readers");
        assertTrue(zts.validateRoleCertificateRequest(certReq, "sports", roles, "sports.scores"));
    }
    
    @Test
    public void testGetRoleTokenCert() throws Exception{

        // this csr is for sports:role.readers role
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(Long.valueOf(3600));
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

        File caCert = new File("src/test/resources/valid_cn_x509.cert");
        X509Certificate caCertificate = Crypto.loadX509Certificate(caCert);
        
        File caKey = new File("src/test/resources/private_encrypted.key");
        PrivateKey caPrivateKey = Crypto.loadPrivateKey(caKey, "athenz");
        CertSigner certSigner = new SelfCertSigner(caPrivateKey, caCertificate);

        CloudStore cloudStore = new MockCloudStore(certSigner);
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
    public void testGetRoleTokenCertInvalidRequests() throws Exception{

        // this csr is for sports:role.readers role
        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_CORETECH_REQUEST).setExpiryTime(Long.valueOf(3600));
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather", "storage", true);
        store.processDomain(signedDomain, false);

        Principal principal = SimplePrincipal.create("user_domain", "user1",
                "v=U1;d=user_domain;n=user;s=signature", 0, null);
        ResourceContext context = createResourceContext(principal);

        // this time we're passing an invalid role name so we should
        // get no accss - 403
        
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
    public void testGetRoleTokenCertMismatchDomain() throws Exception{

        RoleCertificateRequest req = new RoleCertificateRequest()
                .setCsr(ROLE_CERT_DB_REQUEST).setExpiryTime(Long.valueOf(3600));
        
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
    public void testLogPrincipal() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        ResourceContext ctx = zts.newResourceContext(request, null);
        zts.logPrincipal(ctx);
        assertTrue(request.attributes.isEmpty());
        
        Authority principalAuthority = new com.yahoo.athenz.common.server.debug.DebugPrincipalAuthority();
        Principal principal = SimplePrincipal.create("sports", "nhl", "v=S1;d=sports;n=nhl;s=signature",
                0, principalAuthority);
        ResourceContext ctx2 = createResourceContext(principal, request);
        zts.logPrincipal(ctx2);
        assertEquals((String) request.getAttribute(AthenzRequestLog.REQUEST_PRINCIPAL), "sports.nhl");
    }
}
