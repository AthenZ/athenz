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

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.MockZMSFileChangeLogStore;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.InstanceProviderManager.ProviderScheme;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.rdl.Timestamp;

import javax.net.ssl.SSLContext;

public class InstanceProviderManagerTest {

    private PrivateKey privateKey = null;
    private Metric ztsMetric = null;
    private DataStore store = null;
    
    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String ZTS_PRIVATE_KEY = "src/test/resources/unit_test_zts_private.pem";
    
    @BeforeClass
    public void setUpClass() {
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");

        // setup our metric class

        ztsMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();
    }
    
    @BeforeMethod
    public void setup() {

        // we want to make sure we start we clean dir structure

        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        File privKeyFile = new File(ZTS_PRIVATE_KEY);
        String privKey = Crypto.encodedFile(privKeyFile);
        
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        System.setProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS, ".athenz2.com,.athenz.com");
        
        store = new DataStore(structStore, null, ztsMetric);
    }

    @AfterMethod
    public void shutdown() {
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        System.clearProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS);
    }
    
    private SignedDomain createSignedDomainClassEndpoint(String domainName, String serviceName,
            boolean includeService, boolean includeEndPoint) {
        return createSignedDomain(domainName, serviceName, includeService,
                includeEndPoint, "class://com.yahoo.athenz.zts.InstanceTestClassProvider");
    }
    
    private SignedDomain createSignedDomainHttpsEndpoint(String domainName, String serviceName,
            boolean includeService, boolean includeEndPoint) {
        return createSignedDomain(domainName, serviceName, includeService,
                includeEndPoint, "https://provider.athenz.com:4443");
    }
    
    private SignedDomain createSignedDomain(String domainName, String serviceName,
            boolean includeService, boolean includeEndPoint, String endPoint) {
        
        SignedDomain signedDomain = new SignedDomain();
        
        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.adminuser"));
        role.setRoleMembers(members);
        roles.add(role);
        
        List<ServiceIdentity> services = new ArrayList<>();
        ServiceIdentity service = new ServiceIdentity();
        service.setName(domainName + "." + serviceName);
            
        if (includeEndPoint) {
            service.setProviderEndpoint(endPoint);
        }
        services.add(service);
        
        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":instance");
        assertion.setAction("read");
        assertion.setRole(domainName + ":role.admin");
        
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        
        policy.setAssertions(assertions);
        policy.setName(domainName + ":policy.test");
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
        if (includeService) {
            domain.setServices(services);
        }
        domain.setPolicies(signedPolicies);
        domain.setModified(Timestamp.fromCurrentTime());
        
        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), privateKey));
        signedDomain.setKeyId("0");
        
        return signedDomain;
    }
    
    @Test
    public void testGetHttpsProviderInvalidName() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech", null);
        assertNull(client);
    }
    
    @Test
    public void testGetHttpsProvider() throws NoSuchAlgorithmException {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, SSLContext.getDefault(),
                null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", null);
        assertNotNull(client);
        client.close();
    }
    
    @Test
    public void testGetHttpsProviderUnknownProvider() throws NoSuchAlgorithmException {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, SSLContext.getDefault(),
                null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather2", null);
        assertNull(client);
    }
    
    @Test
    public void testGetClassProvider() {

        SignedDomain signedDomain = createSignedDomainClassEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", new HostnameResolver(){});
        assertNotNull(client);
        client.close();
    }

    @Test
    public void testGetClassProviderForZTS() {

        SignedDomain signedDomain = createSignedDomainClassEndpoint("sys.auth", "zts", true, true);
        store.processSignedDomain(signedDomain, false);

        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        ServerPrivateKey serverPrivateKey = new ServerPrivateKey(privateKey, "0");
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null,
                serverPrivateKey, null, null, null);
        InstanceProvider client = provider.getProvider("sys.auth.zts", new HostnameResolver(){});
        assertNotNull(client);
        client.close();
    }

    @Test
    public void testGetClassProviderException() {

        SignedDomain signedDomain = createSignedDomainClassEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);

        System.setProperty("athenz.instance.test.class.exception", "true");
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", new HostnameResolver(){});
        assertNull(client);
        System.clearProperty("athenz.instance.test.class.exception");
    }

    @Test
    public void testGetProviderClientInvalidDomain() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech2.weather", null);
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientInvalidService() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather2", null);
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientNoEndpoint() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, false);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", null);
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientInvalidEndpoint() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather",
                true, true, "http://invalid");
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", null);
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientInvalidEndpointParse() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather",
                true, true, "://test.athenz.com/");
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", null);
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientNoServices() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", false, true);
        store.processSignedDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store, null, null, null, null, null, null);
        InstanceProvider client = provider.getProvider("coretech.weather", null);
        assertNull(client);
    }
    
    @Test
    public void testGetProviderScheme() throws URISyntaxException {

        InstanceProviderManager provider = new InstanceProviderManager(null, null, null, null, null, null, null);

        URI uri = new URI("https://test.athenz2.com/");
        assertEquals(provider.getProviderScheme(uri), ProviderScheme.HTTPS);
        
        uri = new URI("class://com.yahoo.athenz.AWSProvider");
        assertEquals(provider.getProviderScheme(uri), ProviderScheme.CLASS);
        
        uri = new URI("http://test.athenz2.com/");
        assertEquals(provider.getProviderScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("ftp://test.athenz2.com/");
        assertEquals(provider.getProviderScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("test.athenz2.com/");
        assertEquals(provider.getProviderScheme(uri), ProviderScheme.UNKNOWN);
    }
    
    @Test
    public void testGetProviderEndpointScheme() throws URISyntaxException {
        
        InstanceProviderManager provider = new InstanceProviderManager(null, null, null, null, null, null, null);
        URI uri = new URI("https://test.athenz2.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.HTTPS);
        
        uri = new URI("https://test.athenz2.com:4443/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.HTTPS);
        
        uri = new URI("https://test.athenz2.com:4443/test1");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.HTTPS);
        
        uri = new URI("class://com.yahoo.athenz.AWSProvider");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.CLASS);

        uri = new URI("http://test.athenz.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("https://test.athenz4.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("http://test.athenz.com:4443/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("http://test.athenz.com:4443/test1");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("http://:4443?key=value");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("http://test.athenz3.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("http://test.athenz3.com:4443/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("http://test.athenz3.com:4443/test1");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
        
        uri = new URI("test.athenz.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("file://test.athenz.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("//test.athenz.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("test://test.athenz.com:4443/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("uri://test.athenz.com:4443/test1");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
    }
    
    @Test
    public void testGetClassInstance() {
        HostnameResolver hostnameResolver = new HostnameResolver(){};

        InstanceProviderManager providerManager = new InstanceProviderManager(null, null, null, null, null, null, null);
        InstanceProvider provider = providerManager.getClassProvider("unknown.class", "provider", null,  hostnameResolver);
        assertNull(provider);
        
        provider = providerManager.getClassProvider("com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider",
                "provider", null, hostnameResolver);
        assertNotNull(provider);

        provider = providerManager.getClassProvider("com.yahoo.athenz.instance.provider.impl.InstanceAWSECSProvider",
                "provider", null, hostnameResolver);
        assertNotNull(provider);

        provider = providerManager.getClassProvider("com.yahoo.athenz.instance.provider.impl.InstanceAWSLambdaProvider",
                "provider", null, hostnameResolver);
        assertNotNull(provider);

        // we should get this from the cache now
        
        provider = providerManager.getClassProvider("com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider",
                "provider", null, hostnameResolver);
        assertNotNull(provider);
        
        // some invalid class name
        
        provider = providerManager.getClassProvider("com.yahoo.athenz.unknown.class", "provider",
                null, hostnameResolver);
        assertNull(provider);
        
        // class name that doesn't implement expected interface

        providerManager.getClassProvider("com.yahoo.athenz.zts.ZTSConsts", "provider", null, hostnameResolver);
        assertNull(provider);
    }
    
    @Test
    public void testVerifyProviderEndpoint() {
        InstanceProviderManager providerManager = new InstanceProviderManager(null, null, null, null, null, null, null);
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz.com"));
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz2.com"));
        assertFalse(providerManager.verifyProviderEndpoint("test1.athenz3.com"));
        
        // now let's remove our config in which case all is true
        
        providerManager.providerEndpoints = Collections.emptyList();
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz.com"));
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz2.com"));
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz3.com"));
    }

    @Test
    public void testGetProviderEndpoint() throws URISyntaxException {
        InstanceProviderManager providerManager = new InstanceProviderManager(null, null, null, null, null, null, null);

        String providerEndpoint = "https://test.athenz2.com/";
        URI uri = new URI(providerEndpoint);
        assertEquals(providerManager.getProviderEndpoint(uri, false, providerEndpoint), providerEndpoint);

        providerEndpoint = "https://athenz.client@test.athenz2.com/";
        uri = new URI(providerEndpoint);
        assertEquals(providerManager.getProviderEndpoint(uri, true, providerEndpoint), "https://test.athenz2.com/");

        providerEndpoint = "https://athenz.client%82@test.athenz2.com/";
        uri = new URI(providerEndpoint);
        assertEquals(providerManager.getProviderEndpoint(uri, true, providerEndpoint), "https://test.athenz2.com/");
    }

    @Test
    public void testGetSSLContext() {

        SSLContext serverContext = Mockito.mock(SSLContext.class);
        SSLContext clientContext = Mockito.mock(SSLContext.class);

        // when both are specified, the appropriate context is returned

        InstanceProviderManager providerManager = new InstanceProviderManager(null, serverContext, clientContext,
                null, null, null, null);
        assertEquals(providerManager.getSSLContext(true), clientContext);
        assertEquals(providerManager.getSSLContext(false), serverContext);

        // if client is only specified then we get that for both values

        providerManager = new InstanceProviderManager(null, null, clientContext, null, null, null, null);
        assertEquals(providerManager.getSSLContext(true), clientContext);
        assertEquals(providerManager.getSSLContext(false), clientContext);

        // if server is only specified then we get that for both values

        providerManager = new InstanceProviderManager(null, serverContext, null, null, null, null, null);
        assertEquals(providerManager.getSSLContext(true), serverContext);
        assertEquals(providerManager.getSSLContext(false), serverContext);
    }
}
