/**
 * Copyright 2017 Yahoo Inc.
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
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.fail;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.InstanceProviderClient;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zts.InstanceProviderManager;
import com.yahoo.athenz.zts.InstanceProviderManager.ProviderScheme;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.store.ChangeLogStore;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.store.impl.MockZMSFileChangeLogStore;
import com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStore;
import com.yahoo.rdl.Timestamp;

public class InstanceProviderManagerTest {

    PrivateKey privateKey = null;
    DataStore store = null;
    
    static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    static final String ZTS_PRIVATE_KEY = "src/test/resources/zts_private.pem";
    
    @BeforeClass
    public void setUpClass() throws Exception {
        System.setProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTSConsts.ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
    }
    
    @BeforeMethod
    public void setup() {

        // we want to make sure we start we clean dir structure

        ZMSFileChangeLogStore.deleteDirectory(new File(ZTS_DATA_STORE_PATH));

        File privKeyFile = new File(ZTS_PRIVATE_KEY);
        String privKey = Crypto.encodedFile(privKeyFile);
        
        privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        ChangeLogStore structStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                privateKey, "0");
        
        System.setProperty(ZTSConsts.ZTS_PROP_PROVIDER_ENDPOINTS, ".athenz2.com,.athenz.com");
        
        store = new DataStore(structStore, null);
    }

    @AfterMethod
    public void shutdown() {
        ZMSFileChangeLogStore.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
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
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech");
        assertNull(client);
    }
    
    @Test
    public void testGetHttpsProvider() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNotNull(client);
        client.close();
    }
    
    @Test
    public void testGetHttpsProviderUnknownProvider() {

        
        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNotNull(client);
        client.close();
    }
    
    @Test
    public void testGetClassProvider() {

        SignedDomain signedDomain = createSignedDomainClassEndpoint("coretech", "weather", true, true);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNotNull(client);
        client.close();
    }
    
    @Test
    public void testGetProviderClientInvalidDomain() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech2.weather");
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientInvalidService() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, true);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather2");
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientNoEndpoint() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", true, false);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientInvalidEndpoint() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather",
                true, true, "http://invalid");
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientInvalidEndpointParse() {

        SignedDomain signedDomain = createSignedDomain("coretech", "weather",
                true, true, "://test.athenz.com/");
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNull(client);
    }
    
    @Test
    public void testGetProviderClientNoServices() {

        SignedDomain signedDomain = createSignedDomainHttpsEndpoint("coretech", "weather", false, true);
        store.processDomain(signedDomain, false);
        
        InstanceProviderManager provider = new InstanceProviderManager(store);
        InstanceProvider client = provider.getProvider("coretech.weather");
        assertNull(client);
    }
    
    @Test
    public void testInstanceProviderClient() {
        InstanceProviderClient client = new InstanceProviderClient("https://localhost:8443");
        assertNotNull(client);
        
        client = client.setProperty("Property", "Value");
        assertNotNull(client);
        
        client = client.addCredentials("Header", "token");
        assertNotNull(client);
        
        client.close();
    }
    
    @Test
    public void testGetProviderScheme() throws URISyntaxException {

        InstanceProviderManager provider = new InstanceProviderManager(null);

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
        
        InstanceProviderManager provider = new InstanceProviderManager(null);
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
        
//        uri = new URI("\ninvalid\turi-format");
//        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

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
        
//        uri = new URI("://test.athenz.com/");
//        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("//test.athenz.com/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("test://test.athenz.com:4443/");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);

        uri = new URI("uri://test.athenz.com:4443/test1");
        assertEquals(provider.getProviderEndpointScheme(uri), ProviderScheme.UNKNOWN);
    }
    
    @Test
    public void testGetClassInstance() {

        InstanceProviderManager providerManager = new InstanceProviderManager(null);
        InstanceProvider provider = providerManager.getClassInstance("unknown.class");
        assertNull(provider);
        
        provider = providerManager.getClassInstance("com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        assertNotNull(provider);

        // we should get this from the cache now
        
        provider = providerManager.getClassInstance("com.yahoo.athenz.instance.provider.impl.InstanceAWSProvider");
        assertNotNull(provider);
        
        // some invalid class name
        
        provider = providerManager.getClassInstance("com.yahoo.athenz.unknown.class");
        assertNull(provider);
        
        // class name that doesn't implement expected interface
        
        try {
            providerManager.getClassInstance("com.yahoo.athenz.zts.ZTSConsts");
            fail();
        } catch (Exception ex) {
        }
    }
    
    @Test
    public void testVerifyProviderEndpoint() {
        InstanceProviderManager providerManager = new InstanceProviderManager(null);
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz.com"));
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz2.com"));
        assertFalse(providerManager.verifyProviderEndpoint("test1.athenz3.com"));
        
        // now let's remove our config in which case all is true
        
        providerManager.providerEndpoints = Collections.emptyList();
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz.com"));
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz2.com"));
        assertTrue(providerManager.verifyProviderEndpoint("test1.athenz3.com"));
    }
}
