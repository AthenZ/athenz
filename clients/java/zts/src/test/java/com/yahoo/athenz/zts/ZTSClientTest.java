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
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.impl.SimpleServiceIdentityProvider;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.rdl.Timestamp;

public class ZTSClientTest {

    final private Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();
    private SimpleServiceIdentityProvider siaMockProvider = null;

    @BeforeClass
    public void init() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL,  "5");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE,  "false");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_X509CSR_DN, "ou=eng,o=athenz,c=us");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_X509CSR_DOMAIN, "athenz.cloud");
    }
    
    @AfterMethod
    public void cleanup() {
        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME);
        ZTSClient.initConfigValues();
    }
    
    @BeforeMethod
    public void setup() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        siaMockProvider = Mockito.mock(SimpleServiceIdentityProvider.class);
    }
    
    @Test
    public void testGetHeader() {
        assertEquals(ZTSClient.getHeader(), "Athenz-Role-Auth");
    }
    
    @Test
    public void testLookupZTSUrl() {
        
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient(null, principal);
        assertEquals(client.getZTSUrl(), "https://dev.zts.athenzcompany.com:4443/zts/v1");
        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }
    
    @Test
    public void testLookupZTSUrlInvalidFile() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz_invaild.conf");
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        
        // we have 2 possible values - if no serviceloader is defined then
        // the result is null otherwise we get back default http://localhost:4080/
        // so we'll look for one of those values instead of forcing the tests
        // to be carried out in specific order
        
        String url = client.getZTSUrl();
        if (url != null && !url.equals("http://localhost:4080/zts/v1")) {
            fail();
        }
        client.close();
    }
    
    @Test
    public void testIsExpiredTokenSmallerThanMin() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertTrue(client.isExpiredToken(100, 200, null));
        client.close();
    }
    
    @Test
    public void testIsExpiredTokenBiggerThanMax() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertTrue(client.isExpiredToken(500, null, 300));
        assertTrue(client.isExpiredToken(500, 200, 300));
        client.close();
    }
    
    @Test
    public void testIsExpiredTokenAtLeastOneLimitIsNotNull() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertFalse(client.isExpiredToken(500, null, 600));
        assertFalse(client.isExpiredToken(500, 200, null));
        assertFalse(client.isExpiredToken(500, 200, 501));
        client.close();
    }
    
    @Test
    public void testIsExpiredTokenAtLeastBothLimitsNullSmallerThanMin() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME, "600");
        ZTSClient.initConfigValues();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertTrue(client.isExpiredToken(500, null, null));
        client.close();
    }

    @Test
    public void testIsExpiredTokenAtLeastBothLimitsNullBiggerThanMin() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME, "400");
        ZTSClient.initConfigValues();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertFalse(client.isExpiredToken(500, null, null));
        client.close();
    }
    
    @Test
    public void testGetRoleTokenCacheKeyNullPrincipalCredentials() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                (String) null, PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertNotNull(client.getRoleTokenCacheKey("coretech", null, "TrustDomain"));
        client.close();
    }
    
    @Test
    public void testGetRoleTokenCacheKeyNullRole() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertEquals(client.getRoleTokenCacheKey("coretech", null, null),
                "p=user_domain.user;d=coretech");
        client.close();
    }
    
    @Test
    public void testGetRoleTokenCacheKeyEmptyRole() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertEquals(client.getRoleTokenCacheKey("coretech", "", null),
                "p=user_domain.user;d=coretech");
        client.close();
    }
    
    @Test
    public void testGetRoleTokenCacheKey() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertEquals(client.getRoleTokenCacheKey("coretech", "Role1", "proxy"),
                "p=user_domain.user;d=coretech;r=Role1;u=proxy");
        client.close();
    }
    
    @Test
    public void testGetRoleTokenCacheKeyMultipleRoles() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertEquals(client.getRoleTokenCacheKey("coretech", "writers,admin,readers", "proxyuser"),
                "p=user_domain.user;d=coretech;r=admin,readers,writers;u=proxyuser");
        client.close();
    }
    
    @Test
    public void testLookupAwsCredInCacheNotPresent() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        
        String cacheKey = "p=auth_creds;d=coretech;r=Role1";
        assertNull(client.lookupAwsCredInCache(cacheKey, null, null));
        client.close();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupAwsCredInCacheExpired() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        
        String cacheKey = "p=auth_creds;d=coretech;r=Role1";
        AWSTemporaryCredentials awsCred = new AWSTemporaryCredentials().setAccessKeyId("accesskey")
            .setExpiration(Timestamp.fromMillis((System.currentTimeMillis() / 1000) + 1000L))
            .setSecretAccessKey("secretkey").setSessionToken("sesstoken");
        client.AWS_CREDS_CACHE.put(cacheKey, awsCred);
        
        assertNull(client.lookupAwsCredInCache(cacheKey, 3000, 4000));
        assertNull(client.lookupAwsCredInCache(cacheKey, 500, 800));
        
        client.AWS_CREDS_CACHE.clear();
        client.close();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupAwsCredInCacheSecondClient() {
        
        // test cache with ZTSClient created using a principal object
        //
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient ztsClient = new ZTSClient("http://localhost:4080/", principal);
        String accessKey = "accesskey";
        String secretKey = "secretkey";
        String sessToken = "sesstoken";
        AWSTemporaryCredentials awsCred = new AWSTemporaryCredentials()
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3500000L))
                .setAccessKeyId(accessKey).setSecretAccessKey(secretKey).setSessionToken(sessToken);
        String cacheKey = ztsClient.getRoleTokenCacheKey("coretech", "Role1", null);
        ztsClient.AWS_CREDS_CACHE.put(cacheKey, awsCred);
        assertEquals(cacheKey, "p=user_domain.user;d=coretech;r=Role1");
        AWSTemporaryCredentials cred = ztsClient.lookupAwsCredInCache(cacheKey, 3000, 4000);
        assertTrue(cred.getAccessKeyId().contains(accessKey));
        assertEquals(cred.getSecretAccessKey(), secretKey);
        assertEquals(cred.getSessionToken(), sessToken);
        
        ztsClient.close();

        // rest of tests use ZTSClient object created using domain name and service parameters

        ZTSClient client = new ZTSClient(null, "mytenantdomain", "myservice", siaMockProvider);
        
        String cacheKey1 = client.getRoleTokenCacheKey("mydomain", "Role1", null);
        client.AWS_CREDS_CACHE.put(cacheKey1, awsCred);
        assertNotNull(client.lookupAwsCredInCache(cacheKey1, 3000, 4000));
        
        // add new aws cred for caching

        String cacheKey2 = client.getRoleTokenCacheKey("mydomain", "admin", null);
        AWSTemporaryCredentials awsCredNoTrustDomain = new AWSTemporaryCredentials()
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3500000L))
                .setAccessKeyId("notrustdomaccesskey")
                .setSecretAccessKey(secretKey).setSessionToken(sessToken);
        client.AWS_CREDS_CACHE.put(cacheKey2, awsCredNoTrustDomain);
        assertEquals(cacheKey2, "p=mytenantdomain.myservice;d=mydomain;r=admin");
        assertNotNull(client.lookupAwsCredInCache(cacheKey2, 3000, 4000));

        // now let's get another client - same domain and service as first one
        //
        ZTSClient client1 = new ZTSClient(null, "mytenantdomain", "myservice", siaMockProvider);
        assertNotNull(client1.lookupAwsCredInCache(cacheKey, 3000, 4000));
        assertEquals(client1.lookupAwsCredInCache(cacheKey2, 3000, 4000).getAccessKeyId(), "notrustdomaccesskey");
        
        // now let's get yet another client - different domain and service 
        //
        ZTSClient client2 = new ZTSClient(null, "mytenantdomain2", "myservice2", siaMockProvider);

        // cache still contains aws creds for the following keys
        assertNotNull(client2.lookupAwsCredInCache(cacheKey, 3000, 4000));

        // add new role token to cache using new domain=mydomain2 and new tenant domain=mytenantdomain2 and new service=myservice2
        String cacheKeyNewDomain = client2.getRoleTokenCacheKey("mydomain2", "admin", null);
        AWSTemporaryCredentials awsCredNewDomain = new AWSTemporaryCredentials()
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3500000L))
                .setAccessKeyId("newdomaccesskey")
                .setSecretAccessKey(secretKey).setSessionToken(sessToken);
        client.AWS_CREDS_CACHE.put(cacheKeyNewDomain, awsCredNewDomain);
        assertEquals(cacheKeyNewDomain, "p=mytenantdomain2.myservice2;d=mydomain2;r=admin");
        assertEquals(client2.lookupAwsCredInCache(cacheKeyNewDomain, 3000, 4000).getAccessKeyId(), "newdomaccesskey");

        // set aws cred without specifying role for the key
        //
        String cacheKeyNoRole = client2.getRoleTokenCacheKey("mydomain2", null, null);
        AWSTemporaryCredentials awsCredNoRole = new AWSTemporaryCredentials()
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3500000L))
                .setAccessKeyId("noroleaccesskey")
                .setSecretAccessKey(secretKey).setSessionToken(sessToken);
        client.AWS_CREDS_CACHE.put(cacheKeyNoRole, awsCredNoRole);
        assertEquals(cacheKeyNoRole, "p=mytenantdomain2.myservice2;d=mydomain2");
        assertEquals(client2.lookupAwsCredInCache(cacheKeyNoRole, 3000, 4000).getAccessKeyId(), "noroleaccesskey");

        // now let's get yet another client - specify domain but no service 
        //
        ZTSClient client3 = new ZTSClient(null, "mytenantdomain3", "newservice", siaMockProvider);

        // cache still contains role tokens for the following keys
        assertNotNull(client3.lookupAwsCredInCache(cacheKey, 3000, 4000));

        // token principal field has no service so in sync with ZTSClient
        String cacheKeyNoSvc = client3.getRoleTokenCacheKey("mydomain3", null, null);
        assertEquals(cacheKeyNoSvc, "p=mytenantdomain3.newservice;d=mydomain3");

        client.ROLE_TOKEN_CACHE.clear();
        client.close();
        client1.close();
        client2.close();
        client3.close();
    }
    
    @Test
    public void testLookupRoleTokenInCacheNotPresent() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        
        String cacheKey = "p=auth_creds;d=coretech;r=Role1";
        assertNull(client.lookupRoleTokenInCache(cacheKey, null, null));
        client.close();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupRoleTokenInCacheExpired() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        
        String cacheKey = "p=auth_creds;d=coretech;r=Role1";
        RoleToken roleToken = new RoleToken().setToken("role_token").setExpiryTime((System.currentTimeMillis() / 1000) + 1000L);
        client.ROLE_TOKEN_CACHE.put(cacheKey, roleToken);
        
        assertNull(client.lookupRoleTokenInCache(cacheKey, 3000, 4000));
        assertNull(client.lookupRoleTokenInCache(cacheKey, 500, 800));
        
        client.ROLE_TOKEN_CACHE.clear();
        client.close();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupRoleTokenInCache() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        
        String cacheKey = "p=user_domain.user;d=coretech;r=Role1";
        RoleToken roleToken = new RoleToken().setToken("role_token").setExpiryTime((System.currentTimeMillis() / 1000) + 3500L);
        client.ROLE_TOKEN_CACHE.put(cacheKey, roleToken);
        
        assertNotNull(client.lookupRoleTokenInCache(cacheKey, 3000, 4000));

        Long expiryTime = roleToken.getExpiryTime();
        String token = "v=Z1;d=mydomain;r=admin;p=user_domain.user;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime.toString() + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(token, "admin", null);
        cacheKey = client.getRoleTokenCacheKey("mydomain", "admin", null);
        assertEquals(cacheKey, "p=user_domain.user;d=mydomain;r=admin");
        assertNotNull(client.lookupRoleTokenInCache(cacheKey, 3000, 4000));
        
        client.ROLE_TOKEN_CACHE.clear();
        client.close();
    }

    @SuppressWarnings("static-access")
    @Test
    public void testLookupRoleTokenInCacheSecondClient() {
        
        // test cache with ZTSClient created using a principal object
        //
        
        Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds",
                PRINCIPAL_AUTHORITY);
        ZTSClient ztsClient = new ZTSClient("http://localhost:4080/", principal);
        RoleToken roleToken = new RoleToken().setToken("role_token")
                .setExpiryTime((System.currentTimeMillis() / 1000) + 3500L);
        String coreTechToken = "v=Z1;d=coretech;r=admin;p=user_domain.user;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + roleToken.getExpiryTime() + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(coreTechToken, "Role1", null);
        String cacheKey = ztsClient.getRoleTokenCacheKey("coretech", "Role1", null);
        assertEquals(cacheKey, "p=user_domain.user;d=coretech;r=Role1");
        assertEquals(ztsClient.lookupRoleTokenInCache(cacheKey, 3000, 4000).getToken(), coreTechToken);
        ztsClient.close();

        // rest of tests use ZTSClient object created using domain name and service parameters

        ZTSClient client = new ZTSClient(null, "mytenantdomain", "myservice", siaMockProvider);
        
        String cacheKeyRole1 = client.getRoleTokenCacheKey("mydomain", "Role1", null);
        client.ROLE_TOKEN_CACHE.put(cacheKeyRole1, roleToken);
        
        assertNotNull(client.lookupRoleTokenInCache(cacheKeyRole1, 3000, 4000));
        
        // add new role token to the cache
        //
        Long expiryTime = roleToken.getExpiryTime();
        String token = "v=Z1;d=mydomain;r=admin;p=mytenantdomain.myservice;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime.toString() + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(token, "admin", null);
        String cacherKeyCacher = client.getRoleTokenCacheKey("mydomain", "admin", null);
        assertEquals(cacherKeyCacher, "p=mytenantdomain.myservice;d=mydomain;r=admin");
        assertNotNull(client.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000));

        // now let's get another client - same domain and service as first one
        //
        ZTSClient client1 = new ZTSClient(null, "mytenantdomain", "myservice", siaMockProvider);
        assertNotNull(client1.lookupRoleTokenInCache(cacheKey, 3000, 4000));
        assertNotNull(client1.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000));
        
        // now let's get yet another client - different domain and service 
        //
        ZTSClient client2 = new ZTSClient(null, "mytenantdomain2", "myservice2", siaMockProvider);

        // cache still contains role tokens for the following keys
        assertNotNull(client2.lookupRoleTokenInCache(cacheKey, 3000, 4000));
        assertNotNull(client2.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000));

        // add new role token to cache using new domain=mydomain2 and new tenant domain=mytenantdomain2 and new service=myservice2
        String token2 = "v=Z1;d=mydomain2;r=admin;p=mytenantdomain2.myservice2;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime.toString() + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(token2, "admin", null);
        String cacheKeyNewDomain = client2.getRoleTokenCacheKey("mydomain2", "admin", null);
        assertEquals(cacheKeyNewDomain, "p=mytenantdomain2.myservice2;d=mydomain2;r=admin");
        assertEquals(client2.lookupRoleTokenInCache(cacheKeyNewDomain, 3000, 4000).getToken(), token2);

        // set role token without specifying role for the key
        //
        ZTSClientTokenCacher.setRoleToken(token2, null, null);
        String cacheKeyNoRole = client2.getRoleTokenCacheKey("mydomain2", null, null);
        assertEquals(cacheKeyNoRole, "p=mytenantdomain2.myservice2;d=mydomain2");
        assertEquals(client2.lookupRoleTokenInCache(cacheKeyNoRole, 3000, 4000).getToken(), token2);

        // now let's get yet another client
        //
        ZTSClient client3 = new ZTSClient(null, principal);

        // cache still contains role tokens for the following keys
        assertNotNull(client3.lookupRoleTokenInCache(cacheKey, 3000, 4000));
        assertNotNull(client3.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000));

        String cacheKeyNoSvc = client3.getRoleTokenCacheKey("mydomain3", null, null);
        assertEquals(cacheKeyNoSvc, "p=user_domain.user;d=mydomain3");

        client.ROLE_TOKEN_CACHE.clear();
        client.close();
        client1.close();
        client2.close();
        client3.close();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupRoleTokenServiceProvider() {

        String domName = "svcdomtest";
        Long expiryTime = (System.currentTimeMillis() / 1000) + 3500L;
        String token = "v=Z1;d=" + domName + ";r=admin;p=sports.hockey;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime.toString()
                + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        RoleToken roleToken = new RoleToken().setToken(token).setExpiryTime((System.currentTimeMillis() / 1000) + 3500L);

        java.util.ServiceLoader<ZTSClientService> providers = java.util.ServiceLoader.load(ZTSClientService.class);
        for (ZTSClientService provider: providers) {
            if (provider instanceof ZTSClientServiceProvider) {
                ZTSClientServiceProvider sprov = (ZTSClientServiceProvider) provider;
                sprov.setToken(roleToken, domName, null, null);
                roleToken = null;
                break;
            }
        }
        assertNull(roleToken); // means it found the test service provider

        // now get role token for that domain
        Authority principalAuthority = new PrincipalAuthority();
        Principal principal = SimplePrincipal.create("sports", "hockey",
                "v=S1;d=sports;n=hockey;s=sig", principalAuthority);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        // purposely ignoring cache so 1st thing it will do is check in the providers
        RoleToken rToken = client.getRoleToken(domName, null, null, null, true, null);
        assertNotNull(rToken);

        // not in cache
        String cacheKey = client.getRoleTokenCacheKey(domName, null, null);
        rToken = client.lookupRoleTokenInCache(cacheKey, null, null);
        assertNull(rToken);

        // don't ignore cache so 1st thing it will do is check in the cache
        // before it checks the providers
        rToken = client.getRoleToken(domName, null, null, null, false, null);
        assertNotNull(rToken);

        client.close();
    }
    
    @Test
    public void testUpdateServicePrincipal() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertFalse(client.updateServicePrincipal());
        client.close();
    }

    @Test
    public void testUpdateServicePrincipalException() throws IOException {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.eq("iaas.athenz"),
                Mockito.eq("ci"))).thenThrow(IllegalArgumentException.class);

        ZTSClient client = new ZTSClient("http://localhost:4080/",
                "iaas.athenz", "ci", siaProvider);
        try {
            client.updateServicePrincipal();
            fail();
        } catch (IllegalArgumentException ex) {
        }
        client.close();
    }
    
    @Test
    public void testSameCredentialsAsBeforeNullPrincipal() {
        
        ZTSClient client = new ZTSClient("http://localhost:4080/",
                "iaas.athenz", "ci", siaMockProvider);
        Principal principal = SimplePrincipal.create("user_domain", "user",
                (String) null, PRINCIPAL_AUTHORITY);
        assertFalse(client.sameCredentialsAsBefore(principal));
        client.close();
    }
    
    @Test
    public void testSameCredentialsAsBeforePrincipalNoCreds() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                (String) null, PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        Principal newPrincipal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        assertFalse(client.sameCredentialsAsBefore(newPrincipal));
        client.close();
    }
    
    @Test
    public void testSameCredentialsAsBeforePrincipalDiffCreds1() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds2", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        Principal newPrincipal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        assertFalse(client.sameCredentialsAsBefore(newPrincipal));
        client.close();
    }
    
    @Test
    public void testSameCredentialsAsBeforePrincipalDiffCreds2() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        Principal newPrincipal = SimplePrincipal.create("user_domain", "user",
                "auth_creds2", PRINCIPAL_AUTHORITY);
        assertFalse(client.sameCredentialsAsBefore(newPrincipal));
        client.close();
    }
    
    @Test
    public void testSameCredentialsAsBeforePrincipalSameCreds() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds",
                PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        Principal newPrincipal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        assertTrue(client.sameCredentialsAsBefore(newPrincipal));
        client.close();
    }
    
    @Test
    public void testAddandClearCredentials() {
        
        // add credential
        ZTSClient client = new ZTSClient("http://localhost:4080", "coretech", "storage", siaMockProvider);
        Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds",
                PRINCIPAL_AUTHORITY);
        client.addCredentials(principal);
        assertNotNull(client.principal);
        
        // clear credential
        client.clearCredentials();
        assertNull(client.principal);
        
        client.close();
    }
    
    @Test
    public void testAddPrincipalCredentialsNoSIAReset() {
        
        ZTSClient client = new ZTSClient("http://localhost:4080", "coretech", "storage", siaMockProvider);
        Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds",
                PRINCIPAL_AUTHORITY);
        client.addPrincipalCredentials(principal, false);
        assertNotNull(client);
        client.close();
    }

    @Test
    public void testAddPrincipalCredentialsSIAReset() {
        
        ZTSClient client = new ZTSClient("http://localhost:4080", "coretech", "storage", siaMockProvider);
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        client.addPrincipalCredentials(principal, true);
        assertNotNull(client);
        client.close();
    }
    
    @Test
    public void testConstructorPrincipal() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        assertNotNull(client);
        assertNotNull(client.ztsClient);
        assertEquals(client.principal, principal);
    }
    
    @Test
    public void testConstructorPrincipalAndUrl() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertNotNull(client);
        assertNotNull(client.ztsClient);
        assertEquals(client.principal, principal);
        assertEquals(client.getZTSUrl(), "http://localhost:4080/zts/v1");
    }
    
    @Test
    public void testConstructorServiceWithClients() {
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "coretech",
                "storage", siaMockProvider);
        assertNotNull(client);
        assertNull(client.principal);
    }
    
    @Test
    public void testGetZTSUrlWithTrailingSlash() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertEquals(client.getZTSUrl(), "http://localhost:4080/zts/v1");
        client.close();
    }
    
    @Test
    public void testGetZTSUrlWithoutTrailingSlash() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);
        assertEquals(client.getZTSUrl(), "http://localhost:4080/zts/v1");
        client.close();
    }
    
    @Test
    public void testClientInvalidPort() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:11080/", principal);

        try {
            client.getRoleToken("coretech");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }
    
    @Test
    public void testGetRoleToken() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech");
        assertNotNull(roleToken);
        
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getDomain(), "coretech");
        assertEquals(1, token.getRoles().size());
        assertTrue(token.getRoles().contains("role1"));
        
        // now we're going to get a token again and this time we should get back
        // from our cache thus the same exact one
        
        RoleToken roleToken2 = client.getRoleToken("coretech");
        assertTrue(roleToken2.getToken().equals(roleToken.getToken()));
        
        // now we're going to use the full API to request the token with ignoring from the cache
        // and we should get back a new token
        
        roleToken2 = client.getRoleToken("coretech", null, null, null, true, null);
        assertFalse(roleToken2.getToken().equals(roleToken.getToken()));
        client.close();
    }
    
    @Test
    public void testGetRoleTokenWithSiaProvider() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech");
        assertNotNull(roleToken);
        
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getDomain(), "coretech");
        assertEquals(1, token.getRoles().size());
        assertTrue(token.getRoles().contains("role1"));
        
        // now we're going to get a token again and this time we should get back
        // from our cache thus the same exact one but we're going to use
        // the sia provider instead of principal given
        
        SimpleServiceIdentityProvider siaProvider = Mockito.mock(SimpleServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity("user_domain", "user")).thenReturn(principal);
        
        ZTSClient client2 = new ZTSClient("http://localhost:4080", "user_domain", "user", siaProvider);
        client2.setZTSRDLGeneratedClient(ztsClientMock);
        
        RoleToken roleToken2 = client2.getRoleToken("coretech");
        assertTrue(roleToken2.getToken().equals(roleToken.getToken()));
        
        // now we're going to use the full API to request the token with ignoring from the cache
        // and we should get back a new token
        
        roleToken2 = client2.getRoleToken("coretech", null, null, null, true, null);
        assertFalse(roleToken2.getToken().equals(roleToken.getToken()));
        
        // close our clients
        client.close();
        client2.close();
    }
    
    @Test
    public void testPrefetchRoleTokenShouldNotCallServer() throws Exception {

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);

        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        String domain1 = "coretech";
        String domain2 = "providerdomain";
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null) < 0);
        
        // initialize the prefetch token process.
        client.prefetchRoleToken(domain1, null, null, null, null);
        int scheduledItemsSize = client.getScheduledItemsSize();
        
        // make sure only unique items are in the queue
        client.prefetchRoleToken(domain1, null, null, null, null);
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertTrue(roleToken1 != null);
        long rt1Expiry = roleToken1.getExpiryTime();

        client.prefetchRoleToken(domain2, null, null, null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        RoleToken roleToken2 = client.getRoleToken(domain2);
        assertTrue(roleToken2 != null);
        long rt2Expiry = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_secs=" + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchRoleTokenShouldNotCallServer: sleep Secs=" + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        assertTrue(lastTokenFetchedTime1 > 0);

        roleToken2 = client.getRoleToken(domain2);
        long rt2Expiry2 = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken2:domain="
                + domain2 + " expires at " + rt2Expiry2 + " curtime_secs=" + (System.currentTimeMillis() / 1000));
        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: again sleep Secs=" + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: again nap over so what happened");

        RoleToken roleToken3 = client.getRoleToken(domain2);
        long rt2Expiry3 = roleToken3.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken3:domain="
                + domain2 + " expires at " + rt2Expiry3);
        assertTrue(rt2Expiry3 > rt2Expiry2); // this token was refreshed

        long lastTokenFetchedTime2 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 2 hrs, lastTokenFetchedTime1 & 2 & 3 all should be the same
        // because token is not expired yet.
        assertEquals(lastTokenFetchedTime1, lastTokenFetchedTime2);
        assertEquals(lastTokenFetchedTime3, lastTokenFetchedTime2);
        
        // token should be identical since didnt get refreshed
        RoleToken roleToken1b = client.getRoleToken(domain1);
        long rt1bExpiry = roleToken1b.getExpiryTime();
        assertEquals(rt1Expiry, rt1bExpiry);
        assertEquals(roleToken1.getToken(), roleToken1b.getToken());
        
        // But, make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.removePrefetcher();
        client.close();
    }

    @Test
    public void testPrefetchRoleTokenWithUserDataShouldNotCallServer() throws Exception {
        System.out.println("testPrefetchRoleTokenShouldNotCallServer");

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        
        final Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        String domain1 = "coretech";
        String domain2 = "providerdomain";
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, "user_domain.userdata1") < 0);
        
        // initialize the prefetch token process.
        client.prefetchRoleToken(domain1, null, null, null, "user_domain.userdata1");
        int scheduledItemsSize = client.getScheduledItemsSize();
        
        // make sure only unique items are in the queue
        client.prefetchRoleToken(domain1, null, null, null, "user_domain.userdata1");
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        RoleToken roleToken1 = client.getRoleToken(domain1, null, null, null, false,
                "user_domain.userdata1");
        assertTrue(roleToken1 != null);
        long rt1Expiry = roleToken1.getExpiryTime();

        client.prefetchRoleToken(domain2, null, null, null, "user_domain.userdata2");
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        RoleToken roleToken2 = client.getRoleToken(domain2, null, null, null, false,
                "user_domain.userdata2");
        assertTrue(roleToken2 != null);
        long rt2Expiry = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_secs="
                + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchRoleTokenShouldNotCallServer: sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1,
                null, "user_domain.userdata1");
        assertTrue(lastTokenFetchedTime1 > 0);

        roleToken2 = client.getRoleToken(domain2, null, null, null, false, "user_domain.userdata2");
        long rt2Expiry2 = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken2:domain="
                + domain2 + " expires at " + rt2Expiry2 + " curtime_secs="
                + (System.currentTimeMillis() / 1000));
        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: again sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: again nap over so what happened");

        RoleToken roleToken3 = client.getRoleToken(domain2, null, null, null,
                false, "user_domain.userdata2");
        assertTrue(roleToken3.getToken().contains(";proxy=user_domain.userdata2;"));
        long rt2Expiry3 = roleToken3.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken3:domain="
                + domain2 + " expires at " + rt2Expiry3);
        assertTrue(rt2Expiry3 > rt2Expiry2); // this token was refreshed

        long lastTokenFetchedTime2 = ztsClientMock.getLastRoleTokenFetchedTime(domain1,
                null, "user_domain.userdata1");
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1,
                null, "user_domain.userdata1");
        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 2 hrs, lastTokenFetchedTime1 & 2 & 3 all should be the same
        // because token is not expired yet.
        assertEquals(lastTokenFetchedTime1, lastTokenFetchedTime2);
        assertEquals(lastTokenFetchedTime3, lastTokenFetchedTime2);
        
        // token should be identical since didnt get refreshed
        RoleToken roleToken1b = client.getRoleToken(domain1, null, null, null, false,
                "user_domain.userdata1");
        assertTrue(roleToken1b.getToken().contains(";proxy=user_domain.userdata1;"));
        long rt1bExpiry = roleToken1b.getExpiryTime();
        assertEquals(rt1Expiry, rt1bExpiry);
        assertEquals(roleToken1.getToken(), roleToken1b.getToken());
        
        // But, make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.removePrefetcher();
        client.close();
    }
    
    @Test
    public void testPrefetchAwsCredShouldNotCallServer() throws Exception {
        System.out.println("testPrefetchAwsCredShouldNotCallServer");

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        
        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user" , siaProvider);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        String domain1 = "coretech";
        String domain2 = "providerdomain";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain2, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain2, "role2");
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null) < 0);
        
        // initialize the prefetch token process.
        client.prefetchAwsCred(domain1, "role1", null, null);
        int scheduledItemsSize = client.getScheduledItemsSize();
        
        // make sure only unique items are in the queue
        client.prefetchAwsCred(domain1, "role1", null, null);
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertTrue(awsCred1 != null);
        long rt1Expiry = awsCred1.getExpiration().millis();

        client.prefetchAwsCred(domain2, "role1", null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        AWSTemporaryCredentials awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1");
        assertTrue(awsCred2 != null);
        long rt2Expiry = awsCred2.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_millis="
                + System.currentTimeMillis());

        System.out.println("testPrefetchAwsCredShouldNotCallServer: sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldNotCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        assertTrue(lastTokenFetchedTime1 > 0);

        awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1");
        long rt2Expiry2 = awsCred2.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred2:domain="
                + domain2 + " expires at " + rt2Expiry2 + " curtime_millis="
                + System.currentTimeMillis());
        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchAwsCredShouldNotCallServer: again sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldNotCallServer: again nap over so what happened");

        AWSTemporaryCredentials awsCred3 = client.getAWSTemporaryCredentials(domain2, "role1");
        long rt2Expiry3 = awsCred3.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred3:domain="
                + domain2 + " expires at " + rt2Expiry3);
        assertTrue(rt2Expiry3 > rt2Expiry2); // this token was refreshed

        long lastTokenFetchedTime2 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 2 hrs, lastTokenFetchedTime1 & 2 & 3 all should be the same
        // because token is not expired yet.
        assertEquals(lastTokenFetchedTime1, lastTokenFetchedTime2);
        assertEquals(lastTokenFetchedTime3, lastTokenFetchedTime2);
        
        // token should be identical since didnt get refreshed
        AWSTemporaryCredentials awsCred1b = client.getAWSTemporaryCredentials(domain1, "role1");
        long rt1bExpiry = awsCred1b.getExpiration().millis();
        assertEquals(rt1Expiry, rt1bExpiry);
        assertEquals(awsCred1.getSessionToken(), awsCred1b.getSessionToken());
        
        // But, make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.prefetchAwsCred(domain2, "role2", null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 2);

        AWSTemporaryCredentials awsCred4 = client.getAWSTemporaryCredentials(domain2, "role2");
        assertTrue(awsCred4 != null);
        long rtExpiry3 = awsCred4.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred4:domain="
                + domain2 + " role=role2 expires at " + rtExpiry3 + " curtime_millis="
                + System.currentTimeMillis());

        lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain2, "role2", null);
        assertTrue(lastTokenFetchedTime3 > lastTokenFetchedTime2);
        
        AWSTemporaryCredentials awsCred5 = client.getAWSTemporaryCredentials(domain2, "role1");
        assertTrue(awsCred5 != null);
        assertNotEquals(awsCred4.getAccessKeyId(), awsCred5.getAccessKeyId());
        
        client.removePrefetcher();
        client.close();
    }
    
    @Test
    public void testPrefetchShouldNotCallServer() throws Exception {
        System.out.println("testPrefetchShouldNotCallServer");

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        
        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        String domain1 = "coretech";
        String domain2 = "providerdomain";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain2, "role1");
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null) < 0);
        
        // initialize the prefetch token process.
        client.prefetchRoleToken(domain1, null, null, null, null);
        int scheduledItemsSize = client.getScheduledItemsSize();
        
        // make sure only unique items are in the queue
        client.prefetchRoleToken(domain1, null, null, null, null);
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);
        
        // repeat for aws cred
        //
        client.prefetchAwsCred(domain1, "role1", null, null);
        scheduledItemsSize = client.getScheduledItemsSize();
        assertTrue(scheduledItemsSize > scheduledItemsSize2);
        
        // make sure only unique items are in the queue
        client.prefetchAwsCred(domain1, "role1", null, null);
        scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);
        
        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertTrue(awsCred1 != null);
        long awsCredExpiryd1r1 = awsCred1.getExpiration().millis();

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertTrue(roleToken1 != null);
        long rt1Expiry = roleToken1.getExpiryTime();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        long lastTokenFetchedTime1nr = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        
        // work with domain2
        //
        client.prefetchRoleToken(domain2, null, null, null, null);
        scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize2, scheduledItemsSize + 1);
        
        client.prefetchAwsCred(domain2, "role1", null, null);
        scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize2, scheduledItemsSize + 2);

        RoleToken roleToken2 = client.getRoleToken(domain2);
        assertTrue(roleToken2 != null);
        long rt2Expiry = roleToken2.getExpiryTime();
        
        AWSTemporaryCredentials awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1");
        assertTrue(awsCred2 != null);
        long awsCredExpiry = awsCred2.getExpiration().millis();
                
        System.out.println("testPrefetchShouldNotCallServer: sleep Secs=" + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchShouldNotCallServer: nap over so what happened");
        
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 2);
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTimeDom2 = ztsClientMock.getLastRoleTokenFetchedTime(domain2, null, null);
        assertTrue(lastTokenFetchedTimeDom2 > 0);

        roleToken2 = client.getRoleToken(domain2);
        long rt2Expiry2 = roleToken2.getExpiryTime();
        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed
        
        awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1");
        long awsCredExpiry2 = awsCred2.getExpiration().millis();
        assertTrue(awsCredExpiry2 > awsCredExpiry); // this cred was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: again sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchShouldNotCallServer: again nap over so what happened");
        
        RoleToken roleToken3 = client.getRoleToken(domain2);
        long rt2Expiry3 = roleToken3.getExpiryTime();
        System.out.println("testPrefetchShouldNotCallServer: roleToken3:domain="
                + domain2 + " expires at " + rt2Expiry3);
        assertTrue(rt2Expiry3 > rt2Expiry2); // this token was refreshed
        
        AWSTemporaryCredentials awsCred3 = client.getAWSTemporaryCredentials(domain2, "role1");
        long awsCredExpiry3 = awsCred3.getExpiration().millis();
        assertTrue(awsCredExpiry3 > awsCredExpiry2); // this cred was refreshed

        long lastTokenFetchedTimed1r1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);

        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 2 hrs, lastTokenFetchedTime1 & 2 & 3 all should be the same
        // because token is not expired yet.
        assertEquals(lastTokenFetchedTime1, lastTokenFetchedTimed1r1);
        assertEquals(lastTokenFetchedTime3, lastTokenFetchedTime1nr);
        
        // token should be identical since didnt get refreshed
        RoleToken roleToken1b = client.getRoleToken(domain1);
        long rt1bExpiry = roleToken1b.getExpiryTime();
        assertEquals(rt1Expiry, rt1bExpiry);
        assertEquals(roleToken1.getToken(), roleToken1b.getToken());
        
        // aws cred should be identical since didnt get refreshed
        AWSTemporaryCredentials awsCred1b = client.getAWSTemporaryCredentials(domain1, "role1");
        long ac1bExpiry = awsCred1b.getExpiration().millis();
        assertEquals(awsCredExpiryd1r1, ac1bExpiry);
        assertEquals(awsCred1.getSessionToken(), awsCred1b.getSessionToken());
        
        // But, make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.removePrefetcher();
        client.close();
    }

    @Test
    public void testPrefetchRoleTokenShouldCallServer() throws Exception {
        System.out.println("testPrefetchRoleTokenShouldCallServer");
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        String domain1 = "coretech";
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null) < 0);

        // initialize the prefetch token process.
        client.prefetchRoleToken(domain1, null, null, null, null);
        // make sure only unique items are in the queue
        assertEquals(client.getScheduledItemsSize(), 1);

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertTrue(roleToken1 != null);
        long rtExpiry = roleToken1.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldCallServer: roleToken1:domain="
                + domain1 + " expires at " + rtExpiry + " curtime_secs="
                + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchRoleTokenShouldCallServer: sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchRoleTokenShouldCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), 1);
        
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        roleToken1 = client.getRoleToken(domain1);
        long rtExpiry2 = roleToken1.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldCallServer: roleToken1:domain="
                + domain1 + " expires at " + rtExpiry2 + " curtime_secs="
                + (System.currentTimeMillis() / 1000));
        assertTrue(rtExpiry2 > rtExpiry); // this token was refreshed

        assertTrue(lastTokenFetchedTime1 > 0);

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchRoleTokenShouldCallServer: again sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchRoleTokenShouldCallServer: again nap over so what happened");

        long lastTokenFetchedTime2 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        RoleToken roleToken2 = client.getRoleToken(domain1);
        long rt2Expiry = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldCallServer: roleToken2:domain="
                + domain1 + " expires at " + rt2Expiry + " curtime_secs="
                + (System.currentTimeMillis() / 1000));
        assertTrue(rt2Expiry > rtExpiry2); // this token was refreshed

        // token should be different
        assertNotEquals(roleToken1.getToken(), roleToken2.getToken());
        
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        
        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 5 seconds,
        // lastTokenFetchedTime1 & 2 & 3 all should be different,
        assertNotEquals(lastTokenFetchedTime1, lastTokenFetchedTime2);
        assertNotEquals(lastTokenFetchedTime3, lastTokenFetchedTime2);
        
        // make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.removePrefetcher();
        client.close();
    }
    
    @Test
    public void testPrefetchAwsCredShouldCallServer() throws Exception {
        System.out.println("testPrefetchAwsCredShouldCallServer");
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        String domain1 = "coretech";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role2");
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null) < 0);

        // initialize the prefetch token process.
        client.prefetchAwsCred(domain1, "role1", null, null);
        // make sure only unique items are in the queue
        long scheduledItemsSize = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, 1);

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertTrue(awsCred1 != null);
        long rtExpiry = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: awsCred1:domain=" + domain1
                    + " expires at " + rtExpiry + " curtime_millis=" + System.currentTimeMillis());

        System.out.println("testPrefetchAwsCredShouldCallServer: sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), 1);
        
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        long rtExpiry2 = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: roleToken1:domain=" + domain1
                    + " expires at " + rtExpiry2 + " curtime_millis=" + System.currentTimeMillis());
        assertTrue(rtExpiry2 > rtExpiry); // this token was refreshed

        assertTrue(lastTokenFetchedTime1 > 0);

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchAwsCredShouldCallServer: again sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldCallServer: again nap over so what happened");

        long lastTokenFetchedTime2 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        AWSTemporaryCredentials awsCred2 = client.getAWSTemporaryCredentials(domain1, "role1");
        long rt2Expiry = awsCred2.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: awsCred2:domain=" + domain1
                    + " expires at " + rt2Expiry + " curtime_millis=" + System.currentTimeMillis());
        assertTrue(rt2Expiry > rtExpiry2); // this token was refreshed

        // token should be different
        assertNotEquals(awsCred1.getSessionToken(), awsCred2.getSessionToken());
        
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        
        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 5 seconds,
        // lastTokenFetchedTime1 & 2 & 3 all should be different,
        assertNotEquals(lastTokenFetchedTime1, lastTokenFetchedTime2);
        assertNotEquals(lastTokenFetchedTime3, lastTokenFetchedTime2);
        
        // make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.prefetchAwsCred(domain1, "role2", null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        AWSTemporaryCredentials awsCred4 = client.getAWSTemporaryCredentials(domain1, "role2");
        assertTrue(awsCred4 != null);
        long rtExpiry3 = awsCred4.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: awsCred4:domain=" + domain1
                + " role=role2 expires at " + rtExpiry3 + " curtime_millis="
                + System.currentTimeMillis());

        lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role2", null);
        assertTrue(lastTokenFetchedTime3 > lastTokenFetchedTime2);
        
        AWSTemporaryCredentials awsCred5 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertTrue(awsCred5 != null);
        assertNotEquals(awsCred4.getAccessKeyId(), awsCred5.getAccessKeyId());
        
        client.removePrefetcher();
        client.close();
    }
    
    @Test
    public void testPrefetchShouldCallServer() throws Exception {
        System.out.println("testPrefetchShouldCallServer");
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.<String>any(),
                Mockito.<String>any())).thenReturn(principal);
        
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        String domain1 = "coretech";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        
        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null) < 0);
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null) < 0);
        
        // initialize the prefetch token process.
        client.prefetchRoleToken(domain1, null, null, null, null);
        // make sure only unique items are in the queue
        assertEquals(client.getScheduledItemsSize(), 1);
        
        // initialize the prefetch aws processing
        client.prefetchAwsCred(domain1, "role1", null, null);
        assertEquals(client.getScheduledItemsSize(), 2);

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertTrue(roleToken1 != null);
        long rtExpiry = roleToken1.getExpiryTime();
        System.out.println("testPrefetchShouldCallServer: roleToken1:domain=" + domain1 +
                " expires at " + rtExpiry + " curtime_secs=" + (System.currentTimeMillis() / 1000));

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertTrue(awsCred1 != null);
        long awsExpiry = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchShouldCallServer: awsCred1:domain=" + domain1 + " expires at "
                + awsExpiry + " curtime_millis=" + System.currentTimeMillis());
        assertEquals(client.getScheduledItemsSize(), 2);
        
        System.out.println("testPrefetchShouldCallServer: sleep Secs=" + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchShouldCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), 2);
        
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        roleToken1 = client.getRoleToken(domain1);
        long rtExpiry2 = roleToken1.getExpiryTime();
        System.out.println("testPrefetchShouldCallServer: roleToken1:domain=" + domain1 +
                " expires at " + rtExpiry2 + " curtime_secs=" + (System.currentTimeMillis() / 1000));
        assertTrue(rtExpiry2 > rtExpiry); // this token was refreshed

        assertTrue(lastTokenFetchedTime1 > 0);
        
        long lastTokenFetchedTime1aws = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        AWSTemporaryCredentials awsCredLast = client.getAWSTemporaryCredentials(domain1, "role1");
        long awsExpiry2 = awsCredLast.getExpiration().millis();
        System.out.println("testPrefetchShouldCallServer: awsCred1:domain="
                + domain1 + " expires at "
                + awsExpiry2 + " curtime_millis=" + System.currentTimeMillis());
        assertTrue(awsExpiry2 > awsExpiry); // this token was refreshed

        assertTrue(lastTokenFetchedTime1aws > 0);

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchShouldCallServer: again sleep Secs="
                + (2*intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchShouldCallServer: again nap over so what happened");

        long lastTokenFetchedTime2 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        long lastTokenFetchedTime2aws = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);

        RoleToken roleToken2 = client.getRoleToken(domain1);
        long rt2Expiry = roleToken2.getExpiryTime();
        System.out.println("testPrefetchShouldCallServer: roleToken2:domain="
                + domain1 + " expires at "
                + rt2Expiry + " curtime_secs=" + (System.currentTimeMillis() / 1000));
        assertTrue(rt2Expiry > rtExpiry2); // this token was refreshed

        // token should be different
        assertNotEquals(roleToken1.getToken(), roleToken2.getToken());
        
        long lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);
        
        AWSTemporaryCredentials awsCred3 = client.getAWSTemporaryCredentials(domain1, "role1");
        long awsExpiry3 = awsCred3.getExpiration().millis();
        System.out.println("testPrefetchShouldCallServer: awsCred3:domain="
                + domain1 + " expires at "
                + awsExpiry3 + " curtime_millis=" + System.currentTimeMillis());
        assertTrue(awsExpiry3 > awsExpiry2); // this token was refreshed

        // token should be different
        assertNotEquals(awsCredLast.getSessionToken(), awsCred3.getSessionToken());
        
        long lastTokenFetchedTime3aws = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        
        long lastTimerTriggered2 = ZTSClient.FETCHER_LAST_RUN_AT.get();
        
        // Since token should be good for 5 seconds,
        // lastTokenFetchedTime1 & 2 & 3 all should be different,
        assertNotEquals(lastTokenFetchedTime1, lastTokenFetchedTime2);
        assertNotEquals(lastTokenFetchedTime3, lastTokenFetchedTime2);
        
        assertNotEquals(lastTokenFetchedTime1aws, lastTokenFetchedTime2aws);
        assertNotEquals(lastTokenFetchedTime3aws, lastTokenFetchedTime2aws);
        
        // make sure the Timer actually triggered.
        assertTrue(lastTimerTriggered1 > 0);
        assertTrue(lastTimerTriggered2 > 0);
        assertNotEquals(lastTimerTriggered1, lastTimerTriggered2);
        assertTrue(lastTimerTriggered2 > lastTimerTriggered1);
        
        client.removePrefetcher();
        client.close();
    }
    
    @Test
    public void testGetHostServices() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        HostServices hostServices = client.getHostServices("host.exist");
        
        assertEquals(hostServices.getHost(), "host.exist");
        assertEquals(hostServices.getNames().size(), 2);
        
        try {
            client.getHostServices("not.exist.host");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        client.close();
    }
    
    @Test
    public void testGetPublicKeyEntry() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        PublicKeyEntry publicKeyEntry = client.getPublicKeyEntry("coretech", "storage", "key1");
        assertEquals(publicKeyEntry.getId(), "key1");
        assertEquals(publicKeyEntry.getKey(), "test-key");
        
        try {
            client.getPublicKeyEntry("invalid.domain", "storage", "key1");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        client.close();
    }
    
    @Test
    public void testGetServiceIdentity() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        ServiceIdentity serviceIdentity = client.getServiceIdentity("coretech", "storage");
        assertEquals(serviceIdentity.getName(), "storage");
        
        try {
            client.getServiceIdentity("unknown.domain", "storage");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        client.close();
    }
    
    @Test
    public void testGetServiceIdentityList() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        ServiceIdentityList serviceIdentityList = client.getServiceIdentityList("coretech");
        assertEquals(serviceIdentityList.getNames(), Arrays.asList("storage"));
        
        try {
            client.getServiceIdentityList("unknown.domain");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }
        
        client.close();
    }
    
    @Test
    public void testGetRoleTokenName() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech", "role1");
        assertNotNull(roleToken);
        
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("role1"));
        
        try {
            roleToken = client.getRoleToken("coretech", "role2");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }
        client.close();
    }
    
    @Test
    public void testGetRoleTokenSuffixInvalid() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        try {
            client.getRoleToken("coretech", null);
            fail();
        } catch (IllegalArgumentException ex) {
            // expected exception
            assertTrue(true);
        } catch (Exception ex) {
            fail();
        }
        
        try {
            client.getRoleToken("coretech", "");
            fail();
        } catch (IllegalArgumentException ex) {
            // expected exception
            assertTrue(true);
        } catch (Exception ex) {
            fail();
        }
        client.close();
    }
    
    @Test
    public void testGetRoleTokenCacheExpire() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.removePrefetcher();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech");
        assertNotNull(roleToken);
        
        // now we're going to get a token again without any expiry timeouts and this time
        // we should get back from our cache thus the same exact one
        
        RoleToken roleToken2 = client.getRoleToken("coretech");
        assertTrue(roleToken2.getToken().equals(roleToken.getToken()));
        
        // now we're going to use the full API to request the token with timeouts
        // that should satisfy the expiry time and thus get back the same one
        
        roleToken2 = client.getRoleToken("coretech", null, 1800, 3600, false);
        assertTrue(roleToken2.getToken().equals(roleToken.getToken()));
        
        // this time we're going to ask for an increased min expiry time
        // thus the cache should no longer be satisfied
        
        roleToken2 = client.getRoleToken("coretech", null, 2800, 3600, false);
        assertFalse(roleToken2.getToken().equals(roleToken.getToken()));
        client.close();
    }
    
    @Test
    public void testGetDomainSignedPolicyDataNull() {
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
         
        Map<String, List<String>> responseHeaders = new HashMap<>();
        DomainSignedPolicyData domainSignedPolicyData =
                client.getDomainSignedPolicyData("coretech", null, responseHeaders);
        assertNull(domainSignedPolicyData);
        client.close();
    }
    
    @Test
    public void testGetDomainSignedPolicyData() {
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setPolicyName("policy1");
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
         
        Map<String, List<String>> responseHeaders = new HashMap<>();
        DomainSignedPolicyData domainSignedPolicyData =
                client.getDomainSignedPolicyData("coretech", null, responseHeaders);
        assertNotNull(domainSignedPolicyData);
        
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        assertNotNull(signedPolicyData);
        assertEquals(signedPolicyData.getZmsSignature(), "zmsSignature");
        assertEquals(signedPolicyData.getZmsKeyId(), "0");
        
        try {
            client.getDomainSignedPolicyData(null, null, responseHeaders);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        PolicyData policyData = signedPolicyData.getPolicyData();
        assertNotNull(policyData);
        assertEquals(policyData.getDomain(), "coretech");
        
        List<Policy> policyList = policyData.getPolicies();
        assertNotNull(policyList);
        assertEquals(policyList.size(), 1);
        assertEquals(policyList.get(0).getName(), "policy1");
        client.close();
    }
    
    @Test
    public void testGetTenantDomains() {
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        List<String> tenantDomains = new ArrayList<>();
        tenantDomains.add("iaas.athenz");
        tenantDomains.add("coretech.storage");
        ztsClientMock.setTenantDomains(tenantDomains);
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
         
        TenantDomains doms = client.getTenantDomains("provider", "user", "admin", "storage");
        assertNotNull(doms);
        assertTrue(doms.getTenantDomainNames().contains("iaas.athenz"));
        assertTrue(doms.getTenantDomainNames().contains("coretech.storage"));
        
        try {
            client.getTenantDomains("unknown", "user", "admin", "storage");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        } catch (Exception ex) {
            fail();
        }
        
        client.close();
    }

    @Test
    public void testGetAWSTemporaryCredentials() {
        
        Timestamp currentTime = Timestamp.fromCurrentTime();
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setAwsCreds(currentTime, "coretech", "role", "sessionToken",
                "secretAccessKey", "accessKeyId");
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
         
        AWSTemporaryCredentials awsCreds = client.getAWSTemporaryCredentials("coretech", "role");
        assertNotNull(awsCreds);
        assertEquals("accessKeyId", awsCreds.getAccessKeyId());
        assertEquals("secretAccessKey", awsCreds.getSecretAccessKey());
        assertTrue(awsCreds.getSessionToken().startsWith("sessionToken"));
        currentTime = awsCreds.getExpiration();
        
        AWSTemporaryCredentials awsCreds2 = client.getAWSTemporaryCredentials("coretech", "role");
        assertNotNull(awsCreds2);
        assertEquals("accessKeyId", awsCreds2.getAccessKeyId());
        assertEquals("secretAccessKey", awsCreds2.getSecretAccessKey());
        assertTrue(awsCreds2.getSessionToken().startsWith("sessionToken"));
        assertEquals(currentTime.millis() / 1000, awsCreds2.getExpiration().millis() / 1000);
        
        // now let's try with invalid domain/role values;
        
        assertNull(client.getAWSTemporaryCredentials("coretech", "role1"));
        assertNull(client.getAWSTemporaryCredentials("coretech1", "role"));
        
        client.close();
    }
    
    @Test
    public void testGetAWSTemporaryCredentialsException() {
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
         
        try {
            client.getAWSTemporaryCredentials("coretech", "role");
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }

        client.close();
    }
    
    @Test
    public void testHostnameVerifierSupport() {
        
        ZTSRDLGeneratedClientMock client = new ZTSRDLGeneratedClientMock("http://localhost:4080", null);
        assertNull(client.getHostnameVerifier());

        HostnameVerifier hostnameVerifier = new ZTSClientTest.TestHostVerifier();
        client = new ZTSRDLGeneratedClientMock("http://localhost:4080", null, hostnameVerifier);
        assertNotNull(client.getHostnameVerifier());
    }
    
    @Test
    public void testHostnamVerifierDnsMatchStandard() {
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = client.new AWSHostNameVerifier("host1");
        
        ArrayList<List<?>> altNames = new ArrayList<>();
        ArrayList<Object> rfcName = new ArrayList<>();
        rfcName.add(Integer.valueOf(1));
        rfcName.add("rfcname");
        altNames.add(rfcName);
        
        ArrayList<Object> dnsName = new ArrayList<>();
        dnsName.add(Integer.valueOf(2));
        dnsName.add("host1");
        altNames.add(dnsName);
        
        assertTrue(hostnameVerifier.matchDnsHostname(altNames));
        
        ArrayList<List<?>> altNames2 = new ArrayList<>();
        ArrayList<Object> rfcName2 = new ArrayList<>();
        rfcName2.add(Integer.valueOf(1));
        rfcName2.add("rfcname");
        altNames2.add(rfcName2);
        
        ArrayList<Object> dnsName2 = new ArrayList<>();
        dnsName2.add(Integer.valueOf(2));
        dnsName2.add("host11");
        altNames2.add(dnsName2);
        
        assertFalse(hostnameVerifier.matchDnsHostname(altNames2));

        client.close();
    }
    
    @Test
    public void testHostnamVerifierDnsMatchWildcard() {
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = client.new AWSHostNameVerifier("*.host1");
        
        ArrayList<List<?>> altNames = new ArrayList<>();
        ArrayList<Object> rfcName = new ArrayList<>();
        rfcName.add(Integer.valueOf(1));
        rfcName.add("rfcname");
        altNames.add(rfcName);
        
        ArrayList<Object> dnsName = new ArrayList<>();
        dnsName.add(Integer.valueOf(2));
        dnsName.add("*.host1");
        altNames.add(dnsName);
        
        assertTrue(hostnameVerifier.matchDnsHostname(altNames));
        
        ArrayList<List<?>> altNames2 = new ArrayList<>();
        ArrayList<Object> rfcName2 = new ArrayList<>();
        rfcName2.add(Integer.valueOf(1));
        rfcName2.add("rfcname");
        altNames2.add(rfcName2);
        
        ArrayList<Object> dnsName2 = new ArrayList<>();
        dnsName2.add(Integer.valueOf(2));
        dnsName2.add("*.host11");
        altNames2.add(dnsName2);
        
        assertFalse(hostnameVerifier.matchDnsHostname(altNames2));

        client.close();
    }
    
    @Test
    public void testHostnamVerifierDnsMatchNone() {
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = client.new AWSHostNameVerifier("host1");
        
        ArrayList<List<?>> altNames = new ArrayList<>();
        ArrayList<Object> rfcName = new ArrayList<>();
        rfcName.add(Integer.valueOf(1));
        rfcName.add("rfcname");
        altNames.add(rfcName);
        
        ArrayList<Object> dnsName = new ArrayList<>();
        dnsName.add(Integer.valueOf(3));
        dnsName.add("host1");
        altNames.add(dnsName);
        
        assertFalse(hostnameVerifier.matchDnsHostname(altNames));
        client.close();
    }
    
    @Test
    public void testHostnamVerifierDnsNull() {
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = client.new AWSHostNameVerifier("host1");
        
        assertFalse(hostnameVerifier.matchDnsHostname(null));
        client.close();
    }
    
    private static class TestHostVerifier implements HostnameVerifier {
        
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }
    
    @Test
    public void testPostInstanceRefreshRequest() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRefreshRequest req = new InstanceRefreshRequest().setExpiryTime(600);
        Identity identity = client.postInstanceRefreshRequest("coretech", "unit", req);
        assertNotNull(identity);
        assertNotNull(identity.getServiceToken());
        client.close();
    }
    
    @Test
    public void testPostInstanceRefreshRequestException() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRefreshRequest req = new InstanceRefreshRequest().setExpiryTime(600);
        try {
            client.postInstanceRefreshRequest("exc", "unit", req);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        client.close();
    }
    
    @Test
    public void testGetRoleTokenWithUserData() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech", null, null, null,
                true, "user_domain.user4");
        assertNotNull(roleToken);
        
        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getDomain(), "coretech");
        assertEquals(1, token.getRoles().size());
        assertTrue(token.getRoles().contains("role1"));
        assertEquals(token.getProxyUser(), "user_domain.user4");

        client.close();
    }
    
    @Test
    public void testGetRoleAccess() {
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        RoleAccess roleAccess = client.getRoleAccess("coretech", "user.joe");
        List<String> roles = roleAccess.getRoles();
        assertEquals(roles.size(), 2);
        assertTrue(roles.contains("role1"));
        
        try {
            client.getRoleAccess("exc", "user.joe");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        try {
            client.getRoleAccess("unknown", "user.joe");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }
        client.close();
    }
    
    @Test
    public void testGetAccess() {
    
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
         
        Access access = client.getAccess("coretech", "match", "user_domain.user1");
        assertTrue(access.getGranted());
        
        access = client.getAccess("coretech", "no-match", "user_domain.user1");
        assertFalse(access.getGranted());
        
        try {
            client.getAccess("exc", "match", "user_domain.user1");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        client.close();
    }
    
    @Test
    public void testGetResourceAccess() {
    
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        
        ResourceAccess access = client.getResourceAccess("access", "resource", null, null);
        assertTrue(access.getGranted());
        
        access = client.getResourceAccess("access", "resource1", null, null);
        assertFalse(access.getGranted());
        
        try {
            client.getResourceAccess("exc", "resource", null, null);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        client.close();
    }
    
    @Test
    public void testPostDomainMetrics() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        List<DomainMetric> metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(99));
        DomainMetrics req = new DomainMetrics().
            setDomainName("coretech").
            setMetricList(metricList);
        client.postDomainMetrics("coretech", req);
        client.close();
    }
    
    @Test
    public void testPostDomainMetricsBadRequest() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        List<DomainMetric> metricList = new ArrayList<>();
        metricList.add(
            new DomainMetric().
                setMetricType(DomainMetricType.ACCESS_ALLOWED_DENY_NO_MATCH).
                setMetricVal(99));
        DomainMetrics req = new DomainMetrics().
            setDomainName("coretech").
            setMetricList(metricList);
        try {
            client.postDomainMetrics("exc", req);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        client.close();
    }
    
    @Test
    public void testPrefetchInterval() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setPrefetchInterval(10L);
        assertEquals(client.getPrefetchInterval(), 10l);
        
        client.close();
    }
    
    @Test
    public void testException() {
        
        List<Integer> codes = Arrays.asList(200, 201, 202, 204, 301, 302, 303, 304
                ,307, 400, 401, 403, 404, 409, 410, 412, 415, 500, 501, 503);
        
        for (int code : codes) {
            ResourceException e = new ResourceException(code);
            assertNotNull(e.getData());
        }
        
        ResourceException ex = new ResourceException(400);
        
        assertEquals(ex.getCode(), 400);
        assertEquals(ex.getData().toString(), "{code: 400, message: \"Bad Request\"}");
    }
    
    @Test
    public void testHostNameVerifierVerifyCertNull() throws SSLPeerUnverifiedException {
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = client.new AWSHostNameVerifier("host1");
        
        SSLSession session = Mockito.mock(SSLSession.class);
        Mockito.when(session.getPeerCertificates()).thenReturn(null);
        
        assertFalse(hostnameVerifier.verify("host1", session));
        
        System.out.println("hashCode:" + client.hashCode());
        
        client.close();
    }
    
    
    final static String crlf = System.getProperty("line.separator");
    final static String test_cert =
            "-----BEGIN CERTIFICATE-----"+crlf
            + "MIIDRDCCAiwCCQDltWO9Xjhd8DANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJK"+crlf
            + "UDEOMAwGA1UECBMFVG9reW8xEjAQBgNVBAcTCVN1bWlkYS1rdTEPMA0GA1UEChMG"+crlf
            + "WUpURVNUMQ8wDQYDVQQLEwZZSlRFU1QxDzANBgNVBAMTBllKVEVTVDAeFw0xNjEx"+crlf
            + "MTEwODMzMTVaFw0yNjExMDkwODMzMTVaMGQxCzAJBgNVBAYTAkpQMQ4wDAYDVQQI"+crlf
            + "EwVUb2t5bzESMBAGA1UEBxMJU3VtaWRhLWt1MQ8wDQYDVQQKEwZZSlRFU1QxDzAN"+crlf
            + "BgNVBAsTBllKVEVTVDEPMA0GA1UEAxMGWUpURVNUMIIBIjANBgkqhkiG9w0BAQEF"+crlf
            + "AAOCAQ8AMIIBCgKCAQEA1Ssz+hLCTXyMlDH9E0bd9EEm0yNyPH4XhtUkSEDdYE+Z"+crlf
            + "0m/7BkfrKTRRew8wrfpLkK0wZsoVkEjwd0GktZXnGTRUs42Bd5tSYXV1Z78oqjS4"+crlf
            + "AGpjkQlQva+f6ANnDhPNxHJ6QlY6DLePIByjepmJS8UZGRuNPiDpbtWWhuCLbn6p"+crlf
            + "to2SiclLHr6K/5uFYjawS8k3bGmoV9QfeWvY+aiGvuxDsPCxcePpwSA8btubpTsJ"+crlf
            + "CvC31rJChgN5VQFE26vfhVCwmuhwOCcUThdgaI9LAjLETknrLt/kiFaiIhm5peSG"+crlf
            + "t0DP89u9fnaUX7P8jc/4V57lnp+ynRpGpHfv4Fi4wQIDAQABMA0GCSqGSIb3DQEB"+crlf
            + "BQUAA4IBAQARH92fKPsVoCq80ARt70LM8ynaq9dlXcLjr34CWINbGbXG4a0RP1l9"+crlf
            + "bFZih7rCG96W+fDKxvgR2YwXhRJq5NchOoBB0mtOBG3VwbXFNm6CBHqwtbrNiPzv"+crlf
            + "BvK7jerZd1g0CgTWzfoPgO/87F2uX5J92CsvXRYrDJsFYHnhmUg3JWCT4q+Xe9J4"+crlf
            + "/Eyw+C1DgDwWjjBB1Qb3QBO/dpGR+EWv4mtNK8D2o+iEFJLjtNdqIkcrUIXfqI8M"+crlf
            + "z+7Tph5eLFgI5lEW+Pu/myzLIXCNWoRr7UQute898v/1XZiRS4sSCEQSgXnZflA8"+crlf
            + "c2KrYjMGSUogzw6+1gKeucygV32rA2B2"+crlf
            + "-----END CERTIFICATE-----";
    
    @Test
    public void testHostNameVerifierVerifyCert() throws CertificateException, IOException {
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = client.new AWSHostNameVerifier("host1");
                
        InputStream is = new ByteArrayInputStream(test_cert.getBytes("utf-8"));
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate cert = cf.generateCertificate(is);
        is.close();
        
        Certificate[] certs = new Certificate[1]; certs[0] = cert;
        
        SSLSession session = Mockito.mock(SSLSession.class);
        Mockito.when(session.getPeerCertificates()).thenReturn(certs);
        
        assertFalse(hostnameVerifier.verify("unknown", session));
        client.close();
    }
    
    @Test
    public void testPostRoleCertificateRequest() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleCertificateRequest req = new RoleCertificateRequest().setCsr("csr");
        RoleToken roleToken = client.postRoleCertificateRequest("coretech", "role1", req);
        assertNotNull(roleToken);
        
        try {
            client.postRoleCertificateRequest("exc", "no-role", req);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        try {
            client.postRoleCertificateRequest("good-domain", "no-role", req);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }
        client.close();
    }
    
    @Test
    public void testGenerateRoleCertificateRequest() {
        
        File privkey = new File("./src/test/resources/test_private_k0.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(privkey);

        RoleCertificateRequest req = ZTSClient.generateRoleCertificateRequest("coretech",
                "test", "sports", "readers", privateKey, "aws", 3600);
        assertNotNull(req);
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(req.getCsr());
        assertEquals("sports:role.readers", Crypto.extractX509CSRCommonName(certReq));
        assertEquals("coretech.test@aws.athenz.cloud", Crypto.extractX509CSREmail(certReq));
    }
    
    @Test
    public void testGenerateInstanceRefreshRequestTopDomain() {
        
        File privkey = new File("./src/test/resources/test_private_k0.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(privkey);

        InstanceRefreshRequest req = ZTSClient.generateInstanceRefreshRequest("coretech",
                "test", privateKey, "aws", 3600);
        assertNotNull(req);
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(req.getCsr());
        assertEquals("coretech.test", Crypto.extractX509CSRCommonName(certReq));
        assertEquals("test.coretech.aws.athenz.cloud", Crypto.extractX509CSRDnsNames(certReq).get(0));
    }
    
    @Test
    public void testGenerateInstanceRefreshRequestSubDomain() {
        
        File privkey = new File("./src/test/resources/test_private_k0.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(privkey);

        InstanceRefreshRequest req = ZTSClient.generateInstanceRefreshRequest("coretech.system",
                "test", privateKey, "aws", 3600);
        assertNotNull(req);
        
        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(req.getCsr());
        assertEquals("coretech.system.test", Crypto.extractX509CSRCommonName(certReq));

        X500Name x500name = certReq.getSubject();
        RDN cnRdn = x500name.getRDNs(BCStyle.CN)[0];
        assertEquals("coretech.system.test", IETFUtils.valueToString(cnRdn.getFirst().getValue()));
        assertEquals("test.coretech-system.aws.athenz.cloud", Crypto.extractX509CSRDnsNames(certReq).get(0));
    }
    
    @Test
    public void testPostInstanceRegisterInformationRequest() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("good-instance-document")
                .setCsr("x509-csr").setDomain("athenz")
                .setProvider("openstack.provider")
                .setService("storage").setToken(false);
        Map<String, List<String>> responseHeaders = new HashMap<>();
        InstanceIdentity identity = client.postInstanceRegisterInformation(info, responseHeaders);
        assertNotNull(identity);
        assertNotNull(identity.getX509Certificate(), "x509");
        assertEquals(identity.getName(), "athenz.storage");
        
        client.close();
    }
    
    @Test
    public void testPostInstanceRegisterInformationRequestException() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRegisterInformation info = new InstanceRegisterInformation()
                .setAttestationData("bad-instance-document")
                .setCsr("x509-csr").setDomain("athenz")
                .setProvider("openstack.provider")
                .setService("storage").setToken(false);
        Map<String, List<String>> responseHeaders = new HashMap<>();
        try {
            client.postInstanceRegisterInformation(info, responseHeaders);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        client.close();
    }
    
    @Test
    public void testPostInstanceRefreshInformationRequest() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr("good-x509-csr").setToken(false);
        InstanceIdentity identity = client.postInstanceRefreshInformation("openstack.provider",
                "athenz", "storage", "instance-id", info);
        assertNotNull(identity);
        assertNotNull(identity.getX509Certificate(), "x509");
        assertEquals(identity.getName(), "athenz.storage");
        
        client.close();
    }
    
    @Test
    public void testPostInstanceRefreshInformationRequestException() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setCsr("bad-x509-csr").setToken(false);
        try {
            client.postInstanceRefreshInformation("openstack.provider",
                    "athenz", "storage", "instance-id", info);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }
        
        client.close();
    }
    
    @Test
    public void testDeleteInstanceIdentity() {
        
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        
        ZTSClientMock ztsClientMock = new ZTSClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        client.deleteInstanceIdentity("openstack.provider", "athenz", "storage", "instance-id");
        
        try {
            client.deleteInstanceIdentity("openstack.provider", "athenz", "storage", "bad-instance-id");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }
    
    @Test
    public void testMultipleRoleKey() {
        
        assertNull(ZTSClient.multipleRoleKey(null));
        
        List<String> roles = new ArrayList<>();
        assertNull(ZTSClient.multipleRoleKey(roles));
        
        roles.add("role");
        assertEquals(ZTSClient.multipleRoleKey(roles), "role");
        
        roles.add("one");
        roles.add("apple");
        roles.add("yellow");
        roles.add("ones");
        
        assertEquals(ZTSClient.multipleRoleKey(roles), "apple,one,ones,role,yellow");
    }
}
