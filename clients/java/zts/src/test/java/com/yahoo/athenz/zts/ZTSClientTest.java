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

import static com.yahoo.athenz.zts.AccessTokenTestFileHelper.setupInvalidTokenFile;
import static com.yahoo.athenz.zts.AccessTokenTestFileHelper.setupTokenFile;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.*;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.impl.SimpleServiceIdentityProvider;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.rdl.Timestamp;

import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

public class ZTSClientTest {

    final private Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();
    private SimpleServiceIdentityProvider siaMockProvider = null;

    @BeforeClass
    public void init() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5");
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "false");
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
        ZTSClient.initConfigValues();
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
        assertTrue(ZTSClient.isExpiredToken(100, 200, null, 900));
    }

    @Test
    public void testIsExpiredTokenBiggerThanMax() {
        // we allow 300 sec offset
        assertFalse(ZTSClient.isExpiredToken(500, null, 300, 900));
        assertTrue(ZTSClient.isExpiredToken(650, null, 300, 900));
        assertTrue(ZTSClient.isExpiredToken(650, 200, 300, 900));
    }

    @Test
    public void testIsExpiredTokenAtLeastOneLimitIsNotNull() {
        assertFalse(ZTSClient.isExpiredToken(500, null, 600, 900));
        assertFalse(ZTSClient.isExpiredToken(500, 200, null, 900));
        assertFalse(ZTSClient.isExpiredToken(500, 200, 501, 900));
    }

    @Test
    public void testIsExpiredTokenAtLeastBothLimitsNullSmallerThanMin() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME, "600");
        ZTSClient.initConfigValues();
        assertTrue(ZTSClient.isExpiredToken(500, null, null, 600));
    }

    @Test
    public void testIsExpiredTokenAtLeastBothLimitsNullBiggerThanMin() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_TOKEN_MIN_EXPIRY_TIME, "400");
        ZTSClient.initConfigValues();
        assertFalse(ZTSClient.isExpiredToken(500, null, null, 400));
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
        ZTSClient.ROLE_TOKEN_CACHE.clear();

        String cacheKey = "p=auth_creds;d=coretech;r=Role1";
        assertNull(client.lookupRoleTokenInCache(cacheKey, null, null, 900));
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

        assertNull(client.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900));
        assertNull(client.lookupRoleTokenInCache(cacheKey, 300, 600, 900));

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

        assertNotNull(client.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900));

        long expiryTime = roleToken.getExpiryTime();
        String token = "v=Z1;d=mydomain;r=admin;p=user_domain.user;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(token, "admin");
        cacheKey = client.getRoleTokenCacheKey("mydomain", "admin", null);
        assertEquals(cacheKey, "p=user_domain.user;d=mydomain;r=admin");
        assertNotNull(client.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900));

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
        ZTSClientTokenCacher.setRoleToken(coreTechToken, "Role1");
        String cacheKey = ztsClient.getRoleTokenCacheKey("coretech", "Role1", null);
        assertEquals(cacheKey, "p=user_domain.user;d=coretech;r=Role1");
        assertEquals(ztsClient.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900).getToken(), coreTechToken);
        ztsClient.close();

        // rest of tests use ZTSClient object created using domain name and service parameters

        ZTSClient client = new ZTSClient(null, "mytenantdomain", "myservice", siaMockProvider);

        String cacheKeyRole1 = client.getRoleTokenCacheKey("mydomain", "Role1", null);
        client.ROLE_TOKEN_CACHE.put(cacheKeyRole1, roleToken);

        assertNotNull(client.lookupRoleTokenInCache(cacheKeyRole1, 3000, 4000, 900));

        // add new role token to the cache
        //
        long expiryTime = roleToken.getExpiryTime();
        String token = "v=Z1;d=mydomain;r=admin;p=mytenantdomain.myservice;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(token, "admin");
        String cacherKeyCacher = client.getRoleTokenCacheKey("mydomain", "admin", null);
        assertEquals(cacherKeyCacher, "p=mytenantdomain.myservice;d=mydomain;r=admin");
        assertNotNull(client.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000, 900));

        // now let's get another client - same domain and service as first one
        //
        ZTSClient client1 = new ZTSClient(null, "mytenantdomain", "myservice", siaMockProvider);
        assertNotNull(client1.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900));
        assertNotNull(client1.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000, 900));

        // now let's get yet another client - different domain and service 
        //
        ZTSClient client2 = new ZTSClient(null, "mytenantdomain2", "myservice2", siaMockProvider);

        // cache still contains role tokens for the following keys
        assertNotNull(client2.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900));
        assertNotNull(client2.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000, 900));

        // add new role token to cache using new domain=mydomain2 and new tenant domain=mytenantdomain2 and new service=myservice2
        String token2 = "v=Z1;d=mydomain2;r=admin;p=mytenantdomain2.myservice2;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        ZTSClientTokenCacher.setRoleToken(token2, "admin");
        String cacheKeyNewDomain = client2.getRoleTokenCacheKey("mydomain2", "admin", null);
        assertEquals(cacheKeyNewDomain, "p=mytenantdomain2.myservice2;d=mydomain2;r=admin");
        assertEquals(client2.lookupRoleTokenInCache(cacheKeyNewDomain, 3000, 4000, 900).getToken(), token2);

        // set role token without specifying role for the key
        //
        ZTSClientTokenCacher.setRoleToken(token2, null);
        String cacheKeyNoRole = client2.getRoleTokenCacheKey("mydomain2", null, null);
        assertEquals(cacheKeyNoRole, "p=mytenantdomain2.myservice2;d=mydomain2");
        assertEquals(client2.lookupRoleTokenInCache(cacheKeyNoRole, 3000, 4000, 900).getToken(), token2);

        // now let's get yet another client
        //
        ZTSClient client3 = new ZTSClient(null, principal);

        // cache still contains role tokens for the following keys
        assertNotNull(client3.lookupRoleTokenInCache(cacheKey, 3000, 4000, 900));
        assertNotNull(client3.lookupRoleTokenInCache(cacherKeyCacher, 3000, 4000, 900));

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
        long expiryTime = (System.currentTimeMillis() / 1000) + 3500L;
        String token = "v=Z1;d=" + domName + ";r=admin;p=sports.hockey;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" + expiryTime
                + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24bCw5Hm7AP9dUQkmkwNfX2bPhVXyhdRkOlbttF4exJm9V571sJXid6vsihgopCdxqW_qA--";
        RoleToken roleToken = new RoleToken().setToken(token).setExpiryTime((System.currentTimeMillis() / 1000) + 3500L);

        java.util.ServiceLoader<ZTSClientService> providers = java.util.ServiceLoader.load(ZTSClientService.class);
        for (ZTSClientService provider : providers) {
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        // purposely ignoring cache so 1st thing it will do is check in the providers
        RoleToken rToken = client.getRoleToken(domName, null, null, null, true, null);
        assertNotNull(rToken);

        // not in cache
        String cacheKey = client.getRoleTokenCacheKey(domName, null, null);
        rToken = client.lookupRoleTokenInCache(cacheKey, null, null, 900);
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
    public void testUpdateServicePrincipalException() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(Mockito.eq("iaas.athenz"),
                Mockito.eq("ci"))).thenThrow(IllegalArgumentException.class);

        ZTSClient client = new ZTSClient("http://localhost:4080/",
                "iaas.athenz", "ci", siaProvider);
        try {
            client.updateServicePrincipal();
            fail();
        } catch (IllegalArgumentException ignored) {
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
        assertEquals(roleToken2.getToken(), roleToken.getToken());

        // now we're going to use the full API to request the token with ignoring from the cache
        // and we should get back a new token

        roleToken2 = client.getRoleToken("coretech", null, null, null, true, null);
        assertNotEquals(roleToken2.getToken(), roleToken.getToken());
        client.close();
    }

    @Test
    public void testGetRoleTokenWithSiaProvider() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
        assertEquals(roleToken2.getToken(), roleToken.getToken());

        // now we're going to use the full API to request the token with ignoring from the cache
        // and we should get back a new token

        roleToken2 = client2.getRoleToken("coretech", null, null, null, true, null);
        assertNotEquals(roleToken2.getToken(), roleToken.getToken());

        // close our clients
        client.close();
        client2.close();
    }

    @Test
    public void testPrefetchRoleTokenShouldNotCallServer() throws Exception {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);

        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

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
        assertNotNull(roleToken1);
        long rt1Expiry = roleToken1.getExpiryTime();

        client.prefetchRoleToken(domain2, null, null, null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        RoleToken roleToken2 = client.getRoleToken(domain2);
        assertNotNull(roleToken2);
        long rt2Expiry = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_secs=" + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchRoleTokenShouldNotCallServer: sleep Secs=" + (2 * intervalSecs) + "+0.1");
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
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: again sleep Secs=" + (2 * intervalSecs) + "+0.1");
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

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchRoleTokenWithUserDataShouldNotCallServer() throws Exception {
        System.out.println("testPrefetchRoleTokenShouldNotCallServer");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);

        final Principal principal = SimplePrincipal.create("user_domain", "user", "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

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
        assertNotNull(roleToken1);
        long rt1Expiry = roleToken1.getExpiryTime();

        client.prefetchRoleToken(domain2, null, null, null, "user_domain.userdata2");
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        RoleToken roleToken2 = client.getRoleToken(domain2, null, null, null, false,
                "user_domain.userdata2");
        assertNotNull(roleToken2);
        long rt2Expiry = roleToken2.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldNotCallServer: roleToken2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_secs="
                + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchRoleTokenShouldNotCallServer: sleep Secs="
                + (2 * intervalSecs) + "+0.1");
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
                + (2 * intervalSecs) + "+0.1");
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

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchAwsCredShouldNotCallServer() throws Exception {
        System.out.println("testPrefetchAwsCredShouldNotCallServer");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);

        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        String domain1 = "coretech";
        String domain2 = "providerdomain";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain2, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain2, "role2");

        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null) < 0);

        // initialize the prefetch token process.
        client.prefetchAwsCreds(domain1, "role1", null, null, null);
        int scheduledItemsSize = client.getScheduledItemsSize();

        // make sure only unique items are in the queue
        client.prefetchAwsCreds(domain1, "role1", null, null, null);
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertNotNull(awsCred1);
        long rt1Expiry = awsCred1.getExpiration().millis();

        client.prefetchAwsCreds(domain2, "role1", null, null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        AWSTemporaryCredentials awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1", false);
        assertNotNull(awsCred2);
        long rt2Expiry = awsCred2.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_millis="
                + System.currentTimeMillis());

        System.out.println("testPrefetchAwsCredShouldNotCallServer: sleep Secs="
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2 * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldNotCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);
        long lastTimerTriggered1 = ZTSClient.FETCHER_LAST_RUN_AT.get();

        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        assertTrue(lastTokenFetchedTime1 > 0);

        awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1", null, null, null);
        long rt2Expiry2 = awsCred2.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred2:domain="
                + domain2 + " expires at " + rt2Expiry2 + " curtime_millis="
                + System.currentTimeMillis());
        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchAwsCredShouldNotCallServer: again sleep Secs="
                + (2 * intervalSecs) + "+0.1");
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

        client.prefetchAwsCreds(domain2, "role2", null, null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 2);

        AWSTemporaryCredentials awsCred4 = client.getAWSTemporaryCredentials(domain2, "role2");
        assertNotNull(awsCred4);
        long rtExpiry3 = awsCred4.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldNotCallServer: awsCred4:domain="
                + domain2 + " role=role2 expires at " + rtExpiry3 + " curtime_millis="
                + System.currentTimeMillis());

        lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain2, "role2", null);
        assertTrue(lastTokenFetchedTime3 > lastTokenFetchedTime2);

        AWSTemporaryCredentials awsCred5 = client.getAWSTemporaryCredentials(domain2, "role1");
        assertNotNull(awsCred5);
        assertNotEquals(awsCred4.getAccessKeyId(), awsCred5.getAccessKeyId());

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchShouldNotCallServer() throws Exception {
        System.out.println("testPrefetchShouldNotCallServer");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        long intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);

        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

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
        client.prefetchAwsCreds(domain1, "role1", null, null, null);
        scheduledItemsSize = client.getScheduledItemsSize();
        assertTrue(scheduledItemsSize > scheduledItemsSize2);

        // make sure only unique items are in the queue
        client.prefetchAwsCreds(domain1, "role1", null, null, null);
        scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertNotNull(awsCred1);
        long awsCredExpiryd1r1 = awsCred1.getExpiration().millis();

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertNotNull(roleToken1);
        long rt1Expiry = roleToken1.getExpiryTime();

        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        long lastTokenFetchedTime1nr = ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null);

        // work with domain2
        //
        client.prefetchRoleToken(domain2, null, null, null, null);
        scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize2, scheduledItemsSize + 1);

        client.prefetchAwsCreds(domain2, "role1", null, null, null);
        scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize2, scheduledItemsSize + 2);

        RoleToken roleToken2 = client.getRoleToken(domain2);
        assertNotNull(roleToken2);
        long rt2Expiry = roleToken2.getExpiryTime();

        AWSTemporaryCredentials awsCred2 = client.getAWSTemporaryCredentials(domain2, "role1");
        assertNotNull(awsCred2);
        long awsCredExpiry = awsCred2.getExpiration().millis();

        System.out.println("testPrefetchShouldNotCallServer: sleep Secs=" + (2 * intervalSecs) + "+0.1");
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
                + (2 * intervalSecs) + "+0.1");
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

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchRoleTokenShouldCallServer() throws Exception {
        System.out.println("testPrefetchRoleTokenShouldCallServer");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        String domain1 = "coretech";

        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, null, null) < 0);

        // initialize the prefetch token process.
        client.prefetchRoleToken(domain1, null, null, null, null);
        // make sure only unique items are in the queue
        assertEquals(client.getScheduledItemsSize(), 1);

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertNotNull(roleToken1);
        long rtExpiry = roleToken1.getExpiryTime();
        System.out.println("testPrefetchRoleTokenShouldCallServer: roleToken1:domain="
                + domain1 + " expires at " + rtExpiry + " curtime_secs="
                + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchRoleTokenShouldCallServer: sleep Secs="
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
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
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
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

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchAwsCredShouldCallServerNoNotification() throws Exception {
        System.out.println("testPrefetchAwsCredShouldCallServer");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClientNotificationSender notificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.setNotificationSender(notificationSender);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        String domain1 = "coretech";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role2");

        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null) < 0);

        // initialize the prefetch token process.
        client.prefetchAwsCreds(domain1, "role1", null, null, null);
        // make sure only unique items are in the queue
        long scheduledItemsSize = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, 1);

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertNotNull(awsCred1);
        long rtExpiry = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: awsCred1:domain=" + domain1
                + " expires at " + rtExpiry + " curtime_millis=" + System.currentTimeMillis());

        System.out.println("testPrefetchAwsCredShouldCallServer: sleep Secs="
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
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
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
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

        client.prefetchAwsCreds(domain1, "role2", null, null, null);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        AWSTemporaryCredentials awsCred4 = client.getAWSTemporaryCredentials(domain1, "role2");
        assertNotNull(awsCred4);
        long rtExpiry3 = awsCred4.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: awsCred4:domain=" + domain1
                + " role=role2 expires at " + rtExpiry3 + " curtime_millis="
                + System.currentTimeMillis());

        lastTokenFetchedTime3 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role2", null);
        assertTrue(lastTokenFetchedTime3 > lastTokenFetchedTime2);

        AWSTemporaryCredentials awsCred5 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertNotNull(awsCred5);
        assertNotEquals(awsCred4.getAccessKeyId(), awsCred5.getAccessKeyId());

        // Assert no notifications were sent
        Mockito.verify(notificationSender, Mockito.times(0)).sendNotification(any(ZTSClientNotification.class));

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchAwsCredShouldSendNotifications() throws Exception {
        System.out.println("testPrefetchAwsCredShouldSendNotifications");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClientNotificationSender notificationSender = Mockito.mock(ZTSClientNotificationSender.class);
        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        client.setNotificationSender(notificationSender);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        String domain1 = "coretech";
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role2");

        // initially, roleToken was never fetched.
        assertTrue(ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null) < 0);

        // initialize the prefetch token process.
        client.prefetchAwsCreds(domain1, "role1", null, null, null);

        ZTSClient.setPrefetchAutoEnable(true);
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_AUTO_ENABLE, "true");
        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertNotNull(awsCred1);
        long rtExpiry = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: awsCred1:domain=" + domain1
                + " expires at " + rtExpiry + " curtime_millis=" + System.currentTimeMillis());

        System.out.println("testPrefetchAwsCredShouldCallServer: sleep Secs="
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), 1);

        long lastTokenFetchedTime1 = ztsClientMock.getLastRoleTokenFetchedTime(domain1, "role1", null);
        awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        long rtExpiry2 = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchAwsCredShouldCallServer: roleToken1:domain=" + domain1
                + " expires at " + rtExpiry2 + " curtime_millis=" + System.currentTimeMillis());
        assertTrue(rtExpiry2 > rtExpiry); // this token was refreshed

        assertTrue(lastTokenFetchedTime1 > 0);

        // Now clear credentials to cause failure and see if notification sent
        ztsClientMock.credsMap.clear();

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchAwsCredShouldCallServer: again sleep Secs="
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
        System.out.println("testPrefetchAwsCredShouldCallServer: again nap over so what happened");

        long lastFailureTime = ztsClientMock.getLastTokenFailTime(domain1, "role1");
        assertNotEquals(lastFailureTime, -1L);

        // assert notification sent
        ArgumentCaptor<ZTSClientNotification> argument = ArgumentCaptor.forClass(ZTSClientNotification.class);
        Mockito.verify(notificationSender, Mockito.times(1)).sendNotification(argument.capture());
        assertEquals(domain1, argument.getValue().getDomain());

        // Restore credentials, now fetching should work fine
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role1");
        ztsClientMock.setAwsCreds(Timestamp.fromCurrentTime(), domain1, "role2");

        client.getAWSTemporaryCredentials(domain1, "role1");
        lastFailureTime = ztsClientMock.getLastTokenFailTime(domain1, "role1");
        assertEquals(lastFailureTime, -1L);

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPrefetchShouldCallServer() throws Exception {
        System.out.println("testPrefetchShouldCallServer");

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        int intervalSecs = Integer.parseInt(System.getProperty(ZTSClient.ZTS_CLIENT_PROP_PREFETCH_SLEEP_INTERVAL, "5"));
        ztsClientMock.setTestSleepInterval(intervalSecs);
        ztsClientMock.setExpiryTime(intervalSecs); // token expires in 5 seconds
        ztsClientMock.setRoleName("role1");

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        ZTSClient.cancelPrefetch();
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
        client.prefetchAwsCreds(domain1, "role1", null, null, null);
        assertEquals(client.getScheduledItemsSize(), 2);

        RoleToken roleToken1 = client.getRoleToken(domain1);
        assertNotNull(roleToken1);
        long rtExpiry = roleToken1.getExpiryTime();
        System.out.println("testPrefetchShouldCallServer: roleToken1:domain=" + domain1 +
                " expires at " + rtExpiry + " curtime_secs=" + (System.currentTimeMillis() / 1000));

        AWSTemporaryCredentials awsCred1 = client.getAWSTemporaryCredentials(domain1, "role1");
        assertNotNull(awsCred1);
        long awsExpiry = awsCred1.getExpiration().millis();
        System.out.println("testPrefetchShouldCallServer: awsCred1:domain=" + domain1 + " expires at "
                + awsExpiry + " curtime_millis=" + System.currentTimeMillis());
        assertEquals(client.getScheduledItemsSize(), 2);

        System.out.println("testPrefetchShouldCallServer: sleep Secs=" + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
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
                + (2 * intervalSecs) + "+0.1");
        Thread.sleep((2L * intervalSecs * 1000) + 100);
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

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testGetHostServices() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
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
    public void testGetOpenIDConfig() {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient();
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        OpenIDConfig openIDConfig = client.getOpenIDConfig();
        assertNotNull(openIDConfig);

        assertEquals("https://athenz.cloud", openIDConfig.getIssuer());
        assertEquals("https://athenz.cloud/oauth2/keys", openIDConfig.getJwks_uri());
        assertEquals("https://athenz.cloud/access", openIDConfig.getAuthorization_endpoint());
        assertEquals(Collections.singletonList("RS256"), openIDConfig.getId_token_signing_alg_values_supported());
        assertEquals(Collections.singletonList("id_token"), openIDConfig.getResponse_types_supported());
        assertEquals(Collections.singletonList("public"), openIDConfig.getSubject_types_supported());

        try {
            ztsClientMock.setOpenIDConfigFailure(403);
            client.getOpenIDConfig();
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // with server exceptions we default back to 400

        try {
            ztsClientMock.setOpenIDConfigFailure(500);
            client.getOpenIDConfig();
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }

    @Test
    public void testGetJWKList() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        JWKList jwkList = client.getJWKList();
        assertNotNull(jwkList);
        assertEquals(jwkList.getKeys().size(), 1);
        assertEquals(jwkList.getKeys().get(0).getKid(), "id1");
        assertEquals(jwkList.getKeys().get(0).getKty(), "RSA");

        try {
            ztsClientMock.setJwkFailure(403);
            client.getJWKList();
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        // with server exceptions we default back to 400

        try {
            ztsClientMock.setJwkFailure(500);
            client.getJWKList();
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }

    @Test
    public void testGetJWKListRFC() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        JWKList jwkList = client.getJWKList(true);
        assertNotNull(jwkList);
        assertEquals(jwkList.getKeys().size(), 1);
        assertEquals(jwkList.getKeys().get(0).getKid(), "id1");
        assertEquals(jwkList.getKeys().get(0).getKty(), "EC");
        assertEquals(jwkList.getKeys().get(0).getX(), "x");
        assertEquals(jwkList.getKeys().get(0).getY(), "y");
        assertEquals(jwkList.getKeys().get(0).getCrv(), "P-256");

        try {
            ztsClientMock.setJwkFailure(403);
            client.getJWKList(true);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        client.close();
    }

    @Test
    public void testGetPublicKeyEntry() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ServiceIdentityList serviceIdentityList = client.getServiceIdentityList("coretech");
        assertEquals(serviceIdentityList.getNames(), Collections.singletonList("storage"));

        try {
            client.getServiceIdentityList("unknown.domain");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }

        client.close();
    }

    @Test
    public void testGetRolesRequireRoleCert() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleAccess roleList = client.getRolesRequireRoleCert("coretech");
        assertEquals(roleList.getRoles(), Collections.singletonList("role1"));

        try {
            client.getRolesRequireRoleCert("unknown.service");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }

        try {
            client.getRolesRequireRoleCert("error.service");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }

    @Test
    public void testGetRoleTokenName() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech", "role1");
        assertNotNull(roleToken);

        com.yahoo.athenz.auth.token.RoleToken token = new com.yahoo.athenz.auth.token.RoleToken(roleToken.getToken());
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getRoles().size(), 1);
        assertTrue(token.getRoles().contains("role1"));

        try {
            client.getRoleToken("coretech", "role2");
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSClient.cancelPrefetch();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleToken roleToken = client.getRoleToken("coretech");
        assertNotNull(roleToken);

        // now we're going to get a token again without any expiry timeouts and this time
        // we should get back from our cache thus the same exact one

        RoleToken roleToken2 = client.getRoleToken("coretech");
        assertEquals(roleToken2.getToken(), roleToken.getToken());

        // now we're going to use the full API to request the token with timeouts
        // that should satisfy the expiry time and thus get back the same one

        roleToken2 = client.getRoleToken("coretech", null, 1800, 3600, false);
        assertEquals(roleToken2.getToken(), roleToken.getToken());

        // this time we're going to ask for an increased min expiry time
        // thus the cache should no longer be satisfied

        roleToken2 = client.getRoleToken("coretech", null, 2800, 3600, false);
        assertNotEquals(roleToken2.getToken(), roleToken.getToken());
        client.close();
    }

    @Test
    public void testGetDomainSignedPolicyDataNull() {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
    public void testGetJWSPolicyData() {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setPolicyName("policy1");
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        Map<String, List<String>> responseHeaders = new HashMap<>();
        JWSPolicyData jwsPolicyData = client.postSignedPolicyRequest("coretech", new SignedPolicyRequest(), null, responseHeaders);
        assertNotNull(jwsPolicyData);

        try {
            client.postSignedPolicyRequest("invalid-domain", new SignedPolicyRequest(), null, responseHeaders);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 404);
        }

        try {
            client.postSignedPolicyRequest(null, new SignedPolicyRequest(), null, responseHeaders);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }

    @Test
    public void testGetTenantDomains() {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
        HostnameVerifier hostnameVerifier = client.getHostnameVerifier();
        assertTrue(hostnameVerifier == null || hostnameVerifier instanceof org.apache.http.conn.ssl.DefaultHostnameVerifier);

        HostnameVerifier ztsHostnameVerifier = new ZTSClientTest.TestHostVerifier();
        client = new ZTSRDLGeneratedClientMock("http://localhost:4080", ztsHostnameVerifier);
        hostnameVerifier = client.getHostnameVerifier();
        assertTrue(hostnameVerifier instanceof com.yahoo.athenz.zts.ZTSClientTest.TestHostVerifier);
    }

    @Test
    public void testHostnamVerifierDnsMatchStandard() throws SSLPeerUnverifiedException, CertificateParsingException {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = new ZTSClient.AWSHostNameVerifier("host1");

        SSLSession session = Mockito.mock(SSLSession.class);

        ArrayList<List<?>> altNames1 = new ArrayList<>();
        ArrayList<Object> rfcName1 = new ArrayList<>();
        rfcName1.add(1);
        rfcName1.add("rfcname");
        altNames1.add(rfcName1);

        ArrayList<Object> dnsName1 = new ArrayList<>();
        dnsName1.add(2);
        dnsName1.add("host1");
        altNames1.add(dnsName1);

        Certificate[] certs1 = new Certificate[1];
        X509Certificate cert1 = Mockito.mock(X509Certificate.class);
        Mockito.when(cert1.getSubjectAlternativeNames()).thenReturn(altNames1);
        certs1[0] = cert1;

        ArrayList<List<?>> altNames2 = new ArrayList<>();
        ArrayList<Object> rfcName2 = new ArrayList<>();
        rfcName2.add(1);
        rfcName2.add("rfcname");
        altNames2.add(rfcName2);

        ArrayList<Object> dnsName2 = new ArrayList<>();
        dnsName2.add(2);
        dnsName2.add("host11");
        altNames2.add(dnsName2);

        Certificate[] certs2 = new Certificate[1];
        X509Certificate cert2 = Mockito.mock(X509Certificate.class);
        Mockito.when(cert2.getSubjectAlternativeNames()).thenReturn(altNames2);
        certs2[0] = cert2;

        Mockito.when(session.getPeerCertificates()).thenReturn(certs1).thenReturn(certs2);

        assertTrue(hostnameVerifier.verify("host1", session));
        assertFalse(hostnameVerifier.verify("host1", session));

        client.close();
    }

    @Test
    public void testGetWorkloadsByIP() {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        Workloads workloads = client.getWorkloadsByIP("10.0.0.1");
        assertNotNull(workloads);
        assertEquals(workloads.getWorkloadList().get(0).getProvider(), "openstack");
        assertEquals(workloads.getWorkloadList().get(0).getUuid(), "avve-resw");
        assertEquals(workloads.getWorkloadList().get(0).getDomainName(), "athenz");
        assertEquals(workloads.getWorkloadList().get(0).getServiceName(), "api");
        assertNotNull(workloads.getWorkloadList().get(0).getUpdateTime());
        assertNull(workloads.getWorkloadList().get(0).getIpAddresses());
        try {
            client.getWorkloadsByIP("127.0.0.1");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }
        client.close();
    }

    @Test
    public void testGetWorkloadsByService() {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        Workloads workloads = client.getWorkloadsByService("athenz", "api");
        assertNotNull(workloads);
        assertEquals(workloads.getWorkloadList().get(0).getProvider(), "openstack");
        assertEquals(workloads.getWorkloadList().get(0).getUuid(), "avve-resw");
        assertNull(workloads.getWorkloadList().get(0).getDomainName());
        assertNull(workloads.getWorkloadList().get(0).getServiceName());
        assertNotNull(workloads.getWorkloadList().get(0).getUpdateTime());
        assertTrue(workloads.getWorkloadList().get(0).getIpAddresses().contains("10.0.0.1"));
        try {
            client.getWorkloadsByService("bad-domain", "api");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }
        client.close();
    }

    @Test
    public void testGetTransportRules() {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        TransportRules transportRules = client.getTransportRules("ingress-domain", "api");
        assertNotNull(transportRules);
        assertEquals(transportRules.getIngressRules().get(0).getProtocol(), "TCP");
        assertEquals(transportRules.getIngressRules().get(0).getPort(), 4443);
        assertEquals(transportRules.getIngressRules().get(0).getSourcePortRange(), "1024-65535");
        assertEquals(transportRules.getIngressRules().get(0).getEndPoint(), "10.0.0.1/26");

        assertNull(transportRules.getEgressRules());

        transportRules = client.getTransportRules("egress-domain", "api");
        assertNotNull(transportRules);
        assertEquals(transportRules.getEgressRules().get(0).getProtocol(), "TCP");
        assertEquals(transportRules.getEgressRules().get(0).getPort(), 8443);
        assertEquals(transportRules.getEgressRules().get(0).getSourcePortRange(), "1024-65535");
        assertEquals(transportRules.getEgressRules().get(0).getEndPoint(), "10.0.0.1/23");

        assertNull(transportRules.getIngressRules());
        try {
            client.getTransportRules("bad-domain", "api");
            fail();
        } catch (ResourceException re) {
            assertEquals(re.getCode(), 404);
        }

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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
    public void testGetRoleAccessWithCache() {

        ZTSClientCache ztsClientDisabledCache = new ZTSClientCache();

        System.setProperty(ZTSClientCache.ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS,
                this.getClass().getClassLoader().getResource("zts-client-ehcache.xml").getPath());
        ZTSClientCache ztsClientEnabledCache = new ZTSClientCache();
        System.clearProperty(ZTSClientCache.ZTS_CLIENT_PROP_EHCACHE_XML_PATH_ROLE_ACCESS);

        class SpyZTSRDLClientMock extends ZTSRDLClientMock {
            int getRoleAccessCount = 0;
            public RoleAccess getRoleAccess(String domainName, String principal) {
                getRoleAccessCount++;
                return super.getRoleAccess(domainName, principal);
            }
        }

        class TesterHelp {
            void makeTest(ZTSClientCache ztsClientCache, int expectedGetRoleAccessCountCallsCount) {
                SpyZTSRDLClientMock ztsRDLClientMock = new SpyZTSRDLClientMock();

                Principal principal = SimplePrincipal.create("user_domain", "user",
                        "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
                ZTSClient client = new ZTSClient("http://localhost:4080", principal);
                client.setZTSRDLGeneratedClient(ztsRDLClientMock);
                client.setZTSClientCache(ztsClientCache);

                // Call getRoleAccess() multiple times: the matching RDL method should only be called once - due to caching.
                for (int cycle = 0; cycle < 3; cycle++) {
                    RoleAccess roleAccess = client.getRoleAccess("coretech", "user.joe");
                    List<String> roles = roleAccess.getRoles();
                    assertEquals(roles.size(), 2);
                    assertTrue(roles.contains("role1"));
                }

                client.close();
                assertEquals(ztsRDLClientMock.getRoleAccessCount, expectedGetRoleAccessCountCallsCount);
            }
        }

        // With cache disabled - com.yahoo.athenz.zts.ZTSClient.getRoleAccess() should be called 3 times
        new TesterHelp().makeTest(ztsClientDisabledCache, 3);

        // With cache enabled - com.yahoo.athenz.zts.ZTSClient.getRoleAccess() should be called only once
        new TesterHelp().makeTest(ztsClientEnabledCache, 1);
    }

    @Test
    public void testGetAccess() {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
    public void testGetResourceAccessExt() {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ResourceAccess access = client.getResourceAccessExt("access", "resource", null, "principal");
        assertTrue(access.getGranted());

        access = client.getResourceAccessExt("access", "resource", null, "principal1");
        assertFalse(access.getGranted());

        try {
            client.getResourceAccessExt("exc", "resource", null, "principal");
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
        assertEquals(client.getPrefetchInterval(), 10L);

        client.close();
    }

    @Test
    public void testException() {

        List<Integer> codes = Arrays.asList(200, 201, 202, 204, 301, 302, 303, 304
                , 307, 400, 401, 403, 404, 409, 410, 412, 415, 500, 501, 503);

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
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = new ZTSClient.AWSHostNameVerifier("host1");

        SSLSession session = Mockito.mock(SSLSession.class);
        Mockito.when(session.getPeerCertificates()).thenReturn(null);

        assertFalse(hostnameVerifier.verify("host1", session));

        System.out.println("hashCode:" + client.hashCode());

        client.close();
    }


    private final static String crlf = System.getProperty("line.separator");
    private final static String test_cert =
            "-----BEGIN CERTIFICATE-----" + crlf
                    + "MIIDRDCCAiwCCQDltWO9Xjhd8DANBgkqhkiG9w0BAQUFADBkMQswCQYDVQQGEwJK" + crlf
                    + "UDEOMAwGA1UECBMFVG9reW8xEjAQBgNVBAcTCVN1bWlkYS1rdTEPMA0GA1UEChMG" + crlf
                    + "WUpURVNUMQ8wDQYDVQQLEwZZSlRFU1QxDzANBgNVBAMTBllKVEVTVDAeFw0xNjEx" + crlf
                    + "MTEwODMzMTVaFw0yNjExMDkwODMzMTVaMGQxCzAJBgNVBAYTAkpQMQ4wDAYDVQQI" + crlf
                    + "EwVUb2t5bzESMBAGA1UEBxMJU3VtaWRhLWt1MQ8wDQYDVQQKEwZZSlRFU1QxDzAN" + crlf
                    + "BgNVBAsTBllKVEVTVDEPMA0GA1UEAxMGWUpURVNUMIIBIjANBgkqhkiG9w0BAQEF" + crlf
                    + "AAOCAQ8AMIIBCgKCAQEA1Ssz+hLCTXyMlDH9E0bd9EEm0yNyPH4XhtUkSEDdYE+Z" + crlf
                    + "0m/7BkfrKTRRew8wrfpLkK0wZsoVkEjwd0GktZXnGTRUs42Bd5tSYXV1Z78oqjS4" + crlf
                    + "AGpjkQlQva+f6ANnDhPNxHJ6QlY6DLePIByjepmJS8UZGRuNPiDpbtWWhuCLbn6p" + crlf
                    + "to2SiclLHr6K/5uFYjawS8k3bGmoV9QfeWvY+aiGvuxDsPCxcePpwSA8btubpTsJ" + crlf
                    + "CvC31rJChgN5VQFE26vfhVCwmuhwOCcUThdgaI9LAjLETknrLt/kiFaiIhm5peSG" + crlf
                    + "t0DP89u9fnaUX7P8jc/4V57lnp+ynRpGpHfv4Fi4wQIDAQABMA0GCSqGSIb3DQEB" + crlf
                    + "BQUAA4IBAQARH92fKPsVoCq80ARt70LM8ynaq9dlXcLjr34CWINbGbXG4a0RP1l9" + crlf
                    + "bFZih7rCG96W+fDKxvgR2YwXhRJq5NchOoBB0mtOBG3VwbXFNm6CBHqwtbrNiPzv" + crlf
                    + "BvK7jerZd1g0CgTWzfoPgO/87F2uX5J92CsvXRYrDJsFYHnhmUg3JWCT4q+Xe9J4" + crlf
                    + "/Eyw+C1DgDwWjjBB1Qb3QBO/dpGR+EWv4mtNK8D2o+iEFJLjtNdqIkcrUIXfqI8M" + crlf
                    + "z+7Tph5eLFgI5lEW+Pu/myzLIXCNWoRr7UQute898v/1XZiRS4sSCEQSgXnZflA8" + crlf
                    + "c2KrYjMGSUogzw6+1gKeucygV32rA2B2" + crlf
                    + "-----END CERTIFICATE-----";

    @Test
    public void testHostNameVerifierVerifyCert() throws CertificateException, IOException {
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.AWSHostNameVerifier hostnameVerifier = new ZTSClient.AWSHostNameVerifier("host1");

        InputStream is = new ByteArrayInputStream(test_cert.getBytes(StandardCharsets.UTF_8));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate cert = cf.generateCertificate(is);
        is.close();

        Certificate[] certs = new Certificate[1];
        certs[0] = cert;

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
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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
    public void testPostRoleCertificateRequestExt() {
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        client.setZTSRDLGeneratedClient(ztsClientMock);

        RoleCertificateRequest req = new RoleCertificateRequest().setCsr("csr");
        RoleCertificate roleCert = client.postRoleCertificateRequest(req);
        assertNotNull(roleCert);

        try {
            req.setCsr("exc");
            client.postRoleCertificateRequest(req);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            req.setCsr("no-role");
            client.postRoleCertificateRequest(req);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }
        client.close();
    }

    @Test
    public void testGenerateRoleCertificateRequest() {

        File privkey = new File("./src/test/resources/unit_test_private_k0.pem");
        PrivateKey privateKey = Crypto.loadPrivateKey(privkey);

        RoleCertificateRequest req = ZTSClient.generateRoleCertificateRequest("coretech",
                "test", "sports", "readers", privateKey, "aws", 3600);
        assertNotNull(req);

        PKCS10CertificationRequest certReq = Crypto.getPKCS10CertRequest(req.getCsr());
        assertEquals(Crypto.extractX509CSRCommonName(certReq), "sports:role.readers");
        assertEquals(Crypto.extractX509CSREmail(certReq), "coretech.test@aws.athenz.cloud");

        List<String> uris = Crypto.extractX509CSRURIs(certReq);
        assertEquals(uris.size(), 2);
        assertEquals(uris.get(0), "spiffe://sports/ra/readers");
        assertEquals(uris.get(1), "athenz://principal/coretech.test");

        // check failure cases

        try {
            ZTSClient.generateRoleCertificateRequest(null,
                    "test", "sports", "readers", privateKey, "aws", 3600);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }

        try {
            ZTSClient.generateRoleCertificateRequest("coretech",
                    null, "sports", "readers", privateKey, "aws", 3600);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }

        try {
            ZTSClient.generateRoleCertificateRequest("coretech",
                    "api", null, "readers", privateKey, "aws", 3600);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }

        try {
            ZTSClient.generateRoleCertificateRequest("coretech",
                    "api", "sports", null, privateKey, "aws", 3600);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }

        try {
            ZTSClient.generateRoleCertificateRequest("coretech",
                    "api", "sports", "readers", privateKey, null, 3600);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testGenerateInstanceRefreshRequestTopDomain() {

        File privkey = new File("./src/test/resources/unit_test_private_k0.pem");
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

        File privkey = new File("./src/test/resources/unit_test_private_k0.pem");
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
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

        List<String> unmRoles = Collections.unmodifiableList(roles);
        assertEquals(ZTSClient.multipleRoleKey(unmRoles), "apple,one,ones,role,yellow");
    }

    @Test
    public void testGetAssumeRoleRequest() {

        ZTSClient client = new ZTSClient("http://localhost:4080");
        AssumeRoleRequest req = client.getAssumeRoleRequest("1234", "role1");
        assertNotNull(req);
        assertEquals(req.roleArn(), "arn:aws:iam::1234:role/role1");
        assertEquals(req.roleSessionName(), "role1");
        client.close();
    }

    @Test
    public void testGetAWSLambdaAttestationData() throws IOException {
        ZTSClientMock client = new ZTSClientMock("http://localhost:4080");
        String jsonData = client.getAWSLambdaAttestationData("athenz.service", "12345");

        // convert data into our object

        ObjectMapper mapper = new ObjectMapper();
        AWSAttestationData data = mapper.readValue(jsonData, AWSAttestationData.class);
        assertEquals(data.getAccess(), "access");
        assertEquals(data.getRole(), "athenz.service");
        assertEquals(data.getSecret(), "secret");
        assertEquals(data.getToken(), "token");

        client.close();
    }

    @Test
    public void testGetAWSLambdaServiceCertificate() {

        ZTSClientMock client = new ZTSClientMock("http://localhost:4080");
        ZTSClientMock.setX509CsrDetails("o=Athenz", "athenz.cloud");

        // configure the values to be verified

        client.setCsrUriVerifyValue("spiffe://athenz/sa/service");
        List<String> dnsValues = new ArrayList<>();
        dnsValues.add("service.athenz.athenz.cloud");
        dnsValues.add("lambda-1234-service.instanceid.athenz.athenz.cloud");
        client.setCsrDnsVerifyValues(dnsValues);

        AWSLambdaIdentity identity = client.getAWSLambdaServiceCertificate("athenz", "service", "1234", "provider");
        assertNotNull(identity);
        assertNotNull(identity.getPrivateKey());
        assertNotNull(identity.getX509Certificate());

        client.close();
    }

    @Test
    public void testGetAWSCredentialsProvider() {

        ZTSClientMock client = new ZTSClientMock("http://localhost:40888");
        try {
            client.getAWSCredentialProvider("domain", "role");
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 503);
        }
        try {
            client.getAWSCredentialProvider("domain", "role", "id", 100, 300);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 503);
        }
        try {
            client.getAWSCredentialProvider("domain", "role", "id", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 503);
        }
        client.close();
    }

    @Test
    public void testPrefetchRoleTokenScheduledItem() {
        ZTSClient.PrefetchTokenScheduledItem item1 = new ZTSClient.PrefetchTokenScheduledItem();
        ZTSClient.PrefetchTokenScheduledItem item2 = new ZTSClient.PrefetchTokenScheduledItem();

        // identity domain check

        item1.setIdentityDomain("domain1");
        item2.setIdentityDomain("domain2");
        assertNotEquals(item1.hashCode(), item2.hashCode());
        assertNotEquals(item1, item2);

        item2.setIdentityDomain("domain1");
        assertEquals(item1.hashCode(), item2.hashCode());
        assertEquals(item1, item2);

        // identity name check

        item1.setIdentityName("name1");
        item2.setIdentityName("name2");
        assertNotEquals(item1.hashCode(), item2.hashCode());
        assertNotEquals(item1, item2);

        item2.setIdentityName("name1");
        assertEquals(item1.hashCode(), item2.hashCode());
        assertEquals(item1, item2);

        // is invalid check

        item1.setIsInvalid(false);
        item2.setIsInvalid(true);
        assertNotEquals(item1.hashCode(), item2.hashCode());
        assertNotEquals(item1, item2);

        item2.setIsInvalid(false);
        assertEquals(item1.hashCode(), item2.hashCode());
        assertEquals(item1, item2);

        // domainname check

        item1.setDomainName("dom1");
        assertNotEquals(item1, item2);

        item2.setDomainName("dom2");
        assertNotEquals(item1, item2);

        item2.setDomainName("dom1");
        assertEquals(item1, item2);

        // external id check

        item1.setExternalId("id1");
        assertNotEquals(item1, item2);

        item2.setExternalId("id2");
        assertNotEquals(item1, item2);

        item2.setExternalId("id1");
        assertEquals(item1, item2);

        // proxy for principal check

        item1.setProxyForPrincipal("proxy1");
        assertNotEquals(item1, item2);

        item2.setProxyForPrincipal("proxy2");
        assertNotEquals(item1, item2);

        item2.setProxyForPrincipal("proxy1");
        assertEquals(item1, item2);
    }

    @Test
    public void testRoleTokenDescriptor() {
        ZTSClientService.RoleTokenDescriptor descr = new ZTSClientService.RoleTokenDescriptor("signedToken");
        assertNotNull(descr);

        assertEquals("signedToken", descr.getSignedToken());
    }

    @Test
    public void testGenerateAccessTokenRequestBody() throws UnsupportedEncodingException {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);

        assertEquals("grant_type=client_credentials&scope=coretech%3Adomain",
                client.generateAccessTokenRequestBody("coretech", null, null, null, null, null, 0));
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Adomain",
                client.generateAccessTokenRequestBody("coretech", null, null, null, null, null, 100));
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Adomain",
                client.generateAccessTokenRequestBody("coretech", null, "", null, null, null, 100));
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Adomain+openid+coretech%3Aservice.api",
                client.generateAccessTokenRequestBody("coretech", null, "api", null, null, null, 100));
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Arole.readers+openid+coretech%3Aservice.api",
                client.generateAccessTokenRequestBody("coretech", Collections.singletonList("readers"), "api", null, null, "", 100));
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Arole.readers+openid+coretech%3Aservice.api",
                client.generateAccessTokenRequestBody("coretech", Collections.singletonList("readers"), "api", "", null, null, 100));
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Arole.readers+openid+coretech%3Aservice.api&proxy_for_principal=user.proxy",
                client.generateAccessTokenRequestBody("coretech", Collections.singletonList("readers"), "api", "user.proxy", null, "", 100));
        List<String> roles = new ArrayList<>();
        roles.add("readers");
        roles.add("writers");
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Arole.readers+coretech%3Arole.writers+openid+coretech%3Aservice.api",
                client.generateAccessTokenRequestBody("coretech", roles, "api", null, null, null, 100));
        final String authorizationDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";
        final String encodedDetails = "%5B%7B%22type%22%3A%22message_access%22%2C%22location%22%3A%5B%22https%3A%2F%2Flocation1%22%2C%22https%3A%2F%2Flocation2%22%5D%2C%22identifier%22%3A%22id1%22%7D%5D";
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Arole.readers+openid+coretech%3Aservice.api&authorization_details=" + encodedDetails,
                client.generateAccessTokenRequestBody("coretech", Collections.singletonList("readers"), "api", null, authorizationDetails, null, 100));
        final String proxyPrincipalsEncoded = "spiffe%3A%2F%2Fathenz%2Fsa%2Fservice1%2Cspiffe%3A%2F%2Fathenz%2Fsa%2Fservice2";
        assertEquals("grant_type=client_credentials&expires_in=100&scope=coretech%3Arole.readers+openid+coretech%3Aservice.api&authorization_details="
                        + encodedDetails + "&proxy_principal_spiffe_uris=" + proxyPrincipalsEncoded,
                client.generateAccessTokenRequestBody("coretech", Collections.singletonList("readers"), "api", null,
                        authorizationDetails, "spiffe://athenz/sa/service1,spiffe://athenz/sa/service2", 100));

        client.close();
    }

    @Test
    public void testLookupAccessTokenResponseInCache() throws InterruptedException {

        final String cacheKey = "accesstestkey1";

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);

        assertNull(client.lookupAccessTokenResponseInCache(cacheKey, 3600));

        AccessTokenResponse response1 = new AccessTokenResponse();
        response1.setExpires_in(3600);
        ZTSClient.ACCESS_TOKEN_CACHE.put(cacheKey, new AccessTokenResponseCacheEntry(response1));

        // with standard 1 hour check, our entry is not expired

        assertNotNull(client.lookupAccessTokenResponseInCache(cacheKey, 3600));

        // with a 60 hour check, our entry is expired, however our entry
        // will not be removed from the cache

        assertNull(client.lookupAccessTokenResponseInCache(cacheKey, 36000));
        assertNotNull(ZTSClient.ACCESS_TOKEN_CACHE.get(cacheKey));

        // add a second entry with 1 second timeout

        AccessTokenResponse response2 = new AccessTokenResponse();
        response2.setExpires_in(1);
        ZTSClient.ACCESS_TOKEN_CACHE.put(cacheKey, new AccessTokenResponseCacheEntry(response2));

        // sleep a second and then ask for a cache entry

        Thread.sleep(1000);

        // entry is not returned from lookup and also removed from the cache

        assertNull(client.lookupAccessTokenResponseInCache(cacheKey, 3600));
        assertNull(ZTSClient.ACCESS_TOKEN_CACHE.get(cacheKey));
        client.close();
    }

    @Test
    public void testGetAccessTokenCacheKey() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080/", principal);

        assertNull(ZTSClient.getAccessTokenCacheKey(null, "service", "coretech", null, null, null, null, null));

        assertEquals("p=sports;d=coretech",
                ZTSClient.getAccessTokenCacheKey("sports", null, "coretech", null, null, null, null, null));
        assertEquals("p=sports.api;d=coretech",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", null, null, null, null, null));
        assertEquals("p=sports.api;d=coretech;r=readers",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech",
                        Collections.singletonList("readers"), null, null, null, null));

        List<String> roles = new ArrayList<>();
        roles.add("writers");
        roles.add("readers");
        assertEquals("p=sports.api;d=coretech;r=readers,writers",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", roles, null, null, null, null));

        assertEquals("p=sports.api;d=coretech;r=readers,writers",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", roles, "", null, null, null));

        assertEquals("p=sports.api;d=coretech;r=readers,writers;o=backend",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", roles, "backend", null, null, null));

        // using tenant domain details from principal object

        assertEquals("p=user_domain.user;d=coretech;r=readers,writers;o=backend",
                client.getAccessTokenCacheKey("coretech", roles, "backend", null, null, null));

        // using authorization details

        assertEquals("p=sports.api;d=coretech;r=readers,writers;o=backend;z=ZHMaRw4r9BWIPOWxVv9kDcCMTFzXm3nCUzNs9SA5aL8",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", roles, "backend", null,
                        "[{\"type\": \"message\",\"uuid\": \"uuid-12345678\"}]", null));

        assertEquals("p=sports.api;d=coretech;r=readers,writers;o=backend;z=ZHMaRw4r9BWIPOWxVv9kDcCMTFzXm3nCUzNs9SA5aL8",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", roles, "backend", null,
                        "[{\"type\": \"message\",\"uuid\": \"uuid-12345678\"}]", ""));

        // using proxy principal spiffe uris

        assertEquals("p=sports.api;d=coretech;r=readers,writers;o=backend;z=ZHMaRw4r9BWIPOWxVv9kDcCMTFzXm3nCUzNs9SA5aL8;s=spiffe://athenz/sa/service1",
                ZTSClient.getAccessTokenCacheKey("sports", "api", "coretech", roles, "backend", null,
                        "[{\"type\": \"message\",\"uuid\": \"uuid-12345678\"}]", "spiffe://athenz/sa/service1"));
        client.close();
    }

    @Test
    public void testGetAccessTokenCacheKeySSLContext() {

        SSLContext sslContext = Mockito.mock(SSLContext.class);
        final String contextStr = sslContext.toString();

        ZTSClientMock client = new ZTSClientMock("http://localhost:4080/", sslContext);

        final String expectedStr = "p=" + contextStr + ";d=coretech;r=readers;o=backend";
        assertEquals(expectedStr, client.getAccessTokenCacheKey("coretech",
                Collections.singletonList("readers"), "backend", null, null, null));

        client.close();
    }

    @Test
    public void testGetAccessTokenFromFile() {
        File ecPublicKey = new File("./src/test/resources/ec_public.key");
        JwtsSigningKeyResolver resolver = new JwtsSigningKeyResolver(null, null);
        PublicKey publicKey = Crypto.loadPublicKey(ecPublicKey);
        resolver.addPublicKey("eckey1", publicKey);
        Path path = Paths.get("./src/test/resources/");
        System.setProperty(ZTSAccessTokenFileLoader.ACCESS_TOKEN_PATH_PROPERTY, path.toString());
        setupTokenFile();
        setupInvalidTokenFile();

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        ZTSClient.setAccessTokenSignKeyResolver(resolver);
        ZTSClient.initZTSAccessTokenFileLoader();

        AccessTokenResponse accessTokenResponse = client.getAccessToken("test.domain", Collections.singletonList("admin"), 3600);
        assertNotNull(accessTokenResponse);
        assertEquals(accessTokenResponse.getScope(), "admin");
        assertEquals((int) accessTokenResponse.getExpires_in(), 28800);

        client.close();
    }

    @Test
    public void testGetAccessToken() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        AccessTokenResponse accessTokenResponse = client.getAccessToken("coretech", null, 3600);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken", accessTokenResponse.getAccess_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);
        assertNull(accessTokenResponse.getId_token());

        accessTokenResponse = client.getAccessToken("coretech", Collections.singletonList("role1"), 3600);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken", accessTokenResponse.getAccess_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);
        assertNull(accessTokenResponse.getId_token());

        // the second request should be addressed from the cache

        accessTokenResponse = client.getAccessToken("coretech", Collections.singletonList("role1"), 3600);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken", accessTokenResponse.getAccess_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);
        assertNull(accessTokenResponse.getId_token());

        // now with id token

        accessTokenResponse = client.getAccessToken("coretech", null, "backend", 3600, false);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken", accessTokenResponse.getAccess_token());
        assertEquals("idtoken", accessTokenResponse.getId_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);

        // now with id token and cache disabled

        accessTokenResponse = client.getAccessToken("coretech", null, "backend", 3600, true);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken", accessTokenResponse.getAccess_token());
        assertEquals("idtoken", accessTokenResponse.getId_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);


        ZTSClient.setCacheDisable(true);
        accessTokenResponse = client.getAccessToken("coretech", null, "backend", 3600, true);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken", accessTokenResponse.getAccess_token());
        assertEquals("idtoken", accessTokenResponse.getId_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);
        ZTSClient.setCacheDisable(false);

        client.close();
    }

    @Test
    public void testGetAccessTokenWithAuthorizationDetails() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        final String authorizationDetails = "[{\"type\":\"message_access\",\"location\":[\"https://location1\"," +
                "\"https://location2\"],\"identifier\":\"id1\"}]";

        AccessTokenResponse accessTokenResponse = client.getAccessToken("coretech", "role1", authorizationDetails, 3600);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken-authz-details", accessTokenResponse.getAccess_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);

        // the second request should be addressed from the cache

        accessTokenResponse = client.getAccessToken("coretech", "role1", authorizationDetails, 3600);
        assertNotNull(accessTokenResponse);
        assertEquals("accesstoken-authz-details", accessTokenResponse.getAccess_token());
        assertEquals((int) accessTokenResponse.getExpires_in(), 3600);

        client.close();
    }

    @Test
    public void testGetAccessTokenFailures() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        try {
            client.getAccessToken("weather", null, 500);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(404, ex.getCode());
        }

        // look for regular general exception

        try {
            client.getAccessToken("exception", null, 500);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(400, ex.getCode());
        }

        // add an entry to the cache and expect to find the entry
        // in the cache with failed request.

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token("accesstoken1");
        tokenResponse.setExpires_in(100);

        ZTSClient.ACCESS_TOKEN_CACHE.put("p=user_domain.user;d=weather", new AccessTokenResponseCacheEntry(tokenResponse));
        ZTSClient.ACCESS_TOKEN_CACHE.put("p=user_domain.user;d=exception", new AccessTokenResponseCacheEntry(tokenResponse));

        // with cache disabled we're not going to get any data back

        try {
            client.getAccessToken("weather", null, null, 500, true);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(404, ex.getCode());
        }

        // look for regular general exception

        try {
            client.getAccessToken("exception", null, null, 500, true);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(400, ex.getCode());
        }

        // with cache enabled we'll get our entries back even if
        // the request is rejected

        AccessTokenResponse result = client.getAccessToken("weather", null, 500);
        assertNotNull(result);
        assertEquals("accesstoken1", result.getAccess_token());

        result = client.getAccessToken("exception", null, 500);
        assertNotNull(result);
        assertEquals("accesstoken1", result.getAccess_token());

        client.close();
    }

    @Test
    public void testShouldRefresh() {

        ZTSClient.TokenPrefetchTask task = new ZTSClient.TokenPrefetchTask();

        // last fetch is 1000
        // last fail time 0
        // expiry time is 1800

        // current time 1200 - no refresh
        // current time 1300 - no refresh
        // current time 1400 - refresh
        // current time 1500 - refresh

        assertFalse(task.shouldRefresh(ZTSClient.TokenType.ACCESS, 1200, 1000, 0, 1800));
        assertFalse(task.shouldRefresh(ZTSClient.TokenType.ACCESS, 1300, 1000, 0, 1800));
        assertTrue(task.shouldRefresh(ZTSClient.TokenType.ACCESS, 1400, 1000, 0, 1800));
        assertTrue(task.shouldRefresh(ZTSClient.TokenType.ACCESS, 1500, 1000, 0, 1800));

        // last fetch is 1000
        // last fail time 1400
        // expiry time is 1800

        // current time 1500 - no refresh
        // current time 1600 - refresh

        assertFalse(task.shouldRefresh(ZTSClient.TokenType.ROLE, 1500, 1000, 1400, 1800));
        assertTrue(task.shouldRefresh(ZTSClient.TokenType.ROLE, 1600, 1000, 1400, 1800));

        // tests using last refresh time

        long currentTime = System.currentTimeMillis() / 1000;
        long lastFetchTime = System.currentTimeMillis() / 1000 - 100;
        long expiryTime = System.currentTimeMillis() / 1000 + 24 * 60 * 60;

        assertFalse(task.shouldRefresh(ZTSClient.TokenType.ROLE, currentTime, lastFetchTime, 0, expiryTime));
        assertFalse(task.shouldRefresh(ZTSClient.TokenType.ACCESS, currentTime, lastFetchTime, 0, expiryTime));

        // now set the key refresher which should make it enabled for refresh
        // but only for access tokens

        ZTSClient.KEY_REFRESHER_LISTENER.onKeyChangeEvent();
        assertTrue(task.shouldRefresh(ZTSClient.TokenType.ACCESS, currentTime, lastFetchTime, 0, expiryTime));
        assertFalse(task.shouldRefresh(ZTSClient.TokenType.ROLE, currentTime, lastFetchTime, 0, expiryTime));
    }

    @Test
    public void testPrefetchAccessTokenShouldNotCallServer() throws Exception {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");

        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        ZTSClient.setPrefetchInterval(1);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        String domain1 = "coretech";
        String domain2 = "coretech2";

        // initially, access token was never fetched.
        assertTrue(ztsClientMock.getLastAccessTokenFetchedTime(domain1, null, null) < 0);

        // initialize the prefetch token process.
        client.prefetchAccessToken(domain1, null, null, null, null, null, 8);
        int scheduledItemsSize = client.getScheduledItemsSize();

        // make sure only unique items are in the queue
        client.prefetchAccessToken(domain1, null, null, null, null, null, 8);
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        AccessTokenResponse access1 = client.getAccessToken(domain1, null, 8);
        assertNotNull(access1);

        client.prefetchAccessToken(domain2, null, null, null, null, null, 8);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        AccessTokenResponse access2 = client.getAccessToken(domain2, null, 8);
        assertNotNull(access2);
        long rt2Expiry = System.currentTimeMillis() / 1000 + access2.getExpires_in();
        System.out.println("testPrefetchAccessTokenShouldNotCallServer: accessToken2:domain="
                + domain2 + " expires at " + rt2Expiry + " curtime_secs=" + (System.currentTimeMillis() / 1000));

        System.out.println("testPrefetchAccessTokenShouldNotCallServer: sleep Secs=5");
        Thread.sleep(5000);
        System.out.println("testPrefetchAccessTokenShouldNotCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        long lastTokenFetchedTime1 = ztsClientMock.getLastAccessTokenFetchedTime(domain1, null, null);
        assertTrue(lastTokenFetchedTime1 > 0);

        access2 = client.getAccessToken(domain2, null, 8);
        long rt2Expiry2 = System.currentTimeMillis() / 1000 + access2.getExpires_in();
        System.out.println("testPrefetchAccessTokenShouldNotCallServer: accessToken2:domain="
                + domain2 + " expires at " + rt2Expiry2 + " curtime_secs=" + (System.currentTimeMillis() / 1000));
        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchAccessTokenShouldNotCallServer: sleep Secs=5");
        Thread.sleep(5000);
        System.out.println("testPrefetchAccessTokenShouldNotCallServer: again nap over so what happened");

        AccessTokenResponse access3 = client.getAccessToken(domain2, null, 8);
        long rt2Expiry3 = System.currentTimeMillis() / 1000 + access3.getExpires_in();
        System.out.println("testPrefetchAccessTokenShouldNotCallServer: accessToken3:domain="
                + domain2 + " expires at " + rt2Expiry3);
        assertTrue(rt2Expiry3 > rt2Expiry2); // this token was refreshed

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testGetCertificateAuthorityBundle() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        CertificateAuthorityBundle bundle = client.getCertificateAuthorityBundle("athenz");
        assertNotNull(bundle);
        assertEquals(bundle.getName(), "athenz");
        assertEquals(bundle.getCerts(), "certs");

        try {
            client.getCertificateAuthorityBundle("exc");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        try {
            client.getCertificateAuthorityBundle("system");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 404);
        }

        client.close();
    }

    @Test
    public void getGetInstanceRegisterToken() {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        InstanceRegisterToken token = client.getInstanceRegisterToken("sys.auth.zts", "coretech",
                "api", "id-001");
        assertNotNull(token);

        try {
            client.getInstanceRegisterToken("sys.auth.zts", "bad-domain", "api", "id-001");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_FOUND);
        }

        try {
            client.getInstanceRegisterToken("sys.auth.zts", "exc", "api", "id-001");
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
        }

        client.close();
    }

    @Test
    public void testGetInfo() throws IOException, URISyntaxException {
        ZTSRDLGeneratedClient c = Mockito.mock(ZTSRDLGeneratedClient.class);
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(c);
        Info info = new Info().setBuildJdkSpec("17")
                .setImplementationTitle("title")
                .setImplementationVendor("vendor")
                .setImplementationVersion("version");
        Mockito.when(c.getInfo()).thenReturn(info)
                .thenThrow(new ZTSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        Info infoRes = client.getInfo();
        assertNotNull(infoRes);
        assertEquals(infoRes.getBuildJdkSpec(), "17");
        assertEquals(infoRes.getImplementationVersion(), "version");

        // second time it fails

        try {
            client.getInfo();
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.getInfo();
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testEncodeAWSRoleName() {

        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZTSClient.initConfigValues();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient(null, principal);

        assertEquals(client.encodeAWSRoleName("aws-role"), "aws-role");
        assertEquals(client.encodeAWSRoleName("sso/aws-role"), "sso%252Faws-role");

        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }

    @Test
    public void testGenerateIdTokenScope() {

        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZTSClient.initConfigValues();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient(null, principal);

        assertEquals(client.generateIdTokenScope("sports.api", null), "openid roles sports.api:domain");
        assertEquals(client.generateIdTokenScope("sports.api", Collections.emptyList()), "openid roles sports.api:domain");

        List<String> roles = new ArrayList<>();
        roles.add("readers");
        assertEquals(client.generateIdTokenScope("sports.api", roles), "openid sports.api:role.readers");

        roles.add("writers");
        assertEquals(client.generateIdTokenScope("sports.api", roles), "openid sports.api:role.readers sports.api:role.writers");

        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }

    @Test
    public void testGenerateRedirectUri() {

        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZTSClient.initConfigValues();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient(null, principal);

        assertEquals(client.generateRedirectUri("sports", "athenz.io"), "");
        assertEquals(client.generateRedirectUri("sports.api", "athenz.io"), "https://api.sports.athenz.io");
        assertEquals(client.generateRedirectUri("sports.prod.api", "athenz.io"), "https://api.sports-prod.athenz.io");

        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }

    @Test
    public void testGetIdTokenCacheKey() {
        System.setProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ZTSClient.initConfigValues();
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient(null, principal);

        assertNull(client.getIdTokenCacheKey(null, "id", "uri", "scope", "state", "EC", true));
        assertNull(client.getIdTokenCacheKey("id_token", null, "uri", "scope", "state", "EC", true));
        assertNull(client.getIdTokenCacheKey("id_token", "id", null, "scope", "state", "EC", true));
        assertNull(client.getIdTokenCacheKey("id_token", "id", "uri", null, "state", "EC", true));

        assertEquals(client.getIdTokenCacheKey("id_token", "sports.api", "https://api.sports", "openid", null, null, null),
                "t=id_token;c=sports.api;s=openid;r=https://api.sports");
        assertEquals(client.getIdTokenCacheKey("id_token", "sports.api", "https://api.sports", "openid", "", "", null),
                "t=id_token;c=sports.api;s=openid;r=https://api.sports");
        assertEquals(client.getIdTokenCacheKey("id_token", "sports.api", "https://api.sports", "openid", "state", "", null),
                "t=id_token;c=sports.api;s=openid;r=https://api.sports;a=state");
        assertEquals(client.getIdTokenCacheKey("id_token", "sports.api", "https://api.sports", "openid", "state", "EC", true),
                "t=id_token;c=sports.api;s=openid;r=https://api.sports;a=state;k=EC;f=true");

        System.clearProperty(ZTSClient.ZTS_CLIENT_PROP_ATHENZ_CONF);
        client.close();
    }

    @Test
    public void testLookupIdTokenResponseInCache() throws InterruptedException {

        final String cacheKey = "idtestkey1";

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);

        assertNull(client.lookupIdTokenResponseInCache(cacheKey, 3600));

        ZTSClient.ID_TOKEN_CACHE.put(cacheKey,
                new OIDCResponse().setId_token("token")
                        .setExpiration_time(System.currentTimeMillis() / 1000 + 3600));

        // with standard 1 hour check, our entry is not expired

        assertNotNull(client.lookupIdTokenResponseInCache(cacheKey, 3600));

        // if we pass null for expiry time, we default to 1 hour

        assertNotNull(client.lookupIdTokenResponseInCache(cacheKey, null));

        // with a 60-hour check, our entry is expired, however our entry
        // will not be removed from the cache

        assertNull(client.lookupIdTokenResponseInCache(cacheKey, 36000));
        assertNotNull(ZTSClient.ID_TOKEN_CACHE.get(cacheKey));

        // add a second entry with 1 second timeout

        ZTSClient.ID_TOKEN_CACHE.put(cacheKey,
                new OIDCResponse().setId_token("token")
                        .setExpiration_time(System.currentTimeMillis() / 1000 + 1));
        // sleep a second and then ask for a cache entry

        Thread.sleep(1000);

        // entry is not returned from lookup and also removed from the cache

        assertNull(client.lookupIdTokenResponseInCache(cacheKey, 3600));
        assertNull(ZTSClient.ID_TOKEN_CACHE.get(cacheKey));
        client.close();
    }

    @Test
    public void testGetIdToken() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.setPrefetchAutoEnable(true);
        client.setEnablePrefetch(true);

        OIDCResponse oidcResponse = client.getIDToken("sports", "readers", "sys.auth.gcp",
                "gcp.athenz.io", true, null);
        assertNotNull(oidcResponse);

        // passing the role name as a list should give us the same token back
        // as we should be caching our results

        OIDCResponse oidcResponse2 = client.getIDToken("sports", Collections.singletonList("readers"), "sys.auth.gcp",
                "gcp.athenz.io", true, null);
        assertNotNull(oidcResponse2);
        assertEquals(oidcResponse, oidcResponse2);

        // now let's pass with the expiry time of 1 hour, and we still should get
        // back the same token from the cache

        oidcResponse2 = client.getIDToken("sports", Collections.singletonList("readers"), "sys.auth.gcp",
                "gcp.athenz.io", true, 3600);
        assertNotNull(oidcResponse2);
        assertEquals(oidcResponse, oidcResponse2);

        // now let's try with the full api and ignore cache disabled

        oidcResponse2 = client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.readers", null, "EC", true, 3600, false);
        assertNotNull(oidcResponse2);
        assertEquals(oidcResponse, oidcResponse2);

        // finally let's try with cached disabled, and we should get a new token

        oidcResponse2 = client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.readers", null, "EC", true, 3600, true);
        assertNotNull(oidcResponse2);
        assertNotEquals(oidcResponse, oidcResponse2);

        client.close();
    }

    @Test
    public void testGetIdTokenMissingArguments() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        try {
            client.getIDToken("", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                    "openid sports:role.readers", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken(null, "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                    "openid sports:role.readers", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken("id_token", "", "https://gcp.sys-auth.gcp.athenz.io",
                    "openid sports:role.readers", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken("id_token", null, "https://gcp.sys-auth.gcp.athenz.io",
                    "openid sports:role.readers", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken("id_token", "sys.auth.gcp", "",
                    "openid sports:role.readers", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken("id_token", "sys.auth.gcp", null,
                    "openid sports:role.readers", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                    "", null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        try {
            client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                    null, null, "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertTrue(ex.getMessage().contains("missing required attribute"));
        }

        client.close();
    }

    @Test
    public void testGetIdTokenExceptions() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        try {
            client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                    "openid sports:role.readers", "zts-403", "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 403);
        }

        try {
            client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                    "openid sports:role.readers", "zts-500", "EC", true, 3600, false);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(ex.getCode(), 400);
        }

        client.close();
    }

    @Test
    public void testPrefetchIdTokenShouldNotCallServer() throws Exception {

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ztsClientMock.setRoleName("role1");

        final Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        Mockito.when(siaProvider.getIdentity(any(),
                any())).thenReturn(principal);

        ZTSClient client = new ZTSClient("http://localhost:4080/", "user_domain",
                "user", siaProvider);
        ZTSClient.setPrefetchInterval(1);
        client.setZTSRDLGeneratedClient(ztsClientMock);
        client.clearScheduledItems();

        // initially, id token was never fetched.
        assertTrue(ztsClientMock.getLastIdTokenFetchedTime("openid sports.api:role.readers") < 0);

        // initialize the prefetch token process.
        client.prefetchIdToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.readers", null, "EC", true, 8);
        int scheduledItemsSize = client.getScheduledItemsSize();

        // make sure only unique items are in the queue
        client.prefetchIdToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.readers", null, "EC", true, 8);
        int scheduledItemsSize2 = client.getScheduledItemsSize();
        assertEquals(scheduledItemsSize, scheduledItemsSize2);

        OIDCResponse oidcResponse = client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.readers", null, "EC", true, 8, false);
        assertNotNull(oidcResponse);
        assertFalse(oidcResponse.getId_token().isEmpty());

        client.prefetchIdToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.writers", null, "EC", true, 8);
        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        OIDCResponse oidcResponse2 = client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.writers", null, "EC", true, 8, false);
        assertNotNull(oidcResponse2);
        long rt2Expiry = oidcResponse2.getExpiration_time();

        System.out.println("testPrefetchIdTokenShouldNotCallServer: sleep Secs=5");
        Thread.sleep(5000);
        System.out.println("testPrefetchIdTokenShouldNotCallServer: nap over so what happened");

        assertEquals(client.getScheduledItemsSize(), scheduledItemsSize + 1);

        long lastTokenFetchedTime1 = ztsClientMock.getLastIdTokenFetchedTime("openid sports:role.readers");
        assertTrue(lastTokenFetchedTime1 > 0);

        oidcResponse2 = client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.writers", null, "EC", true, 8, false);
        long rt2Expiry2 = oidcResponse2.getExpiration_time();

        assertTrue(rt2Expiry2 > rt2Expiry); // this token was refreshed

        // wait a few seconds, and see subsequent fetch happened.
        System.out.println("testPrefetchIdTokenShouldNotCallServer: sleep Secs=5");
        Thread.sleep(5000);
        System.out.println("testPrefetchIdTokenShouldNotCallServer: again nap over so what happened");

        oidcResponse2 = client.getIDToken("id_token", "sys.auth.gcp", "https://gcp.sys-auth.gcp.athenz.io",
                "openid sports:role.writers", null, "EC", true, 8, false);
        long rt2Expiry3 = oidcResponse2.getExpiration_time();
        assertTrue(rt2Expiry3 > rt2Expiry2); // this token was refreshed

        ZTSClient.cancelPrefetch();
        client.close();
    }

    @Test
    public void testPostExternalCredentialsRequest() throws IOException, URISyntaxException {

        ZTSRDLGeneratedClient c = Mockito.mock(ZTSRDLGeneratedClient.class);
        Principal principal = SimplePrincipal.create("user_domain", "user",
                "v=S1;d=user_domain;n=user;s=sig", PRINCIPAL_AUTHORITY);
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(c);

        ExternalCredentialsRequest request = new ExternalCredentialsRequest()
                .setClientId("athenz.api")
                .setExpiryTime(3600);
        ExternalCredentialsResponse response = new ExternalCredentialsResponse();
        Mockito.when(c.postExternalCredentialsRequest(anyString(), anyString(), any()))
                .thenReturn(response)
                .thenThrow(new ZTSClientException(401, "fail"))
                .thenThrow(new IllegalArgumentException("other-error"));

        ExternalCredentialsResponse creds = client.postExternalCredentialsRequest("gcp", "athenz", request);
        assertNotNull(creds);

        // second time it fails

        try {
            client.postExternalCredentialsRequest("gcp", "athenz", request);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(401, ex.getCode());
        }

        // last time with std exception

        try {
            client.postExternalCredentialsRequest("gcp", "athenz", request);
            fail();
        } catch (ZTSClientException ex) {
            assertEquals(400, ex.getCode());
        }
    }

    @Test
    public void testConstructorWithValidProxyUrl() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        ZTSClient client = new ZTSClient("http://localhost:4080/",
                "http://localhost:8080", "iaas.athenz", "ci", siaProvider);
        client.close();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithInvalidProxyUrlException() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);

        ZTSClient client = null;
        try {
            client = new ZTSClient("http://localhost:4080/",
                    "invalid-proxy", "iaas.athenz", "ci", siaProvider);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithProxyUrlNullDomainNameException() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        ZTSClient client = null;

        try {
            client = new ZTSClient("http://localhost:4080/",
                    "http://localhost:8080/", null, "ci", siaProvider);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithProxyUrlNullServiceNameException() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        ZTSClient client = null;

        try {
            client = new ZTSClient("http://localhost:4080/",
                    "http://localhost:8080/", "iaas.athenz", null, siaProvider);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithProxyUrlNullSiaProviderException() {
        ZTSClient client = null;

        try {
            client = new ZTSClient("http://localhost:4080/",
                    "http://localhost:8080/", "iaas.athenz", "ci", null);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithProxyUrlEmptyDomainNameException() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        ZTSClient client = null;

        try {
            client = new ZTSClient("http://localhost:4080/",
                    "http://localhost:8080/", "", "ci", siaProvider);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testConstructorWithProxyUrlEmptyServiceNameException() {
        ServiceIdentityProvider siaProvider = Mockito.mock(ServiceIdentityProvider.class);
        ZTSClient client = null;

        try {
            client = new ZTSClient("http://localhost:4080/",
                    "http://localhost:8080/", "iaas.athenz", "", siaProvider);
        } finally {
            if (client != null) {
                client.close();
            }
        }
    }

    @Test
    public void testGetExceptionCode() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSClient client = new ZTSClient("http://localhost:4080", principal);

        assertEquals(503, client.getExceptionCode(new java.net.UnknownHostException()));
        assertEquals(503, client.getExceptionCode(new java.net.SocketException()));
        assertEquals(503, client.getExceptionCode(new java.net.SocketTimeoutException()));
        assertEquals(400, client.getExceptionCode(new ZTSClientException(403, "Forbidden")));

        client.close();
    }
}
