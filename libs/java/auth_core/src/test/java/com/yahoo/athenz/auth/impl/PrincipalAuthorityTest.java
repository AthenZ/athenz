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
package com.yahoo.athenz.auth.impl;

import java.lang.reflect.Field;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doReturn;
import static org.testng.Assert.*;

import org.mockito.Mockito;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.Authority.CredSource;
import com.yahoo.athenz.auth.impl.PrincipalAuthority.IpCheckMode;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.CryptoException;

public class PrincipalAuthorityTest {

    private final String svcVersion = "S1";
    private final String svcDomain = "sports";
    private final String svcName = "fantasy";
    private final String host = "somehost.somecompany.com";
    private final String salt = "saltvalue";
    private final String usrVersion = "U1";
    private final String usrDomain = "user";
    private final String usrName = "john";
    
    private final long expirationTime = 10; // 10 seconds
    private String servicePrivateKeyStringK0 = null;
    private String servicePrivateKeyStringK1 = null;

    @BeforeTest
    private void loadKeys() throws IOException {

        Path path = Paths.get("./src/test/resources/unit_test_fantasy_private_k0.key");
        servicePrivateKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/unit_test_fantasy_private_k1.key");
        servicePrivateKeyStringK1 = new String(Files.readAllBytes(path));
    }
    
    @SuppressWarnings("ConstantConditions")
    private String tamperWithServiceToken(String signedToken) {
        String version = null;
        String salt = null;
        String domain = null;
        String host = null;
        String signature = null;
        long timestamp = 0;
        long expiryTime = 0;

        for (String item : signedToken.split(";")) {
            String[] kv = item.split("=");
            if (kv.length == 2) {
                if ("v".equals(kv[0])) {
                    version = kv[1];
                } else if ("a".equals(kv[0])) {
                    salt = kv[1];
                } else if ("d".equals(kv[0])) {
                    domain = kv[1];
                } else if ("h".equals(kv[0])) {
                    host = kv[1];
                } else if ("s".equals(kv[0])) {
                    signature = kv[1];
                } else if ("t".equals(kv[0])) {
                    timestamp = Long.parseLong(kv[1]);
                } else if ("e".equals(kv[0])) {
                    expiryTime = Long.parseLong(kv[1]);
                }
            }
        }

        final String name = "nfl"; // tamper here by changing the name

        return "v=" + version + ";d=" + domain
                + ";n=" + name + ";h=" + host + ";a=" + salt + ";t="
                + timestamp + ";e=" + expiryTime
                + ";s=" + signature;
    }

    @Test
    public void testPrincipalAuthority() throws IOException, CryptoException {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        assertNull(serviceAuthority.getDomain());
        assertEquals(serviceAuthority.getHeader(), "Athenz-Principal-Auth");

        // Create and sign token with no key version
        PrincipalToken serviceToken = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).build();
        serviceToken.sign(servicePrivateKeyStringK0);

        StringBuilder errMsg = new StringBuilder();
        Principal principal = serviceAuthority.authenticate(
                serviceToken.getSignedToken(), null, "GET", errMsg);

        assertNotNull(principal);
        assertNotNull(principal.getAuthority());
        assertEquals(principal.getCredentials(), serviceToken.getSignedToken());
        assertEquals(principal.getDomain(), serviceToken.getDomain());
        assertEquals(principal.getName(), serviceToken.getName());
        assertEquals(principal.getKeyId(), "0");
        
        principal = serviceAuthority.authenticate(
                serviceToken.getSignedToken(), null, "GET", null);
        assertNotNull(principal);
        
        // Create and sign token with key version 0
        String testKeyVersionK0 = "0";
        serviceToken = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
                .host(host).salt(salt).expirationWindow(expirationTime)
                .keyId(testKeyVersionK0).build();
        serviceToken.sign(servicePrivateKeyStringK0);

        principal = serviceAuthority.authenticate(serviceToken.getSignedToken(), null, "GET", errMsg);
        
        assertNotNull(principal);
        assertEquals(principal.getCredentials(), serviceToken.getSignedToken());
        
        // Create and sign token with key version 1
        String testKeyVersionK1 = "1";
        serviceToken = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).keyId(testKeyVersionK1).build();
        serviceToken.sign(servicePrivateKeyStringK1);

        principal = serviceAuthority.authenticate(serviceToken.getSignedToken(), null, "GET", errMsg);
        
        assertNotNull(principal);
        assertEquals(principal.getCredentials(), serviceToken.getSignedToken());
    }

    @Test
    public void testPrincipalAuthority_TamperedToken() throws IOException,
            CryptoException {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        // Create and sign token
        PrincipalToken serviceToken = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).build();
        serviceToken.sign(servicePrivateKeyStringK0);

        String tokenToTamper = serviceToken.getSignedToken();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = serviceAuthority.authenticate(
                tamperWithServiceToken(tokenToTamper), null, "GET", errMsg);

        // Service Authority should return null when authenticate() fails
        assertNull(principal);
        assertFalse(errMsg.toString().isEmpty());
        assertTrue(errMsg.toString().contains("authenticate"));

        principal = serviceAuthority.authenticate(
                tamperWithServiceToken(tokenToTamper), null, "GET", null);
        assertNull(principal);
    }
    
    @Test
    public void testPrincipalAuthorityWithAuthorizedService() throws IOException, CryptoException {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);
        
        // Create and sign token with key version 0
        
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");
        authorizedServices.add("sports.hockey");
        
        long issueTime = System.currentTimeMillis() / 1000;
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).ip("127.0.0.2").issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);
        
        // now let's sign the token for an authorized service
        
        userTokenToSign.signForAuthorizedService("sports.fantasy", "1", servicePrivateKeyStringK1);
        
        // we're going to pass a different IP so we get the authorized service checks
        
        StringBuilder errMsg = new StringBuilder();
        Principal principal = serviceAuthority.authenticate(userTokenToSign.getSignedToken(),
                "127.0.0.3", "POST", errMsg);
        
        assertNotNull(principal);
        assertEquals(principal.getAuthorizedService(), "sports.fantasy");
    }

    @Test
    public void testGetID() {
        PrincipalAuthority authority = new PrincipalAuthority();
        assertEquals("Auth-NTOKEN", authority.getID());
    }

    @Test
    public void testPrincipalAuthorityWithAuthorizedServiceInvalid() throws IOException, CryptoException {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        // Create and sign token with key version 0

        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");
        authorizedServices.add("sports.hockey");

        long issueTime = System.currentTimeMillis() / 1000;
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).ip("127.0.0.2").issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // we're going to pass a different IP so we get the authorized service checks
        // but it should fail since there is no service signature

        StringBuilder errMsg = new StringBuilder();
        Principal principal = serviceAuthority.authenticate(userTokenToSign.getSignedToken(),
                "127.0.0.3", "POST", errMsg);

        assertNull(principal);
    }

    @Test
    public void testValidateAuthorizedServiceSingle() throws IOException {
        
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");
        
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);
        
        // now let's sign the token for an authorized service
        
        userTokenToSign.signForAuthorizedService("sports.fantasy", "1", servicePrivateKeyStringK1);
        
        // Create a token for validation using the signed data
        assertEquals(serviceAuthority.validateAuthorizeService(userTokenToSign, null), "sports.fantasy");
    }
    
    @Test
    public void testValidateAuthorizedServiceMultiple() throws IOException {
        
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");
        authorizedServices.add("sports.hockey");
        
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);
        
        // now let's sign the token for an authorized service
        
        userTokenToSign.signForAuthorizedService("sports.fantasy", "1", servicePrivateKeyStringK1);
        
        // Create a token for validation using the signed data
        StringBuilder errMsg = new StringBuilder();
        assertEquals(serviceAuthority.validateAuthorizeService(userTokenToSign, errMsg), "sports.fantasy");
    }
    
    @Test
    public void testValidateAuthorizedServiceNoServices() throws IOException {
        
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);
        
        // Create a token for validation using the signed data
        StringBuilder errMsg = new StringBuilder();
        assertNull(serviceAuthority.validateAuthorizeService(userTokenToSign, errMsg));
    }
    
    @Test
    public void testValidateAuthorizedServiceNoSignature() throws IOException {
        
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");
        authorizedServices.add("media.storage");
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).authorizedServices(authorizedServices)
            .expirationWindow(expirationTime).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);
        
        // Create a token for validation using the signed data
        StringBuilder errMsg = new StringBuilder();
        assertNull(serviceAuthority.validateAuthorizeService(userTokenToSign, errMsg));
    }
    
    @Test
    public void testGetAuthorizedServiceNameMultipleServices() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");
        authorizedServices.add("media.storage");
        assertNull(serviceAuthority.getAuthorizedServiceName(authorizedServices, null));
        assertNull(serviceAuthority.getAuthorizedServiceName(authorizedServices, "sports.storage"));
        assertEquals(serviceAuthority.getAuthorizedServiceName(authorizedServices, "coretech.storage"),
                "coretech.storage");
    }
    
    @Test
    public void testGetAuthorizedServiceNameSingleServices() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");
        assertEquals(serviceAuthority.getAuthorizedServiceName(authorizedServices, null), "coretech.storage");
        assertNull(serviceAuthority.getAuthorizedServiceName(authorizedServices, "sports.storage"));
        assertEquals(serviceAuthority.getAuthorizedServiceName(authorizedServices, "coretech.storage"),
                "coretech.storage");
    }
    
    @Test
    public void testIsWriteOperation() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        assertTrue(serviceAuthority.isWriteOperation("PUT"));
        assertTrue(serviceAuthority.isWriteOperation("put"));
        assertTrue(serviceAuthority.isWriteOperation("Post"));
        assertTrue(serviceAuthority.isWriteOperation("POST"));
        assertTrue(serviceAuthority.isWriteOperation("DeLete"));
        assertTrue(serviceAuthority.isWriteOperation("DELETE"));
        assertFalse(serviceAuthority.isWriteOperation("GET"));
        assertFalse(serviceAuthority.isWriteOperation("Get"));
        assertFalse(serviceAuthority.isWriteOperation("HEAD"));
        assertFalse(serviceAuthority.isWriteOperation(null));
        assertFalse(serviceAuthority.isWriteOperation("Unknown"));
        assertFalse(serviceAuthority.isWriteOperation(""));
    }
    
    @Test
    public void testGetCredSource() {
        PrincipalAuthority authority = new PrincipalAuthority();
        authority.initialize();
        assertEquals(CredSource.HEADER, authority.getCredSource());
    }
    
    @Test
    public void testGetPublicKeyKeyServiceZms() {
        
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);
        
        Mockito.when(keyStore.getPublicKey("sys.auth", "zms", "v1")).thenReturn("zms-key");
        Mockito.when(keyStore.getPublicKey("athenz", "svc", "v1")).thenReturn("athenz-key");

        String key = serviceAuthority.getPublicKey("athenz", "svc", "zms", "v1", false);
        assertEquals(key, "zms-key");
    }
    
    @Test
    public void testGetPublicKeyKeyServiceZts() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);
        
        Mockito.when(keyStore.getPublicKey("sys.auth", "zms", "v1")).thenReturn("zms-key");
        Mockito.when(keyStore.getPublicKey("sys.auth", "zts", "v1")).thenReturn("zts-key");
        Mockito.when(keyStore.getPublicKey("athenz", "svc", "v1")).thenReturn("athenz-key");

        String key = serviceAuthority.getPublicKey("athenz", "svc", "zts", "v1", false);
        assertEquals(key, "zts-key");
    }
    
    @Test
    public void testGetPublicKeyKeyServiceInvalid() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);
        
        Mockito.when(keyStore.getPublicKey("sys.auth", "zms", "v1")).thenReturn("zms-key");
        Mockito.when(keyStore.getPublicKey("sys.auth", "zts", "v1")).thenReturn("zts-key");
        Mockito.when(keyStore.getPublicKey("athenz", "svc", "v1")).thenReturn("athenz-key");

        String key = serviceAuthority.getPublicKey("athenz", "svc", "bondo", "v1", false);
        assertEquals(key, "athenz-key");
    }
    
    @Test
    public void testGetPublicKeyKeyServiceEmpty() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);
        
        Mockito.when(keyStore.getPublicKey("sys.auth", "zms", "v1")).thenReturn("zms-key");
        Mockito.when(keyStore.getPublicKey("sys.auth", "zts", "v1")).thenReturn("zts-key");
        Mockito.when(keyStore.getPublicKey("athenz", "svc", "v1")).thenReturn("athenz-key");

        String key = serviceAuthority.getPublicKey("athenz", "svc", "", "v1", false);
        assertEquals(key, "athenz-key");
    }
    
    @Test
    public void testGetPublicKeyUserToken() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);
        
        Mockito.when(keyStore.getPublicKey("sys.auth", "zms", "v1")).thenReturn("zms-key");
        Mockito.when(keyStore.getPublicKey("sys.auth", "zts", "v1")).thenReturn("zts-key");
        Mockito.when(keyStore.getPublicKey("athenz", "svc", "v1")).thenReturn("athenz-key");

        String key = serviceAuthority.getPublicKey("athenz", "svc", null, "v1", true);
        assertEquals(key, "zms-key");
    }
    
    @Test
    public void testGetPublicKeyDefault() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);
        
        Mockito.when(keyStore.getPublicKey("sys.auth", "zms", "v1")).thenReturn("zms-key");
        Mockito.when(keyStore.getPublicKey("sys.auth", "zts", "v1")).thenReturn("zts-key");
        Mockito.when(keyStore.getPublicKey("cd.step", "sd10000", "v1")).thenReturn("cd-key");
        Mockito.when(keyStore.getPublicKey("athenz", "svc", "v1")).thenReturn("athenz-key");

        String key = serviceAuthority.getPublicKey("athenz", "svc", null, "v1", false);
        assertEquals(key, "athenz-key");
    }
    
    @Test
    public void testRemoteIpCheckAll() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        serviceAuthority.ipCheckMode = IpCheckMode.OPS_ALL;
        
        PrincipalToken serviceToken = new PrincipalToken("v=S1;d=domain;n=service;i=10.11.12.23;s=sig");
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.23", false, serviceToken, null));
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.23", true, serviceToken, null));
        assertFalse(serviceAuthority.remoteIpCheck("10.11.12.22", false, serviceToken, null));
        assertFalse(serviceAuthority.remoteIpCheck("10.11.12.22", true, serviceToken, null));
    }
    
    @Test
    public void testRemoteIpCheckWrite() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        serviceAuthority.ipCheckMode = IpCheckMode.OPS_WRITE;
        
        PrincipalToken serviceToken = new PrincipalToken("v=S1;d=user;n=user1;i=10.11.12.23;s=sig");
        
        // first let's verify read operation with and without matches
       
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.23", false, serviceToken, null));
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.22", false, serviceToken, null));
        
        // now let's try write operations without authorized service
        
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.23", true, serviceToken, null));
        assertFalse(serviceAuthority.remoteIpCheck("10.11.12.22", true, serviceToken, null));
        
        // finally mismatch operation with authorized service
        
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.22", true, serviceToken, "authz_service"));
    }
    
    @Test
    public void testRemoteIpCheckNone() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        serviceAuthority.ipCheckMode = IpCheckMode.OPS_NONE;
        
        PrincipalToken serviceToken = new PrincipalToken("v=S1;d=user;n=user1;i=10.11.12.23;s=sig");
        
        // all operations must return true
        
        // first let's verify read operation with and without matches
       
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.23", false, serviceToken, null));
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.22", false, serviceToken, null));
        
        // now let's try write operations without authorized service
        
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.23", true, serviceToken, null));
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.22", true, serviceToken, null));
        
        // finally mismatch operation with authorized service
        
        assertTrue(serviceAuthority.remoteIpCheck("10.11.12.22", true, serviceToken, "authz_service"));
    }

    @Test
    public void testAuthenticateIllegal() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();

        Principal principal = serviceAuthority.authenticate("aaaa", null, "GET", null);
        assertNull(principal);
    }

    @Test
    public void testInitialize()
            throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        Class<PrincipalAuthority> c = PrincipalAuthority.class;
        PrincipalAuthority principalAuthority = new PrincipalAuthority();
        System.setProperty(PrincipalAuthority.ATHENZ_PROP_TOKEN_OFFSET, "-1");

        principalAuthority.initialize();
        Field f1 = c.getDeclaredField("allowedOffset");
        f1.setAccessible(true);
        int m = (Integer) f1.get(principalAuthority);

        assertEquals(m, 300);
        assertEquals(principalAuthority.userDomain, "user");
    }

    @Test
    public void testValidateAuthorizedIlligalServiceName() throws IOException {

        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add(".fantasy");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service
        userTokenToSign.signForAuthorizedService(".fantasy", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data
        StringBuilder errMsg = new StringBuilder();
        assertNull(serviceAuthority.validateAuthorizeService(userTokenToSign, errMsg));
    }

    @Test
    public void testValidateAuthorizedIlligalForAuthorizedService() {

        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);

        Mockito.when(keyStore.getPublicKey("sports", "fantasy", "1")).thenReturn(null);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service
        userTokenToSign.signForAuthorizedService("sports.fantasy", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data
        StringBuilder errMsg = new StringBuilder();
        assertNull(serviceAuthority.validateAuthorizeService(userTokenToSign, errMsg));
    }

    @Test
    public void testPrincipalAuthorityAuthenticateIlligal() throws CryptoException {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = Mockito.mock(KeyStore.class);
        serviceAuthority.setKeyStore(keyStore);

        String t = "v=S1;d=domain;n=hoge;bs=aaaa;s=signature";

        Principal check = serviceAuthority.authenticate(t, "10", "10", null);
        assertNull(check);
    }

    @Test
    public void testGetAuthenticateChallenge() {
        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        assertEquals(serviceAuthority.getAuthenticateChallenge(), "AthenzPrincipalToken realm=\"athenz\"");
    }

    @Test
    public void testPrincipalAuthorityWithNullAuthorizedService() throws IOException {
        PrincipalAuthority authority = new PrincipalAuthority();
        PrincipalAuthority serviceAuthority = Mockito.spy(authority);
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        // Create and sign token with key version 0

        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");
        authorizedServices.add("sports.hockey");

        long issueTime = System.currentTimeMillis() / 1000;
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).ip("127.0.0.2").issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("sports.fantasy", "1", servicePrivateKeyStringK1);

        // we're going to pass a different IP so we get the authorized service checks

        doReturn(null).when(serviceAuthority).validateAuthorizeService(any(), any());
        StringBuilder errMsg = new StringBuilder();
        Principal principal = serviceAuthority.authenticate(userTokenToSign.getSignedToken(),
                "127.0.0.3", "POST", errMsg);

        assertNull(principal);
    }

    @Test
    public void testAuthenticateWithRemoteIpCheck() throws IOException {
        PrincipalAuthority authority = new PrincipalAuthority();
        PrincipalAuthority serviceAuthority = Mockito.spy(authority);
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        // Create and sign token with key version 0

        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("sports.fantasy");
        authorizedServices.add("sports.hockey");

        long issueTime = System.currentTimeMillis() / 1000;
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).ip("127.0.0.2").issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("sports.fantasy", "1", servicePrivateKeyStringK1);

        // we're going to pass a different IP so we get the authorized service checks

        doReturn(false).when(serviceAuthority).remoteIpCheck(anyString(), anyBoolean(), any(), any());
        StringBuilder errMsg = new StringBuilder();
        Principal principal = serviceAuthority.authenticate(userTokenToSign.getSignedToken(),
                "127.0.0.3", "POST", errMsg);

        assertNull(principal);
    }

//    @Test
    public void testPrincipalTokenValidateForAuthorizedService() throws IOException {

        PrincipalAuthority serviceAuthority = new PrincipalAuthority();
        KeyStore keyStore = new KeyStoreMock();
        serviceAuthority.setKeyStore(keyStore);

        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("test.fantasy");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("test.fantasy", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data
        serviceAuthority.validateAuthorizeService(userTokenToSign, null);
    }
}
