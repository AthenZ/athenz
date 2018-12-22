/*
 * Copyright 2018 Oath, Inc.
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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class InstanceZTSProviderTest {

    private String servicePublicKeyStringK0 = null;
    private String servicePrivateKeyStringK0 = null;

    @BeforeMethod
    public void setup() throws IOException {
        Path path = Paths.get("./src/test/resources/public_k0.key");
        servicePublicKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/private_k0.key");
        servicePrivateKeyStringK0 = new String(Files.readAllBytes(path));
    }

    @Test
    public void testInitializeDefaults() {
        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertEquals("zts.athenz.cloud", provider.dnsSuffix);
        assertEquals(InstanceProvider.Scheme.CLASS, provider.getProviderScheme());
        assertNull(provider.keyStore);
        assertNull(provider.principals);
        provider.close();
    }

    @Test
    public void testInitialize() {

        System.setProperty(InstanceZTSProvider.ZTS_PROVIDER_DNS_SUFFIX, "zts.cloud");
        System.setProperty(InstanceZTSProvider.ZTS_PRINCIPAL_LIST, "athenz.api,sports.backend");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertEquals("zts.cloud", provider.dnsSuffix);
        assertNull(provider.keyStore);
        assertEquals(provider.principals.size(), 2);
        assertTrue(provider.principals.contains("athenz.api"));
        assertTrue(provider.principals.contains("sports.backend"));
        provider.close();

        System.setProperty(InstanceZTSProvider.ZTS_PROVIDER_DNS_SUFFIX, "");
        System.setProperty(InstanceZTSProvider.ZTS_PRINCIPAL_LIST, "");

        provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertEquals("zts.athenz.cloud", provider.dnsSuffix);
        assertNull(provider.keyStore);
        assertNull(provider.principals);
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROVIDER_DNS_SUFFIX);
    }

    @Test
    public void testRefreshInstance() {

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        try {
            provider.refreshInstance(null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(403, ex.getCode());
        }
        provider.close();
    }

    @Test
    public void testValidateIPAddress() {

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertTrue(provider.validateIPAddress("10.1.1.1", "10.1.1.1"));
        assertTrue(provider.validateIPAddress("10.1.1.1", null));
        assertTrue(provider.validateIPAddress("10.1.1.1", ""));
        assertFalse(provider.validateIPAddress("10.1.1.1", "10.1.1.2"));
        provider.close();
    }

    @Test
    public void testAuthenticate() {

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        StringBuilder errMsg = new StringBuilder(256);

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        String token = "invalidtoken";
        assertNull(provider.authenticate(token, null, servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("Invalid token"));

        errMsg.setLength(0);
        token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1,svc2;s=signature;bk=0;bn=svc1;bs=signature";
        assertNull(provider.authenticate(token, null, servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("authorized service token"));

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        errMsg.setLength(0);
        assertNotNull(provider.authenticate(tokenToSign.getSignedToken(), keystore, servicePublicKeyStringK0, errMsg));

        // test with mismatch public key

        assertNull(provider.authenticate(tokenToSign.getSignedToken(), keystore, "publicKey", errMsg));

        // create invalid signature

        errMsg.setLength(0);
        assertNull(provider.authenticate(tokenToSign.getSignedToken().replace(";s=", ";s=abc"),
                keystore, servicePublicKeyStringK0, errMsg));
        provider.close();
    }

    @Test
    public void testValidateToken() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        StringBuilder errMsg = new StringBuilder(256);

        String token = "invalidtoken";
        assertFalse(provider.validateToken(token, "sports", "api", servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("Invalid token"));

        errMsg.setLength(0);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        errMsg.setLength(0);
        assertTrue(provider.validateToken(tokenToSign.getSignedToken(), "sports", "api",
                servicePublicKeyStringK0, errMsg));

        errMsg.setLength(0);
        assertFalse(provider.validateToken(tokenToSign.getSignedToken(), "sports", "ui",
                servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("service mismatch"));

        errMsg.setLength(0);
        assertFalse(provider.validateToken(tokenToSign.getSignedToken(), "weather", "api",
                servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("domain mismatch"));

        provider.close();
    }

    @Test
    public void testConfirmInstance() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PRINCIPAL_LIST, "sports.api");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceUtils.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceUtils.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceUnsupportedService() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PRINCIPAL_LIST, "sports.api");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "backend")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("backend");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceUtils.ZTS_INSTANCE_SAN_DNS, "backend.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceUtils.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Service not supported to be launched by ZTS Provider"));
        }
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceInvalidIP() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceUtils.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceUtils.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceUtils.ZTS_INSTANCE_SAN_IP, "10.1.1.2");
        attributes.put(InstanceUtils.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate request IP address"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidDNSName() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceUtils.ZTS_INSTANCE_SAN_DNS, "api.weather.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceUtils.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceUtils.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceUtils.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request hostnames"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidToken() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken().replace(";s=", ";s=abc"));
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate Certificate Request Auth Token"));
        }
        provider.close();
    }
}
