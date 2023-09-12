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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import com.yahoo.athenz.zts.InstanceRegisterToken;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider.*;
import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class InstanceZTSProviderTest {

    private String servicePublicKeyStringK0 = null;
    private String servicePrivateKeyStringK0 = null;

    @BeforeMethod
    public void setup() throws IOException {
        Path path = Paths.get("./src/test/resources/public_k0.key");
        servicePublicKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/unit_test_private_k0.key");
        servicePrivateKeyStringK0 = new String(Files.readAllBytes(path));
    }

    @Test
    public void testInitializeDefaults() {
        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.athenz.cloud"));
        assertEquals(InstanceProvider.Scheme.CLASS, provider.getProviderScheme());
        assertNull(provider.keyStore);
        assertNull(provider.principals);
        provider.close();
    }

    @Test
    public void testInitialize() {

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PROVIDER_DNS_SUFFIX, "zts.cloud");
        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "athenz.api,sports.backend");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.cloud"));
        assertNull(provider.keyStore);
        assertEquals(provider.principals.size(), 2);
        assertTrue(provider.principals.contains("athenz.api"));
        assertTrue(provider.principals.contains("sports.backend"));
        provider.close();

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PROVIDER_DNS_SUFFIX, "");
        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "");

        provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertTrue(provider.dnsSuffixes.contains("zts.athenz.cloud"));
        assertNull(provider.keyStore);
        assertNull(provider.principals);
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PROVIDER_DNS_SUFFIX);
    }

    @Test
    public void testRefreshInstance() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.refreshInstance(confirmation));
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testValidateSanIp() {

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertTrue(provider.validateSanIp(new String[]{"10.1.1.1"}, "10.1.1.1"));
        assertTrue(provider.validateSanIp(null, "10.1.1.1"));
        assertTrue(provider.validateSanIp(new String[]{}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{""}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.2"}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.2"}, null));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.2"}, ""));

        // ipv6
        assertTrue(provider.validateSanIp(new String[]{"2001:db8:a0b:12f0:0:0:0:1"}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertTrue(provider.validateSanIp(null, "2001:db8:a0b:12f0:0:0:0:1"));
        assertTrue(provider.validateSanIp(new String[]{}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, "10.1.1.1"));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, null));
        assertFalse(provider.validateSanIp(new String[]{"2002:db9:a0b:12f0:0:0:0:1"}, ""));

        // ipv4 and ipv6 mixed
        assertTrue(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, "10.1.1.1"));
        assertTrue(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, "2001:db8:a0b:12f0:0:0:0:1"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, "10.1.1.2"));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, null));
        assertFalse(provider.validateSanIp(new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}, ""));

        provider.close();
    }

    @Test
    public void testValidateHostname() {
        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.getAllByName("abc.athenz.com"))
               .thenReturn(new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1")));

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        provider.setHostnameResolver(hostnameResolver);

        assertTrue(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.1"}));
        assertTrue(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.2"}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.1", "1:2:3:4:5:6:7:8"}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{"10.1.1.2", "1:2:3:4:5:6:7:8"}));

        // If hostname is passed, sanIp must be non empty
        assertFalse(provider.validateHostname("abc.athenz.com", null));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{}));
        assertFalse(provider.validateHostname("abc.athenz.com", new String[]{""}));

        // It's possible client didn't set Hostname payload. One sanIp be optionally set, and would have been matched with clientIp upstream
        assertTrue(provider.validateHostname("", new String[]{"10.1.1.1"}));
        assertTrue(provider.validateHostname(null, new String[]{"10.1.1.1"}));

        // If more than one sanIp is passed, hostname must be non empty
        assertFalse(provider.validateHostname(null, new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}));
        assertFalse(provider.validateHostname("", new String[]{"10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"}));

        provider.close();
    }

    @Test
    public void testValidateSanUri() {
        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);
        assertTrue(provider.validateSanUri("athenz://hostname/abc.athenz.com", "abc.athenz.com"));
        assertTrue(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com", "abc.athenz.com"));
        assertTrue(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com,athenz://instanceid/zts/abc.athenz.com", "abc.athenz.com"));
        assertTrue(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com,athenz://hostname/abc.athenz.com", "abc.athenz.com"));

        assertTrue(provider.validateSanUri("", "abc.athenz.com"));
        assertTrue(provider.validateSanUri(null, "abc.athenz.com"));

        assertFalse(provider.validateSanUri("athenz://hostname/abc.athenz.cm", "def.athenz.com"));
        assertFalse(provider.validateSanUri("spiffe://movies/sa/writer,    athenz://hostname/abc.athenz.cm", "def.athenz.com"));
        assertFalse(provider.validateSanUri("spiffe://movies/sa/writer,athenz://hostname/abc.athenz.com,athenz://hostname/def.athenz.com", "abc.athenz.com"));
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

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
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
        assertFalse(provider.validateServiceToken(token, "sports", "api", servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("Invalid token"));

        errMsg.setLength(0);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        errMsg.setLength(0);
        assertTrue(provider.validateServiceToken(tokenToSign.getSignedToken(), "sports", "api",
                servicePublicKeyStringK0, errMsg));

        errMsg.setLength(0);
        assertFalse(provider.validateServiceToken(tokenToSign.getSignedToken(), "sports", "ui",
                servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("service mismatch"));

        errMsg.setLength(0);
        assertFalse(provider.validateServiceToken(tokenToSign.getSignedToken(), "weather", "api",
                servicePublicKeyStringK0, errMsg));
        assertTrue(errMsg.toString().contains("domain mismatch"));

        provider.close();
    }

    @Test
    public void testConfirmInstance() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceUnsupportedService() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "backend")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("backend");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "backend.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("Service not supported to be launched by ZTS Provider"));
        }
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceValidHostname() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1,2001:db8:a0b:12f0:0:0:0:1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/zts/hostabc.athenz.com,athenz://hostname/hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
    }

    @Test
    public void testConfirmInstanceValidHostnameIpv6() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(
                new HashSet<>(Arrays.asList("10.1.1.1", "2001:db8:a0b:12f0:0:0:0:1"))
        );

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "2001:db8:a0b:12f0:0:0:0:1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1,2001:db8:a0b:12f0:0:0:0:1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/zts/hostabc.athenz.com,athenz://hostname/hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
    }

    @Test
    public void testConfirmInstanceUnknownHostname() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(new HashSet<>(Collections.singletonList("10.1.1.2")));

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request hostname"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidHostnameUri() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        HostnameResolver hostnameResolver = Mockito.mock(HostnameResolver.class);
        Mockito.when(hostnameResolver.isValidHostname("hostabc.athenz.com")).thenReturn(true);
        Mockito.when(hostnameResolver.getAllByName("hostabc.athenz.com")).thenReturn(new HashSet<>(Collections.singletonList("10.1.1.1")));

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.setHostnameResolver(hostnameResolver);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_HOSTNAME, "hostabc.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_URI, "athenz://instanceid/zts/def.athenz.com,athenz://hostname/def.athenz.com");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request URI hostname"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidIP() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.2");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
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

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
                .keyId("v0").salt("salt").issueTime(System.currentTimeMillis() / 1000)
                .expirationWindow(3600).build();
        tokenToSign.sign(servicePrivateKeyStringK0);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(tokenToSign.getSignedToken());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.weather.zts.athenz.cloud,inst1.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CLIENT_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_IP, "10.1.1.1");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        confirmation.setAttributes(attributes);

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 403);
            assertTrue(ex.getMessage().contains("validate certificate request DNS"));
        }
        provider.close();
    }

    @Test
    public void testConfirmInstanceInvalidToken() {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);

        PrincipalToken tokenToSign = new PrincipalToken.Builder("S1", "sports", "api")
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

    @Test
    public void testGetInstanceRegisterToken() throws IOException {

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("provider", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, null);

        Path path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        final String keyPem = new String(Files.readAllBytes(path));

        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);
        provider.setPrivateKey(privateKey, "k0", SignatureAlgorithm.ES256);

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        confirmation.setAttributes(attrs);

        InstanceRegisterToken token = provider.getInstanceRegisterToken(confirmation);
        assertNotNull(token.getAttestationData());
        provider.close();
    }

    @Test
    public void testConfirmInstanceWithRegisterToken() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        // get our private key now

        path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        keyPem = new String(Files.readAllBytes(path));

        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);
        provider.setPrivateKey(privateKey, "k0", SignatureAlgorithm.ES256);

        InstanceConfirmation tokenConfirmation = new InstanceConfirmation();
        tokenConfirmation.setDomain("sports");
        tokenConfirmation.setService("api");
        tokenConfirmation.setProvider("sys.auth.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        tokenConfirmation.setAttributes(attrs);

        InstanceRegisterToken token = provider.getInstanceRegisterToken(tokenConfirmation);

        // generate instance confirmation

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(token.getAttestationData());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,id001.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        attributes.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        confirmation.setAttributes(attributes);

        assertNotNull(provider.confirmInstance(confirmation));
        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testValidateRegisterTokenMismatchFields() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        // get our private key now

        path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        keyPem = new String(Files.readAllBytes(path));

        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);
        provider.setPrivateKey(privateKey, "k0", SignatureAlgorithm.ES256);

        InstanceConfirmation tokenConfirmation = new InstanceConfirmation();
        tokenConfirmation.setDomain("sports");
        tokenConfirmation.setService("api");
        tokenConfirmation.setProvider("sys.auth.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        tokenConfirmation.setAttributes(attrs);

        InstanceRegisterToken token = provider.getInstanceRegisterToken(tokenConfirmation);

        // now let's use the validate method for specific cases

        StringBuilder errMsg = new StringBuilder();
        assertFalse(provider.validateRegisterToken(token.getAttestationData(),
                "weather", "api", "id001", false, errMsg));
        assertTrue(errMsg.toString().contains("invalid domain name"));

        // next service mismatch

        errMsg.setLength(0);
        assertFalse(provider.validateRegisterToken(token.getAttestationData(),
                "sports", "backend", "id001", false, errMsg));
        assertTrue(errMsg.toString().contains("invalid service name"));

        // invalid instance id

        errMsg.setLength(0);
        assertFalse(provider.validateRegisterToken(token.getAttestationData(),
                "sports", "api", "id002", false, errMsg));
        assertTrue(errMsg.toString().contains("invalid instance id"));

        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceWithRegisterTokenMismatchProvider() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api,weather.api,sports.backend");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("athenz.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        // get our private key now

        path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        keyPem = new String(Files.readAllBytes(path));

        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);
        provider.setPrivateKey(privateKey, "k0", SignatureAlgorithm.ES256);

        InstanceConfirmation tokenConfirmation = new InstanceConfirmation();
        tokenConfirmation.setDomain("sports");
        tokenConfirmation.setService("api");
        tokenConfirmation.setProvider("sys.auth.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        tokenConfirmation.setAttributes(attrs);

        InstanceRegisterToken token = provider.getInstanceRegisterToken(tokenConfirmation);

        // generate instance confirmation

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setAttestationData(token.getAttestationData());
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,id001.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        attributes.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        confirmation.setAttributes(attributes);

        // provider mismatch

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
        }

        // calling validation directly should fail as well

        StringBuilder errMsg = new StringBuilder();
        assertFalse(provider.validateRegisterToken(token.getAttestationData(),
                "sports", "api", "id001", false, errMsg));
        assertTrue(errMsg.toString().contains("token audience is not ZTS provider"));

        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testValidateRegisterTokenMismatchProvider() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api,weather.api,sports.backend");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        // get our private key now

        path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        keyPem = new String(Files.readAllBytes(path));

        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);
        provider.setPrivateKey(privateKey, "k0", SignatureAlgorithm.ES256);

        InstanceConfirmation tokenConfirmation = new InstanceConfirmation();
        tokenConfirmation.setDomain("sports");
        tokenConfirmation.setService("api");
        tokenConfirmation.setProvider("athenz.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        tokenConfirmation.setAttributes(attrs);

        InstanceRegisterToken token = provider.getInstanceRegisterToken(tokenConfirmation);

        // calling validation directly should fail with invalid provider

        StringBuilder errMsg = new StringBuilder();
        assertFalse(provider.validateRegisterToken(token.getAttestationData(),
                "sports", "api", "id001", false, errMsg));
        assertTrue(errMsg.toString().contains("invalid provider name"));

        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testConfirmInstanceEmptyCredentials() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        InstanceConfirmation tokenConfirmation = new InstanceConfirmation();
        tokenConfirmation.setDomain("sports");
        tokenConfirmation.setService("api");
        tokenConfirmation.setProvider("sys.auth.zts");
        Map<String, String> attrs = new HashMap<>();
        attrs.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        tokenConfirmation.setAttributes(attrs);

        // generate instance confirmation

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("sports");
        confirmation.setService("api");
        confirmation.setProvider("sys.auth.zts");

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_INSTANCE_SAN_DNS, "api.sports.zts.athenz.cloud,id001.instanceid.athenz.zts.athenz.cloud");
        attributes.put(InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY, servicePublicKeyStringK0);
        attributes.put(InstanceProvider.ZTS_INSTANCE_ID, "id001");
        confirmation.setAttributes(attributes);

        // provider mismatch

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Service credentials not provided"));
        }

        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testValidateRegisterTokenNullIssueDate() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        keyPem = new String(Files.readAllBytes(path));
        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);

        // first generate token with no issue date

        final String registerToken = Jwts.builder()
                .setId("001")
                .setSubject("sports.api")
                .setIssuer("sys.auth.zts")
                .setAudience("sys.auth.zts")
                .claim(CLAIM_PROVIDER, "sys.auth.zts")
                .claim(CLAIM_DOMAIN, "sports")
                .claim(CLAIM_SERVICE, "api")
                .claim(CLAIM_INSTANCE_ID, "id001")
                .claim(CLAIM_CLIENT_ID, "user.athenz")
                .setHeaderParam(HDR_KEY_ID, "k0")
                .setHeaderParam(HDR_TOKEN_TYPE, HDR_TOKEN_JWT)
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();


        // with register instance enabled, this is going to be reject since
        // there is no issue date

        StringBuilder errMsg = new StringBuilder();
        assertFalse(provider.validateRegisterToken(registerToken,
                "sports", "api", "id001", true, errMsg));
        assertTrue(errMsg.toString().contains("token is already expired, issued at: null"));

        // with refresh option it's going to be skipped

        errMsg.setLength(0);
        assertTrue(provider.validateRegisterToken(registerToken,
                "sports", "api", "id001", false, errMsg));

        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }

    @Test
    public void testValidateRegisterTokenExpiredIssueDate() throws IOException {

        KeyStore keystore = Mockito.mock(KeyStore.class);
        Mockito.when(keystore.getPublicKey("sports", "api", "v0")).thenReturn(servicePublicKeyStringK0);

        System.setProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST, "sports.api");

        // get our ec public key

        Path path = Paths.get("./src/test/resources/unit_test_ec_public.key");
        String keyPem = new String(Files.readAllBytes(path));
        PublicKey publicKey = Crypto.loadPublicKey(keyPem);

        InstanceZTSProvider provider = new InstanceZTSProvider();
        provider.initialize("sys.auth.zts", "com.yahoo.athenz.instance.provider.impl.InstanceZTSProvider", null, keystore);
        provider.signingKeyResolver.addPublicKey("k0", publicKey);

        path = Paths.get("./src/test/resources/unit_test_ec_private.key");
        keyPem = new String(Files.readAllBytes(path));
        PrivateKey privateKey = Crypto.loadPrivateKey(keyPem);

        // first generate token with no issue date

        Instant issueTime = Instant.ofEpochMilli(System.currentTimeMillis() -
                TimeUnit.MINUTES.toMillis(31));
        Date issueDate = Date.from(issueTime);

        final String registerToken = Jwts.builder()
                .setId("001")
                .setSubject("sports.api")
                .setIssuedAt(issueDate)
                .setIssuer("sys.auth.zts")
                .setAudience("sys.auth.zts")
                .claim(CLAIM_PROVIDER, "sys.auth.zts")
                .claim(CLAIM_DOMAIN, "sports")
                .claim(CLAIM_SERVICE, "api")
                .claim(CLAIM_INSTANCE_ID, "id001")
                .claim(CLAIM_CLIENT_ID, "user.athenz")
                .setHeaderParam(HDR_KEY_ID, "k0")
                .setHeaderParam(HDR_TOKEN_TYPE, HDR_TOKEN_JWT)
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();


        // with register instance enabled, this is going to be reject since
        // there is no issue date

        StringBuilder errMsg = new StringBuilder();
        assertFalse(provider.validateRegisterToken(registerToken,
                "sports", "api", "id001", true, errMsg));
        assertTrue(errMsg.toString().contains("token is already expired, issued at: " + issueDate));

        // with refresh option it's going to be skipped

        errMsg.setLength(0);
        assertTrue(provider.validateRegisterToken(registerToken,
                "sports", "api", "id001", false, errMsg));

        provider.close();
        System.clearProperty(InstanceZTSProvider.ZTS_PROP_PRINCIPAL_LIST);
    }
}
