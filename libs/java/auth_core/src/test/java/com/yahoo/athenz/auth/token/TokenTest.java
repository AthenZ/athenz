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
package com.yahoo.athenz.auth.token;

import static org.mockito.Mockito.doReturn;
import static org.testng.Assert.*;

import java.security.PublicKey;
import java.util.concurrent.TimeUnit;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.mockito.Mockito;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.CryptoException;

public class TokenTest {

    private final String svcVersion = "S1";
    private final String svcDomain = "sports";
    private final String svcName = "fantasy";
    private final String host = "somehost.somecompany.com";
    private final String salt = "saltstring";

    private final long expirationTime = 10; // 10 seconds
    
    private String servicePrivateKeyStringK0 = null;
    private String servicePrivateKeyStringK1 = null;
    private String servicePublicKeyStringK0 = null;

    @BeforeTest
    private void loadKeys() throws IOException {

        Path path = Paths.get("./src/test/resources/unit_test_fantasy_private_k0.key");
        servicePrivateKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/fantasy_public_k0.key");
        servicePublicKeyStringK0 = new String(Files.readAllBytes(path));
        
        path = Paths.get("./src/test/resources/unit_test_fantasy_private_k1.key");
        servicePrivateKeyStringK1 = new String(Files.readAllBytes(path));
    }
    
    @Test
    public void testTokenValidateNullSignature() throws CryptoException {
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).build();
        
        assertFalse(token.validate(servicePublicKeyStringK0, 3600, false));
        assertFalse(token.validate(servicePublicKeyStringK0, 3600, false, null));

        StringBuilder errMsg = new StringBuilder();
        assertFalse(token.validate(servicePublicKeyStringK0, 3600, false, errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }
    
    @Test
    public void testTokenValidateNullData() throws CryptoException {
        
        Token token = new Token();
        assertFalse(token.validate(servicePublicKeyStringK0, 3600, false));
    }
    
    @Test
    public void testTokenValidateFutureTimeStamp() throws CryptoException {
        
        long timestamp = System.currentTimeMillis() / 1000 + 4200;
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).issueTime(timestamp).expirationWindow(expirationTime).build();
        token.sign(servicePrivateKeyStringK0);

        assertFalse(token.validate(servicePublicKeyStringK0, 3600, false));

        timestamp = System.currentTimeMillis() + 1000000;
        token.setTimeStamp(timestamp,1000000);
        PublicKey pubkey = Mockito.mock(PublicKey.class);
        assertFalse(token.validate(pubkey, 3600, false, null));
    }
    
    @Test
    public void testTokenValidateTooFarExpiryTimestamp() throws CryptoException {
        
        long timestamp = System.currentTimeMillis() / 1000;
        long expiration = TimeUnit.SECONDS.convert(30, TimeUnit.DAYS) + 11;
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).issueTime(timestamp).expirationWindow(expiration).build();
        token.sign(servicePrivateKeyStringK0);

        assertFalse(token.validate(servicePublicKeyStringK0, 5, false));
        assertTrue(token.validate(servicePublicKeyStringK0, 20, false));
        
        assertFalse(token.validate(servicePublicKeyStringK0, 5));
        assertTrue(token.validate(servicePublicKeyStringK0, 20));
    }
    
    @Test
    public void testTokenValidateNoExpiryTimestamp() throws CryptoException {
        
        long timestamp = System.currentTimeMillis() / 1000;
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).issueTime(timestamp).build();
        token.expiryTime = 0;
        token.sign(servicePrivateKeyStringK0);

        Token.ATHENZ_TOKEN_NO_EXPIRY = false;
        assertFalse(token.validate(servicePublicKeyStringK0, 20, false));
        assertFalse(token.validate(servicePublicKeyStringK0, 20, true));
        
        Token.ATHENZ_TOKEN_NO_EXPIRY = true;
        assertFalse(token.validate(servicePublicKeyStringK0, 20, false));
        assertTrue(token.validate(servicePublicKeyStringK0, 20, true));

        Token.ATHENZ_TOKEN_NO_EXPIRY = false;
    }
    
    @Test
    public void testTokenValidateInvalidKey() throws CryptoException {
        
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).build();
        token.sign(servicePrivateKeyStringK0);

        assertFalse(token.validate("InvalidPublicKey", 3600, false));

        assertFalse(token.validate((PublicKey)null, 3600, false, null));
    }
    
    @Test
    public void testTokenValidateNullKey() throws CryptoException {
        
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).build();
        token.sign(servicePrivateKeyStringK0);

        assertFalse(token.validate(null, 3600, false));
    }
    
    @Test
    public void testTokenGetters() throws CryptoException {
        
        long timestamp = System.currentTimeMillis() / 1000;
        String testKeyVersionK1 = "1";
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).ip("127.0.0.1").salt(salt).issueTime(timestamp)
            .keyId(testKeyVersionK1).expirationWindow(expirationTime).build();
        token.sign(servicePrivateKeyStringK1);
        
        // Validate all input data
        assertEquals(token.getVersion(), svcVersion);
        assertEquals(token.getDomain(), svcDomain);
        assertEquals(token.getName(), svcName);
        assertEquals(token.getHost(), host);
        assertEquals(token.getSalt(), salt);
        assertEquals(token.getKeyId(), testKeyVersionK1);
        assertEquals(token.getIP(), "127.0.0.1");
        assertEquals(token.getTimestamp(), timestamp);
        assertEquals(token.getExpiryTime(), timestamp + expirationTime);
        assertNotNull(token.getSignature());
    }

    @Test
    public void testGetUnsignedTokenFromSignedToken() {
        String [] signedTokens = {
            // this is a RoleToken
            "v=Z1;d=sports;r=storage.tenant.weather.updater;p=user.joe;a=aAkjbbDMhnLX;t=1447361682;e=1447361692;k=0;i=127.0.0.1;s=IKT3MhlfxMajh9KqvNFhuJwyHQB8M9qVmgok389wmcRZ_kqMKaf72sC3.u0Qh4VlWk.DReX8y17V.qV0wnGwNPwfUBKG9SR88SL_MBvSaVHst9wQN20v.gCzFf8IXzehEFID5tjCIFAmaLEn71bCS4oKMiPEx4FtP4OdYdeL_d4",
            "v=Z1;d=sports;r=storage.tenant.weather.updater,fantasy.tenant.sports.admin,fantasy.tenant.sports.reader,fantasy.tenant.sports.writer,fantasy.tenant.sports.scanner;p=coretech.storage;a=aAkjbbDMhnLX;t=1447361682;e=1447361692;k=0;i=127.0.0.1;s=C68KMYxivWqTTg8YWGc1aXUkgbgHOQDH8iRePZWY9aLUidkEQSvBkveRFi4Sap6q800Qt1GVnF6aN1OMk6YNIc_0E_xdRj9LJriS6Qq6ss79y76J_OSGSIwBXNeDWP6fq1SPW_MlUiXPE3TJojG_W8C0lwtWRppP0UZGAjzs4bc-",
            // this is a PrincipalToken
            "v=S1;d=cd.project;n=nfl;h=somehost.somecompany.com;a=saltvalue;t=1447361732;e=1447361742;s=NlISFQqXz1ji8zdVdGKjKZHJBloo11S.tXLo6t.GmnCt9S6c8AATzzZ2XdMeRlX2b0ykRiS0yjmrXg.grMPin3cHiB_FdLL05.w29OUBgxJr71.11_09iOoqy0ivGqyXoSO2GQbtXJfQeJ6HFHWPef1xyNV0Fswd8e6HQtyxGLA-",
            "v=S1;d=cd;n=12345;h=somehost.somecompany.com;a=saltvalue;t=1447361732;e=1447361742;k=0;s=lg5JMqJb9Hd5Vd12VdC2d.Pu0TSlynGtulV7GjT9RQsSFaTsvabLPIehNT7iJczVq_POzWTA7HYRe7ZNGfGTe6P26C_qECX._ylbYVznLnZSFW3IQFMMPc2yjiE_twFgXAVtT1sWHjcf8zxK4RVij_8vziTiUrqU_ExioO019XE-",
        };

        for (String signedToken: signedTokens) {
            String unsignedToken = Token.getUnsignedToken(signedToken);
            assertNotEquals(unsignedToken, signedToken);
            assertTrue(unsignedToken.length() < signedToken.length());
            assertTrue(signedToken.startsWith(unsignedToken));
        }
    }

    @Test
    public void testGetUnsignedTokenFromUnsignedToken() {
        String [] signedTokens = {
            // this is a RoleToken
            "v=Z1;d=sports;r=storage.tenant.weather.updater;p=user.joe;a=aAkjbbDMhnLX;t=1447361682;e=1447361692;k=0;i=127.0.0.1",
            "v=Z1;d=sports;r=storage.tenant.weather.updater,fantasy.tenant.sports.admin,fantasy.tenant.sports.reader,fantasy.tenant.sports.writer,fantasy.tenant.sports.scanner;p=coretech.storage;a=aAkjbbDMhnLX;t=1447361682;e=1447361692;k=0;i=127.0.0.1",
            // this is a PrincipalToken
            "v=S1;d=cd.project;n=nfl;h=somehost.somecompany.com;a=saltvalue;t=1447361732;e=1447361742",
            "v=S1;d=cd;n=12345;h=somehost.somecompany.com;a=saltvalue;t=1447361732;e=1447361742;k=0",
        };

        for (String signedToken: signedTokens) {
            String unsignedToken = Token.getUnsignedToken(signedToken);
            assertSame(unsignedToken, signedToken);
        }
    }

    @Test
    public void testValidateFail() {
        Token token = new Token();
        assertFalse(token.validate((PublicKey) null, 3600, false, null));

        long timestamp = System.currentTimeMillis() / 1000;
        long expiration = TimeUnit.SECONDS.convert(30, TimeUnit.DAYS) + 11;
        PrincipalToken token1 = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
                .host(host).salt(salt).issueTime(timestamp).expirationWindow(expiration).build();
        token1.sign(servicePrivateKeyStringK0);
        Token spyToken = Mockito.spy(token1);
        doReturn(null).when(spyToken).getDigestAlgorithm();

        assertFalse(spyToken.validate(servicePublicKeyStringK0, 5, false));
        assertFalse(spyToken.validate(servicePublicKeyStringK0, 20, false));
    }
}
