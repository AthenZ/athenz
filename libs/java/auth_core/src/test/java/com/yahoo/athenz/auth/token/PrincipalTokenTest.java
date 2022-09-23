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

import static org.testng.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.CryptoException;

public class PrincipalTokenTest {

    private final String svcVersion = "S1";
    private final String usrVersion = "U1";
    private final String svcDomain = "sports";
    private final String svcName = "fantasy";
    private final String usrDomain = "user";
    private final String usrName = "john";
    private final String host = "somehost.somecompany.com";
    private final String salt = "saltvalue";

    private final long expirationTime = 10; // 10 seconds
    
    private String servicePublicKeyStringK0 = null;
    private String servicePrivateKeyStringK0 = null;
    private String servicePublicKeyStringK1 = null;
    private String servicePrivateKeyStringK1 = null;

    @BeforeTest
    private void loadKeys() throws IOException {
        Path path = Paths.get("./src/test/resources/fantasy_public_k0.key");
        servicePublicKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/unit_test_fantasy_private_k0.key");
        servicePrivateKeyStringK0 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/fantasy_public_k1.key");
        servicePublicKeyStringK1 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/unit_test_fantasy_private_k1.key");
        servicePrivateKeyStringK1 = new String(Files.readAllBytes(path));
    }
    
    //backwards compatibility
    private PrincipalToken createServiceToken() throws CryptoException {
        // Create and sign token
        PrincipalToken serviceTokenToSign = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
        .host(host).salt(salt).expirationWindow(expirationTime).build();
        
        serviceTokenToSign.sign(servicePrivateKeyStringK0);

        // Create a token for validation using the signed data
        return new PrincipalToken(serviceTokenToSign.getSignedToken());
    }
    
    private PrincipalToken createServiceToken(String keyVersion) throws CryptoException {
        // Create and sign token
        PrincipalToken serviceTokenToSign = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .host(host).salt(salt).expirationWindow(expirationTime).keyId(keyVersion).build();
        
        String privateKey = null;
        if ("0".equals(keyVersion)) {
            privateKey = servicePrivateKeyStringK0;
        } else  if ("1".equals(keyVersion)) {
            privateKey = servicePrivateKeyStringK1;
        }
        
        serviceTokenToSign.sign(privateKey);

        // Create a token for validation using the signed data
        return new PrincipalToken(serviceTokenToSign.getSignedToken());
    }

    private PrincipalToken createUserToken(long issueTime)
            throws CryptoException {
        // Create and sign token
        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // Create a token for validation using the signed data
        return new PrincipalToken(userTokenToSign.getSignedToken());
    }

    @Test
    public void testServiceToken() throws CryptoException {
        String testKeyVersionK1 = "1";
        PrincipalToken serviceTokenToValidate = createServiceToken(testKeyVersionK1);

        // Validate all input data
        assertEquals(serviceTokenToValidate.getVersion(), svcVersion);
        assertEquals(serviceTokenToValidate.getDomain(), svcDomain);
        assertEquals(serviceTokenToValidate.getName(), svcName);
        assertEquals(serviceTokenToValidate.getHost(), host);
        assertEquals(serviceTokenToValidate.getSalt(), salt);
        assertEquals(serviceTokenToValidate.getKeyId(), testKeyVersionK1);

        // Validate the signature and that expiration time had not elapsed
        assertTrue(serviceTokenToValidate.validate(servicePublicKeyStringK1, 300, false));

        // Create ServiceToken with null keyVersion which should default to 0
        serviceTokenToValidate = createServiceToken();
        assertEquals(serviceTokenToValidate.getKeyId(), "0");

        // Validate the signature using key(k0) and that expiration time had not elapsed
        assertTrue(serviceTokenToValidate.validate(servicePublicKeyStringK0, 300, false));

        PrincipalToken svcToken2 = new PrincipalToken(serviceTokenToValidate.getSignedToken());
        assertEquals(svcToken2.getSignedToken(), serviceTokenToValidate.getSignedToken());
    }

    @Test
    public void testServiceTokenWithInvalidArgs() throws CryptoException {

        String testKeyVersionK1 = "1";
        PrincipalToken serviceToken = createServiceToken(testKeyVersionK1);
        PrincipalToken serviceTokenToValidate = new PrincipalToken(serviceToken.getSignedToken() + ";d=new;n=api2");

        // Validate the signature and that expiration time had not elapsed
        assertFalse(serviceTokenToValidate.validate(servicePublicKeyStringK1, 300, false));
    }

    @Test
    public void testUserToken() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        PrincipalToken userTokenToValidate = createUserToken(issueTime);

        // Validate all input data
        assertEquals(userTokenToValidate.getVersion(), usrVersion);
        assertEquals(userTokenToValidate.getDomain(), usrDomain);
        assertEquals(userTokenToValidate.getName(), usrName);
        assertNull(userTokenToValidate.getHost());
        assertEquals(userTokenToValidate.getSalt(), salt);

        // Validate the signature and that expiration time had not elapsed
        assertTrue(userTokenToValidate.validate(servicePublicKeyStringK0, 300, false));
    }

    @Test
    public void testTokenStringConstructor() {
        long issueTime = System.currentTimeMillis() / 1000;
        PrincipalToken pToken = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime).build();

        pToken.sign(servicePrivateKeyStringK0); // now its signed
        String signedToken = pToken.getSignedToken();
        PrincipalToken sigToken1 = new PrincipalToken(signedToken);
        assertEquals(sigToken1.getSignedToken(), signedToken);

        String unsignedTok = pToken.getUnsignedToken();
        String signature   = pToken.getSignature();
        String newSignedToken = unsignedTok + ";s=" + signature;
        assertEquals(newSignedToken, signedToken);

        // instantiate a Token with the unsigned token + signature
        PrincipalToken sigToken2 = new PrincipalToken(newSignedToken);
        assertEquals(sigToken2.getSignedToken(), signedToken);
        assertEquals(sigToken2.getUnsignedToken(), unsignedTok);
        assertEquals(sigToken2.getSignature(), signature);
    }

    @Test
    public void testUserToken_Expired() throws InterruptedException,
            CryptoException {
        long issueTime = System.currentTimeMillis() / 1000 - 10;
        PrincipalToken userTokenToValidate = createUserToken(issueTime);

        // Let expiration time elapse
        Thread.sleep(expirationTime * 1000);

        // Validate that the expiration time has elapsed
        assertFalse(userTokenToValidate.validate(servicePublicKeyStringK0, 300, false));
    }

    @Test
    public void testServiceToken_Expired() throws InterruptedException,
            CryptoException {
        PrincipalToken serviceTokenToValidate = createServiceToken("0");

        // Let expiration time elapse
        Thread.sleep((expirationTime + 10) * 1000);

        // Validate that the expiration time has elapsed
        assertFalse(serviceTokenToValidate.validate(servicePublicKeyStringK0, 300, false));
    }

    @Test
    public void testEmptyToken() {

        try {
            new PrincipalToken("");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testNullToken() {

        try {
            new PrincipalToken(null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testTokenDomainNull() {

        try {
            new PrincipalToken("v=S1;n=storage;s=sig");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testTokenDomainEmpty() {

        try {
            new PrincipalToken("v=S1;d=;n=storage;s=sig");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void tesTokenNameNull() {

        try {
            new PrincipalToken("v=S1;d=coretech;s=sig");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testTokenNameEmpty() {

        try {
            new PrincipalToken("v=S1;d=coretech;n=;s=sig");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testTokenWithoutSignature() {

        PrincipalToken token = new PrincipalToken("v=S1;d=coretech;n=storage");
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getName(), "storage");
        assertEquals(token.getVersion(), "S1");
        assertNull(token.getUnsignedToken());
    }

    @Test
    public void testTokenInvalidVersionValue() {

        PrincipalToken token = new PrincipalToken("v=S1=S2;d=coretech;n=storage");
        assertEquals(token.getName(), "storage");
        assertEquals(token.getDomain(), "coretech");
        assertNull(token.getVersion());
    }

    @Test
    public void testBuilderRequiredVersionNull() {

        try {
            new PrincipalToken.Builder(null, svcDomain, svcName);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testBuilderRequiredVersionEmptyString() {

        try {
            new PrincipalToken.Builder("", svcDomain, svcName);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testBuilderRequiredDomainNull() {

        try {
            new PrincipalToken.Builder(svcVersion, null, svcName);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testBuilderRequiredDomainEmptyString() {

        try {
            new PrincipalToken.Builder(svcVersion, "", svcName);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testBuilderRequiredNameNull() {

        try {
            new PrincipalToken.Builder(svcVersion, svcDomain, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testBuilderRequiredNameEmptyString() {

        try {
            new PrincipalToken.Builder(svcVersion, svcDomain, "");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testBuilderDefaultOptionalValues() {

        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName).build();
        assertEquals(token.getVersion(), svcVersion);
        assertEquals(token.getDomain(), svcDomain);
        assertEquals(token.getName(), svcName);
        assertNull(token.getHost());
        assertNotNull(token.getSalt());
        assertEquals(token.getKeyId(), "0");
        assertNull(token.getIP());
        long timestamp = token.getTimestamp();
        assertTrue(timestamp != 0);
        assertEquals(token.getExpiryTime(), timestamp + 3600);
    }

    @Test
    public void testBuilderAllValues() {

        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").keyService("zts").originalRequestor("athenz.ci.service").build();

        assertEquals(token.getVersion(), svcVersion);
        assertEquals(token.getDomain(), svcDomain);
        assertEquals(token.getName(), svcName);
        assertEquals(token.getHost(), "localhost");
        assertEquals(token.getSalt(), "salt");
        assertEquals(token.getKeyId(), "zone1");
        assertEquals(token.getIP(), "127.0.0.1");
        assertEquals(token.getKeyService(), "zts");
        assertEquals(token.getOriginalRequestor(), "athenz.ci.service");
        assertEquals(token.getTimestamp(), 36000);
        assertEquals(token.getExpiryTime(), 36000 + 100);
    }

    @Test
    public void testUserTokenWithSingleAuthorizedService() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("coretech.storage", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data

        PrincipalToken userTokenToValidate = new PrincipalToken(userTokenToSign.getSignedToken());

        // Validate all input data
        assertEquals(userTokenToValidate.getVersion(), usrVersion);
        assertEquals(userTokenToValidate.getDomain(), usrDomain);
        assertEquals(userTokenToValidate.getName(), usrName);
        assertNull(userTokenToValidate.getHost());
        assertEquals(userTokenToValidate.getSalt(), salt);
        assertEquals(userTokenToValidate.getAuthorizedServices(), authorizedServices);
        assertEquals(userTokenToValidate.getAuthorizedServiceKeyId(), "1");
        // authorized service name must be null since there is only 1 entry
        // in the authorized services list so there must be a match
        assertNull(userTokenToValidate.getAuthorizedServiceName());

        // Validate the signature and that expiration time had not elapsed
        assertTrue(userTokenToValidate.validateForAuthorizedService(servicePublicKeyStringK1, null));
    }

    @Test
    public void testUserTokenWithSingleAuthorizedServiceInvalidCompsAtEnd() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
                .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
                .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("coretech.storage", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data

        final String newToken = userTokenToSign.getSignedToken() + ";n=api;bn=sports.api";
        PrincipalToken userTokenToValidate = new PrincipalToken(newToken);

        // Validate the signature and that expiration time had not elapsed
        assertFalse(userTokenToValidate.validateForAuthorizedService(servicePublicKeyStringK1, null));

        // authorized service name must be null since there is only 1 entry
        // in the authorized services list so there must be a match
        assertNull(userTokenToValidate.getAuthorizedServiceName());

        // Validate all input data
        assertEquals(userTokenToValidate.getVersion(), usrVersion);
        assertEquals(userTokenToValidate.getDomain(), usrDomain);
        assertEquals(userTokenToValidate.getName(), usrName);
        assertNull(userTokenToValidate.getHost());
        assertEquals(userTokenToValidate.getSalt(), salt);
        assertEquals(userTokenToValidate.getAuthorizedServices(), authorizedServices);
        assertEquals(userTokenToValidate.getAuthorizedServiceKeyId(), "1");
    }

    @Test
    public void testUserTokenWithMultipleAuthorizedServices() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");
        authorizedServices.add("media.storage");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("coretech.storage", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data

        PrincipalToken userTokenToValidate = new PrincipalToken(userTokenToSign.getSignedToken());

        // Validate all input data
        assertEquals(userTokenToValidate.getVersion(), usrVersion);
        assertEquals(userTokenToValidate.getDomain(), usrDomain);
        assertEquals(userTokenToValidate.getName(), usrName);
        assertNull(userTokenToValidate.getHost());
        assertEquals(userTokenToValidate.getSalt(), salt);
        assertEquals(userTokenToValidate.getAuthorizedServices(), authorizedServices);
        assertEquals(userTokenToValidate.getAuthorizedServiceKeyId(), "1");
        // since we have 2 authorized services, the name must be specified that
        // tells us which service is signing the token
        assertEquals(userTokenToValidate.getAuthorizedServiceName(), "coretech.storage");

        // Validate the signature and that expiration time had not elapsed
        StringBuilder errMsg = new StringBuilder();
        assertTrue(userTokenToValidate.validateForAuthorizedService(servicePublicKeyStringK1, errMsg));
    }

    @Test
    public void testUserTokenWithNullAuthorizedService() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service. we must get
        // back illegal argument exception

        try {
            userTokenToSign.signForAuthorizedService("coretech.storage", "0", servicePrivateKeyStringK0);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getClass(), IllegalArgumentException.class);
        }
    }

    @Test
    public void testUserTokenWithInvalidAuthorizedService() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service. we must get
        // back illegal argument exception because of service name mismatch

        try {
            userTokenToSign.signForAuthorizedService("weather.storage", "0", servicePrivateKeyStringK0);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getClass(), IllegalArgumentException.class);
        }

        authorizedServices.add("media.storage");
        PrincipalToken userTokenToSign2 = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign2.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service. we must get
        // back illegal argument exception because of service name mismatch

        try {
            userTokenToSign2.signForAuthorizedService("weather.storage", "0", servicePrivateKeyStringK0);
            fail();
        } catch (Exception ex) {
            assertEquals(ex.getClass(), IllegalArgumentException.class);
        }
    }

    @Test
    public void testValidateForAuthorizedServiceInvalidSignature() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // now let's sign the token for an authorized service

        userTokenToSign.signForAuthorizedService("coretech.storage", "1", servicePrivateKeyStringK1);

        // Create a token for validation using the signed data

        PrincipalToken userTokenToValidate = new PrincipalToken(userTokenToSign.getSignedToken());
        StringBuilder errMsg = new StringBuilder();
        assertTrue(userTokenToValidate.validateForAuthorizedService(servicePublicKeyStringK1, errMsg));

        // now let's add a couple of extra characters to the signature

        String tamperedToken = userTokenToSign.getSignedToken();
        userTokenToValidate = new PrincipalToken(tamperedToken.replace(";bs=", ";bs=ab"));
        errMsg = new StringBuilder();
        assertFalse(userTokenToValidate.validateForAuthorizedService(servicePublicKeyStringK1, errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }

    @Test
    public void testValidateForAuthorizedServiceNoSignature() throws CryptoException {
        long issueTime = System.currentTimeMillis() / 1000;
        // Create and sign token
        List<String> authorizedServices = new ArrayList<>();
        authorizedServices.add("coretech.storage");

        PrincipalToken userTokenToSign = new PrincipalToken.Builder(usrVersion, usrDomain, usrName)
            .salt(salt).issueTime(issueTime).expirationWindow(expirationTime)
            .authorizedServices(authorizedServices).build();

        userTokenToSign.sign(servicePrivateKeyStringK0);

        // Create a token for validation using the signed data without
        // signing for authorized service so there won't be bs field.

        PrincipalToken userTokenToValidate = new PrincipalToken(userTokenToSign.getSignedToken());
        StringBuilder errMsg = new StringBuilder();
        assertFalse(userTokenToValidate.validateForAuthorizedService(servicePublicKeyStringK1, errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }

    @Test
    public void testIsValidAuthorizedServiceTokenStandardToken() {

        // testing standard token

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;s=signature";
        PrincipalToken svcToken = new PrincipalToken(token);
        StringBuilder errMsg = new StringBuilder();
        assertTrue(svcToken.isValidAuthorizedServiceToken(errMsg));
    }

    @Test
    public void testIsValidAuthorizedServiceTokenValidSvcToken() {

        // testing valid service token - we have multiple cases
        // to consider:
        // single service entry in list + service name

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;bk=0;bn=svc1;bs=signature";
        PrincipalToken svcToken = new PrincipalToken(token);
        StringBuilder errMsg = new StringBuilder();
        assertTrue(svcToken.isValidAuthorizedServiceToken(errMsg));

        // single service entry in list + no service name

        token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;bk=0;bs=signature";
        svcToken = new PrincipalToken(token);
        assertTrue(svcToken.isValidAuthorizedServiceToken(null));

        // multiple service entries in list + service name

        token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1,svc2;s=signature;bk=0;bn=svc1;bs=signature";
        svcToken = new PrincipalToken(token);
        assertTrue(svcToken.isValidAuthorizedServiceToken(errMsg));
    }

    @Test
    public void testIsValidAuthorizedServiceTokenSvcYesSigNo() {

        // we're going to test where we have an authorized service
        // name but no corresponding signature

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature";
        PrincipalToken svcToken = new PrincipalToken(token);
        StringBuilder errMsg = new StringBuilder();
        assertFalse(svcToken.isValidAuthorizedServiceToken(errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }

    @Test
    public void testIsValidAuthorizedServiceTokenSvcNoSigYes() {

        // we're going to test where we have an authorized
        // service signature but no service name

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;s=signature;bk=0;bs=signature";
        PrincipalToken svcToken = new PrincipalToken(token);
        StringBuilder errMsg = new StringBuilder();
        assertFalse(svcToken.isValidAuthorizedServiceToken(errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }

    @Test
    public void testIsValidAuthorizedServiceTokenUnknownSvc() {

        // we're going to test where we have both service name
        // and signature but the service name is not in the
        // service list (single entry)

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;bk=0;bn=svc3;bs=signature";
        PrincipalToken svcToken = new PrincipalToken(token);
        StringBuilder errMsg = new StringBuilder();
        assertFalse(svcToken.isValidAuthorizedServiceToken(errMsg));
        assertFalse(errMsg.toString().isEmpty());

        // service list (multiple entries)

        token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1,svc2;s=signature;bk=0;bn=svc3;bs=signature";
        svcToken = new PrincipalToken(token);
        errMsg = new StringBuilder();
        assertFalse(svcToken.isValidAuthorizedServiceToken(errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }

    @Test
    public void testIsValidAuthorizedServiceTokenNoSvcNotSingle() {

        // we're going to test where we have a service list
        // and signature but no service name and our list
        // contains multiple entries

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1,svc2;s=signature;bk=0;bs=signature";
        PrincipalToken svcToken = new PrincipalToken(token);
        StringBuilder errMsg = new StringBuilder();
        assertFalse(svcToken.isValidAuthorizedServiceToken(errMsg));
        assertFalse(errMsg.toString().isEmpty());
    }

    @Test
    public void testPrincipalTokenParserKeyService() {

        String token = "v=S1;d=domain;n=service;t=1234;e=1235;k=0;z=zms;o=athenz.ci.service;h=host1;i=1.2.3.4;s=signature";
        PrincipalToken svcToken = new PrincipalToken(token);

        assertEquals(svcToken.getKeyService(), "zms");
        assertEquals(svcToken.getOriginalRequestor(), "athenz.ci.service");
    }

    @Test
    public void testPrincipalTokenGenerationKeyService() {
        PrincipalToken token = new PrincipalToken.Builder(svcVersion, svcDomain, svcName)
                .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
                .salt("salt").keyId("zone1").keyService("zts").originalRequestor("athenz.ci.service").build();
        token.sign(servicePrivateKeyStringK0);

        String strToken = token.getSignedToken();
        int idx = strToken.indexOf(";z=zts;");
        assertTrue(idx != -1);

        idx = strToken.indexOf(";o=athenz.ci.service;");
        assertTrue(idx != -1);
    }

    @Test
    public void testValidateForAuthorizedServiceIllegal() {
        PrincipalToken token = new PrincipalToken("bs=signature;v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;bk=0;bn=svc1");
        assertFalse(token.validateForAuthorizedService(null, null));
        
        token = new PrincipalToken("v=S1;d=domain;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;bk=1;bn=svc1;bs=signature");
        assertFalse(token.validateForAuthorizedService(null, null));

        assertFalse(token.validateForAuthorizedService(servicePublicKeyStringK1, null));
    }

    @Test
    public void testTokenWithExtraArgsAfterSignature() {

        PrincipalToken token = new PrincipalToken("v=S1;d=coretech;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;d=domain2;n=api");
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getVersion(), "S1");
        assertEquals(token.getName(), "service");
        assertEquals(token.getSignature(), "signature;d=domain2;n=api");
        assertEquals(token.getUnsignedToken(), "v=S1;d=coretech;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1");

        token = new PrincipalToken("v=S1;d=coretech;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1;s=signature;d=domain2;n=api;bs=svc-signature;d=domain2;n=api");
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getVersion(), "S1");
        assertEquals(token.getName(), "service");
        assertEquals(token.getSignature(), "signature");
        assertEquals(token.getUnsignedToken(), "v=S1;d=coretech;n=service;t=1234;e=1235;k=0;h=host1;i=1.2.3.4;b=svc1");
    }
}
