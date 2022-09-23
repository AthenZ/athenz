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

public class RoleTokenTest {

    private final String rolVersion = "Z1";
    private final String svcDomain = "sports";
    private final String salt = "aAkjbbDMhnLX";

    private final long expirationTime = 10; // 10 seconds
    
    private String ztsPublicKeyStringK0 = null;
    private String ztsPrivateKeyStringK0 = null;
    private String ztsPublicKeyStringK1 = null;
    private String ztsPrivateKeyStringK1 = null;

    @BeforeTest
    private void loadKeys() throws IOException {
        
        Path path = Paths.get("./src/test/resources/zts_public_k0.key");
        ztsPublicKeyStringK0 = new String(Files.readAllBytes(path));
        
        path = Paths.get("./src/test/resources/zts_public_k1.key");
        ztsPublicKeyStringK1 = new String(Files.readAllBytes(path));

        path = Paths.get("./src/test/resources/unit_test_zts_private_k0.key");
        ztsPrivateKeyStringK0 = new String(Files.readAllBytes(path));
        
        path = Paths.get("./src/test/resources/unit_test_zts_private_k1.key");
        ztsPrivateKeyStringK1 = new String(Files.readAllBytes(path));
    }
    
    private RoleToken createRoleTokenToValidate(List<String> roles) throws CryptoException {
        // Create token and sign
        RoleToken rollTokenToSign = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).expirationWindow(expirationTime).build();
        
        rollTokenToSign.sign(ztsPrivateKeyStringK0);

        return new RoleToken(rollTokenToSign.getSignedToken());
    }

    private RoleToken createRoleTokenToValidate(List<String> roles, String keyVersion)
            throws CryptoException {
        // Create token and sign
        RoleToken rollTokenToSign = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).expirationWindow(expirationTime).keyId(keyVersion).build();

        String privateKey = null;
        if ("0".equals(keyVersion)) {
            privateKey = ztsPrivateKeyStringK0;
        } else  if ("1".equals(keyVersion)) {
            privateKey = ztsPrivateKeyStringK1;
        }

        rollTokenToSign.sign(privateKey);

        return new RoleToken(rollTokenToSign.getSignedToken());
    }

    @Test
    public void testRoleToken() throws CryptoException {
        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        roles.add("fantasy.tenant.sports.admin");
        roles.add("fantasy.tenant.sports.reader");
        roles.add("fantasy.tenant.sports.writer");
        roles.add("fantasy.tenant.sports.scanner");

        // Create a token for validation using the signed data
        String testKeyVersionK1 = "1";
        RoleToken rollTokenToValidate = createRoleTokenToValidate(roles, testKeyVersionK1);
        assertNotNull(rollTokenToValidate.getSignedToken());

        // Validate all input data
        assertEquals(rollTokenToValidate.getVersion(), rolVersion);
        assertEquals(rollTokenToValidate.getDomain(), svcDomain);
        List<String> rolesToValidate = rollTokenToValidate.getRoles();
        assertEquals(rolesToValidate.size(), roles.size());
        assertEquals(rolesToValidate, roles);
        assertEquals(rollTokenToValidate.getKeyId(), testKeyVersionK1);

        // Validate the signature and that expiration time had not elapsed
        assertTrue(rollTokenToValidate.validate(ztsPublicKeyStringK1, 300, false));
        
        // Create ServiceToken with null keyVersion which should default to 0
        rollTokenToValidate = createRoleTokenToValidate(roles);
        assertEquals(rollTokenToValidate.getKeyId(), "0");
        
        // Validate the signature using key(k0) and that expiration time had not elapsed
        assertTrue(rollTokenToValidate.validate(ztsPublicKeyStringK0, 300, false));
    }

    @Test
    public void testRoleTokenInvalidParamsAtEnd() throws CryptoException {
        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("reader");
        roles.add("writer");

        // Create a token for validation using the signed data
        String testKeyVersionK1 = "1";

        // Create token and sign
        RoleToken rollTokenToSign = new RoleToken.Builder(rolVersion, svcDomain, roles)
                .salt(salt).expirationWindow(expirationTime).keyId(testKeyVersionK1).build();

        rollTokenToSign.sign(ztsPrivateKeyStringK1);
        String signedToken = rollTokenToSign.getSignedToken() + ";d=newdomain;r=newroles";

        RoleToken rollTokenToValidate = new RoleToken(signedToken);

        assertNotNull(rollTokenToValidate.getSignedToken());

        // Validate all input data, we'll be ignoring the data
        // after the signature

        assertEquals(rollTokenToValidate.getDomain(), svcDomain);
        List<String> rolesToValidate = rollTokenToValidate.getRoles();
        assertEquals(rolesToValidate.size(), roles.size());
        assertEquals(rolesToValidate, roles);
        assertEquals(rollTokenToValidate.getKeyId(), testKeyVersionK1);

        // Validate the signature and that expiration time had not elapsed
        // we should get invalid validation due to extra arguments at
        // end of the string

        assertFalse(rollTokenToValidate.validate(ztsPublicKeyStringK1, 300, false));
    }

    @Test
    public void testRoleToken_Expired() throws InterruptedException, CryptoException {
        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        roles.add("fantasy.tenant.sports.admin");
        roles.add("fantasy.tenant.sports.reader");
        roles.add("fantasy.tenant.sports.writer");
        roles.add("fantasy.tenant.sports.scanner");

        // Create a token for validation using the signed data
        String testKeyVersionK0 = "0";
        RoleToken rollTokenToValidate = createRoleTokenToValidate(roles, testKeyVersionK0);

        // Let expiration time elapse
        Thread.sleep((expirationTime + 10) * 1000);

        // Validate that the expiration time has elapsed
        assertFalse(rollTokenToValidate.validate(ztsPublicKeyStringK0, 300, false));
    }
    
    @Test
    public void testTokenStringConstructor() {
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.activator.actionmap.w");
        RoleToken rToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).expirationWindow(expirationTime).build();
        
        rToken.sign(ztsPrivateKeyStringK0); // now its signed
        String signedToken = rToken.getSignedToken();
        RoleToken sigToken1 = new RoleToken(signedToken);
        assertEquals(sigToken1.getSignedToken(), signedToken);

        String unsignedTok = rToken.getUnsignedToken();
        String signature   = rToken.getSignature();
        String newSignedToken = unsignedTok + ";s=" + signature;
        assertEquals(newSignedToken, signedToken);

        // instantiate a Token with the unsigned token + signature
        RoleToken sigToken2 = new RoleToken(newSignedToken);
        assertEquals(sigToken2.getSignedToken(), signedToken);
        assertEquals(sigToken2.getUnsignedToken(), unsignedTok);
        assertEquals(sigToken2.getSignature(), signature);
    }

    @Test
    public void testEmptyToken() {
        
        try {
            new RoleToken("");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testNullToken() {
        
        try {
            new RoleToken(null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }

    @Test
    public void testTokenWithoutSignature() {
        
        RoleToken token = new RoleToken("v=S1;d=coretech;r=role1,role2");
        assertEquals(token.getDomain(), "coretech");
        assertNotNull(token.getRoles());
        assertEquals(token.getVersion(), "S1");
        assertNull(token.getUnsignedToken());
    }

    @Test
    public void testTokenWithExtraArgsAfterSignature() {

        RoleToken token = new RoleToken("v=Z1;d=coretech;r=role1,role2;s=signature;d=sports;r=api");
        assertEquals(token.getDomain(), "coretech");
        assertNotNull(token.getRoles());
        assertEquals(token.getRoles().size(), 2);
        assertTrue(token.getRoles().contains("role1"));
        assertTrue(token.getRoles().contains("role2"));
        assertEquals(token.getVersion(), "Z1");
        assertEquals(token.getSignature(), "signature;d=sports;r=api");
        assertEquals(token.getUnsignedToken(), "v=Z1;d=coretech;r=role1,role2");
    }

    @Test
    public void testTokenInvalidVersionValue() {
        
        RoleToken token = new RoleToken("v=S1=S2;d=coretech;r=role1,role2");
        assertNull(token.getVersion());
    }
    
    @Test
    public void testTokenDomainNull() {
        
        try {
            new RoleToken("v=S1;r=role1,role2;s=signature");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testTokenDomainEmpty() {
        
        try {
            new RoleToken("v=S1;d=;r=role1,role2;s=signature");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testTokenRolesNull() {
        
        try {
            new RoleToken("v=S1;d=coretech;s=signature");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testTokenRolesEmpty() {
        
        try {
            new RoleToken("v=S1;d=coretech;r=;s=signature");
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderRequiredVersionNull() {
        
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        try {
            new RoleToken.Builder(null, svcDomain, roles);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderRequiredVersionEmptyString() {
        
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        try {
            new RoleToken.Builder("", svcDomain, roles);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderRequiredDomainNull() {
        
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        try {
            new RoleToken.Builder(rolVersion, null, roles);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderRequiredDomainEmptyString() {
        
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        try {
            new RoleToken.Builder(rolVersion, "", roles);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderRequiredRoleNull() {
        
        try {
            new RoleToken.Builder(rolVersion, svcDomain, null);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderRequiredRoleEmptyString() {
        
        List<String> roles = new ArrayList<>();
        try {
            new RoleToken.Builder(rolVersion, svcDomain, roles);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof IllegalArgumentException, ex.getMessage());
        }
    }
    
    @Test
    public void testBuilderDefaultOptionalValues() {
        
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles).build();
        assertEquals(token.getVersion(), rolVersion);
        assertEquals(token.getDomain(), svcDomain);
        assertEquals(token.getRoles(), roles);
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
        
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").principal("user.joe").build();
        
        assertEquals(token.getVersion(), rolVersion);
        assertEquals(token.getDomain(), svcDomain);
        assertEquals(token.getRoles(), roles);
        assertEquals(token.getHost(), "localhost");
        assertEquals(token.getSalt(), "salt");
        assertEquals(token.getKeyId(), "zone1");
        assertEquals(token.getIP(), "127.0.0.1");
        assertEquals(token.getPrincipal(), "user.joe");
        assertEquals(token.getTimestamp(), 36000);
        assertEquals(token.getExpiryTime(), 36000 + 100);
    }
    
    @Test
    public void testRoleTokenWithPrincipal() {
        
        List<String> roles = new ArrayList<>();
        roles.add("reader");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").principal("coretech.storage").build();
        token.sign(ztsPrivateKeyStringK0);
        
        assertTrue(token.getSignedToken().contains(";p=coretech.storage;"));
    }
    
    @Test
    public void testRoleTokenWithNullPrincipal() {
        
        List<String> roles = new ArrayList<>();
        roles.add("reader");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").principal(null).build();
        token.sign(ztsPrivateKeyStringK0);
        
        assertFalse(token.getSignedToken().contains(";p="));
    }
    
    @Test
    public void testRoleTokenWithEmptyPrincipal() {
        
        List<String> roles = new ArrayList<>();
        roles.add("reader");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").principal("").build();
        token.sign(ztsPrivateKeyStringK0);
        
        assertFalse(token.getSignedToken().contains(";p="));
    }
    
    @Test
    public void testRoleTokenWithoutPrincipal() {
        
        List<String> roles = new ArrayList<>();
        roles.add("reader");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").build();
        token.sign(ztsPrivateKeyStringK0);
        
        assertFalse(token.getSignedToken().contains(";p="));
    }
    
    @Test
    public void testRoleTokenWithProxyUser() {
        
        List<String> roles = new ArrayList<>();
        roles.add("reader");
        
        RoleToken token = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .issueTime(36000).expirationWindow(100).host("localhost").ip("127.0.0.1")
            .salt("salt").keyId("zone1").principal("coretech.storage")
            .proxyUser("user.user3").domainCompleteRoleSet(true).build();
        token.sign(ztsPrivateKeyStringK0);
        
        assertTrue(token.getSignedToken().contains(";proxy=user.user3;"));
        assertTrue(token.getSignedToken().contains(";c=1"));
    }
    
    @Test
    public void testRoleTokenParseWithProxyUser() {
        
        RoleToken token = new RoleToken("v=S1;d=coretech;r=role1,role2;proxy=user.user3;c=1;s=signature");
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getProxyUser(), "user.user3");
        assertTrue(token.getDomainCompleteRoleSet()); 
    }

    @Test
    public void testRoleTokenWithNotCompleteRoleSet() {
        RoleToken token = new RoleToken("v=S1;d=coretech;r=role1,role2;proxy=user.user3;c=0;s=signature");
        assertEquals(token.getDomain(), "coretech");
        assertEquals(token.getProxyUser(), "user.user3");
        assertFalse(token.getDomainCompleteRoleSet());
    }
    
    @Test
    public void testRoleTokenParseWithoutProxyUser() {
        
        RoleToken token = new RoleToken("v=S1;d=coretech;r=role1,role2;s=signature");
        assertEquals(token.getDomain(), "coretech");
        assertNull(token.getProxyUser());
        assertFalse(token.getDomainCompleteRoleSet());
    }

    @Test
    public void testRoleTokenHost() {
        
        RoleToken token = new RoleToken("v=S1;d=coretech;h=host;r=role1,role2;s=signature");
        assertEquals(token.getHost(), "host");
        assertNull(token.getProxyUser());
    }
}
