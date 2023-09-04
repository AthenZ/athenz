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

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.*;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.util.CryptoException;

public class RoleAuthorityTest {

    private final String rolVersion = "Z1";
    private final String svcDomain = "sports";
    private final String salt = "aAkjbbDMhnLX";
    private final String testKeyVersionK0 = "0";
    private final String testKeyVersionK1 = "1";

    private final long expirationTime = 10; // 10 seconds
    
    private String ztsPrivateKeyStringK0 = null;
    private String ztsPrivateKeyStringK1 = null;
    private static final String ZMS_USER_DOMAIN = "athenz.user_domain";

    private static final String userDomain = System.getProperty(ZMS_USER_DOMAIN, "user");
    
    @BeforeTest
    private void loadKeys() throws IOException {

        Path path = Paths.get("./src/test/resources/unit_test_zts_private_k0.key");
        ztsPrivateKeyStringK0 = new String(Files.readAllBytes(path));
        
        path = Paths.get("./src/test/resources/unit_test_zts_private_k1.key");
        ztsPrivateKeyStringK1 = new String(Files.readAllBytes(path));
    }
    
    private String tamperWithRoleToken(String signedToken) {
        String version = null;
        String domain = null;
        StringBuilder roleNames = null;
        String signature = null;
        long timestamp = 0;
        long expiryTime = 0;

        for (String item : signedToken.split(";")) {
            String[] kv = item.split("=");
            if (kv.length == 2) {
                if ("v".equals(kv[0])) {
                    version = kv[1];
                } else if ("d".equals(kv[0])) {
                    domain = kv[1];
                } else if ("r".equals(kv[0])) {
                    roleNames = new StringBuilder(kv[1]);
                } else if ("t".equals(kv[0])) {
                    timestamp = Long.parseLong(kv[1]);
                } else if ("e".equals(kv[0])) {
                    expiryTime = Long.parseLong(kv[1]);
                } else if ("s".equals(kv[0])) {
                    signature = kv[1];
                }
            }
        }

        assertNotNull(roleNames);
        roleNames.append(",storage.tenant.weather.admin"); // tamper here by adding a role

        List<String> roles = Arrays.asList(roleNames.toString().split(","));

        StringBuilder flattenedRoles = new StringBuilder(256);

        int i = 0;
        for (String role : roles) {
            if (++i == roles.size()) {
                flattenedRoles.append(role);
            } else {
                flattenedRoles.append(role).append(",");
            }
        }

        return "v=" + version + ";d=" + domain
                + ";r=" + flattenedRoles + ";t=" + timestamp
                + ";e=" + expiryTime + ";s=" + signature;
    }

    @Test
    public void testRoleAuthority() throws IOException, CryptoException {
        RoleAuthority rollAuthority = new RoleAuthority();
        KeyStore keyStore = new KeyStoreMock();
        rollAuthority.setKeyStore(keyStore);

        assertEquals(rollAuthority.getDomain(), "sys.auth");
        assertEquals(rollAuthority.getHeader(), "Athenz-Role-Auth");

        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        roles.add("fantasy.tenant.sports.admin");
        roles.add("fantasy.tenant.sports.reader");
        roles.add("fantasy.tenant.sports.writer");
        roles.add("fantasy.tenant.sports.scanner");

        // Create and sign token with no key version
        RoleToken rollToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
                .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
                .principal("coretech.storage").build();
        rollToken.sign(ztsPrivateKeyStringK0);

        StringBuilder errMsg = new StringBuilder();
        Principal principal = rollAuthority.authenticate(rollToken.getSignedToken(),
                "127.0.0.1", "GET", errMsg);

        assertNotNull(principal);
        assertNotNull(principal.getAuthority());
        assertEquals(principal.getCredentials(),
                rollToken.getSignedToken());
        assertEquals(principal.getDomain(), rollToken.getDomain());

        principal = rollAuthority.authenticate(rollToken.getSignedToken(),
                "127.0.0.1", "GET", null);
        assertNotNull(principal);

        List<String> rolesToValidate = principal.getRoles();
        assertEquals(rolesToValidate.size(), roles.size());
        assertEquals(rolesToValidate, roles);

        // Create and sign token with keyVersion = 0
        rollToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal("coretech.storage").keyId(testKeyVersionK0).build();
        rollToken.sign(ztsPrivateKeyStringK0);

        principal = rollAuthority.authenticate(rollToken.getSignedToken(),
                "127.0.0.1", "GET", errMsg);

        assertNotNull(principal);
        assertEquals(principal.getCredentials(),
                rollToken.getSignedToken());
        
        // Create and sign token with keyVersion = 1
        rollToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal("coretech.storage").keyId(testKeyVersionK1).build();
        rollToken.sign(ztsPrivateKeyStringK1);

        principal = rollAuthority.authenticate(rollToken.getSignedToken(),
                "127.0.0.1", "GET", errMsg);

        assertNotNull(principal);
        assertEquals(principal.getCredentials(),
                rollToken.getSignedToken());
    }

    @Test
    public void testGetID() {
        RoleAuthority authority = new RoleAuthority();
        authority.initialize();
        assertEquals("Auth-ROLE", authority.getID());
    }

    @Test
    public void testRoleAuthority_TamperedToken() throws IOException,
            CryptoException {
        RoleAuthority rollAuthority = new RoleAuthority();
        KeyStore keyStore = new KeyStoreMock();
        rollAuthority.setKeyStore(keyStore);

        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");
        roles.add("fantasy.tenant.sports.admin");
        roles.add("fantasy.tenant.sports.reader");
        roles.add("fantasy.tenant.sports.writer");
        roles.add("fantasy.tenant.sports.scanner");

        // Create and sign token
        RoleToken serviceToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal("coretech.storage").keyId(testKeyVersionK1).build();
        serviceToken.sign(ztsPrivateKeyStringK0);

        String tokenToTamper = serviceToken.getSignedToken();

        StringBuilder errMsg = new StringBuilder();
        Principal principal = rollAuthority.authenticate(tamperWithRoleToken(tokenToTamper),
                "127.0.0.1", "GET", errMsg);

        // Role Authority should return null when authenticate() fails
        assertNull(principal);
        assertFalse(errMsg.toString().isEmpty());
        assertTrue(errMsg.toString().contains("authenticate"));

        principal = rollAuthority.authenticate(tamperWithRoleToken(tokenToTamper),
                "127.0.0.1", "GET", null);
        assertNull(principal);
    }
    
    @Test
    public void testRoleAuthorityMismatchIPNonUser() throws IOException, CryptoException {
        RoleAuthority rollAuthority = new RoleAuthority();
        KeyStore keyStore = new KeyStoreMock();
        rollAuthority.setKeyStore(keyStore);

        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");

        // Create and sign token with keyVersion = 0
        RoleToken roleToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal("coretech.storage").keyId(testKeyVersionK0).build();
        roleToken.sign(ztsPrivateKeyStringK0);

        // mismatch IP but should be OK since it's not User
        StringBuilder errMsg = new StringBuilder();
        Principal principal = rollAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", "GET", errMsg);

        assertNotNull(principal);
    }
    
    @Test
    public void testRoleAuthorityMismatchIPNonWrite() throws IOException, CryptoException {
        RoleAuthority rollAuthority = new RoleAuthority();
        KeyStore keyStore = new KeyStoreMock();
        rollAuthority.setKeyStore(keyStore);

        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");

        // Create and sign token with keyVersion = 0
        RoleToken roleToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal(userDomain + ".joe").keyId(testKeyVersionK0).build();
        roleToken.sign(ztsPrivateKeyStringK0);

        // mismatch IP but should be OK since it's not write operation
        StringBuilder errMsg = new StringBuilder();
        Principal principal = rollAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", "GET", errMsg);

        assertNotNull(principal);
    }
    
    @Test
    public void testRoleAuthorityMismatchIP() throws IOException, CryptoException {
        RoleAuthority rollAuthority = new RoleAuthority();
        KeyStore keyStore = new KeyStoreMock();
        rollAuthority.setKeyStore(keyStore);

        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");

        // Create and sign token with keyVersion = 0
        RoleToken roleToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal(userDomain + ".joe").keyId(testKeyVersionK0).build();
        roleToken.sign(ztsPrivateKeyStringK0);

        // mismatch IP should fail
        StringBuilder errMsg = new StringBuilder();
        Principal principal = rollAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", "DELETE", errMsg);

        assertNull(principal);
        assertFalse(errMsg.toString().isEmpty());
        assertTrue(errMsg.toString().contains("authenticate"));
        
        errMsg = new StringBuilder(); // get a fresh one
        principal = rollAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", "PUT", errMsg);

        assertNull(principal);
        assertFalse(errMsg.toString().isEmpty());
        assertTrue(errMsg.toString().contains("authenticate"));
        
        // final check should be ok with valid IP
        principal = rollAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.1", "DELETE", errMsg);

        assertNotNull(principal);
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
    public void testAuthenticateIlligal() throws IOException {
        RoleAuthority roleAuthority = new RoleAuthority();
        roleAuthority.initialize();
        
        Principal principal = roleAuthority.authenticate("", "10.72.118.45", "GET", null);
        assertNull(principal);
        
        KeyStore keyStore = new KeyStoreMock();
        roleAuthority.setKeyStore(keyStore);

        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");

        // Create and sign token with keyVersion = 0
        RoleToken roleToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal(".").keyId(testKeyVersionK0).build();
        roleToken.sign(ztsPrivateKeyStringK0);
        
        principal = roleAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", "DELETE", null);
        assertNull(principal);
        
        roleToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
                .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
                .principal("illigal.joe").keyId(testKeyVersionK0).build();
        roleToken.sign(ztsPrivateKeyStringK0);
        
        principal = roleAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", "DELETE", null);
        assertNotNull(principal);
    }

    @Test
    public void testIsWriteOperationNull() throws IOException {
        RoleAuthority roleAuthority = new RoleAuthority();
        roleAuthority.initialize();
        
        KeyStore keyStore = new KeyStoreMock();
        roleAuthority.setKeyStore(keyStore);
        
        // Add some roles
        List<String> roles = new ArrayList<>();
        roles.add("storage.tenant.weather.updater");

        // Create and sign token with keyVersion = 0
        RoleToken roleToken = new RoleToken.Builder(rolVersion, svcDomain, roles)
            .salt(salt).ip("127.0.0.1").expirationWindow(expirationTime)
            .principal(".").keyId(testKeyVersionK0).build();
        roleToken.sign(ztsPrivateKeyStringK0);
        
        Principal principal = roleAuthority.authenticate(roleToken.getSignedToken(),
                "127.0.0.2", null, null);
        assertNotNull(principal);
    }

    @Test
    public void testInitialize() throws NoSuchFieldException, SecurityException,
            IllegalArgumentException, IllegalAccessException {
        Class<RoleAuthority> c = RoleAuthority.class;
        RoleAuthority roleAuthority = new RoleAuthority();
        System.setProperty(RoleAuthority.ATHENZ_PROP_TOKEN_OFFSET, "-1");
        
        roleAuthority.initialize();
        
        Field f1 = c.getDeclaredField("allowedOffset");
        f1.setAccessible(true);
        int m = (Integer) f1.get(roleAuthority);
        
        assertEquals(m,300);
        assertEquals(roleAuthority.userDomain,"user");
    }

    @Test
    public void testGetAuthenticateChallenge() {
        RoleAuthority roleAuthority = new RoleAuthority();
        assertEquals(roleAuthority.getAuthenticateChallenge(), "AthenzRoleToken realm=\"athenz\"");
    }
}
