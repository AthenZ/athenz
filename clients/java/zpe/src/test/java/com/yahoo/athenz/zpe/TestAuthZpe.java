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
package com.yahoo.athenz.zpe;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zpe.AuthZpeClient;
import com.yahoo.athenz.zpe.ZpeUpdPolLoader;
import com.yahoo.athenz.zpe.AuthZpeClient.AccessCheckStatus;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.rdl.JSON;

/**
 * These tests are dependent on a policy file in a local dir.
 */
public class TestAuthZpe {
    
    private PrivateKey ztsPrivateKeyK0;
    private PrivateKey ztsPrivateKeyK1;
    private PrivateKey ztsPrivateKeyK17;
    private PrivateKey ztsPrivateKeyK99;
    private PrivateKey zmsPrivateKeyK0;

    private final String roleVersion = "Z1";
    private final long   expirationTime = 100; // 100 seconds
    private final String salt = "aAkjbbDMhnLX";

    private RoleToken rToken0AnglerPublic = null;
    private RoleToken rToken0AnglerExpirePublic = null;
    private RoleToken rToken0AnglerAdmin = null;
    private RoleToken rToken0SportsAdmin = null;
    private RoleToken rToken1SportsAdmin = null;
    private RoleToken rToken0AnglerPachinko = null;
    private RoleToken rToken0CoreTechPublic = null;
    private RoleToken rToken0EmptyPublic = null;
    private RoleToken rToken0AnglerRegex = null;
    
    private static boolean sleepCompleted = false;
    
    @BeforeClass
    public void beforeClass() throws IOException {

        Path path = Paths.get("./src/test/resources/zts_private_k0.pem");
        ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get("./src/test/resources/zms_private_k0.pem");
        zmsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));
        
        path = Paths.get("./src/test/resources/zts_private_k1.pem");
        ztsPrivateKeyK1 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get("./src/test/resources/zts_private_k17.pem");
        ztsPrivateKeyK17 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get("./src/test/resources/zts_private_k99.pem");
        ztsPrivateKeyK99 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        List<String> roles = new ArrayList<String>();
        roles.add("public");
        rToken0AnglerPublic = createRoleToken("angler", roles, "0");
        rToken0AnglerExpirePublic = createRoleToken("angler", roles, "0", 3);
        rToken0CoreTechPublic = createRoleToken("coretech", roles, "0");
        rToken0EmptyPublic = createRoleToken("empty", roles, "0");
        roles = new ArrayList<String>();
        roles.add("admin");
        rToken0AnglerAdmin = createRoleToken("angler", roles, "0");
        rToken0SportsAdmin = createRoleToken("sports", roles, "0");
        rToken1SportsAdmin = createRoleToken("sports", roles, "1");

        roles = new ArrayList<String>();
        roles.add("pachinko");
        rToken0AnglerPachinko = createRoleToken("angler", roles, "0");
        
        roles = new ArrayList<String>();
        roles.add("full_regex");
        roles.add("matchall");
        roles.add("matchstarts");
        roles.add("matchcompare");
        roles.add("matchregex");
        rToken0AnglerRegex = createRoleToken("angler", roles, "0");

        // NOTE: we will create file with different suffix so as not to confuse
        // ZPE update-load thread due to possible timing issue.
        // Then rename it with ".pol" suffix afterwards.
        // Issue: file is created, but file is empty because it has not 
        // been written out yet - thus zpe thinks its a bad file and will
        // wait for it to get updated before trying to reload.
        // Ouch, but the file doesnt get a change in modified timestamp so zpe
        // never reloads.
        
        path = Paths.get("./src/test/resources/angler.pol");
        DomainSignedPolicyData domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path),
                DomainSignedPolicyData.class);
        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        String signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData.getPolicyData()), zmsPrivateKeyK0);
        signedPolicyData.setZmsSignature(signature).setZmsKeyId("0");
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsPrivateKeyK0);
        domainSignedPolicyData.setSignature(signature).setKeyId("0");
        File file = new File("./src/test/resources/pol_dir/angler.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));
        File renamedFile = new File("./src/test/resources/pol_dir/angler.pol");
        file.renameTo(renamedFile);
        
        path = Paths.get("./src/test/resources/sports.pol");
        domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData.getPolicyData()), zmsPrivateKeyK0);
        signedPolicyData.setZmsSignature(signature).setZmsKeyId("0");
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsPrivateKeyK1);
        domainSignedPolicyData.setSignature(signature).setKeyId("1");
        file = new File("./src/test/resources/pol_dir/sports.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));
        renamedFile = new File("./src/test/resources/pol_dir/sports.pol");
        file.renameTo(renamedFile);
        
        path = Paths.get("./src/test/resources/empty.pol");
        domainSignedPolicyData = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        signedPolicyData = domainSignedPolicyData.getSignedPolicyData();
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData.getPolicyData()), zmsPrivateKeyK0);
        signedPolicyData.setZmsSignature(signature).setZmsKeyId("0");
        signature = Crypto.sign(SignUtils.asCanonicalString(signedPolicyData), ztsPrivateKeyK0);
        domainSignedPolicyData.setSignature(signature).setKeyId("0");
        file = new File("./src/test/resources/pol_dir/empty.gen");
        file.createNewFile();
        Files.write(file.toPath(), JSON.bytes(domainSignedPolicyData));

        renamedFile = new File("./src/test/resources/pol_dir/empty.pol");
        file.renameTo(renamedFile);
    }
    
    @BeforeMethod
    private void loadFiles() {
        
        if (sleepCompleted) {
            return;
        }
        // sleep for a short period of time so the library has a chance
        // to load all the policy files since that's done by a background
        // thread
        
        AuthZpeClient.init();
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
        }
        
        sleepCompleted = true;
    }
    
    private RoleToken createRoleToken(String svcDomain, List<String> roles, String keyId, long expiry) {
        RoleToken token = new RoleToken.Builder(roleVersion, svcDomain, roles)
            .salt(salt).expirationWindow(expiry).keyId(keyId).build();
        
        PrivateKey key = null;
        if ("1".equals(keyId)) {
            key = ztsPrivateKeyK1;
        } else if ("0".equals(keyId)) {
            key = ztsPrivateKeyK0;
        } else if ("17".equals(keyId)) {
            key = ztsPrivateKeyK17;
        } else if ("99".equals(keyId)) {
            key = ztsPrivateKeyK99;
        }
        
        token.sign(key);
        return token;
    }

    private RoleToken createRoleToken(String svcDomain, List<String> roles, String keyId) {
        return createRoleToken(svcDomain, roles, keyId, expirationTime);
    }

    @Test
    public void testKeyIds() {
        String action      = "read";
        StringBuilder roleName = new StringBuilder();
        
        //Test key id 0 on Angler domain
        String angResource = "angler:stuff";
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW, "rsrc=" + angResource + " act=" + action);
        Assert.assertEquals(roleName.toString(), "public");

        //Test key id 1 on Sports domain
        roleName.setLength(0);
        String resource = "sports.NFL_DB";
        status = AuthZpeClient.allowAccess(rToken1SportsAdmin, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW, "rsrc=" + resource + " act=" + action);
        Assert.assertEquals(roleName.toString(), "admin");
    }
    
    @Test
    public void testWrongKeyId() {
        String action      = "REad";
        StringBuilder roleName = new StringBuilder();

        //Test key id 0 on Sports domain - should fail because its signed with key id 1
        String resource = "sports.NFL_DB";
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0SportsAdmin, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "admin");

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0SportsAdmin.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "admin");

        // multi tokens test with duplicate tokens
        tokenList = new ArrayList<String>();
        tokenList.add(rToken0SportsAdmin.getSignedToken());
        tokenList.add(rToken0SportsAdmin.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "admin");
    }
    
    @Test
    public void testPublicReadAllowedMixCaseActionResource() {

        String action      = "REad";
        String angResource = "ANGler:stuff";
        StringBuilder roleName = new StringBuilder();
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        status = AuthZpeClient.allowAccess(rToken0AnglerPublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }
    
    @Test
    public void testTokenExpired() {
        String action      = "REad";
        String angResource = "ANGler:stuff";
        StringBuilder roleName = new StringBuilder();
        
        RoleToken tokenMock = Mockito.mock(RoleToken.class);
        Mockito.when(tokenMock.getExpiryTime()).thenReturn(1L); // too old
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(tokenMock, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_EXPIRED);
    }

    @Test
    public void testPublicReadAllowed() {
        String action      = "read";
        String angResource = "angler:stuff";
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testPublicReadMismatchDomain() {
        String action      = "read";
        String angResource = "anglerTest:stuff";
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_MISMATCH);

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_MISMATCH);
        Assert.assertEquals(roleName.toString(), "");
    }

    @Test
    public void testPublicReadDomainNotFound() {
        String action      = "read";
        String angResource = "CoreTech:stuff";
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0CoreTechPublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_NOT_FOUND);

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_NOT_FOUND);
        Assert.assertEquals(roleName.toString(), "");
    }

    @Test
    public void testPublicReadDomainEmpty() {
        String action      = "read";
        String angResource = "empty:stuff";
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0EmptyPublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_EMPTY);

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0EmptyPublic.getSignedToken());
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_EMPTY);
        Assert.assertEquals(roleName.toString(), "");
    }

    @Test
    public void testPublicReadInvalidRoleToken() {
        String action      = "read";
        String angResource = "angler:stuff";

        // make the token invalid by adding chars to the signature
        String roleToken = rToken0AnglerPublic.getSignedToken();
        roleToken = roleToken.replace(";s=", ";s=ab");
        AccessCheckStatus status = AuthZpeClient.allowAccess(roleToken, angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_INVALID);

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(roleToken); // add the bad one in
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "public");
    }

    @Test
    public void testPublicReadExpiredRoleToken() {
        String action      = "read";
        String angResource = "angler:stuff";

        // sleep 3 seconds so our token gets expired

        try {
            Thread.sleep(3000);
        } catch (Exception exc) {
        }
        
        // the roletoken validate return false regardless if the token is 
        // invalid due to expiry or invalid signature. So we'll only
        // the expired roletoken if we add it to the cache and then
        // try to use it again, but the cache clear test case sets
        // the timeout to 1secs so as soon as it's added, within a
        // second it's removed so we can't wait until it's expired to
        // test again. so for know we'll just get invalid token
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerExpirePublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_INVALID);

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken()); // add the expired one in
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "public");
    }

    @Test
    public void testPublicReadInvalidParameters() {
        String action      = "read";
        String angResource = "anglerTest:stuff";
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic.getSignedToken(), "", action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_INVALID_PARAMETERS);

        status = AuthZpeClient.allowAccess(rToken0AnglerPublic.getSignedToken(), angResource, "");
        Assert.assertEquals(status, AccessCheckStatus.DENY_INVALID_PARAMETERS);
    }
    
    @Test
    public void testPublicWriteAllowed() {
        String action      = "write";
        String angResource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "public");
    }

    @Test
    public void testPublicWriteAllowedMixCaseActionResource() {
        String action      = "WRite";
        String angResource = "angLEr:STUff";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testPublicUknActDenied() {
        String action      = "WRiteREad";
        String angResource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }
    
    @Test
    public void testPublicThrowDenied() {
        String action      = "THrow";
        String angResource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY);
    }
    
    @Test
    public void testAdminThrowAllowed() {
        String action      = "THrow";
        String angResource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerAdmin, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testValidAccessResource() {
        String action      = "ACCESS";
        String angResource = "angler:tables.blah";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPachinko, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "pachinko");
    }

    @Test
    public void testInvalidAccessResource() {
        String action      = "ACCESS";
        String angResource = "angler:tables.blahblah";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPachinko, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
        Assert.assertEquals(roleName.toString(), "");
    }

    @Test
    public void testPublicFishingDenied() {
        String action      = "fish";
        String angResource = "angler:spawningpondLittleBassLake";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY);
        Assert.assertEquals(roleName.toString(), "public");
    }

    @Test
    public void testPublicFishingAllowed() {
        String action      = "fish";
        String angResource = "angler:stockedpondBigBassLake";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "public");
    }

    @Test
    public void testPublicFishingAllowedTokenString() {
        String action      = "fish";
        String angResource = "angler:stockedpondBigBassLake";
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerPublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testCleanupOfToken() {
        // perform an allowed access check
        String action      = "fish";
        String angResource = "angler:stockedpondBigBassLake";
        List<String> roles = new ArrayList<String>();
        roles.add("public");
        roles.add("admin");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1); // 1 sec expiry
        String signedToken = rtoken.getSignedToken();
        AccessCheckStatus status = AuthZpeClient.allowAccess(signedToken, angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Map<String, RoleToken> roleMap = ZpeUpdPolLoader.getRoleTokenCacheMap();
        RoleToken mapToken = roleMap.get(signedToken);
        Assert.assertEquals(signedToken.equals(mapToken.getSignedToken()), true);
        // then in a loop, check for existence of the token in the token map
        // increase the timeout to 30 secs. in sd sometimes it takes a while
        // before the entry is expired.
        for (int cnt = 0; mapToken != null && cnt < 30; ++cnt) {
            // -Dyahoo.zpeclient.updater.monitor_timeout_secs=1
            // -Dyahoo.zpeclient.updater.cleanup_tokens_secs=1
            try {
                Thread.sleep(1000); // test has timeout set to 1 second
            } catch (Exception exc) {
                System.out.println("testCleanupOfToken: sleep was interrupted: in loop, cnt=" + cnt + " token=" + signedToken);
            }

            mapToken = roleMap.get(signedToken);
            if (mapToken != null) {
                Assert.assertEquals(signedToken.equals(mapToken.getSignedToken()), true);
            }
        }
        // assert token is not in the map outside of the loop
        Assert.assertNull(mapToken);
    }

    @Test
    public void testCleanupOfTokenNotCleaned() {
        // perform an allowed access check
        String action      = "fish";
        String angResource = "angler:stockedpondBigBassLake";
        List<String> roles = new ArrayList<String>();
        roles.add("public");
        roles.add("admin");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 10); // 10 sec expiry
        String signedToken = rtoken.getSignedToken();
        AccessCheckStatus status = AuthZpeClient.allowAccess(signedToken, angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Map<String, RoleToken> roleMap = ZpeUpdPolLoader.getRoleTokenCacheMap();
        RoleToken mapToken = roleMap.get(signedToken);
        Assert.assertEquals(signedToken.equals(mapToken.getSignedToken()), true);
        // then in a loop, check for existence of the token in the token map
        for (int cnt = 0; mapToken != null && cnt < 5; ++cnt) {
            // -Dyahoo.zpeclient.updater.monitor_timeout_secs=1
            // -Dyahoo.zpeclient.updater.cleanup_tokens_secs=1
            try {
                Thread.sleep(1000); // test has timeout set to 1 second
            } catch (Exception exc) {
                System.out.println("testCleanupOfToken: sleep was interrupted: in loop, cnt=" + cnt + " token=" + signedToken);
            }

            mapToken = roleMap.get(signedToken);
            Assert.assertNotNull(mapToken);
            Assert.assertEquals(signedToken.equals(mapToken.getSignedToken()), true);
        }
        // assert token is not in the map outside of the loop
        Assert.assertNotNull(mapToken);
        Assert.assertEquals(signedToken.equals(mapToken.getSignedToken()), true);
    }

    @Test
    public void testWildcardManagePondsKernDenied() {
        String action      = "manage";
        String angResource = "angler:pondsVenturaCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerkernco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        StringBuilder roleName = new StringBuilder(256);
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken, angResource, action, roleName);
        // Kern county manager not allowed to manage Ventura county ponds
        Assert.assertEquals(status, AccessCheckStatus.DENY);
    }

    @Test
    public void testWildcardManagePondsKernAllowed() {
        String action      = "manage";
        String angResource = "angler:pondsKernCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerkernco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        StringBuilder roleName = new StringBuilder(256);

        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken, angResource, action, roleName);
        // Ventura county manager is allowed to manage Kern county ponds
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "manager*");
    }

    @Test
    public void testWildcardManageRiversKernAllowed() {
        String action      = "manage";
        String angResource = "angler:RiversKernCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerkernco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        StringBuilder roleName = new StringBuilder(256);

        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken, angResource, action, roleName);
        // Ventura county manager is allowed to manage Kern county ponds
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "manager*");
    }

    @Test
    public void testWildcardManagePondsVenturaAllowed() {
        String action      = "manage";
        String angResource = "angler:pondsKernCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerventuraco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        StringBuilder roleName = new StringBuilder(256);

        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken, angResource, action, roleName);
        // Ventura county manager is allowed to manage Kern county ponds
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "manager*");
    }

    @Test
    public void testWildcardManageRiversVenturaAllowed() {
        String action      = "manage";
        String angResource = "angler:RiversVenturaCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerventuraco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        StringBuilder roleName = new StringBuilder(256);

        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken, angResource, action, roleName);
        // Ventura county manager is allowed to manage Kern county ponds
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testWildcardManageRiversVenturaDenied() {
        String action      = "manage";
        String angResource = "angler:RiversKernCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerventuraco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        StringBuilder roleName = new StringBuilder(256);

        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken, angResource, action, roleName);
        // Ventura county manager is allowed to manage Kern county ponds
        Assert.assertEquals(status, AccessCheckStatus.DENY);
        Assert.assertEquals(roleName.toString(), "managerventura*");
    }

    @Test
    public void testWildcardManagePondsAllowedTokenString() {
        String action      = "manage";
        String angResource = "angler:pondsKernCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerkernco");
        roles.add("managerventuraco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testWildcardManageRiversDeniedTokenString() {
        String action      = "manage";
        String angResource = "angler:riversKernCounty";
        List<String> roles = new ArrayList<String>();
        roles.add("managerkernco");
        roles.add("managerventuraco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY);

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerAdmin.getSignedToken()); // add an ALLOW role
        tokenList.add(rtoken.getSignedToken()); // add the DENY role token in
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY); // DENY over-rides ALLOW
        Assert.assertEquals(roleName.toString(), "managerventura*");

        tokenList = new ArrayList<String>();
        tokenList.add(rToken0CoreTechPublic.getSignedToken()); // add a DENY_DOMAIN_MISMATCH
        tokenList.add(rToken0AnglerAdmin.getSignedToken()); // add an ALLOW role
        tokenList.add(rtoken.getSignedToken()); // add the DENY role token in
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY); // DENY over-rides everything else
        Assert.assertEquals(roleName.toString(), "managerventura*");

        // order wont matter
        tokenList = new ArrayList<String>();
        tokenList.add(rtoken.getSignedToken()); // add the DENY role token in
        tokenList.add(rToken0CoreTechPublic.getSignedToken()); // add a DENY_DOMAIN_MISMATCH
        tokenList.add(rToken0AnglerAdmin.getSignedToken()); // add an ALLOW role
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY); // DENY over-rides everything else
        Assert.assertEquals(roleName.toString(), "managerventura*");
    }

    @Test
    public void testAllowAccessMatchAll() {

        String action = "all";
        String resource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchall");

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchall");
    }

    @Test
    public void testAllowAccessMatchStartsWithAllowed() {

        String action = "startswith";
        String resource = "angler:startswithgreat";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchstarts");

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchstarts");
    }

    @Test
    public void testAllowAccessMatchEqualAllowed() {

        String action = "compare";
        String resource = "angler:compare";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchcompare");

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchcompare");
    }

    @Test
    public void testAllowAccessMatchRegexAllowed() {

        String action = "regex";
        String resource = "angler:nhllosangeleskings";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchregex");

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchregex");
    }

    @Test
    public void testAllowAccessMatchStartsWithDenied() {

        String action = "startswith";
        String resource = "angler:startswitgreat"; /* missing h from startswith */
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
        Assert.assertEquals(roleName.toString(), "");

        // multi tokens test
        List<String> tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        // last token was for domain coretech
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_MISMATCH);
        Assert.assertEquals(roleName.toString(), "");

        tokenList = new ArrayList<String>();
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken());
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        // last token was for domain angler with regex token
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
        Assert.assertEquals(roleName.toString(), "");

    }

    @Test
    public void testAllowAccessMatchEqualDenied() {

        String action = "compare";
        String resource = "angler:compares"; /* extra s after compare */
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }

    @Test
    public void testAllowAccessMatchRegexDenied() {

        String action = "regex";
        String resource = "angler:nhllosangeleskingsA"; /* extra A after kings */
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }

    @Test
    public void testAllowAccessMatchRegexInvalidOr1() {

        String action = "full_regex";
        String resource = "angler:coretech";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }

    @Test
    public void testAllowAccessMatchRegexInvalidOr2() {

        String action = "full_regex";
        String resource = "angler:corecommit";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }

    @Test
    public void testAllowAccessMatchRegexInvalidRange1() {

        String action = "full_regex";
        String resource = "angler:corea";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }

    @Test
    public void testAllowAccessMatchRegexInvalidRange2() {

        String action = "full_regex";
        String resource = "angler:coreb";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }

    @Test
    public void testAllowAccessMatchRegexInvalidRange3() {

        String action = "full_regex";
        String resource = "angler:coref";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
    }
    
    @Test
    public void testPatternFromGlob() {
        assertEquals("^abc$", AuthZpeClient.patternFromGlob("abc"));
        assertEquals("^abc.*$", AuthZpeClient.patternFromGlob("abc*"));
        assertEquals("^abc.$", AuthZpeClient.patternFromGlob("abc?"));
        assertEquals("^.*abc.$", AuthZpeClient.patternFromGlob("*abc?"));
        assertEquals("^abc\\.abc:.*$", AuthZpeClient.patternFromGlob("abc.abc:*"));
        assertEquals("^ab\\[a-c]c$", AuthZpeClient.patternFromGlob("ab[a-c]c"));
        assertEquals("^ab.*\\.\\(\\)\\^\\$c$", AuthZpeClient.patternFromGlob("ab*.()^$c"));
        assertEquals("^abc\\\\test\\\\$", AuthZpeClient.patternFromGlob("abc\\test\\"));
        assertEquals("^ab\\{\\|c\\+$", AuthZpeClient.patternFromGlob("ab{|c+"));
        assertEquals("^\\^\\$\\[\\(\\)\\\\\\+\\{\\..*.\\|$", AuthZpeClient.patternFromGlob("^$[()\\+{.*?|"));
    }
    
    @Test
    public void testValidateRoleToken() {
        
        List<String> roles = new ArrayList<String>();
        roles.add("public_role");
        RoleToken rToken = createRoleToken("coretech", roles, "0");
        
        RoleToken validatedToken = AuthZpeClient.validateRoleToken(rToken.getSignedToken());
        assertNotNull(validatedToken);
        assertEquals(validatedToken.getRoles().size(), 1);
        assertEquals(validatedToken.getRoles().get(0), "public_role");
        assertEquals(validatedToken.getDomain(), "coretech");
        
        // asking for the same token should return the data from our cache
        
        validatedToken = AuthZpeClient.validateRoleToken(rToken.getSignedToken());
        assertNotNull(validatedToken);
        assertEquals(validatedToken.getRoles().size(), 1);
        assertEquals(validatedToken.getRoles().get(0), "public_role");
        assertEquals(validatedToken.getDomain(), "coretech");
    }
    
    @Test
    public void testValidateRoleTokenInvalidKeyVersion() {
        
        List<String> roles = new ArrayList<String>();
        roles.add("public_role");
        RoleToken rToken = createRoleToken("coretech", roles, "0");
        
        String tamperedToken = rToken.getSignedToken().replace(";k=0;", ";k=zone1.invalid");
        RoleToken validatedToken = AuthZpeClient.validateRoleToken(tamperedToken);
        assertNull(validatedToken);
    }
    
    @Test
    public void testValidateRoleTokenInvalidSignature() {
        
        List<String> roles = new ArrayList<String>();
        roles.add("public_role");
        RoleToken rToken = createRoleToken("coretech", roles, "0");
        
        String tamperedToken = rToken.getSignedToken().replace(";s=", ";s=siginvalid");
        RoleToken validatedToken = AuthZpeClient.validateRoleToken(tamperedToken);
        assertNull(validatedToken);
    }

    @Test
    public void testAccessCheckStatus() {
        for (AccessCheckStatus stat : AccessCheckStatus.values()) {
            assertNotNull(stat.toString());
        }
    }

    @Test
    public void testInit() {
        AuthZpeClient.init();
    }

    @Test
    public void testgetZtsPublicKeyNull() throws Exception {
        PublicKey key = AuthZpeClient.getZtsPublicKey("notexist");
        assertNull(key);
    }
}

