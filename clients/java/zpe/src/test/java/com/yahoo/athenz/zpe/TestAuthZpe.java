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
package com.yahoo.athenz.zpe;

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zpe.AuthZpeClient.AccessCheckStatus;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;
import com.yahoo.rdl.JSON;
import io.jsonwebtoken.SignatureAlgorithm;
import org.mockito.Mockito;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.HttpResponse;
import org.testng.Assert;
import org.testng.annotations.*;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_JWK_ATHENZ_CONF;
import static org.mockito.Mockito.mock;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.testng.Assert.*;

/**
 * These tests are dependent on a policy file in a local dir.
 */
public class TestAuthZpe {
    
    private PrivateKey ztsPrivateKeyK0;
    private PrivateKey ztsPrivateKeyK1;
    private PrivateKey ztsPrivateKeyK17;
    private PrivateKey ztsPrivateKeyK99;

    private final long expirationTime = 100; // 100 seconds

    private RoleToken rToken0AnglerPublic = null;
    private RoleToken rToken0AnglerExpirePublic = null;
    private RoleToken rToken0AnglerAdmin = null;
    private RoleToken rToken0SportsAdmin = null;
    private RoleToken rToken1SportsAdmin = null;
    private RoleToken rToken0AnglerPachinko = null;
    private RoleToken rToken0CoreTechPublic = null;
    private RoleToken rToken0EmptyPublic = null;
    private RoleToken rToken0AnglerRegex = null;

    private String accessToken0AnglerRegex = null;

    private static boolean sleepCompleted = false;
    
    @SuppressWarnings("ResultOfMethodCallIgnored")
    @BeforeClass
    public void beforeClass() throws IOException {
        System.setProperty(ZPE_PROP_JWK_ATHENZ_CONF, TestAuthZpe.class.getClassLoader().getResource("jwk/athenz.conf").getPath());
        System.setProperty(ZpeConsts.ZPE_PROP_CHECK_POLICY_ZMS_SIGNATURE, "true");

        Path path = Paths.get("./src/test/resources/unit_test_zts_private_k0.pem");
        ztsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));
        
        path = Paths.get("./src/test/resources/unit_test_zts_private_k1.pem");
        ztsPrivateKeyK1 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get("./src/test/resources/unit_test_zts_private_k17.pem");
        ztsPrivateKeyK17 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get("./src/test/resources/unit_test_zts_private_k99.pem");
        ztsPrivateKeyK99 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        path = Paths.get("./src/test/resources/unit_test_zms_private_k0.pem");
        PrivateKey zmsPrivateKeyK0 = Crypto.loadPrivateKey(new String((Files.readAllBytes(path))));

        List<String> roles = new ArrayList<>();
        roles.add("public");
        rToken0AnglerPublic = createRoleToken("angler", roles, "0");
        rToken0AnglerExpirePublic = createRoleToken("angler", roles, "0", 3);
        rToken0CoreTechPublic = createRoleToken("coretech", roles, "0");
        rToken0EmptyPublic = createRoleToken("empty", roles, "0");
        roles = new ArrayList<>();
        roles.add("admin");
        rToken0AnglerAdmin = createRoleToken("angler", roles, "0");
        rToken0SportsAdmin = createRoleToken("sports", roles, "0");
        rToken1SportsAdmin = createRoleToken("sports", roles, "1");

        roles = new ArrayList<>();
        roles.add("pachinko");
        rToken0AnglerPachinko = createRoleToken("angler", roles, "0");
        
        roles = new ArrayList<>();
        roles.add("full_regex");
        roles.add("matchall");
        roles.add("matchstarts");
        roles.add("matchcompare");
        roles.add("matchregex");
        rToken0AnglerRegex = createRoleToken("angler", roles, "0");
        accessToken0AnglerRegex = createAccessToken("angler", roles, "0");

        // NOTE: we will create file with different suffix so as not to confuse
        // ZPE update-load thread due to possible timing issue.
        // Then rename it with ".pol" suffix afterwards.
        // Issue: file is created, but file is empty because it has not 
        // been written out yet - thus zpe thinks it's a bad file and will
        // wait for it to get updated before trying to reload.
        // Ouch, but the file doesn't get a change in modified timestamp so zpe
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
    
    @AfterClass
    public void afterClass() {
        System.clearProperty(ZPE_PROP_JWK_ATHENZ_CONF);
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
        } catch (InterruptedException ignored) {
        }
        
        sleepCompleted = true;

        // even if we're passing invalid value, we'll default
        // to 300 seconds

        AuthZpeClient.setTokenAllowedOffset(-100);

        // set up our public keys for access tokens

        AuthZpeClient.addAccessTokenSignKeyResolverKey("0", Crypto.extractPublicKey(ztsPrivateKeyK0));
        AuthZpeClient.addAccessTokenSignKeyResolverKey("1", Crypto.extractPublicKey(ztsPrivateKeyK1));
        AuthZpeClient.addAccessTokenSignKeyResolverKey("17", Crypto.extractPublicKey(ztsPrivateKeyK17));
        AuthZpeClient.addAccessTokenSignKeyResolverKey("99", Crypto.extractPublicKey(ztsPrivateKeyK99));
    }
    
    private RoleToken createRoleToken(String svcDomain, List<String> roles, String keyId, long expiry) {

        final String salt = "aAkjbbDMhnLX";
        final String roleVersion = "Z1";

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
        assertNotNull(key);
        token.sign(key);
        return token;
    }

    private RoleToken createRoleToken(String svcDomain, List<String> roles, String keyId) {
        return createRoleToken(svcDomain, roles, keyId, expirationTime);
    }

    private String createAccessToken(String svcDomain, List<String> roles, String keyId, long expiry) {

        AccessToken token = new AccessToken();
        token.setVersion(1);
        token.setAudience(svcDomain);
        token.setScope(roles);

        long now = System.currentTimeMillis();
        token.setIssuer("athenz");
        token.setIssueTime(now);
        token.setExpiryTime(now + expiry);

        try {
            Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
            String certStr = new String(Files.readAllBytes(path));
            X509Certificate cert = Crypto.loadX509Certificate(certStr);
            token.setConfirmX509CertHash(cert);
        } catch (IOException ignored) {
            fail();
        }

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
        assertNotNull(key);
        return token.getSignedToken(key, keyId, SignatureAlgorithm.RS256);
    }

    private String createInvalidAccessToken(String svcDomain, List<String> roles) {

        AccessToken token = new AccessToken();
        token.setVersion(1);
        token.setAudience(svcDomain);
        token.setScope(roles);

        long now = System.currentTimeMillis();
        token.setIssuer("athenz");
        token.setIssueTime(now);
        token.setExpiryTime(now + 120);

        // using key with id 0 but including id of 1

        return token.getSignedToken(ztsPrivateKeyK0, "1", SignatureAlgorithm.RS256);
    }

    private String createAccessToken(String svcDomain, List<String> roles, String keyId) {
        return createAccessToken(svcDomain, roles, keyId, expirationTime);
    }

    @Test
    public void testInvalidPublicKeyStore() {

        try {
            AuthZpeClient.setPublicKeyStoreFactoryClass("invalidclass");
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testInvalidZpeClientClass() {

        try {
            AuthZpeClient.setZPEClientClass("invalidclass");
            fail();
        } catch (Exception ignored) {
        }

        AuthZpeClient.setZPEClientClass("com.yahoo.athenz.zpe.ZpeUpdater");
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
    public void testMultipleTokens() {
        String action = "REad";
        StringBuilder roleName = new StringBuilder();

        String resource = "sports.NFL_DB";
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0SportsAdmin, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "admin");

        // multi tokens test
        List<String> tokenList = new ArrayList<>();
        tokenList.add(rToken0SportsAdmin.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "admin");

        // multi tokens test with duplicate tokens
        tokenList = new ArrayList<>();
        tokenList.add(rToken0SportsAdmin.getSignedToken());
        tokenList.add(rToken0SportsAdmin.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "admin");
    }

    @Test
    public void testMultipleTokenListEmpty() {
        String action = "REad";
        String resource = "sports.NFL_DB";
        StringBuilder roleName = new StringBuilder();

        // multi token list - empty

        List<String> tokenList = new ArrayList<>();
        AccessCheckStatus status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_NO_MATCH);
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
        
        RoleToken tokenMock = mock(RoleToken.class);
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
        List<String> tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
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
        } catch (Exception ignored) {
        }
        
        // the roletoken validate return false regardless if the token is 
        // invalid due to expiry or invalid signature. So we'll only
        // the expired roletoken if we add it to the cache and then
        // try to use it again, but the cache clear test case sets
        // the timeout to 1secs so as soon as it's added, within a
        // second it's removed, so we can't wait until it's expired to
        // test again. so for know we'll just get invalid token
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rToken0AnglerExpirePublic.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_EXPIRED);

        // multi tokens test
        List<String> tokenList = new ArrayList<>();
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
    public void testPublicThrowDeniedCaseSensitive() {
        String action      = "THrow2";
        String angResource = "angler:StufF2";
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
    public void testValidAccessResourceCaseSensitive() {
        String action      = "AccesS2";
        String angResource = "angler:TableS.BlaH2";
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
        // perform allowed access check
        String action      = "fish";
        String angResource = "angler:stockedpondBigBassLake";
        List<String> roles = new ArrayList<>();
        roles.add("public");
        roles.add("admin");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1); // 1 sec expiry
        String signedToken = rtoken.getSignedToken();
        AccessCheckStatus status = AuthZpeClient.allowAccess(signedToken, angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Map<String, RoleToken> roleMap = ZpeUpdPolLoader.getRoleTokenCacheMap();
        RoleToken mapToken = roleMap.get(signedToken);
        Assert.assertEquals(signedToken, mapToken.getSignedToken());
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
                Assert.assertEquals(signedToken, mapToken.getSignedToken());
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
        List<String> roles = new ArrayList<>();
        roles.add("public");
        roles.add("admin");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 10); // 10 sec expiry
        String signedToken = rtoken.getSignedToken();
        AccessCheckStatus status = AuthZpeClient.allowAccess(signedToken, angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Map<String, RoleToken> roleMap = ZpeUpdPolLoader.getRoleTokenCacheMap();
        RoleToken mapToken = roleMap.get(signedToken);
        Assert.assertEquals(signedToken, mapToken.getSignedToken());
        // then in a loop, check for existence of the token in the token map
        for (int cnt = 0; cnt < 5; ++cnt) {
            // -Dyahoo.zpeclient.updater.monitor_timeout_secs=1
            // -Dyahoo.zpeclient.updater.cleanup_tokens_secs=1
            try {
                Thread.sleep(1000); // test has timeout set to 1 second
            } catch (Exception exc) {
                System.out.println("testCleanupOfToken: sleep was interrupted: in loop, cnt=" + cnt + " token=" + signedToken);
            }

            mapToken = roleMap.get(signedToken);
            Assert.assertNotNull(mapToken);
            Assert.assertEquals(signedToken, mapToken.getSignedToken());
        }
        // assert token is not in the map outside of the loop
        Assert.assertNotNull(mapToken);
        Assert.assertEquals(signedToken, mapToken.getSignedToken());
    }

    @Test
    public void testWildcardManagePondsKernDenied() {
        String action      = "manage";
        String angResource = "angler:pondsVenturaCounty";
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
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
        List<String> roles = new ArrayList<>();
        roles.add("managerkernco");
        roles.add("managerventuraco");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 1000); // 1000 sec expiry
        
        AccessCheckStatus status = AuthZpeClient.allowAccess(rtoken.getSignedToken(), angResource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY);

        // multi tokens test
        List<String> tokenList = new ArrayList<>();
        tokenList.add(rToken0AnglerAdmin.getSignedToken()); // add an ALLOW role
        tokenList.add(rtoken.getSignedToken()); // add the DENY role token in
        StringBuilder roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY); // DENY over-rides ALLOW
        Assert.assertEquals(roleName.toString(), "managerventura*");

        tokenList = new ArrayList<>();
        tokenList.add(rToken0CoreTechPublic.getSignedToken()); // add a DENY_DOMAIN_MISMATCH
        tokenList.add(rToken0AnglerAdmin.getSignedToken()); // add an ALLOW role
        tokenList.add(rtoken.getSignedToken()); // add the DENY role token in
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, angResource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY); // DENY over-rides everything else
        Assert.assertEquals(roleName.toString(), "managerventura*");

        // order wont matter
        tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchall");
    }

    @Test
    public void testAllowAccessMatchAllAccessToken() throws IOException {

        String action = "all";
        String resource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessCheckStatus status = AuthZpeClient.allowAccess(accessToken0AnglerRegex, cert, null, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchall");

        // second time for the same token we should get from the cache

        status = AuthZpeClient.allowAccess(accessToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchall");

        // now we're going to include the Bearer part

        status = AuthZpeClient.allowAccess("Bearer " + accessToken0AnglerRegex, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
        Assert.assertEquals(roleName.toString(), "matchall");
    }

    @Test
    public void testAllowAccessMatchAllAccessTokenNoRoleName() throws IOException {

        String action = "all";
        String resource = "angler:stuff";

        Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessCheckStatus status = AuthZpeClient.allowAccess(accessToken0AnglerRegex, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        // second time for the same token we should get from the cache

        status = AuthZpeClient.allowAccess(accessToken0AnglerRegex, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        // now we're going to include the Bearer part

        status = AuthZpeClient.allowAccess("Bearer " + accessToken0AnglerRegex, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);
    }

    @Test
    public void testAllowAccessCertHashMismatch() throws IOException {

        String action = "all";
        String resource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        Path path = Paths.get("src/test/resources/mtls_token_mismatch.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessCheckStatus status = AuthZpeClient.allowAccess(accessToken0AnglerRegex, cert, null, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_CERT_HASH_MISMATCH);
    }

    @Test
    public void testAllowAccessCertHashMismatchNoRoleName() throws IOException {

        String action = "all";
        String resource = "angler:stuff";

        Path path = Paths.get("src/test/resources/mtls_token_mismatch.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessCheckStatus status = AuthZpeClient.allowAccess(accessToken0AnglerRegex, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.DENY_CERT_HASH_MISMATCH);
    }

    @Test
    public void testAllowAccessMatchAllAccessTokenInvalid() {

        String action = "all";
        String resource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        // create a token with a key id that does not exist

        List<String> roles = Collections.singletonList("matchall");
        final String invalidKeyIdToken = createInvalidAccessToken("angler", roles);

        AccessCheckStatus status = AuthZpeClient.allowAccess(invalidKeyIdToken, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    @Test
    public void testAllowAccessNullAccessToken() {

        String action = "all";
        String resource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        AccessCheckStatus status = AuthZpeClient.allowAccess((AccessToken) null, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    @Test
    public void testAllowAccessExpiredAccessToken() {

        String action = "all";
        String resource = "angler:stuff";
        StringBuilder roleName = new StringBuilder();

        long now = System.currentTimeMillis() / 1000;
        AccessToken accessToken = new AccessToken();
        accessToken.setIssueTime(now -3600);
        accessToken.setExpiryTime(now - 3000);
        accessToken.setAudience("angler");
        accessToken.setScope(Collections.singletonList("matchall"));

        AccessCheckStatus status = AuthZpeClient.allowAccess(accessToken, resource, action, roleName);
        Assert.assertEquals(status, AccessCheckStatus.DENY_ROLETOKEN_EXPIRED);
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
        List<String> tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
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
        List<String> tokenList = new ArrayList<>();
        tokenList.add(rToken0AnglerExpirePublic.getSignedToken());
        tokenList.add(rToken0AnglerRegex.getSignedToken());
        tokenList.add(rToken0AnglerPublic.getSignedToken());
        tokenList.add(rToken0CoreTechPublic.getSignedToken());
        roleName = new StringBuilder();
        status = AuthZpeClient.allowAccess(tokenList, resource, action, roleName);
        // last token was for domain coretech
        Assert.assertEquals(status, AccessCheckStatus.DENY_DOMAIN_MISMATCH);
        Assert.assertEquals(roleName.toString(), "");

        tokenList = new ArrayList<>();
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
    public void testValidateRoleToken() {
        
        List<String> roles = new ArrayList<>();
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
        
        List<String> roles = new ArrayList<>();
        roles.add("public_role");
        RoleToken rToken = createRoleToken("coretech", roles, "0");
        
        String tamperedToken = rToken.getSignedToken().replace(";k=0;", ";k=zone1.invalid");
        RoleToken validatedToken = AuthZpeClient.validateRoleToken(tamperedToken);
        assertNull(validatedToken);
    }
    
    @Test
    public void testValidateRoleTokenInvalidSignature() {
        
        List<String> roles = new ArrayList<>();
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
    public void testgetZtsPublicKeyNull() {
        PublicKey key = AuthZpeClient.getZtsPublicKey("notexist");
        assertNull(key);
    }

    @DataProvider(name = "x509CertData")
    public static Object[][] x509CertData() {
        return new Object[][] { 
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", AccessCheckStatus.ALLOW, "angler:stuff" }, 
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.private", AccessCheckStatus.DENY_NO_MATCH, "angler:stuff" }, 
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role", AccessCheckStatus.DENY_CERT_MISSING_ROLE_NAME, "angler:stuff" }, 
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler", AccessCheckStatus.DENY_CERT_MISSING_ROLE_NAME, "angler:stuff" }, 
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "", AccessCheckStatus.DENY_CERT_MISSING_SUBJECT, "angler:stuff" }, 
            { "", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", AccessCheckStatus.DENY_CERT_MISMATCH_ISSUER, "angler:stuff"},
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler.test:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler.test:role.public", AccessCheckStatus.DENY_DOMAIN_NOT_FOUND, "angler.test:stuff"},
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=:role.public", AccessCheckStatus.DENY_CERT_MISSING_DOMAIN, "angler:stuff" },
            { "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public", "C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.", AccessCheckStatus.DENY_CERT_MISSING_ROLE_NAME, "angler:stuff" }
        };
    }
    
    @Test(dataProvider = "x509CertData")
    public void testX509CertificateReadAllowed(String issuer, String subject, AccessCheckStatus expectedStatus, String angResource) {

        final String issuers = "InvalidToBeSkipped | C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public | C=US, ST=CA, O=Athenz, OU=Testing Domain2, CN=angler:role.public | C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler.test:role.public";
        AuthZpeClient.setX509CAIssuers(issuers);

        final String action = "read";
        X509Certificate cert = mock(X509Certificate.class);
        X500Principal x500Principal = mock(X500Principal.class);
        X500Principal x500PrincipalS = mock(X500Principal.class);
        Mockito.when(x500Principal.getName()).thenReturn(issuer);
        Mockito.when(x500PrincipalS.getName()).thenReturn(subject);
        Mockito.when(cert.getIssuerX500Principal()).thenReturn(x500Principal);
        Mockito.when(cert.getSubjectX500Principal()).thenReturn(x500PrincipalS);
        AccessCheckStatus status = AuthZpeClient.allowAccess(cert, angResource, action);
        Assert.assertEquals(status, expectedStatus);
    }

    @Test
    public void testIssuerMatch() {

        // passing null or empty list to the set method has no impact
        // make sure no exceptions are thrown

        AuthZpeClient.setX509CAIssuers(null);
        AuthZpeClient.setX509CAIssuers("");

        assertTrue(AuthZpeClient.certIssuerMatch(null));

        // our default set contains the following issuers:

        // C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public
        // C=US, ST=CA, O=Athenz, OU=Testing Domain2, CN=angler:role.public
        // C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler.test:role.public";

        final String issuers = "InvalidToBeSkipped | C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler:role.public | C=US, ST=CA, O=Athenz, OU=Testing Domain2, CN=angler:role.public | C=US, ST=CA, O=Athenz, OU=Testing Domain, CN=angler.test:role.public";
        AuthZpeClient.setX509CAIssuers(issuers);

        // add a new entry in our list

        AuthZpeClient.setX509CAIssuers("cn=Athenz CA, ou=engineering, o=My Company! Inc., c=us");

        // passing values in the same order should match with our string set

        assertTrue(AuthZpeClient.issuerMatch("cn=Athenz CA, ou=engineering, o=My Company! Inc., c=us"));

        // passing values in different order should match our rdn check

        assertTrue(AuthZpeClient.issuerMatch("o=My Company! Inc., cn=Athenz CA, c=us, ou=engineering"));

        // passing an extra or less rdn component should fail

        assertFalse(AuthZpeClient.issuerMatch("cn=Athenz CA, ou=engineering, o=My Company! Inc., l=Los Angeles, c=us"));
        assertFalse(AuthZpeClient.issuerMatch("cn=Athenz CA, ou=engineering, c=us"));

        // same number of components but different values

        assertFalse(AuthZpeClient.issuerMatch("cn=Athenz CA, ou=engineering, o=My Company Inc., c=us"));
    }

    @Test
    public void testAllowActionZPEInvalid() {

        // failure when roles is empty or not specified

        StringBuilder matchRoleName = new StringBuilder();
        assertEquals(AuthZpeClient.allowActionZPE("update", "athenz", "athenz:table", null, matchRoleName),
                AccessCheckStatus.DENY_ROLETOKEN_INVALID);
        List<String> roles = new ArrayList<>();
        assertEquals(AuthZpeClient.allowActionZPE("update", "athenz", "athenz:table", roles,
                matchRoleName), AccessCheckStatus.DENY_ROLETOKEN_INVALID);

        // invalid when token domain is empty or null

        roles.add("writers");
        assertEquals(AuthZpeClient.allowActionZPE("update", "", "athenz:table", roles,
                matchRoleName), AccessCheckStatus.DENY_ROLETOKEN_INVALID);
        assertEquals(AuthZpeClient.allowActionZPE("update", null, "athenz:table", roles,
                matchRoleName), AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    @Test
    public void testAllowAccessInvalidRoleToken() {

        // failure when role token is null

        StringBuilder matchRoleName = new StringBuilder();
        assertEquals(AuthZpeClient.allowAccess((RoleToken) null, "athenz:table", "update", matchRoleName),
                AccessCheckStatus.DENY_ROLETOKEN_INVALID);
    }

    @Test
    public void testValidateRoleTokenExpired() {

        List<String> roles = new ArrayList<>();
        roles.add("public");
        RoleToken rtoken = createRoleToken("angler", roles, "0", 2);

        assertNotNull(AuthZpeClient.validateRoleToken(rtoken.getSignedToken()));

        // sleep 3 seconds for the token to expire

        try {
            Thread.sleep(3000);
        } catch (InterruptedException ignored) {
        }

        // we should now get null since the token is expired

        assertNull(AuthZpeClient.validateRoleToken(rtoken.getSignedToken()));
    }

    @Test
    public void testValidateAccessTokenWithMtlsBound() throws IOException {

        Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        AccessToken accessToken = AuthZpeClient.validateAccessToken(accessToken0AnglerRegex, cert, null);
        assertNotNull(accessToken);

        // now we're going to include the Bearer part

        accessToken = AuthZpeClient.validateAccessToken("Bearer " + accessToken0AnglerRegex, cert, null);
        assertNotNull(accessToken);
    }

    @Test
    public void testValidateAccessTokenWithoutMtlsBound() {

        AccessToken accessToken = AuthZpeClient.validateAccessToken(accessToken0AnglerRegex, null, null);
        assertNotNull(accessToken);

        // now we're going to include the Bearer part

        accessToken = AuthZpeClient.validateAccessToken("Bearer " + accessToken0AnglerRegex, null, null);
        assertNotNull(accessToken);
    }

    @Test
    public void testValidateAccessTokenInvalid() {

        // create a token with a key id that does not exist

        List<String> roles = Collections.singletonList("matchall");
        final String invalidKeyIdToken = createInvalidAccessToken("angler", roles);

        AccessToken accessToken = AuthZpeClient.validateAccessToken(invalidKeyIdToken, null, null);
        assertNull(accessToken);

        // now we're going to include the Bearer part

        accessToken = AuthZpeClient.validateAccessToken("Bearer " + invalidKeyIdToken, null, null);
        assertNull(accessToken);
    }

    @Test
    public void testFetchPublicKeysUsingSignKeyResolver() {
        AuthZpeClient.setMillisBetweenZtsCalls(0);
        String ecKeys = "{\n" +
                "        \"keys\": [\n" +
                "            {\n" +
                "                \"kid\" : \"FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ\",\n" +
                "                \"kty\" : \"EC\",\n" +
                "                \"crv\" : \"prime256v1\",\n" +
                "                \"x\"   : \"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74\",\n" +
                "                \"y\"   : \"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI\",\n" +
                "                \"d\"   : \"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk\"\n" +
                "            }\n" +
                "        ]\n" +
                "    }";
        HttpResponse response = new HttpResponse()
                .withStatusCode(200)
                .withBody(ecKeys);
        ClientAndServer mockServer = startClientAndServer(1080);
        mockServer
                .when(request().withPath("/mockJwksUri"))
                .respond(response);
        
        AuthZpeClient.setAccessTokenSignKeyResolver("http://127.0.0.1:1080/mockJwksUri", null);
        assertNotNull(AuthZpeClient.getZtsPublicKey("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"));
        mockServer.stop();
    }

    @Test
    public void testMaxCacheTokenSize() throws IOException {

        // perform allowed access check

        List<String> roles = new ArrayList<>();
        roles.add("full_regex");
        roles.add("matchall");
        roles.add("matchstarts");
        roles.add("matchcompare");
        roles.add("matchregex");
        String signedToken = createAccessToken("angler", roles, "0");

        String action = "all";
        String resource = "angler:stuff";

        Path path = Paths.get("src/test/resources/mtls_token_spec.cert");
        String certStr = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(certStr);

        // clear our cache

        Map<String, AccessToken> roleMap = ZpeUpdPolLoader.getAccessTokenCacheMap();
        roleMap.clear();

        // successful access check should add the entry to the cache

        AccessCheckStatus status = AuthZpeClient.allowAccess(signedToken, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Assert.assertEquals(roleMap.size(), 1);

        // with our new token cache size limit of 1 the size should not change

        AuthZpeClient.setTokenCacheMaxValue(1);

        roles.add("testrole1");
        signedToken = createAccessToken("angler", roles, "0");
        status = AuthZpeClient.allowAccess(signedToken, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Assert.assertEquals(roleMap.size(), 1);

        // set a negative value will be ignored, so we'll still
        // have a single entry in the cache

        AuthZpeClient.setTokenCacheMaxValue(-2);

        status = AuthZpeClient.allowAccess(signedToken, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Assert.assertEquals(roleMap.size(), 1);


        // now let's increase the size and try again

        AuthZpeClient.setTokenCacheMaxValue(10);

        status = AuthZpeClient.allowAccess(signedToken, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Assert.assertEquals(roleMap.size(), 2);

        // let's set the limit to 0 and verify again

        AuthZpeClient.setTokenCacheMaxValue(0);

        roles.add("testrole2");
        signedToken = createAccessToken("angler", roles, "0");
        status = AuthZpeClient.allowAccess(signedToken, cert, null, resource, action);
        Assert.assertEquals(status, AccessCheckStatus.ALLOW);

        Assert.assertEquals(roleMap.size(), 3);
    }
}
