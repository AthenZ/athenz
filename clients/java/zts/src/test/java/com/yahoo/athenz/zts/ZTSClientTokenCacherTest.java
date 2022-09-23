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

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.PrincipalAuthority;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.SignatureAlgorithm;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import java.io.File;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.testng.Assert.*;
import static org.testng.Assert.assertNotNull;

public class ZTSClientTokenCacherTest {

    final private Authority PRINCIPAL_AUTHORITY = new PrincipalAuthority();
    private final File ecPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");

    @BeforeMethod
    public void setUp() {
    }

    @AfterMethod
    public void tearDown() {
    }

    @Test
    public void testZTSClientAccessTokenCacherNullEmpty() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        ZTSClientTokenCacher.setAccessToken(null, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 0);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token("header.invalid-token.");

        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 0);

        client.close();
    }

    AccessToken createAccessToken(final String audience, final String clientId,
                                  final String proxyPrincipal, final String authzDetails,
                                  final String proxyPrincipalsSpiffeUris) {

        AccessToken accessToken = new AccessToken();
        long now = System.currentTimeMillis();

        accessToken.setAuthTime(now);
        accessToken.setJwtId("jwt-id001");
        accessToken.setSubject("subject");
        accessToken.setUserId("userid");
        accessToken.setExpiryTime(now + 3600);
        accessToken.setIssueTime(now);
        accessToken.setClientId(clientId);
        accessToken.setAudience(audience);
        accessToken.setVersion(1);
        accessToken.setIssuer("athenz");
        accessToken.setProxyPrincipal(proxyPrincipal);
        accessToken.setAuthorizationDetails(authzDetails);

        if (proxyPrincipalsSpiffeUris != null) {
            List<String> uris = Stream.of(proxyPrincipalsSpiffeUris.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());
            accessToken.setConfirmProxyPrincipalSpiffeUris(uris);
        }
        return accessToken;
    }

    @Test
    public void testZTSClientAccessTokenCacherSimpleEntry() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        AccessToken accessToken = createAccessToken("coretech", "athenz.prod", null, null, null);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setExpires_in(3600);

        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        final String cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        final String clientKey = ZTSClient.getAccessTokenCacheKey("athenz", "prod", "coretech",
                null, null, null, null, null);
        assertEquals(cacheKey, clientKey);

        client.close();
    }

    @Test
    public void testZTSClientAccessTokenCacherInvalidPrincipal() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        AccessToken accessToken = createAccessToken("coretech", "athenz", null, null, null);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setExpires_in(3600);

        // invalid client id (athenz) without the service name will cause
        // the request to be skipped

        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 0);

        client.close();
    }

    @Test
    public void testZTSClientAccessTokenCacherWithRoleNames() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        AccessToken accessToken = createAccessToken("coretech", "athenz.prod", null, null, null);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setExpires_in(3600);

        List<String> roleNames = new ArrayList<>();
        roleNames.add("role1");
        roleNames.add("role2");

        ZTSClientTokenCacher.setAccessToken(tokenResponse, roleNames);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        final String cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        final String clientKey = ZTSClient.getAccessTokenCacheKey("athenz", "prod", "coretech",
                roleNames, null, null, null, null);
        assertEquals(cacheKey, clientKey);

        client.close();
    }

    @Test
    public void testZTSClientAccessTokenCacherWithOptionalComponents() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        final String authzDetails = "[{\"type\":\"message_access\",\"data\":\"resource\"}]";

        AccessToken accessToken = createAccessToken("coretech", "weather.prod", "sports.proxy", authzDetails, null);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setExpires_in(3600);

        List<String> roleNames = new ArrayList<>();
        roleNames.add("role1");
        roleNames.add("role2");

        ZTSClientTokenCacher.setAccessToken(tokenResponse, roleNames);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        final String cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        final String clientKey = ZTSClient.getAccessTokenCacheKey("weather", "prod", "coretech",
                roleNames, null, "sports.proxy", authzDetails, null);
        assertEquals(cacheKey, clientKey);

        client.close();
    }

    @Test
    public void testZTSClientAccessTokenCacherWithIDToken() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        final String authzDetails = "[{\"type\":\"message_access\",\"data\":\"resource\"}]";

        AccessToken accessToken = createAccessToken("coretech", "athenz.prod", "sports.proxy", authzDetails, null);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessToken idToken = createAccessToken("coretech.api", "athenz.prod", null, null, null);
        String idJws = idToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(idJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setId_token(idJws);
        tokenResponse.setExpires_in(3600);

        List<String> roleNames = new ArrayList<>();
        roleNames.add("role1");
        roleNames.add("role2");

        ZTSClientTokenCacher.setAccessToken(tokenResponse, roleNames);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        final String cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        final String clientKey = ZTSClient.getAccessTokenCacheKey("athenz", "prod", "coretech",
                roleNames, "api", "sports.proxy", authzDetails, null);
        assertEquals(cacheKey, clientKey);

        client.close();
    }

    @Test
    public void testZTSClientAccessTokenCacherWithProxyPrincipals() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        final String proxyPrincipalsSpiffeUris = "spiffe://sports/sa/svc1,spiffe://weather/sa/svc2";
        AccessToken accessToken = createAccessToken("coretech", "athenz.prod", null, null, proxyPrincipalsSpiffeUris);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setExpires_in(3600);

        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        final String cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        final String clientKey = ZTSClient.getAccessTokenCacheKey("athenz", "prod", "coretech",
                null, null, null, null, proxyPrincipalsSpiffeUris);
        assertEquals(cacheKey, clientKey);

        client.close();
    }

    @Test
    public void testZTSClientAccessTokenCacherWithInvalidIDToken() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        AccessToken accessToken = createAccessToken("coretech", "athenz.prod", null, null, null);
        PrivateKey privateKey = Crypto.loadPrivateKey(ecPrivateKey);
        String accessJws = accessToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(accessJws);

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessJws);
        tokenResponse.setId_token("invalid-id-token");
        tokenResponse.setExpires_in(3600);

        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        // our key should be without id service name

        String cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        String clientKey = ZTSClient.getAccessTokenCacheKey("athenz", "prod", "coretech",
                null, null, null, null, null);
        assertEquals(cacheKey, clientKey);

        ZTSClient.ACCESS_TOKEN_CACHE.clear();

        // id token without audience

        AccessToken idToken = createAccessToken(null, "athenz.prod", null, null, null);
        String idJws = idToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(idJws);

        tokenResponse.setId_token(idJws);
        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        assertEquals(cacheKey, clientKey);

        // id token with invalid audience - no service name

        idToken = createAccessToken("coretech", "athenz.prod", null, null, null);
        idJws = idToken.getSignedToken(privateKey, "eckey1", SignatureAlgorithm.ES256);
        assertNotNull(idJws);

        tokenResponse.setId_token(idJws);
        ZTSClientTokenCacher.setAccessToken(tokenResponse, null);
        assertEquals(ZTSClient.ACCESS_TOKEN_CACHE.size(), 1);

        cacheKey = ZTSClient.ACCESS_TOKEN_CACHE.keys().nextElement();
        assertEquals(cacheKey, clientKey);

        client.close();
    }

    @Test
    public void testZTSClientRoleTokenCacherInvalid() {

        Principal principal = SimplePrincipal.create("user_domain", "user",
                "auth_creds", PRINCIPAL_AUTHORITY);

        ZTSRDLClientMock ztsClientMock = new ZTSRDLClientMock();
        ZTSClient client = new ZTSClient("http://localhost:4080", principal);
        client.setZTSRDLGeneratedClient(ztsClientMock);

        ZTSClient.ROLE_TOKEN_CACHE.clear();

        long expiry = System.currentTimeMillis() + 3600;
        String roleToken = "v=Z1;d=coretech;r=admin;p=sports;h=localhost;a=f10bc905071a72d1;t=1448045776;e=" +
                expiry + ";k=0;i=10.11.12.13;s=pujvQuvaLa2jgE3k24b";
        ZTSClientTokenCacher.setRoleToken(roleToken, "role1", null);

        // it should be ignored since p=sports does not have service component

        assertEquals(ZTSClient.ROLE_TOKEN_CACHE.size(), 0);

        client.close();
    }
}
