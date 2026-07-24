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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.OpenIdConfiguration;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import com.yahoo.athenz.zts.AccessTokenResponse;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class ExternalMemberCertificateProviderTest {

    @AfterMethod
    public void tearDown() {
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CONFIG_ENDPOINT);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_REDIRECT_URI);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_AUDIENCE);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CONNECT_TIMEOUT);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_READ_TIMEOUT);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_MEMBER_NAME_CLAIM);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_APP);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYGROUP);
        System.clearProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYNAME);
    }

    @Test
    public void testGetProviderScheme() {
        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testSetPrivateKeyStore() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertSame(provider.privateKeyStore, keyStore);
    }

    @Test
    public void testInitializeSuccess() throws ProviderResourceException {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "https://idp.example.com/oauth2/v1/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT,
                "https://idp.example.com/oauth2/v1/keys");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_AUDIENCE,
                "external-member-audience");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_REDIRECT_URI,
                "http://localhost:9214/oauth2/callback");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CONNECT_TIMEOUT, "5000");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_READ_TIMEOUT, "8000");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_MEMBER_NAME_CLAIM,
                "external_member");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYNAME,
                "external-secret-key");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("", "", "external-secret-key"))
                .thenReturn("external-secret".toCharArray());

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        provider.initialize("sys.auth.external_member_cert",
                "class://com.yahoo.athenz.instance.provider.impl.ExternalMemberCertificateProvider",
                null, null);

        assertEquals(provider.tokenEndpoint, "https://idp.example.com/oauth2/v1/token");
        assertEquals(provider.clientId, "external-member-client-id");
        assertEquals(provider.clientSecret, "external-secret");
        assertEquals(provider.redirectUri, "http://localhost:9214/oauth2/callback");
        assertEquals(provider.audience, "external-member-audience");
        assertEquals(provider.connectTimeout, 5000);
        assertEquals(provider.readTimeout, 8000);
        assertEquals(provider.memberNameClaim, "external_member");
        assertNotNull(provider.signingKeyResolver);
    }

    @Test
    public void testInitializeWithConfigEndpoint() throws ProviderResourceException {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CONFIG_ENDPOINT,
                "https://idp.example.com/.well-known/openid-configuration");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_AUDIENCE,
                "external-member-audience");

        OpenIdConfiguration openIdConfig = new OpenIdConfiguration();
        openIdConfig.setTokenEndpoint("https://idp.example.com/oauth2/token");
        openIdConfig.setJwksUri("https://idp.example.com/oauth2/keys");

        try (MockedConstruction<JwtsHelper> mocked = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractOpenIdConfiguration(
                        Mockito.anyString(), Mockito.any(), Mockito.any())).thenReturn(openIdConfig))) {

            ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
            provider.initialize("sys.auth.external_member_cert", null, null, null);

            assertEquals(provider.tokenEndpoint, "https://idp.example.com/oauth2/token");
            assertEquals(provider.clientId, "external-member-client-id");
            assertNotNull(provider.signingKeyResolver);
        }
    }

    @Test
    public void testInitializeConfigEndpointReturnsNull() throws ProviderResourceException {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CONFIG_ENDPOINT,
                "https://idp.example.com/.well-known/openid-configuration");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "https://idp.example.com/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT,
                "https://idp.example.com/keys");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_AUDIENCE,
                "external-member-audience");

        try (MockedConstruction<JwtsHelper> mocked = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractOpenIdConfiguration(
                        Mockito.anyString(), Mockito.any(), Mockito.any())).thenReturn(null))) {

            ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
            provider.initialize("sys.auth.external_member_cert", null, null, null);

            assertEquals(provider.tokenEndpoint, "https://idp.example.com/token");
        }
    }

    @Test
    public void testInitializeMissingExternalMemberTokenEndpoint() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        try {
            provider.initialize("sys.auth.external_member_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("External member IdP token endpoint not configured"));
        }
    }

    @Test
    public void testInitializeMissingExternalMemberJwksEndpoint() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "https://idp.example.com/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        try {
            provider.initialize("sys.auth.external_member_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("External member IdP jwks endpoint not configured"));
        }
    }

    @Test
    public void testInitializeExternalMemberTokenEndpointNotHttps() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "http://idp.example.com/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT,
                "https://idp.example.com/keys");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_AUDIENCE,
                "external-member-audience");

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        try {
            provider.initialize("sys.auth.external_member_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("External member IdP token endpoint must be an https url"));
        }
    }

    @Test
    public void testInitializeExternalMemberJwksEndpointNotHttps() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "https://idp.example.com/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT,
                "http://idp.example.com/keys");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_AUDIENCE,
                "external-member-audience");

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        try {
            provider.initialize("sys.auth.external_member_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("External member IdP jwks endpoint must be an https url"));
        }
    }

    @Test
    public void testInitializeMissingExternalMemberClientId() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "https://idp.example.com/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT,
                "https://idp.example.com/keys");

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        try {
            provider.initialize("sys.auth.external_member_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("External member IdP client id not configured"));
        }
    }

    @Test
    public void testInitializeMissingExternalMemberAudience() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_TOKEN_ENDPOINT,
                "https://idp.example.com/token");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_JWKS_ENDPOINT,
                "https://idp.example.com/keys");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_ID,
                "external-member-client-id");

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        try {
            provider.initialize("sys.auth.external_member_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("External member IdP audience not configured"));
        }
    }

    @Test
    public void testGetClientSecretNoPrivateKeyStore() {
        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        assertEquals(provider.getClientSecret(), "");
    }

    @Test
    public void testGetClientSecretNoKeyName() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertEquals(provider.getClientSecret(), "");
    }

    @Test
    public void testGetClientSecretNullReturnFromKeyStore() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYNAME,
                "external-secret-key");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("", "", "external-secret-key")).thenReturn(null);

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertEquals(provider.getClientSecret(), "");
    }

    @Test
    public void testGetClientSecretSuccess() {
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_APP,
                "external_member_cert");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYGROUP,
                "idp");
        System.setProperty(ExternalMemberCertificateProvider.EXT_MEMBER_CERT_PROP_CLIENT_SECRET_KEYNAME,
                "client-secret");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("external_member_cert", "idp", "client-secret"))
                .thenReturn("external-secret".toCharArray());

        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertEquals(provider.getClientSecret(), "external-secret");
    }

    @Test
    public void testConfirmInstanceSuccess() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        String accessToken = generateMockAccessToken("email:ext.joe@athenz.io", "external-member-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = createConfirmation("code=test-auth-code");
        InstanceConfirmation result = spyProvider.confirmInstance(confirmation);
        assertSame(result, confirmation);
    }

    @Test
    public void testConfirmInstanceNoAttestationData() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = createConfirmation(null);
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member attestation data not provided"));
        }
    }

    @Test
    public void testConfirmInstanceEmptyAttestationData() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = createConfirmation("");
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member attestation data not provided"));
        }
    }

    @Test
    public void testConfirmInstanceNoMemberName() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = createConfirmation("code=test-code");
        confirmation.setService(null);
        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member name not provided"));
        }
    }

    @Test
    public void testConfirmInstanceInvalidToken() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token("not-a-valid-jwt");

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = createConfirmation("code=test-auth-code");
        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to validate external member access token"));
        }
    }

    @Test
    public void testConfirmInstanceSubjectMismatch() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        String accessToken = generateMockAccessToken("email:other@athenz.io", "external-member-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = createConfirmation("code=test-auth-code");
        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Subject token does not match requested external member name"));
        }
    }

    @Test
    public void testConfirmInstanceAudienceMismatch() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        String accessToken = generateMockAccessToken("email:ext.joe@athenz.io", "wrong-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = createConfirmation("code=test-auth-code");
        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member token audience mismatch"));
        }
    }

    @Test
    public void testRefreshInstanceNotSupported() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateTokenSubjectExternalMemberMatch() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("email:ext.joe@athenz.io");

        assertTrue(provider.validateTokenSubject(accessToken, "email:ext.joe@athenz.io"));
    }

    @Test
    public void testValidateTokenSubjectDoesNotUseUserDomainPrefixMatch() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("user.email:ext.joe@athenz.io");

        assertFalse(provider.validateTokenSubject(accessToken, "email:ext.joe@athenz.io"));
    }

    @Test
    public void testValidateTokenSubjectClaimExternalMemberMatch() {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.memberNameClaim = "external_member";

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("uid-12345");
        Mockito.when(accessToken.getClaim("external_member")).thenReturn("email:ext.joe@athenz.io");

        assertTrue(provider.validateTokenSubject(accessToken, "email:ext.joe@athenz.io"));
    }

    @Test
    public void testValidateTokenSubjectClaimExternalMemberNoMatch() {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.memberNameClaim = "external_member";

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("uid-12345");
        Mockito.when(accessToken.getClaim("external_member")).thenReturn("email:other@athenz.io");

        assertFalse(provider.validateTokenSubject(accessToken, "email:ext.joe@athenz.io"));
    }

    @Test
    public void testGenerateAccessTokenRequestBodyCodeOnly() throws ProviderResourceException {
        ExternalMemberCertificateProvider provider = createTestProvider();

        String body = provider.generateAccessTokenRequestBody("code=my-auth-code");
        assertTrue(body.contains("grant_type=authorization_code"));
        assertTrue(body.contains("client_id="));
        assertTrue(body.contains("redirect_uri="));
        assertTrue(body.contains("client_secret="));
        assertTrue(body.contains("code=my-auth-code"));
        assertFalse(body.contains("code_verifier="));
    }

    @Test
    public void testGenerateAccessTokenRequestBodyWithClientSecret() throws ProviderResourceException {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.clientSecret = "my-secret";

        String body = provider.generateAccessTokenRequestBody(
                "code=my-code&state=my-state&code_verifier=my-verifier");
        assertTrue(body.contains("grant_type=authorization_code"));
        assertTrue(body.contains("client_secret="));
        assertTrue(body.contains("code=my-code"));
        assertTrue(body.contains("code_verifier=my-verifier"));
    }

    @Test
    public void testGenerateAccessTokenRequestBodyMissingCode() {
        ExternalMemberCertificateProvider provider = createTestProvider();

        try {
            provider.generateAccessTokenRequestBody("state=some-state&code_verifier=some-verifier");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Code not provided in external member attestation data"));
        }
    }

    @Test
    public void testGenerateAccessTokenRequestBodyPkceRequiredNoVerifier() {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        try {
            provider.generateAccessTokenRequestBody("code=my-code");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member PKCE is required"));
        }
    }

    @Test
    public void testGenerateAccessTokenRequestBodyPkceWithVerifier() throws ProviderResourceException {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        String body = provider.generateAccessTokenRequestBody("code=my-code&code_verifier=my-verifier");
        assertTrue(body.contains("grant_type=authorization_code"));
        assertFalse(body.contains("client_secret="));
        assertTrue(body.contains("code=my-code"));
        assertTrue(body.contains("code_verifier=my-verifier"));
    }

    @Test
    public void testExchangeAuthCodeWithClientSecret() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.clientSecret = "my-secret";

        String accessTokenJwt = generateMockAccessToken("email:ext.joe@athenz.io", null, null);
        String tokenResponseJson = "{\"access_token\":\"" + accessTokenJwt + "\",\"token_type\":\"Bearer\"}";

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        String result = spyProvider.exchangeAuthCodeForAccessToken("code=test-code");
        assertEquals(result, accessTokenJwt);
    }

    @Test
    public void testExchangeAuthCodeWithoutClientSecret() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        String accessTokenJwt = generateMockAccessToken("email:ext.joe@athenz.io", null, null);
        String tokenResponseJson = "{\"access_token\":\"" + accessTokenJwt + "\",\"token_type\":\"Bearer\"}";

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        String result = spyProvider.exchangeAuthCodeForAccessToken("code=test-code&code_verifier=test-verifier");
        assertEquals(result, accessTokenJwt);
    }

    @Test
    public void testExchangeAuthCodeEmptyAccessToken() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        String tokenResponseJson = "{\"token_type\":\"Bearer\"}";

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        try {
            spyProvider.exchangeAuthCodeForAccessToken("code=test-code");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("does not contain an access token"));
        }
    }

    @Test
    public void testPostTokenRequestSuccess() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        String accessTokenJwt = generateMockAccessToken("email:ext.joe@athenz.io", null, null);
        String tokenResponseJson = "{\"access_token\":\"" + accessTokenJwt + "\",\"token_type\":\"Bearer\"}";

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        AccessTokenResponse result = spyProvider.postTokenRequest("grant_type=authorization_code&code=test");
        assertNotNull(result);
        assertEquals(result.getAccess_token(), accessTokenJwt);
    }

    @Test
    public void testPostTokenRequestError() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(401, "");
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        try {
            spyProvider.postTokenRequest("grant_type=authorization_code&code=test");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("External member IdP token endpoint returned error"));
        }
    }

    @Test
    public void testPostTokenRequestException() throws Exception {
        ExternalMemberCertificateProvider provider = createTestProvider();

        ExternalMemberCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doThrow(new IOException("Connection refused"))
                .when(spyProvider).createTokenEndpointConnection();

        try {
            spyProvider.postTokenRequest("grant_type=authorization_code&code=test");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to exchange external member auth code with IdP"));
        }
    }

    @Test
    public void testCreateTokenEndpointConnection() throws IOException {
        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.tokenEndpoint = "https://idp.example.com/token";
        HttpURLConnection conn = provider.createTokenEndpointConnection();
        assertNotNull(conn);
        conn.disconnect();
    }

    private ExternalMemberCertificateProvider createTestProvider() {
        ExternalMemberCertificateProvider provider = new ExternalMemberCertificateProvider();
        provider.tokenEndpoint = "https://idp.example.com/oauth2/v1/token";
        provider.clientId = "external-member-client-id";
        provider.clientSecret = "external-secret";
        provider.redirectUri = ExternalMemberCertificateProvider.DEFAULT_REDIRECT_URI;
        provider.audience = "external-member-audience";
        provider.connectTimeout = 10000;
        provider.readTimeout = 15000;
        return provider;
    }

    private InstanceConfirmation createConfirmation(final String attestationData) {
        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("email:ext.joe@athenz.io");
        confirmation.setProvider("sys.auth.external_member_cert");
        confirmation.setAttestationData(attestationData);
        return confirmation;
    }

    private String generateMockAccessToken(String subject, String audience,
            Map<String, Object> extraClaims) throws IOException {

        String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        String encodedHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(header.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "https://idp.example.com");
        claims.put("iat", System.currentTimeMillis() / 1000);
        claims.put("exp", System.currentTimeMillis() / 1000 + 3600);
        if (subject != null) {
            claims.put("sub", subject);
        }
        if (audience != null) {
            claims.put("aud", audience);
        }
        if (extraClaims != null) {
            claims.putAll(extraClaims);
        }

        ObjectMapper mapper = new ObjectMapper();
        String payload = mapper.writeValueAsString(claims);
        String encodedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        return encodedHeader + "." + encodedPayload + ".";
    }

    private HttpURLConnection createMockConnection(int responseCode, String responseBody) throws IOException {
        HttpURLConnection mockConn = Mockito.mock(HttpURLConnection.class);
        Mockito.when(mockConn.getResponseCode()).thenReturn(responseCode);
        Mockito.when(mockConn.getInputStream()).thenReturn(
                new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8)));
        Mockito.when(mockConn.getOutputStream()).thenReturn(new ByteArrayOutputStream());
        return mockConn;
    }
}
