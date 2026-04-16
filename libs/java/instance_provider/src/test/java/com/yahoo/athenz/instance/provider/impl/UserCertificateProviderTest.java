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

public class UserCertificateProviderTest {

    @AfterMethod
    public void tearDown() {
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_CONFIG_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_REDIRECT_URI);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_CONNECT_TIMEOUT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_READ_TIMEOUT);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_USER_NAME_CLAIM);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_APP);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYGROUP);
        System.clearProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYNAME);
    }

    @Test
    public void testGetProviderScheme() {
        UserCertificateProvider provider = new UserCertificateProvider();
        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.CLASS);
    }

    @Test
    public void testSetPrivateKeyStore() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        UserCertificateProvider provider = new UserCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertSame(provider.privateKeyStore, keyStore);
    }

    @Test
    public void testInitializeSuccess() throws ProviderResourceException {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/oauth2/v1/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "https://idp.example.com/oauth2/v1/keys");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYNAME, "test-secret-key");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("", "", "test-secret-key"))
                .thenReturn("test-secret".toCharArray());

        UserCertificateProvider provider = new UserCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        provider.initialize("sys.auth.user_cert", "class://com.yahoo.athenz.instance.provider.impl.UserCertificateProvider",
                null, null);

        assertEquals(provider.tokenEndpoint, "https://idp.example.com/oauth2/v1/token");
        assertEquals(provider.clientId, "test-client-id");
        assertEquals(provider.clientSecret, "test-secret");
        assertEquals(provider.redirectUri, UserCertificateProvider.DEFAULT_REDIRECT_URI);
        assertEquals(provider.audience, "test-audience");
        assertEquals(provider.connectTimeout, 10000);
        assertEquals(provider.readTimeout, 15000);
        assertNotNull(provider.signingKeyResolver);
    }

    @Test
    public void testInitializeWithCustomValues() throws ProviderResourceException {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "https://idp.example.com/keys");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "my-client");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_REDIRECT_URI, "http://localhost:8080/callback");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "my-audience");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CONNECT_TIMEOUT, "5000");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_READ_TIMEOUT, "8000");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_USER_NAME_CLAIM, "preferred_username");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_APP, "user_cert");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYGROUP, "idp");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYNAME, "client-secret");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("user_cert", "idp", "client-secret"))
                .thenReturn("my-secret".toCharArray());

        UserCertificateProvider provider = new UserCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        provider.initialize("sys.auth.user_cert", null, null, null);

        assertEquals(provider.tokenEndpoint, "https://idp.example.com/token");
        assertEquals(provider.clientId, "my-client");
        assertEquals(provider.clientSecret, "my-secret");
        assertEquals(provider.redirectUri, "http://localhost:8080/callback");
        assertEquals(provider.audience, "my-audience");
        assertEquals(provider.connectTimeout, 5000);
        assertEquals(provider.readTimeout, 8000);
        assertEquals(provider.userNameClaim, "preferred_username");
    }

    @Test
    public void testInitializeWithConfigEndpoint() throws ProviderResourceException {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CONFIG_ENDPOINT, "https://idp.example.com/.well-known/openid-configuration");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");

        OpenIdConfiguration openIdConfig = new OpenIdConfiguration();
        openIdConfig.setTokenEndpoint("https://idp.example.com/oauth2/token");
        openIdConfig.setJwksUri("https://idp.example.com/oauth2/keys");

        try (MockedConstruction<JwtsHelper> mocked = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractOpenIdConfiguration(
                        Mockito.anyString(), Mockito.any(), Mockito.any())).thenReturn(openIdConfig))) {

            UserCertificateProvider provider = new UserCertificateProvider();
            provider.initialize("sys.auth.user_cert", null, null, null);

            assertEquals(provider.tokenEndpoint, "https://idp.example.com/oauth2/token");
            assertEquals(provider.clientId, "test-client-id");
            assertNotNull(provider.signingKeyResolver);
        }
    }

    @Test
    public void testInitializeConfigEndpointReturnsNull() throws ProviderResourceException {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CONFIG_ENDPOINT, "https://idp.example.com/.well-known/openid-configuration");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "https://idp.example.com/keys");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");

        try (MockedConstruction<JwtsHelper> mocked = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractOpenIdConfiguration(
                        Mockito.anyString(), Mockito.any(), Mockito.any())).thenReturn(null))) {

            UserCertificateProvider provider = new UserCertificateProvider();
            provider.initialize("sys.auth.user_cert", null, null, null);

            assertEquals(provider.tokenEndpoint, "https://idp.example.com/token");
        }
    }

    @Test
    public void testInitializeMissingTokenEndpoint() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");

        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.initialize("sys.auth.user_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("IdP token endpoint not configured"));
        }
    }

    @Test
    public void testInitializeMissingJwksEndpoint() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");

        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.initialize("sys.auth.user_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("IdP jwks endpoint not configured"));
        }
    }

    @Test
    public void testInitializeTokenEndpointNotHttps() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "http://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "https://idp.example.com/keys");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");

        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.initialize("sys.auth.user_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("IdP token endpoint must be an https url"));
        }
    }

    @Test
    public void testInitializeJwksEndpointNotHttps() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "http://idp.example.com/keys");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");

        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.initialize("sys.auth.user_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("IdP jwks endpoint must be an https url"));
        }
    }

    @Test
    public void testInitializeConfigEndpointTokenNotHttps() throws ProviderResourceException {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CONFIG_ENDPOINT, "https://idp.example.com/.well-known/openid-configuration");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");

        OpenIdConfiguration openIdConfig = new OpenIdConfiguration();
        openIdConfig.setTokenEndpoint("http://idp.example.com/oauth2/token");
        openIdConfig.setJwksUri("https://idp.example.com/oauth2/keys");

        try (MockedConstruction<JwtsHelper> mocked = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractOpenIdConfiguration(
                        Mockito.anyString(), Mockito.any(), Mockito.any())).thenReturn(openIdConfig))) {

            UserCertificateProvider provider = new UserCertificateProvider();
            try {
                provider.initialize("sys.auth.user_cert", null, null, null);
                fail();
            } catch (ProviderResourceException ex) {
                assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
                assertTrue(ex.getMessage().contains("IdP token endpoint must be an https url"));
            }
        }
    }

    @Test
    public void testInitializeConfigEndpointJwksNotHttps() throws ProviderResourceException {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CONFIG_ENDPOINT, "https://idp.example.com/.well-known/openid-configuration");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_AUDIENCE, "test-audience");

        OpenIdConfiguration openIdConfig = new OpenIdConfiguration();
        openIdConfig.setTokenEndpoint("https://idp.example.com/oauth2/token");
        openIdConfig.setJwksUri("http://idp.example.com/oauth2/keys");

        try (MockedConstruction<JwtsHelper> mocked = Mockito.mockConstruction(JwtsHelper.class,
                (mock, context) -> Mockito.when(mock.extractOpenIdConfiguration(
                        Mockito.anyString(), Mockito.any(), Mockito.any())).thenReturn(openIdConfig))) {

            UserCertificateProvider provider = new UserCertificateProvider();
            try {
                provider.initialize("sys.auth.user_cert", null, null, null);
                fail();
            } catch (ProviderResourceException ex) {
                assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
                assertTrue(ex.getMessage().contains("IdP jwks endpoint must be an https url"));
            }
        }
    }

    @Test
    public void testInitializeMissingClientId() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "https://idp.example.com/keys");

        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.initialize("sys.auth.user_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("IdP client id not configured"));
        }
    }

    @Test
    public void testInitializeMissingAudience() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_TOKEN_ENDPOINT, "https://idp.example.com/token");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_JWKS_ENDPOINT, "https://idp.example.com/keys");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_ID, "test-client-id");

        UserCertificateProvider provider = new UserCertificateProvider();
        try {
            provider.initialize("sys.auth.user_cert", null, null, null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("IdP audience not configured"));
        }
    }

    @Test
    public void testGetClientSecretNoPrivateKeyStore() {
        UserCertificateProvider provider = new UserCertificateProvider();
        assertEquals(provider.getClientSecret(), "");
    }

    @Test
    public void testGetClientSecretNoKeyName() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        UserCertificateProvider provider = new UserCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertEquals(provider.getClientSecret(), "");
    }

    @Test
    public void testGetClientSecretNullReturnFromKeyStore() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYNAME, "my-key");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("", "", "my-key")).thenReturn(null);

        UserCertificateProvider provider = new UserCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertEquals(provider.getClientSecret(), "");
    }

    @Test
    public void testGetClientSecretSuccess() {
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_APP, "app1");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYGROUP, "group1");
        System.setProperty(UserCertificateProvider.USER_CERT_PROP_CLIENT_SECRET_KEYNAME, "key1");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.when(keyStore.getSecret("app1", "group1", "key1"))
                .thenReturn("secret-value".toCharArray());

        UserCertificateProvider provider = new UserCertificateProvider();
        provider.setPrivateKeyStore(keyStore);
        assertEquals(provider.getClientSecret(), "secret-value");
    }

    @Test
    public void testConfirmInstanceSuccess() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        String accessToken = generateMockAccessToken("johndoe", "test-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        InstanceConfirmation result = spyProvider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceWithRawAuthCode() {
        UserCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("raw-auth-code-value");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Code not provided in attestation data"));
        }
    }

    @Test
    public void testConfirmInstanceNoAttestationData() {
        UserCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Attestation data not provided"));
        }
    }

    @Test
    public void testConfirmInstanceEmptyAttestationData() {
        UserCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setAttestationData("");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Attestation data not provided"));
        }
    }

    @Test
    public void testConfirmInstanceNoUserName() {
        UserCertificateProvider provider = createTestProvider();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setAttestationData("code=test-code");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("User name not provided"));
        }
    }

    @Test
    public void testConfirmInstanceSubjectMismatch() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        String accessToken = generateMockAccessToken("different-user", "test-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Subject token does not match requested user name"));
        }
    }

    @Test
    public void testConfirmInstanceInvalidToken() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token("not-a-valid-jwt");

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to validate access token"));
        }
    }

    @Test
    public void testConfirmInstanceAudienceMatch() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.audience = "my-audience";

        String accessToken = generateMockAccessToken("johndoe", "my-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        InstanceConfirmation result = spyProvider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceAudienceMismatch() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.audience = "expected-audience";

        String accessToken = generateMockAccessToken("johndoe", "wrong-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Token audience mismatch"));
        }
    }

    @Test
    public void testConfirmInstanceTokenEndpointError() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(401, "");
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=invalid-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("IdP token endpoint returned error"));
        }
    }

    @Test
    public void testConfirmInstanceNoAccessTokenInResponse() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        String tokenResponseJson = "{\"token_type\":\"Bearer\"}";

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("does not contain an access token"));
        }
    }

    @Test
    public void testConfirmInstanceConnectionException() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doThrow(new IOException("Connection refused"))
                .when(spyProvider).createTokenEndpointConnection();

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to exchange auth code with IdP"));
        }
    }

    @Test
    public void testConfirmInstanceWithClientSecretNotSet() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        String accessToken = generateMockAccessToken("johndoe", "test-audience", null);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code&code_verifier=test-verifier");

        InstanceConfirmation result = spyProvider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testRefreshInstanceNotSupported() {
        UserCertificateProvider provider = createTestProvider();

        try {
            provider.refreshInstance(null);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("User X.509 Certificates cannot be refreshed"));
        }
    }

    @Test
    public void testValidateTokenSubjectMatch() {
        UserCertificateProvider provider = createTestProvider();

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("johndoe");

        assertTrue(provider.validateTokenSubject(accessToken, "user", "johndoe"));
    }

    @Test
    public void testValidateTokenSubjectFullNameMatch() {
        UserCertificateProvider provider = createTestProvider();

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("user.johndoe");

        assertTrue(provider.validateTokenSubject(accessToken, "user", "johndoe"));
    }

    @Test
    public void testValidateTokenSubjectClaimMatch() {
        UserCertificateProvider provider = createTestProvider();
        provider.userNameClaim = "preferred_username";

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("uid-12345");
        Mockito.when(accessToken.getClaim("preferred_username")).thenReturn("johndoe");

        assertTrue(provider.validateTokenSubject(accessToken, "user", "johndoe"));
    }

    @Test
    public void testValidateTokenSubjectClaimFullNameMatch() {
        UserCertificateProvider provider = createTestProvider();
        provider.userNameClaim = "preferred_username";

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("uid-12345");
        Mockito.when(accessToken.getClaim("preferred_username")).thenReturn("user.johndoe");

        assertTrue(provider.validateTokenSubject(accessToken, "user", "johndoe"));
    }

    @Test
    public void testValidateTokenSubjectNoMatch() {
        UserCertificateProvider provider = createTestProvider();

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("different-user");

        assertFalse(provider.validateTokenSubject(accessToken, "user", "johndoe"));
    }

    @Test
    public void testValidateTokenSubjectNoMatchWithClaim() {
        UserCertificateProvider provider = createTestProvider();
        provider.userNameClaim = "preferred_username";

        AccessToken accessToken = Mockito.mock(AccessToken.class);
        Mockito.when(accessToken.getSubject()).thenReturn("uid-12345");
        Mockito.when(accessToken.getClaim("preferred_username")).thenReturn("other-user");

        assertFalse(provider.validateTokenSubject(accessToken, "user", "johndoe"));
    }

    @Test
    public void testExchangeAuthCodeWithClientSecret() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.clientSecret = "my-secret";

        String accessTokenJwt = generateMockAccessToken("johndoe", null, null);
        String tokenResponseJson = "{\"access_token\":\"" + accessTokenJwt + "\",\"token_type\":\"Bearer\"}";

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        String result = spyProvider.exchangeAuthCodeForAccessToken("code=test-code");
        assertEquals(result, accessTokenJwt);
    }

    @Test
    public void testExchangeAuthCodeWithoutClientSecret() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        String accessTokenJwt = generateMockAccessToken("johndoe", null, null);
        String tokenResponseJson = "{\"access_token\":\"" + accessTokenJwt + "\",\"token_type\":\"Bearer\"}";

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        String result = spyProvider.exchangeAuthCodeForAccessToken("code=test-code&code_verifier=test-verifier");
        assertEquals(result, accessTokenJwt);
    }

    @Test
    public void testExchangeAuthCodeEmptyAccessToken() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        String tokenResponseJson = "{\"token_type\":\"Bearer\"}";

        UserCertificateProvider spyProvider = Mockito.spy(provider);
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
        UserCertificateProvider provider = createTestProvider();

        String accessTokenJwt = generateMockAccessToken("johndoe", null, null);
        String tokenResponseJson = "{\"access_token\":\"" + accessTokenJwt + "\",\"token_type\":\"Bearer\"}";

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(200, tokenResponseJson);
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        AccessTokenResponse result = spyProvider.postTokenRequest("grant_type=authorization_code&code=test");
        assertNotNull(result);
        assertEquals(result.getAccess_token(), accessTokenJwt);
    }

    @Test
    public void testPostTokenRequestError() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        HttpURLConnection mockConn = createMockConnection(401, "");
        Mockito.doReturn(mockConn).when(spyProvider).createTokenEndpointConnection();

        try {
            spyProvider.postTokenRequest("grant_type=authorization_code&code=test");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("IdP token endpoint returned error"));
        }
    }

    @Test
    public void testPostTokenRequestException() throws Exception {
        UserCertificateProvider provider = createTestProvider();

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doThrow(new IOException("Connection refused"))
                .when(spyProvider).createTokenEndpointConnection();

        try {
            spyProvider.postTokenRequest("grant_type=authorization_code&code=test");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Unable to exchange auth code with IdP"));
        }
    }

    @Test
    public void testConfirmInstanceWithUserNameClaim() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.userNameClaim = "preferred_username";

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("preferred_username", "johndoe");
        String accessToken = generateMockAccessToken("uid-12345", "test-audience", extraClaims);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        InstanceConfirmation result = spyProvider.confirmInstance(confirmation);
        assertNotNull(result);
    }

    @Test
    public void testConfirmInstanceWithUserNameClaimNoMatch() throws Exception {
        UserCertificateProvider provider = createTestProvider();
        provider.userNameClaim = "preferred_username";

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("preferred_username", "other-user");
        String accessToken = generateMockAccessToken("uid-12345", null, extraClaims);
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessToken);

        UserCertificateProvider spyProvider = Mockito.spy(provider);
        Mockito.doReturn(tokenResponse).when(spyProvider).postTokenRequest(Mockito.anyString());

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            spyProvider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Subject token does not match requested user name"));
        }
    }

    @Test
    public void testCreateTokenEndpointConnection() throws IOException {
        UserCertificateProvider provider = new UserCertificateProvider();
        provider.tokenEndpoint = "https://idp.example.com/token";
        HttpURLConnection conn = provider.createTokenEndpointConnection();
        assertNotNull(conn);
        conn.disconnect();
    }

    @Test
    public void testGenerateAccessTokenRequestBodyCodeOnly() throws ProviderResourceException {
        UserCertificateProvider provider = createTestProvider();

        String body = provider.generateAccessTokenRequestBody("code=my-auth-code");
        assertTrue(body.contains("grant_type=authorization_code"));
        assertTrue(body.contains("client_id="));
        assertTrue(body.contains("redirect_uri="));
        assertTrue(body.contains("client_secret="));
        assertTrue(body.contains("code=my-auth-code"));
        assertFalse(body.contains("code_verifier="));
    }

    @Test
    public void testGenerateAccessTokenRequestBodyWithAllParams() throws ProviderResourceException {
        UserCertificateProvider provider = createTestProvider();

        String body = provider.generateAccessTokenRequestBody(
                "code=my-code&state=my-state&code_verifier=my-verifier");
        assertTrue(body.contains("grant_type=authorization_code"));
        assertTrue(body.contains("client_secret="));
        assertTrue(body.contains("code=my-code"));
        assertTrue(body.contains("code_verifier=my-verifier"));
    }

    @Test
    public void testGenerateAccessTokenRequestBodyMissingCode() {
        UserCertificateProvider provider = createTestProvider();

        try {
            provider.generateAccessTokenRequestBody("state=some-state&code_verifier=some-verifier");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("Code not provided in attestation data"));
        }
    }

    @Test
    public void testGenerateAccessTokenRequestBodyPkceRequiredNoVerifier() {
        UserCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        try {
            provider.generateAccessTokenRequestBody("code=my-code");
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("PKCE is required but code verifier not provided"));
        }
    }

    @Test
    public void testGenerateAccessTokenRequestBodyPkceWithVerifier() throws ProviderResourceException {
        UserCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        String body = provider.generateAccessTokenRequestBody("code=my-code&code_verifier=my-verifier");
        assertTrue(body.contains("grant_type=authorization_code"));
        assertFalse(body.contains("client_secret="));
        assertTrue(body.contains("code=my-code"));
        assertTrue(body.contains("code_verifier=my-verifier"));
    }

    @Test
    public void testConfirmInstancePkceRequiredNoVerifier() {
        UserCertificateProvider provider = createTestProvider();
        provider.clientSecret = "";

        InstanceConfirmation confirmation = new InstanceConfirmation();
        confirmation.setDomain("user");
        confirmation.setService("johndoe");
        confirmation.setProvider("sys.auth.user_cert");
        confirmation.setAttestationData("code=test-auth-code");

        try {
            provider.confirmInstance(confirmation);
            fail();
        } catch (ProviderResourceException ex) {
            assertEquals(ex.getCode(), ProviderResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("PKCE is required but code verifier not provided"));
        }
    }

    // --- helpers ---

    private UserCertificateProvider createTestProvider() {
        UserCertificateProvider provider = new UserCertificateProvider();
        provider.tokenEndpoint = "https://idp.example.com/oauth2/v1/token";
        provider.clientId = "test-client-id";
        provider.clientSecret = "test-secret";
        provider.redirectUri = UserCertificateProvider.DEFAULT_REDIRECT_URI;
        provider.audience = "test-audience";
        provider.connectTimeout = 10000;
        provider.readTimeout = 15000;
        return provider;
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
