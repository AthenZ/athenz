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

package com.yahoo.athenz.zts.external.azure;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.common.server.external.IdTokenSigner;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zts.DomainDetails;
import com.yahoo.athenz.zts.ExternalCredentialsRequest;
import com.yahoo.athenz.zts.ExternalCredentialsResponse;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.assertArg;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class AzureAccessTokenProviderTest {

    public static final String ACCESS_TOKEN_ERROR_RESPONSE = "{\n" +
            "  \"error\": \"invalid_client\",\n" +
            "  \"error_description\": \"AADSTS700212: No matching federated identity record found for presented assertion audience 'my.audience'. Please check your federated identity credential Subject, Audience and Issuer against the presented assertion. https://docs.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation Trace ID: c31234bc-69fd-4797-bbc5-809e7afb5000 Correlation ID: 1b321183-4fb9-4116-bd51-5700f7fbdf0c Timestamp: 2024-04-16 06:58:38Z\",\n" +
            "  \"error_codes\": [\n" +
            "    700212\n" +
            "  ],\n" +
            "  \"timestamp\": \"2024-04-16 06:58:38Z\",\n" +
            "  \"trace_id\": \"c3321110-69fd-4797-bbc5-809e7afb5000\",\n" +
            "  \"correlation_id\": \"13211683-4fb9-4116-bd51-5700f7fbdf0c\"\n" +
            "}";
    public static final String ACCESS_TOKEN_RESPONSE_STR =
            "{\n" +
            "  \"token_type\": \"Bearer\",\n" +
            "  \"expires_in\": 86399,\n" +
            "  \"ext_expires_in\": 86399,\n" +
            "  \"access_token\": \"access-token\"\n" +
            "}";
    public static final String USER_MANAGED_IDENTITY_RESPONSE_STR =
            "{\n" +
            "  \"id\": \"/subscriptions/subid/resourcegroups/rgName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/identityName\",\n" +
            "  \"location\": \"eastus\",\n" +
            "  \"name\": \"identityName\",\n" +
            "  \"properties\": {\n" +
            "    \"clientId\": \"request-azure-client-id\",\n" +
            "    \"principalId\": \"25cc773c-7f05-40fc-a104-32d2300754ad\",\n" +
            "    \"tenantId\": \"b6c948ef-f6b5-4384-8354-da3a15eca969\"\n" +
            "  },\n" +
            "  \"tags\": {\n" +
            "    \"key1\": \"value1\",\n" +
            "    \"key2\": \"value2\"\n" +
            "  },\n" +
            "  \"type\": \"Microsoft.ManagedIdentity/userAssignedIdentities\"\n" +
            "}";
    static final IdTokenSigner signer = (idToken, keyType) -> idToken.getSubject();

    @Test
    public void testAzureAccessTokenProviderFailures() throws IOException {

        AzureAccessTokenProvider provider = new AzureAccessTokenProvider();
        Principal principal = Mockito.mock(Principal.class);
        DomainDetails domainDetails = new DomainDetails();
        List<String> idTokenGroups = new ArrayList<>();
        ExternalCredentialsRequest request = new ExternalCredentialsRequest();
        Map<String, String> attributes = new HashMap<>();
        request.setAttributes(attributes);

        // authorizer not configured

        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("ZTS authorizer not configured"));
        }
        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        // azure tenant not present on domain

        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("azure tenant not configured for domain"));
        }
        domainDetails.setAzureTenant("az-tenant");

        // azure client not set for domain

        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.FORBIDDEN);
            assertTrue(ex.getMessage().contains("azure client not configured for domain"));
        }
        domainDetails.setAzureClient("az-client");

        // no roles accessible to principal

        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("must specify exactly one accessible role"));
        }
        idTokenGroups.add("domain:role.client");

        // http driver failing to get access token for the athenz azure client, for reading the request azure client id

        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);
        provider.setHttpDriver(httpDriver);
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(new HttpDriverResponse(401, ACCESS_TOKEN_ERROR_RESPONSE, null));
        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
            assertTrue(ex.getMessage().contains("assertion audience 'my.audience'"));
        }

        // http driver failing to get access token for the system azure client, when that is requested

        List<String> systemIdTokenGroups = new ArrayList<>();
        systemIdTokenGroups.add("athenz.azure:role.azure-client");
        try {
            provider.getCredentials(principal, domainDetails, systemIdTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
            assertTrue(ex.getMessage().contains("assertion audience 'my.audience'"));
        }
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(new HttpDriverResponse(200, ACCESS_TOKEN_RESPONSE_STR, null));

        // azure client id not indicated, and not system access token request

        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.BAD_REQUEST);
            assertTrue(ex.getMessage().contains("must specify azureClientId, or azureResourceGroup and azureClientName"));
        }
        attributes.put("azureResourceGroup", "group");
        attributes.put("azureClientName", "client");

        // http driver failing to read the request azure client id, from resource group and client names

        Mockito.when(httpDriver.doGet(any(), any())).thenReturn("");
        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
            assertTrue(ex.getMessage().contains("Unable to retrieve Azure client ID"));
        }
        Mockito.when(httpDriver.doGet(any(), any())).thenReturn(USER_MANAGED_IDENTITY_RESPONSE_STR);

        // not authorized for requested scope

        Mockito.when(authorizer.access(any(), any(), any(), any())).thenReturn(false);
        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
            assertTrue(ex.getMessage().contains("Principal not authorized for configured scope"));
        }
        Mockito.when(authorizer.access(any(), any(), any(), any())).thenReturn(true);

        // http driver returning error response when attempting to get the requested access token

        attributes.put("azureClientId", "az-client-id"); // skip getting the client ID
        Mockito.when(httpDriver.doPostHttpResponse(any())).thenReturn(new HttpDriverResponse(401, ACCESS_TOKEN_ERROR_RESPONSE, null));
        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
            assertTrue(ex.getMessage().contains("assertion audience 'my.audience'"));
        }

        // http driver returning failure

        Mockito.when(httpDriver.doPostHttpResponse(any())).thenThrow(new IOException("my http-failure"));
        try {
            provider.getCredentials(principal, domainDetails, idTokenGroups, new IdToken(), signer, request);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ResourceException.FORBIDDEN, ex.getCode());
            assertTrue(ex.getMessage().contains("my http-failure"));
        }
    }

    @Test
    public void testAzureAccessTokenProvider() throws IOException {

        AzureAccessTokenProvider provider = new AzureAccessTokenProvider();

        List<String> idTokenGroups = new ArrayList<>();
        idTokenGroups.add("my-domain:role.client");
        IdToken idToken = new IdToken();
        Principal principal = Mockito.mock(Principal.class);
        DomainDetails domainDetails = new DomainDetails()
                .setName("my-domain")
                .setAzureSubscription("azure-subscription")
                .setAzureTenant("azure-tenant")
                .setAzureClient("athenz-azure-client-id");

        ExternalCredentialsRequest request = new ExternalCredentialsRequest();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("azureResourceGroup", "azure-resource-group");
        attributes.put("azureClientName", "azure-client-name");
        attributes.put("azureTokenScope", "my/scope");
        request.setAttributes(attributes);

        Authorizer authorizer = Mockito.mock(Authorizer.class);
        provider.setAuthorizer(authorizer);

        HttpDriverResponse accessTokenResponse = new HttpDriverResponse(200, ACCESS_TOKEN_RESPONSE_STR, null);
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);

        List<String> expectedScopes = new ArrayList<>();
        List<String> expectedClientIds = new ArrayList<>();
        List<String> expectedIdTokens = new ArrayList<>();

        // first access token request is for the athenz azure client to look up the client id

        expectedScopes.add("https%3A%2F%2Fmanagement.azure.com%2F.default");
        expectedClientIds.add("athenz-azure-client-id");
        expectedIdTokens.add("athenz.azure%3Arole.azure-client");

        // second access token request is for the requested access token

        expectedScopes.add("my%2Fscope");
        expectedClientIds.add("request-azure-client-id");
        expectedIdTokens.add("my-domain%3Arole.client");

        Mockito.when(httpDriver.doPostHttpResponse(assertArg(arg -> {
            assertEquals(arg.getURI(), URI.create("https://login.microsoftonline.com/azure-tenant/oauth2/v2.0/token"));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            arg.getEntity().writeTo(out);
            String body = out.toString();
            assertEquals(body,
                         "scope=" + expectedScopes.remove(0) + "&" +
                         "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&" +
                         "client_assertion=" + expectedIdTokens.remove(0) + "&" +
                         "client_id=" + expectedClientIds.remove(0) + "&" +
                         "grant_type=client_credentials");
        }))).thenReturn(accessTokenResponse);

        String expectedUrl = "https://management.azure.com/subscriptions/azure-subscription/resourceGroups/azure-resource-group" +
                             "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/azure-client-name?api-version=2023-01-31";
        Map<String, String> expectedHeaders = new HashMap<>();
        expectedHeaders.put("Authorization", "Bearer access-token");
        Mockito.when(httpDriver.doGet(eq(expectedUrl), eq(expectedHeaders))).thenReturn(USER_MANAGED_IDENTITY_RESPONSE_STR);

        provider.setHttpDriver(httpDriver);
        Mockito.when(authorizer.access(eq("azure.scope_access"), eq("my-domain:my/scope"), same(principal), isNull())).thenReturn(true);

        ExternalCredentialsResponse response = provider.getCredentials(principal, domainDetails, idTokenGroups, idToken, signer, request);
        assertNotNull(response);
        Map<String, String> responseAttributes = response.getAttributes();
        assertEquals(responseAttributes.get("accessToken"), "access-token");
        assertEquals(responseAttributes.get("azureSubscription"), "azure-subscription");
        assertEquals(responseAttributes.get("azureTenant"), "azure-tenant");
        assertEquals(idToken.getSubject(), "my-domain:role.client");
        assertEquals(idToken.getAudience(), "api://AzureADTokenExchange");

        assertEquals(expectedClientIds.size(), 0);
        assertEquals(expectedIdTokens.size(), 0);
        assertEquals(expectedScopes.size(), 0);
    }


    @Test
    public void testAzureAccessTokenProviderSystemToken() throws IOException {

        AzureAccessTokenProvider provider = new AzureAccessTokenProvider();

        List<String> idTokenGroups = new ArrayList<>();
        idTokenGroups.add("athenz.azure:role.azure-client"); // System azure client role
        IdToken idToken = new IdToken();
        Principal principal = Mockito.mock(Principal.class);
        DomainDetails domainDetails1 = new DomainDetails()
                .setName("domain1")
                .setAzureSubscription("azure-subscription1")
                .setAzureTenant("azure-tenant1")
                .setAzureClient("athenz-azure-client-id1");
        DomainDetails domainDetails2 = new DomainDetails()
                .setName("domain2")
                .setAzureSubscription("azure-subscription2")
                .setAzureTenant("azure-tenant2")
                .setAzureClient("athenz-azure-client-id2");

        ExternalCredentialsRequest request = new ExternalCredentialsRequest();
        request.setAttributes(new HashMap<>());

        provider.setAuthorizer(Mockito.mock(Authorizer.class));

        HttpDriverResponse accessTokenResponse = new HttpDriverResponse(200, ACCESS_TOKEN_RESPONSE_STR, null);
        HttpDriver httpDriver = Mockito.mock(HttpDriver.class);

        List<String> expectedURIs = new ArrayList<>();
        List<String> expectedClientIds = new ArrayList<>();

        // first access token request is for the system azure client for the first domain

        expectedURIs.add("https://login.microsoftonline.com/azure-tenant1/oauth2/v2.0/token");
        expectedClientIds.add("athenz-azure-client-id1");

        // second access token request is for the system azure client for the second domain

        expectedURIs.add("https://login.microsoftonline.com/azure-tenant2/oauth2/v2.0/token");
        expectedClientIds.add("athenz-azure-client-id2");

        Mockito.when(httpDriver.doPostHttpResponse(assertArg(arg -> {
            assertEquals(arg.getURI(), URI.create(expectedURIs.remove(0)));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            arg.getEntity().writeTo(out);
            String body = out.toString();
            assertEquals(body,
                         "scope=https%3A%2F%2Fmanagement.azure.com%2F.default&" +
                         "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&" +
                         "client_assertion=athenz.azure%3Arole.azure-client&" +
                         "client_id=" + expectedClientIds.remove(0) + "&" +
                         "grant_type=client_credentials");
        }))).thenReturn(accessTokenResponse);

        provider.setHttpDriver(httpDriver);

        // First request for system access token for first domain

        ExternalCredentialsResponse response1 = provider.getCredentials(principal, domainDetails1, idTokenGroups, idToken, signer, request);
        assertNotNull(response1);
        Map<String, String> responseAttributes1 = response1.getAttributes();
        assertEquals(responseAttributes1.get("accessToken"), "access-token");
        assertEquals(responseAttributes1.get("azureSubscription"), "azure-subscription1");
        assertEquals(responseAttributes1.get("azureTenant"), "azure-tenant1");
        assertEquals(idToken.getSubject(), "athenz.azure:role.azure-client");
        assertEquals(idToken.getAudience(), "api://AzureADTokenExchange");

        // Another request for system access token for first domain uses the cached result
        ExternalCredentialsResponse response2 = provider.getCredentials(principal, domainDetails1, idTokenGroups, idToken, signer, request);
        assertSame(response1, response2);

        // Third request is for the second domain
        ExternalCredentialsResponse response3 = provider.getCredentials(principal, domainDetails2, idTokenGroups, idToken, signer, request);
        assertNotNull(response3);
        Map<String, String> responseAttributes3 = response3.getAttributes();
        assertEquals(responseAttributes3.get("accessToken"), "access-token");
        assertEquals(responseAttributes3.get("azureSubscription"), "azure-subscription2");
        assertEquals(responseAttributes3.get("azureTenant"), "azure-tenant2");
        assertEquals(idToken.getSubject(), "athenz.azure:role.azure-client");
        assertEquals(idToken.getAudience(), "api://AzureADTokenExchange");

        assertEquals(expectedClientIds.size(), 0);
        assertEquals(expectedURIs.size(), 0);
    }
}
