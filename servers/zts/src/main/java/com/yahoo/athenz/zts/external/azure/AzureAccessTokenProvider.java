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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.common.server.external.ExternalCredentialsProvider;
import com.yahoo.athenz.common.server.external.IdTokenSigner;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zts.AccessTokenResponse;
import com.yahoo.athenz.zts.DomainDetails;
import com.yahoo.athenz.zts.ExternalCredentialsRequest;
import com.yahoo.athenz.zts.ExternalCredentialsResponse;
import com.yahoo.rdl.Timestamp;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.eclipse.jetty.util.StringUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AzureAccessTokenProvider implements ExternalCredentialsProvider {

    static final String AZURE_MGMT_URL = "https://management.azure.com";
    static final String AZURE_MGMT_SCOPE = AZURE_MGMT_URL + "/.default";

    static final String AZURE_OPENID_BASE_URI = "https://login.microsoftonline.com/";
    static final String AZURE_SCOPE_ACTION = "azure.scope_access";

    static final String AZURE_CLIENT_ID = "azureClientId";
    static final String AZURE_RESOURCE_GROUP = "azureResourceGroup";
    static final String AZURE_CLIENT_NAME = "azureClientName";
    static final String AZURE_TOKEN_SCOPE = "azureTokenScope";
    static final String AZURE_ACCESS_TOKEN = "accessToken";
    static final String AZURE_TENANT = "azureTenant";
    static final String AZURE_SUBSCRIPTION = "azureSubscription";

    static final String SYSTEM_AZURE_CLIENT_ROLE = "athenz.azure:role.azure-client";

    final ObjectMapper jsonMapper;
    final Map<String, ExternalCredentialsResponse> systemAccessTokenCache;
    HttpDriver httpDriver;
    Authorizer authorizer;

    public AzureAccessTokenProvider() {
        jsonMapper = new ObjectMapper();
        systemAccessTokenCache = new ConcurrentHashMap<>();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        httpDriver = new HttpDriver.Builder(null, null)
                .clientConnectTimeoutMs(1000)
                .clientReadTimeoutMs(3000)
                .build();
        authorizer = null;
    }

    /** Package-private for unit tests. */
    void setHttpDriver(HttpDriver httpDriver) {
        this.httpDriver = httpDriver;
    }

    @Override
    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    private static String getRequestAttribute(Map<String, String> attributes, String attrName, String attrDefaultValue) {
        String value = attributes.get(attrName);
        return StringUtil.isEmpty(value) ? attrDefaultValue : value;
    }

    /**
     * https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential
     */
    @Override
    public ExternalCredentialsResponse getCredentials(Principal principal, DomainDetails domainDetails, List<String> idTokenGroups,
            IdToken idToken, IdTokenSigner idTokenSigner, ExternalCredentialsRequest externalCredentialsRequest)
            throws ResourceException {

        // First make sure that our required components are available and configured

        if (authorizer == null) {
            throw new ResourceException(ResourceException.FORBIDDEN, "ZTS authorizer not configured");
        }

        // Then verify the Azure tenant and client (for ZTS) is configured on the domain
        String azureTenant = domainDetails.getAzureTenant();
        if (StringUtil.isEmpty(azureTenant)) {
            throw new ResourceException(ResourceException.FORBIDDEN, "azure tenant not configured for domain");
        }
        String azureProviderIdentityLoginUri = AZURE_OPENID_BASE_URI + azureTenant + "/oauth2/v2.0/token";

        String systemAzureClient = domainDetails.getAzureClient();
        if (StringUtil.isEmpty(systemAzureClient)) {
            throw new ResourceException(ResourceException.FORBIDDEN, "azure client not configured for domain");
        }

        // Verify a single role was requested, and accessible to the principal, and use this as the id token subject

        if (idTokenGroups.size() != 1) {
            throw new ResourceException(ResourceException.BAD_REQUEST, "must specify exactly one accessible role");
        }
        idToken.setAudience("api://AzureADTokenExchange");

        // Check that the request contains an Azure client ID, or resource group and client names; or is a request for the system access token.

        Map<String, String> attributes = externalCredentialsRequest.getAttributes();
        String requestAzureClientId = getRequestAttribute(attributes, AZURE_CLIENT_ID, null);
        if (StringUtil.isEmpty(requestAzureClientId)) {

            // If the azure client ID is not indicated directly, we need the system access token, either for returning, or for finding the client ID.

            ExternalCredentialsResponse systemAccessToken = getSystemAccessToken(azureProviderIdentityLoginUri, domainDetails, idToken, idTokenSigner);

            // If the requested role is the system Azure client role, this is an internal request for its access token, so we return that.

            if (idTokenGroups.get(0).equals(SYSTEM_AZURE_CLIENT_ROLE)) {
                return systemAccessToken;
            } else { // Otherwise, we need to find the Azure client ID from the requested resource group and client name
                String azureResourceGroup = getRequestAttribute(attributes, AZURE_RESOURCE_GROUP, null);
                String azureClientName = getRequestAttribute(attributes, AZURE_CLIENT_NAME, null);
                if ((StringUtil.isEmpty(azureResourceGroup) || StringUtil.isEmpty(azureClientName))) {
                    throw new ResourceException(ResourceException.BAD_REQUEST, "must specify azureClientId, or azureResourceGroup and azureClientName");
                }
                try {
                requestAzureClientId = getClientId(domainDetails.getAzureSubscription(), azureResourceGroup,
                        azureClientName, systemAccessToken.getAttributes().get(AZURE_ACCESS_TOKEN));
                } catch (Exception ex) {
                    throw new ResourceException(ResourceException.FORBIDDEN, ex.getMessage());
                }
            }
        }

        // Verify that the given principal is authorized for all scopes requested

        String azureTokenScope = getRequestAttribute(attributes, AZURE_TOKEN_SCOPE, AZURE_MGMT_SCOPE);
        for (String scopeItem : azureTokenScope.split(" ")) {
            String resource = domainDetails.getName() + ":" + scopeItem;
            if (!authorizer.access(AZURE_SCOPE_ACTION, resource, principal, null)) {
                throw new ResourceException(ResourceException.FORBIDDEN, "Principal not authorized for configured scope");
            }
        }

        // Now exchange the ID token of the requested role for an Azure access token for the requested client

        try {
            idToken.setSubject(idTokenGroups.get(0));
            final String signedIdToken = idTokenSigner.sign(idToken, "rsa");
            AccessTokenResponse accessToken = getAccessToken(azureProviderIdentityLoginUri, signedIdToken, requestAzureClientId, azureTokenScope);
            return createResponse(accessToken, domainDetails);
        } catch (Exception ex) {
            throw new ResourceException(ResourceException.FORBIDDEN, ex.getMessage());
        }
    }

    private ExternalCredentialsResponse getSystemAccessToken(String azureProviderIdentityLoginUri, DomainDetails domain, IdToken itToken, IdTokenSigner signer) {
        ExternalCredentialsResponse cached = systemAccessTokenCache.get(domain.getAzureClient());
        if (cached != null && cached.getExpiration().millis() > System.currentTimeMillis() + 300_000) {
            return cached;
        }
        try {
            itToken.setSubject(SYSTEM_AZURE_CLIENT_ROLE);
            final String signedIdToken = signer.sign(itToken, "rsa");
            AccessTokenResponse accessToken = getAccessToken(azureProviderIdentityLoginUri, signedIdToken, domain.getAzureClient(), AZURE_MGMT_SCOPE);
            ExternalCredentialsResponse response = createResponse(accessToken, domain);
            systemAccessTokenCache.put(domain.getAzureClient(), response);
            return response;
        } catch (Exception ex) {
            throw new ResourceException(ResourceException.FORBIDDEN, ex.getMessage());
        }
    }

    private AccessTokenResponse getAccessToken(String azureProviderIdentityLoginUri, String signedIdToken, String azureClientId, String azureTokenScope) {
        try {
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("scope", azureTokenScope));
            params.add(new BasicNameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            params.add(new BasicNameValuePair("client_assertion", signedIdToken));
            params.add(new BasicNameValuePair("client_id", azureClientId));
            params.add(new BasicNameValuePair("grant_type", "client_credentials"));
            HttpPost httpPost = new HttpPost(azureProviderIdentityLoginUri);
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            HttpDriverResponse httpResponse = httpDriver.doPostHttpResponse(httpPost);

            if (httpResponse.getStatusCode() != HttpStatus.SC_OK) {
                String errorMessage = jsonMapper.readTree(httpResponse.getMessage()).get("error_description").asText();
                throw new ResourceException(httpResponse.getStatusCode(), errorMessage);
            }
            return jsonMapper.readValue(httpResponse.getMessage(), AccessTokenResponse.class);
        } catch (Exception ex) {
            throw new ResourceException(ResourceException.FORBIDDEN, ex.getMessage());
        }
    }

    private ExternalCredentialsResponse createResponse(AccessTokenResponse accessToken, DomainDetails domainDetails) {
        ExternalCredentialsResponse response = new ExternalCredentialsResponse();
        Map<String, String> attributes = new HashMap<>();
        attributes.put(AZURE_ACCESS_TOKEN, accessToken.getAccess_token());
        attributes.put(AZURE_SUBSCRIPTION, domainDetails.getAzureSubscription());
        attributes.put(AZURE_TENANT, domainDetails.getAzureTenant());
        response.setAttributes(attributes);
        response.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 1000L * accessToken.getExpires_in()));
        return response;
    }

    private String getClientId(String azureSubscription, String azureResourceGroup, String azureClientName, String accessToken) throws IOException {
        String userManagedIdentityUrl = AZURE_MGMT_URL +
                "/subscriptions/" + azureSubscription +
                "/resourceGroups/" + azureResourceGroup +
                "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + azureClientName +
                "?api-version=2023-01-31";
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + accessToken);

        String response = httpDriver.doGet(userManagedIdentityUrl, headers);
        if (StringUtil.isEmpty(response)) {
            throw new ResourceException(ResourceException.FORBIDDEN, "Unable to retrieve Azure client ID");
        }

        AzureUserManagedIdentityResponse userManagedIdentityResponse = jsonMapper.readValue(response, AzureUserManagedIdentityResponse.class);
        String clientId = userManagedIdentityResponse.getProperties().getClientId();
        if (StringUtil.isEmpty(clientId)) {
            throw new ResourceException(ResourceException.FORBIDDEN, "Unable to retrieve Azure client ID");
        }
        return clientId;
    }

}
