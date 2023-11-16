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

package com.yahoo.athenz.zts.external.gcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.external.ExternalCredentialsProvider;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zts.DomainDetails;
import com.yahoo.athenz.zts.ExternalCredentialsRequest;
import com.yahoo.athenz.zts.ExternalCredentialsResponse;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.rdl.Timestamp;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.eclipse.jetty.util.StringUtil;

import java.io.IOException;
import java.util.*;

public class GcpAccessTokenProvider implements ExternalCredentialsProvider {

    public static final String GCP_STS_TOKEN_URL = "https://sts.googleapis.com/v1/token";
    public static final String GCP_SCOPE_ACTION = "gcp.scope_access";

    public static final String GCP_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String GCP_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    public static final String GCP_ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";

    public static final String GCP_SERVICE_ACCOUNT = "gcpServiceAccount";
    public static final String GCP_TOKEN_SCOPE = "gcpTokenScope";
    public static final String GCP_WORKLOAD_POOL_NAME = "gcpWorkloadPoolName";
    public static final String GCP_WORKLOAD_PROVIDER_NAME = "gcpWorkloadProviderName";
    public static final String GCP_ACCESS_TOKEN = "accessToken";
    public static final String GCP_PROJECT_ID = "gcpProjectId";
    public static final String GCP_PROJECT_NUMBER = "gcpProjectNumber";
    private static final String GCP_DEFAULT_TOKEN_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

    HttpDriver httpDriver;
    Authorizer authorizer;
    ObjectMapper jsonMapper = new ObjectMapper();
    final String defaultWorkloadPoolName;
    final String defaultWorkloadProviderName;

    public GcpAccessTokenProvider() {
        this.httpDriver = new HttpDriver.Builder(null, null)
                .clientConnectTimeoutMs(1000)
                .clientReadTimeoutMs(3000)
                .build();
        this.authorizer = null;
        defaultWorkloadPoolName = System.getProperty(ZTSConsts.ZTS_PROP_GCP_WORKLOAD_POOL_NAME);
        defaultWorkloadProviderName = System.getProperty(ZTSConsts.ZTS_PROP_GCP_WORKLOAD_PROVIDER_NAME);
    }

    /**
     * Primarily for unit tests only
     * @param httpDriver httpDriver to be used
     */
    public void setHttpDriver(HttpDriver httpDriver) {
        this.httpDriver = httpDriver;
    }

    @Override
    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    String getRequestAttribute(Map<String, String> attributes, final String attrName, final String attrDefaultValue) {
        final String value = attributes.get(attrName);
        return StringUtil.isEmpty(value) ? attrDefaultValue : value;
    }

    /**
     * Exchanges the ZTS ID token with Google STD Exchange Token which then
     * we'll use to get our access token as described in the GCP docs:
     * https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
     * @param idToken signed jwt id token
     * @param externalCredentialsRequest request attributes
     * @return GcpExchangeTokenResponse which contains the exchange token
     * @throws IOException in case of any errors
     */
    GcpExchangeTokenResponse getExchangeToken(DomainDetails domainDetails, final String idToken,
            ExternalCredentialsRequest externalCredentialsRequest) throws IOException {

        Map<String, String> attributes = externalCredentialsRequest.getAttributes();
        final String gcpTokenScope = getRequestAttribute(attributes, GCP_TOKEN_SCOPE, GCP_DEFAULT_TOKEN_SCOPE);
        final String gcpWorkloadPoolName = getRequestAttribute(attributes, GCP_WORKLOAD_POOL_NAME, defaultWorkloadPoolName);
        final String gcpWorkloadProviderName = getRequestAttribute(attributes, GCP_WORKLOAD_PROVIDER_NAME, defaultWorkloadProviderName);

        String audience = String.format("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
                domainDetails.getGcpProjectNumber(), gcpWorkloadPoolName, gcpWorkloadProviderName);

        GcpExchangeTokenRequest exchangeTokenRequest = new GcpExchangeTokenRequest();
        exchangeTokenRequest.setGrantType(GCP_GRANT_TYPE);
        exchangeTokenRequest.setAudience(audience);
        exchangeTokenRequest.setScope(gcpTokenScope);
        exchangeTokenRequest.setRequestedTokenType(GCP_ACCESS_TOKEN_TYPE);
        exchangeTokenRequest.setSubjectToken(idToken);
        exchangeTokenRequest.setSubjectTokenType(GCP_ID_TOKEN_TYPE);

        HttpPost httpPost = new HttpPost(GCP_STS_TOKEN_URL);
        httpPost.setEntity(new StringEntity(jsonMapper.writeValueAsString(exchangeTokenRequest), ContentType.APPLICATION_JSON));

        final HttpDriverResponse httpResponse = httpDriver.doPostHttpResponse(httpPost);
        if (httpResponse.getStatusCode() != HttpStatus.SC_OK) {
            GcpExchangeTokenError error = jsonMapper.readValue(httpResponse.getMessage(), GcpExchangeTokenError.class);
            throw new ResourceException(httpResponse.getStatusCode(), error.getErrorDescription());
        }
        return jsonMapper.readValue(httpResponse.getMessage(), GcpExchangeTokenResponse.class);
    }

    /**
     * First, we're going to get our exchange token based on our ZTS ID token
     * and then request an access token for the given scope as described in the GCP docs:
     * https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
     * @param principal Principal making the request
     * @param domainDetails Domain details including cloud info
     * @param idToken signed jwt id token
     * @param externalCredentialsRequest request attributes
     * @return GcpExchangeTokenResponse which contains the exchange token
     * @throws ResourceException in case of any errors
     */
    @Override
    public ExternalCredentialsResponse getCredentials(Principal principal, DomainDetails domainDetails, String idToken, ExternalCredentialsRequest externalCredentialsRequest)
            throws ResourceException {

        // first make sure that our required components are available and configured

        if (authorizer == null) {
            throw new ResourceException(ResourceException.FORBIDDEN, "ZTS authorizer not configured");
        }

        Map<String, String> attributes = externalCredentialsRequest.getAttributes();
        final String gcpServiceAccount = getRequestAttribute(attributes, GCP_SERVICE_ACCOUNT, null);
        if (StringUtil.isEmpty(gcpServiceAccount)) {
            throw new ResourceException(ResourceException.BAD_REQUEST, "missing gcp service account");
        }

        // verify that the given principal is authorized for all scopes requested

        final String gcpTokenScope = getRequestAttribute(attributes, GCP_TOKEN_SCOPE, GCP_DEFAULT_TOKEN_SCOPE);
        String[] gcpTokenScopeList = gcpTokenScope.split(" ");
        for (String scopeItem : gcpTokenScopeList) {
            final String resource = domainDetails.getName() + ":" + scopeItem;
            if (!authorizer.access(GCP_SCOPE_ACTION, resource, principal, null)) {
                throw new ResourceException(ResourceException.FORBIDDEN, "Principal not authorized for configured scope");
            }
        }

        try {
            // first we're going to get our exchange token

            GcpExchangeTokenResponse exchangeTokenResponse = getExchangeToken(domainDetails, idToken, externalCredentialsRequest);

            final String serviceUrl = String.format("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s@%s.iam.gserviceaccount.com:generateAccessToken",
                    gcpServiceAccount, domainDetails.getGcpProjectId());
            final String authorizationHeader = exchangeTokenResponse.getTokenType() + " " + exchangeTokenResponse.getAccessToken();

            GcpAccessTokenRequest accessTokenRequest = new GcpAccessTokenRequest();
            accessTokenRequest.setScopeList(gcpTokenScope);
            int expiryTime = externalCredentialsRequest.getExpiryTime() == null ? 3600 : externalCredentialsRequest.getExpiryTime();
            accessTokenRequest.setLifetimeSeconds(expiryTime);

            HttpPost httpPost = new HttpPost(serviceUrl);
            httpPost.addHeader(HttpHeaders.AUTHORIZATION, authorizationHeader);
            httpPost.setEntity(new StringEntity(jsonMapper.writeValueAsString(accessTokenRequest), ContentType.APPLICATION_JSON));

            final HttpDriverResponse httpResponse = httpDriver.doPostHttpResponse(httpPost);
            if (httpResponse.getStatusCode() != HttpStatus.SC_OK) {
                GcpAccessTokenError error = jsonMapper.readValue(httpResponse.getMessage(), GcpAccessTokenError.class);
                throw new ResourceException(httpResponse.getStatusCode(), error.getErrorMessage());
            }

            GcpAccessTokenResponse gcpAccessTokenResponse = jsonMapper.readValue(httpResponse.getMessage(), GcpAccessTokenResponse.class);

            ExternalCredentialsResponse externalCredentialsResponse = new ExternalCredentialsResponse();
            attributes = new HashMap<>();
            attributes.put(GCP_ACCESS_TOKEN, gcpAccessTokenResponse.getAccessToken());
            attributes.put(GCP_PROJECT_ID, domainDetails.getGcpProjectId());
            attributes.put(GCP_PROJECT_NUMBER, domainDetails.getGcpProjectNumber());
            externalCredentialsResponse.setAttributes(attributes);
            externalCredentialsResponse.setExpiration(Timestamp.fromString(gcpAccessTokenResponse.getExpireTime()));
            return externalCredentialsResponse;

        } catch (Exception ex) {
            throw new ResourceException(ResourceException.FORBIDDEN, ex.getMessage());
        }
    }
}
