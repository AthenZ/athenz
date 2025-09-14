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
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.common.server.external.ExternalCredentialsProvider;
import com.yahoo.athenz.common.server.external.IdTokenSigner;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zts.*;
import com.yahoo.rdl.Timestamp;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

public class GcpTokenProvider implements ExternalCredentialsProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(GcpTokenProvider.class);

    public static final String GCP_STS_TOKEN_URL = "https://sts.googleapis.com/v1/token";
    public static final String GCP_SCOPE_ACTION = "gcp.scope_access";
    public static final String GCP_AUDIENCE_ACTION = "gcp.audience_access";

    public static final String GCP_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String GCP_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    public static final String GCP_ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";

    public static final String GCP_SERVICE_ACCOUNT = "gcpServiceAccount";
    public static final String GCP_TOKEN_SCOPE = "gcpTokenScope";
    public static final String GCP_WORKLOAD_POOL_NAME = "gcpWorkloadPoolName";
    public static final String GCP_WORKLOAD_PROVIDER_NAME = "gcpWorkloadProviderName";
    public static final String GCP_ACCESS_TOKEN = "accessToken";
    public static final String GCP_ID_TOKEN = "token";
    public static final String GCP_PROJECT_ID = "gcpProjectId";
    public static final String GCP_PROJECT_NUMBER = "gcpProjectNumber";
    public static final String GCP_FUNCTION_NAME = "gcpFunctionName";
    public static final String GCP_GENERATE_ACCESS_TOKEN = "generateAccessToken";
    public static final String GCP_GENERATE_ID_TOKEN = "generateIdToken";
    public static final String GCP_AUDIENCE = "gcpAudience";
    public static final String GCP_INCLUDE_EMAIL = "gcpIncludeEmail";
    public static final String GCP_ORG_NUMBER_INCLUDED = "gcpOrganizationNumberIncluded";
    private static final String GCP_DEFAULT_TOKEN_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

    HttpDriver httpDriver;
    Authorizer authorizer;
    ObjectMapper jsonMapper = new ObjectMapper();
    final String defaultWorkloadPoolName;
    final String defaultWorkloadProviderName;

    public GcpTokenProvider() {
        this.httpDriver = new HttpDriver.Builder(null)
                .clientConnectTimeoutMs(3000)
                .clientReadTimeoutMs(10000)
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
            ExternalCredentialsRequest externalCredentialsRequest) throws IOException, ServerResourceException {

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
            throw new ServerResourceException(httpResponse.getStatusCode(), error.getErrorDescription());
        }
        return jsonMapper.readValue(httpResponse.getMessage(), GcpExchangeTokenResponse.class);
    }

    /**
     * Request an access token for the given scope as described in the GCP docs:
     * https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
     */
    ExternalCredentialsResponse getAccessToken(Principal principal, DomainDetails domainDetails,
            final String signedIdToken, ExternalCredentialsRequest externalCredentialsRequest,
            final String gcpServiceAccount, Map<String, String> requestAttributes) throws ServerResourceException {

        // verify that the given principal is authorized for all scopes requested

        final String gcpTokenScope = getRequestAttribute(requestAttributes, GCP_TOKEN_SCOPE, GCP_DEFAULT_TOKEN_SCOPE);
        String[] gcpTokenScopeList = gcpTokenScope.split(" ");
        for (String scopeItem : gcpTokenScopeList) {
            final String resource = domainDetails.getName() + ":" + scopeItem;
            if (!authorizer.access(GCP_SCOPE_ACTION, resource, principal, null)) {
                throw new ServerResourceException(ServerResourceException.FORBIDDEN, "Principal not authorized for configured scope");
            }
        }

        try {
            // first we're going to get our exchange token

            GcpExchangeTokenResponse exchangeTokenResponse = getExchangeToken(domainDetails, signedIdToken, externalCredentialsRequest);

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
                GcpTokenError error = jsonMapper.readValue(httpResponse.getMessage(), GcpTokenError.class);
                throw new ServerResourceException(httpResponse.getStatusCode(), error.getErrorMessage());
            }

            GcpAccessTokenResponse gcpAccessTokenResponse = jsonMapper.readValue(httpResponse.getMessage(), GcpAccessTokenResponse.class);

            ExternalCredentialsResponse externalCredentialsResponse = new ExternalCredentialsResponse();
            Map<String, String> responseAttributes = new HashMap<>();
            responseAttributes.put(GCP_ACCESS_TOKEN, gcpAccessTokenResponse.getAccessToken());
            responseAttributes.put(GCP_PROJECT_ID, domainDetails.getGcpProjectId());
            responseAttributes.put(GCP_PROJECT_NUMBER, domainDetails.getGcpProjectNumber());
            externalCredentialsResponse.setAttributes(responseAttributes);
            externalCredentialsResponse.setExpiration(Timestamp.fromString(gcpAccessTokenResponse.getExpireTime()));
            return externalCredentialsResponse;

        } catch (Exception ex) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, ex.getMessage());
        }
    }

    /**
     * Request an access token for the given scope as described in the GCP docs:
     * https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateIdToken
     */
    ExternalCredentialsResponse getIdToken(Principal principal, DomainDetails domainDetails,
            final String signedIdToken, ExternalCredentialsRequest externalCredentialsRequest,
            final String gcpServiceAccount, Map<String, String> requestAttributes) throws ServerResourceException {

        // verify that the given principal is authorized for all scopes requested

        final String gcpAudience = getRequestAttribute(requestAttributes, GCP_AUDIENCE, null);
        if (StringUtil.isEmpty(gcpAudience)) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, "gcp audience not specified");
        }
        final String resource = domainDetails.getName() + ":" + gcpAudience;
        if (!authorizer.access(GCP_AUDIENCE_ACTION, resource, principal, null)) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, "Principal not authorized for configured audience");
        }

        try {
            // first we're going to get our exchange token

            GcpExchangeTokenResponse exchangeTokenResponse = getExchangeToken(domainDetails, signedIdToken, externalCredentialsRequest);

            GcpIdTokenRequest idTokenRequest = new GcpIdTokenRequest();
            idTokenRequest.setAudience(gcpAudience);
            idTokenRequest.setIncludeEmail(Boolean.parseBoolean(
                    getRequestAttribute(requestAttributes, GCP_INCLUDE_EMAIL, "false")));
            idTokenRequest.setOrganizationNumberIncluded(Boolean.parseBoolean(
                    getRequestAttribute(requestAttributes, GCP_ORG_NUMBER_INCLUDED, "false")));

            final String serviceUrl = String.format("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s@%s.iam.gserviceaccount.com:generateIdToken",
                    gcpServiceAccount, domainDetails.getGcpProjectId());
            final String authorizationHeader = exchangeTokenResponse.getTokenType() + " " + exchangeTokenResponse.getAccessToken();

            HttpPost httpPost = new HttpPost(serviceUrl);
            httpPost.addHeader(HttpHeaders.AUTHORIZATION, authorizationHeader);
            httpPost.setEntity(new StringEntity(jsonMapper.writeValueAsString(idTokenRequest), ContentType.APPLICATION_JSON));

            final HttpDriverResponse httpResponse = httpDriver.doPostHttpResponse(httpPost);
            if (httpResponse.getStatusCode() != HttpStatus.SC_OK) {
                LOGGER.info("error message: request:\n{}\n response:\n{}", jsonMapper.writeValueAsString(idTokenRequest), httpResponse.getMessage());
                GcpTokenError error = jsonMapper.readValue(httpResponse.getMessage(), GcpTokenError.class);
                throw new ServerResourceException(httpResponse.getStatusCode(), error.getErrorMessage());
            }

            GcpIdTokenResponse gcpIdTokenResponse = jsonMapper.readValue(httpResponse.getMessage(), GcpIdTokenResponse.class);

            ExternalCredentialsResponse externalCredentialsResponse = new ExternalCredentialsResponse();
            Map<String, String> responseAttributes = new HashMap<>();
            responseAttributes.put(GCP_ID_TOKEN, gcpIdTokenResponse.getToken());
            responseAttributes.put(GCP_PROJECT_ID, domainDetails.getGcpProjectId());
            responseAttributes.put(GCP_PROJECT_NUMBER, domainDetails.getGcpProjectNumber());
            externalCredentialsResponse.setAttributes(responseAttributes);
            return externalCredentialsResponse;

        } catch (Exception ex) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, ex.getMessage());
        }
    }

    @Override
    public ExternalCredentialsResponse getCredentials(Principal principal, DomainDetails domainDetails,
            List<String> idTokenGroups, IdToken idToken, IdTokenSigner idTokenSigner,
            ExternalCredentialsRequest externalCredentialsRequest) throws ServerResourceException {

        // first make sure that our required components are available and configured

        if (authorizer == null) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, "ZTS authorizer not configured");
        }
        if (StringUtil.isEmpty(domainDetails.getGcpProjectId())) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, "gcp project id not configured for domain");
        }
        if (StringUtil.isEmpty(domainDetails.getGcpProjectNumber())) {
            throw new ServerResourceException(ServerResourceException.FORBIDDEN, "gcp project number not configured for domain");
        }

        Map<String, String> attributes = externalCredentialsRequest.getAttributes();
        final String gcpServiceAccount = getRequestAttribute(attributes, GCP_SERVICE_ACCOUNT, null);
        if (StringUtil.isEmpty(gcpServiceAccount)) {
            throw new ServerResourceException(ServerResourceException.BAD_REQUEST, "missing gcp service account");
        }

        // Set the requested groups as the groups claim in the signed id token

        idToken.setSubject(principal.getFullName());
        idToken.setAudience(externalCredentialsRequest.getClientId());
        idToken.setGroups(idTokenGroups);
        String signedIdToken = idTokenSigner.sign(idToken, null);

        final String gcpFunctionName = getRequestAttribute(attributes, GCP_FUNCTION_NAME, GCP_GENERATE_ACCESS_TOKEN);
        LOGGER.info("GCP Function: {}", gcpFunctionName);
        switch (gcpFunctionName) {
            case GCP_GENERATE_ACCESS_TOKEN:
                return getAccessToken(principal, domainDetails, signedIdToken, externalCredentialsRequest,
                        gcpServiceAccount, attributes);
            case GCP_GENERATE_ID_TOKEN:
                return getIdToken(principal, domainDetails, signedIdToken, externalCredentialsRequest,
                        gcpServiceAccount, attributes);
            default:
                throw new ServerResourceException(ServerResourceException.BAD_REQUEST, "invalid gcp function name");
        }
    }
}
