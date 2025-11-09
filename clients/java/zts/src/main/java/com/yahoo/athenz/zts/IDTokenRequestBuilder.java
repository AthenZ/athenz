/*
 * Copyright The Athenz Authors.
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

import com.yahoo.athenz.auth.util.Crypto;

public class IDTokenRequestBuilder {

    public static final String OPENID_RESPONSE_TYPE_ID_TOKEN = "id_token";

    public static final String OPENID_RESPONSE_OUTPUT_TYPE_JSON = "json";

    final String responseType;
    String clientId;
    String redirectUri;
    String scope;
    String state;
    String keyType;
    String salt = Crypto.randomSalt();
    String outputType = OPENID_RESPONSE_OUTPUT_TYPE_JSON;
    int expiryTime = 0;
    boolean fullArn = false;
    boolean allRolesPresent = false;
    boolean roleInAudtClaim = false;

    /**
     * Set the ID token client id for the id token request.
     * @param clientId the ID token service name
     * @return this builder instance
     */
    public IDTokenRequestBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    /**
     * Set the redirect uri for the id token request.
     * @param redirectUri redirect uri
     * @return this builder instance
     */
    public IDTokenRequestBuilder redirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    /**
     * Set the scope for the id token request.
     * @param scope scope space separated values
     * @return this builder instance
     */
    public IDTokenRequestBuilder scope(String scope) {
        this.scope = scope;
        return this;
    }

    /**
     * Set the state for the id token request.
     * @param state value of the state
     * @return this builder instance
     */
    public IDTokenRequestBuilder state(String state) {
        this.state = state;
        return this;
    }

    /**
     * Set the signature key type for the id token request.
     * @param keyType type of the signing key - RSA or EC
     * @return this builder instance
     */
    public IDTokenRequestBuilder keyType(String keyType) {
        this.keyType = keyType;
        return this;
    }

    /**
     * Set the expiry time for the id token request.
     * @param expiryTime expiry time in seconds (0 for server default)
     * @return this builder instance
     */
    public IDTokenRequestBuilder expiryTime(int expiryTime) {
        this.expiryTime = expiryTime;
        return this;
    }

    /**
     * Set whether to return full arn for scope in the id token request.
     * @param fullArn true to use full arns, false otherwise
     * @return this builder instance
     */
    public IDTokenRequestBuilder fullArn(boolean fullArn) {
        this.fullArn = fullArn;
        return this;
    }

    /** 
     * If set to true all scopes must be present in the response
     * otherwise reject the request as invalid
     * @param allRolesPresent true to make sure all scope values are present
     * @return this builder instance
     */
    public IDTokenRequestBuilder allRolesPresent(boolean allRolesPresent) {
        this.allRolesPresent = allRolesPresent;
        return this;
    }

    /**
     * Tells ZTS Server to return the role in the audience claim
     * @param roleInAudtClaim true to return role in audience claim
     * @return this builder instance
     */
    public IDTokenRequestBuilder roleInAudtClaim(boolean roleInAudtClaim) {
        this.roleInAudtClaim = roleInAudtClaim;
        return this;
    }

    /**
     * Set the salt value for the id token request. It defaults to
     * Crypto.randomSalt() value.
     * @param salt value of the salt
     * @return this builder instance
     */
    public IDTokenRequestBuilder salt(String salt) {
        this.salt = salt;
        return this;
    }

    /**
     * Set the response output type value for the id token request. It defaults to json.
     * @param outputType value of the output type
     * @return this builder instance
     */
    public IDTokenRequestBuilder outputType(String outputType) {
        this.outputType = outputType;
        return this;
    }

    /**
     * Get the cache key responding for this request
     * @return cache key
     */

    public String getCacheKey() {

        if (responseType == null || clientId == null || scope == null) {
            return null;
        }

        StringBuilder cacheKey = new StringBuilder(256);
        cacheKey.append("t=");
        cacheKey.append(responseType);

        cacheKey.append(";c=");
        cacheKey.append(clientId);

        cacheKey.append(";s=");
        cacheKey.append(scope);

        if (!ZTSClient.isEmpty(redirectUri)) {
            cacheKey.append(";r=");
            cacheKey.append(redirectUri);
        }

        if (!ZTSClient.isEmpty(state)) {
            cacheKey.append(";a=");
            cacheKey.append(state);
        }

        if (!ZTSClient.isEmpty(keyType)) {
            cacheKey.append(";k=");
            cacheKey.append(keyType);
        }

        if (fullArn) {
            cacheKey.append(";f=true");
        }

        return cacheKey.toString();
    }

    /**
     * Create a new IDTokenRequestBuilder instance.
     * @param responseType the response type (required)
     * @return new builder instance
     */
    public static IDTokenRequestBuilder newBuilder(String responseType) {
        return new IDTokenRequestBuilder(responseType);
    }

    private IDTokenRequestBuilder(String responseType) {
        if (ZTSClient.isEmpty(responseType)) {
            throw new ZTSClientException(ClientResourceException.BAD_REQUEST, "Response Type cannot be empty");
        }
        this.responseType = responseType;
    }
}
