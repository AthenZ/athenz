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

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.util.Crypto;
import org.apache.commons.codec.digest.DigestUtils;

import javax.net.ssl.SSLContext;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

public class OAuthTokenRequestBuilder {

    public static final String OAUTH_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public static final String OAUTH_TOKEN_TYPE_JAG = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String OAUTH_TOKEN_TYPE_ID = "urn:ietf:params:oauth:token-type:id_token";

    public static final String OAUTH_GRANT_CLIENT_CREDENTIALS = "client_credentials";
    public static final String OAUTH_GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String OAUTH_GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    final String grantType;
    List<String> roleNames;
    String domainName;
    String idTokenServiceName;
    String proxyForPrincipal;
    String authorizationDetails;
    String proxyPrincipalSpiffeUris;
    String clientAssertionType;
    String clientAssertion;
    String requestedTokenType;
    String audience;
    String resource;
    String subjectToken;
    String subjectTokenType;
    String assertion;
    String actorToken;
    String actorTokenType;
    long expiryTime = 0;
    boolean openIdIssuer = false;
    ServiceIdentityProvider clientAssertionProvider = null;

    /**
     * Set the list of role names for the access token request.
     * @param roleNames list of role names
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder roleNames(List<String> roleNames) {
        this.roleNames = roleNames;
        return this;
    }

    /**
     * Set the ID token service name for the access token request.
     * @param idTokenServiceName the ID token service name
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder idTokenServiceName(String idTokenServiceName) {
        this.idTokenServiceName = idTokenServiceName;
        return this;
    }

    /**
     * Set the proxy for principal for the access token request.
     * @param proxyForPrincipal the proxy for principal
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder proxyForPrincipal(String proxyForPrincipal) {
        this.proxyForPrincipal = proxyForPrincipal;
        return this;
    }

    /**
     * Set the authorization details for the access token request.
     * @param authorizationDetails the authorization details
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder authorizationDetails(String authorizationDetails) {
        this.authorizationDetails = authorizationDetails;
        return this;
    }

    /**
     * Set the proxy principal SPIFFE URIs for the access token request.
     * @param proxyPrincipalSpiffeUris the proxy principal SPIFFE URIs
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder proxyPrincipalSpiffeUris(String proxyPrincipalSpiffeUris) {
        this.proxyPrincipalSpiffeUris = proxyPrincipalSpiffeUris;
        return this;
    }

    /**
     * Set the client assertion type for the access token request. If the clientAssertionProvider
     * is specified, then it takes precedence over this field.
     * @param clientAssertionType the client assertion type
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder clientAssertionType(String clientAssertionType) {
        this.clientAssertionType = clientAssertionType;
        return this;
    }

    /**
     * Set the client assertion for the access token request. If the clientAssertionProvider
     * is specified, then it takes precedence over this field.
     * @param clientAssertion the client assertion
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder clientAssertion(String clientAssertion) {
        this.clientAssertion = clientAssertion;
        return this;
    }

    /**
     * Set the client assertion provider for the access token request. If the provider
     * is specified, then it takes precedence over the clientAssertionType and
     * clientAssertion fields.
     * @param clientAssertionProvider the implementation of the ServiceIdentityProvider interface
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder clientAssertionProvider(ServiceIdentityProvider clientAssertionProvider) {
        this.clientAssertionProvider = clientAssertionProvider;
        return this;
    }

    /**
     * Set the expiry time for the access token request.
     * @param expiryTime expiry time in seconds (0 for server default)
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder expiryTime(long expiryTime) {
        this.expiryTime = expiryTime;
        return this;
    }

    /**
     * Set whether to set the configured OpenID issuer for the access token request.
     * @param openIdIssuer true to use the OpenID issuer, false otherwise
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder openIdIssuer(boolean openIdIssuer) {
        this.openIdIssuer = openIdIssuer;
        return this;
    }

    /** 
     * Set the requested token type for the request
     * @param requestedTokenType token type
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder requestedTokenType(String requestedTokenType) {
        this.requestedTokenType = requestedTokenType;
        return this;
    }

    /**
     * Set the audience for the request
     * @param audience audience value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder audience(String audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Set the resource for the request
     * @param resource resource value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder resource(String resource) {
        this.resource = resource;
        return this;
    }

    /**
     * Set the subject token for the request
     * @param subjectToken subject token value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder subjectToken(String subjectToken) {
        this.subjectToken = subjectToken;
        return this;
    }

    /**
     * Set the subject token type for the request
     * @param subjectTokenType subject token value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder subjectTokenType(String subjectTokenType) {
        this.subjectTokenType = subjectTokenType;
        return this;
    }
    
    /**
     * Set the assertion value for the request
     * @param assertion assertion value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder assertion(String assertion) {
        this.assertion = assertion;
        return this;
    }

    /**
     * Set the actor token for the request
     * @param actorToken actor token value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder actorToken(String actorToken) {
        this.actorToken = actorToken;
        return this;
    }

    /**
     * Set the actor token type for the request
     * @param actorTokenType actor token type value
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder actorTokenType(String actorTokenType) {
        this.actorTokenType = actorTokenType;
        return this;
    }

    /**
     * Set the domain name for the request
     * @param domainName request domain name
     * @return this builder instance
     */
    public OAuthTokenRequestBuilder domainName(String domainName) {
        this.domainName = domainName;
        return this;
    }

    /**
     * Get the cache key responding for this request
     * @param principalDomain domain of the principal
     * @param principalService service of the principal
     * @param sslContext ssl context if one is available
     * @return cache key
     */
    public String getCacheKey(final String principalDomain, final String principalService, SSLContext sslContext) {

        // if we don't have a principal domain specified, but we have a ssl context
        // then we're going to use the hash code for our sslcontext as the
        // value for our principal domain. If there is no ssl context, but we
        // have a credential sia provider, then we'll use that

        String keyDomain = principalDomain;
        if (keyDomain == null) {
            if (sslContext != null) {
                keyDomain = sslContext.toString();
            } else if (clientAssertionProvider != null) {
                keyDomain = clientAssertionProvider.toString();
            }
        }

        // before we generate a cache key we need to have a valid domain

        if (keyDomain == null) {
            return null;
        }

        StringBuilder cacheKey = new StringBuilder(256);
        cacheKey.append("p=");
        cacheKey.append(keyDomain);
        if (principalService != null) {
            cacheKey.append(".").append(principalService);
        }

        cacheKey.append(";d=");
        cacheKey.append(domainName);

        if (!ZTSClient.isEmpty(roleNames)) {
            cacheKey.append(";r=");
            cacheKey.append(ZTSClient.multipleRoleKey(roleNames));
        }

        if (!ZTSClient.isEmpty(idTokenServiceName)) {
            cacheKey.append(";o=");
            cacheKey.append(idTokenServiceName);
        }

        if (!ZTSClient.isEmpty(proxyForPrincipal)) {
            cacheKey.append(";u=");
            cacheKey.append(proxyForPrincipal);
        }

        if (!ZTSClient.isEmpty(authorizationDetails)) {
            cacheKey.append(";z=");
            cacheKey.append(Base64.getUrlEncoder().withoutPadding().encodeToString(Crypto.sha256(authorizationDetails)));
        }

        if (!ZTSClient.isEmpty(proxyPrincipalSpiffeUris)) {
            cacheKey.append(";s=");
            cacheKey.append(proxyPrincipalSpiffeUris);
        }

        if (clientAssertionProvider != null) {
            cacheKey.append(";a=");
            cacheKey.append(clientAssertionProvider);
        } else if (!ZTSClient.isEmpty(clientAssertion)) {
            cacheKey.append(";a=");
            cacheKey.append(DigestUtils.md5Hex(clientAssertion));
        }

        return cacheKey.toString();
    }

    /**
     * Generate the body (url form encoded) for the token request
     * @return request body string
     */
    public String getRequestBody() {

        StringBuilder body = new StringBuilder(256);
        body.append("grant_type=").append(URLEncoder.encode(grantType, StandardCharsets.UTF_8));
        if (expiryTime > 0) {
            body.append("&expires_in=").append(expiryTime);
        }

        StringBuilder scope = new StringBuilder(256);
        if (ZTSClient.isEmpty(roleNames)) {
            if (!ZTSClient.isEmpty(domainName)) {
                scope.append(domainName).append(":domain");
            }
        } else {
            for (String role : roleNames) {
                if (scope.length() != 0) {
                    scope.append(' ');
                }
                if (!ZTSClient.isEmpty(domainName)) {
                    scope.append(domainName).append(AuthorityConsts.ROLE_SEP);
                }
                scope.append(role);
            }
        }
        if (!ZTSClient.isEmpty(idTokenServiceName)) {
            scope.append(" openid ");
            if (!ZTSClient.isEmpty(domainName)) {
                scope.append(domainName).append(":service.").append(idTokenServiceName);
            } else {
                scope.append(idTokenServiceName);
            }
        }
        final String scopeStr = scope.toString();
        body.append("&scope=").append(URLEncoder.encode(scopeStr, StandardCharsets.UTF_8));

        if (!ZTSClient.isEmpty(proxyForPrincipal)) {
            body.append("&proxy_for_principal=").append(URLEncoder.encode(proxyForPrincipal, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(authorizationDetails)) {
            body.append("&authorization_details=").append(URLEncoder.encode(authorizationDetails, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(proxyPrincipalSpiffeUris)) {
            body.append("&proxy_principal_spiffe_uris=").append(URLEncoder.encode(proxyPrincipalSpiffeUris, StandardCharsets.UTF_8));
        }

        final String assertionType = clientAssertionProvider == null ?
                clientAssertionType : clientAssertionProvider.getClientAssertionType();
        if (!ZTSClient.isEmpty(assertionType)) {
            body.append("&client_assertion_type=").append(URLEncoder.encode(assertionType, StandardCharsets.UTF_8));
        }

        final String assertionValue = clientAssertionProvider == null ?
                clientAssertion : clientAssertionProvider.getClientAssertionValue();
        if (!ZTSClient.isEmpty(assertionValue)) {
            body.append("&client_assertion=").append(URLEncoder.encode(assertionValue, StandardCharsets.UTF_8));
        }

        if (openIdIssuer) {
            body.append("&openid_issuer=true");
        }

        if (!ZTSClient.isEmpty(requestedTokenType)) {
            body.append("&requested_token_type=").append(URLEncoder.encode(requestedTokenType, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(audience)) {
            body.append("&audience=").append(URLEncoder.encode(audience, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(resource)) {
            body.append("&resource=").append(URLEncoder.encode(resource, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(subjectToken)) {
            body.append("&subject_token=").append(URLEncoder.encode(subjectToken, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(subjectTokenType)) {
            body.append("&subject_token_type=").append(URLEncoder.encode(subjectTokenType, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(assertion)) {
            body.append("&assertion=").append(URLEncoder.encode(assertion, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(actorToken)) {
            body.append("&actor_token=").append(URLEncoder.encode(actorToken, StandardCharsets.UTF_8));
        }

        if (!ZTSClient.isEmpty(actorTokenType)) {
            body.append("&actor_token_type=").append(URLEncoder.encode(actorTokenType, StandardCharsets.UTF_8));
        }

        return body.toString();
    }

    /**
     * Create a new AccessTokenRequestBuilder instance.
     * @param grantType the grant type (required)
     * @return new builder instance
     */
    public static OAuthTokenRequestBuilder newBuilder(String grantType) {
        return new OAuthTokenRequestBuilder(grantType);
    }

    private OAuthTokenRequestBuilder(String grantType) {
        if (ZTSClient.isEmpty(grantType)) {
            throw new ZTSClientException(ClientResourceException.BAD_REQUEST, "Grant Type cannot be empty");
        }
        this.grantType = grantType;
    }
}
