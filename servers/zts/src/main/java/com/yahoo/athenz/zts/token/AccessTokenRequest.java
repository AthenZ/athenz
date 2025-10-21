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
package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AccessTokenRequest {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenRequest.class);

    // define types of access token requests we support

    public enum RequestType {
        ACCESS_TOKEN,
        JAG_TOKEN_EXCHANGE,
        JAG_JWT_BEARER
    }

    private static final String KEY_SCOPE = "scope";
    private static final String KEY_GRANT_TYPE = "grant_type";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_PROXY_FOR_PRINCIPAL = "proxy_for_principal";
    private static final String KEY_AUTHORIZATION_DETAILS = "authorization_details";
    private static final String KEY_PROXY_PRINCIPAL_SPIFFE_URIS = "proxy_principal_spiffe_uris";
    private static final String KEY_OPENID_ISSUER = "openid_issuer";
    private static final String KEY_CLIENT_ASSERTION = "client_assertion";
    private static final String KEY_CLIENT_ASSERTION_TYPE = "client_assertion_type";
    private static final String KEY_REQUESTED_TOKEN_TYPE = "requested_token_type";
    private static final String KEY_AUDIENCE = "audience";
    private static final String KEY_RESOURCE = "resource";
    private static final String KEY_SUBJECT_TOKEN = "subject_token";
    private static final String KEY_SUBJECT_TOKEN_TYPE = "subject_token_type";
    private static final String KEY_ASSERTION = "assertion";
    private static final String KEY_ACTOR_TOKEN = "actor_token";
    private static final String KEY_ACTOR_TOKEN_TYPE = "actor_token_type";

    private static final String OAUTH_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final String OAUTH_TOKEN_TYPE_JAG = "urn:ietf:params:oauth:token-type:id-jag";
    private static final String OAUTH_TOKEN_TYPE_ID = "urn:ietf:params:oauth:token-type:id_token";

    private static final String OAUTH_GRANT_CLIENT_CREDENTIALS = "client_credentials";
    private static final String OAUTH_GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String OAUTH_GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    String grantType = null;
    String scope = null;
    String proxyForPrincipal = null;
    String authzDetails = null;
    String clientAssertion = null;
    String clientAssertionType = null;
    String requestedTokenType = null;
    String audience = null;
    String resource = null;
    String subjectToken = null;
    String subjectTokenType = null;
    String assertion = null;
    String actorToken = null;
    String actorTokenType = null;
    List<String> proxyPrincipalsSpiffeUris = null;
    Principal principal = null;
    int expiryTime = 0;
    boolean useOpenIDIssuer = false;
    RequestType requestType;

    public AccessTokenRequest(final String body, KeyStore publicKeyProvider, final String oauth2Issuer) {

        String[] comps = body.split("&");
        for (String comp : comps) {
            int idx = comp.indexOf('=');
            if (idx == -1) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("AccessTokenBody: skipping invalid component (missing separator): {}", comp);
                }
                continue;
            }
            final String key = decodeString(comp.substring(0, idx));
            if (key == null) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("AccessTokenBody: skipping invalid component (null key): {}", comp);
                }
                continue;
            }
            final String value = decodeString(comp.substring(idx + 1));
            if (value == null) {
                continue;
            }
            switch (key) {
                case KEY_GRANT_TYPE:
                    grantType = value.toLowerCase();
                    break;
                case KEY_SCOPE:
                    scope = value.toLowerCase();
                    break;
                case KEY_EXPIRES_IN:
                    expiryTime = ZTSUtils.parseInt(value, 0);
                    break;
                case KEY_PROXY_FOR_PRINCIPAL:
                    proxyForPrincipal = value.toLowerCase();
                    break;
                case KEY_AUTHORIZATION_DETAILS:
                    authzDetails = value;
                    break;
                case KEY_PROXY_PRINCIPAL_SPIFFE_URIS:
                    proxyPrincipalsSpiffeUris = getProxyPrincipalSpiffeUris(value.toLowerCase());
                    break;
                case KEY_OPENID_ISSUER:
                    useOpenIDIssuer = Boolean.parseBoolean(value);
                    break;
                case KEY_CLIENT_ASSERTION_TYPE:
                    clientAssertionType = value.toLowerCase();
                    break;
                case KEY_CLIENT_ASSERTION:
                    clientAssertion = value;
                    break;
                case KEY_REQUESTED_TOKEN_TYPE:
                    requestedTokenType = value.toLowerCase();
                    break;
                case KEY_AUDIENCE:
                    audience = value;
                    break;
                case KEY_RESOURCE:
                    resource = value;
                    break;
                case KEY_SUBJECT_TOKEN:
                    subjectToken = value;
                    break;
                case KEY_SUBJECT_TOKEN_TYPE:
                    subjectTokenType = value.toLowerCase();
                    break;
                case KEY_ASSERTION:
                    assertion = value;
                    break;
                case KEY_ACTOR_TOKEN:
                    actorToken = value;
                    break;
                case KEY_ACTOR_TOKEN_TYPE:
                    actorTokenType = value.toLowerCase();
                    break;
            }
        }

        // validate the request data

        if (StringUtil.isEmpty(grantType)) {
            throw new IllegalArgumentException("Invalid request: no grant type provided");
        }

        switch (grantType) {

            case OAUTH_GRANT_CLIENT_CREDENTIALS:

                // RFC 6749 access token request

                requestType = RequestType.ACCESS_TOKEN;
                validateAccessTokenRequest(publicKeyProvider, oauth2Issuer);

                break;

            case OAUTH_GRANT_TOKEN_EXCHANGE:

                // Identity Assertion Authorization Grant
                // https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/

                requestType = RequestType.JAG_TOKEN_EXCHANGE;
                validateTokenExchangeRequest();
                break;

            case OAUTH_GRANT_JWT_BEARER:

                // Identity Assertion Authorization Grant
                // https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/

                requestType = RequestType.JAG_JWT_BEARER;
                validateJWTBearerRequest();
                break;

            default:
                throw new IllegalArgumentException("Invalid grant request: " + grantType);
        }
    }

    void validateAccessTokenRequest(KeyStore publicKeyProvider, final String oauth2Issuer) {

        // even though scope is optional in RFC 6749, because we're a multi-tenant
        // service and we have no other way of identifying what access the client
        // is looking for, we'll make the scope mandatory.

        if (StringUtil.isEmpty(scope)) {
            throw new IllegalArgumentException("Invalid request: no scope provided");
        }

        // if we're provided with a client assertion then we must
        // have a client assertion type as well

        if (!StringUtil.isEmpty(clientAssertion)) {

            if (StringUtil.isEmpty(clientAssertionType)) {
                throw new IllegalArgumentException("Invalid request: no client assertion type provided");
            } else if (!OAUTH_ASSERTION_TYPE_JWT_BEARER.equals(clientAssertionType)) {
                throw new IllegalArgumentException("Invalid client assertion type: " + clientAssertionType);
            }

            // now let's check if we have a valid client assertion
            // token provided and, if yes, generate our principal object

            try {
                OAuth2Token token = new OAuth2Token(clientAssertion, publicKeyProvider, oauth2Issuer);
                principal = SimplePrincipal.create(token.getClientIdDomainName(),
                        token.getClientIdServiceName(), clientAssertion, token.getIssueTime(), null);
            } catch (Exception ex) {
                throw new IllegalArgumentException("Invalid client assertion: " + ex.getMessage());
            }
        }
    }

    void validateTokenExchangeRequest() {

        // we must have a requested token type

        if (!OAUTH_TOKEN_TYPE_JAG.equals(requestedTokenType)) {
            throw new IllegalArgumentException("Invalid requested token type: " + requestedTokenType);
        }

        // we must have audience specified

        if (StringUtil.isEmpty(audience)) {
            throw new IllegalArgumentException("Invalid request: no audience provided");
        }

        // for token exchange requests we must have subject token and type.
        // currently we're only supporting id tokens as subject tokens so
        // we'll validate accordingly. the actor_token and actor_token_type
        // are optional and not used in the ID Token Authz Grant spec.

        if (StringUtil.isEmpty(subjectToken)) {
            throw new IllegalArgumentException("Invalid request: no subject token provided");
        }
        if (!OAUTH_TOKEN_TYPE_ID.equals(subjectTokenType)) {
            throw new IllegalArgumentException("Invalid subject token type: " + subjectTokenType);
        }
    }

    void validateJWTBearerRequest() {

        // the only required attribute is assertion

        if (StringUtil.isEmpty(assertion)) {
            throw new IllegalArgumentException("Invalid request: no assertion provided");
        }
    }

    public String getActorToken() {
        return actorToken;
    }

    public String getActorTokenType() {
        return actorTokenType;
    }

    public RequestType getRequestType() {
        return requestType;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getClientAssertion() {
        return clientAssertion;
    }

    public String getClientAssertionType() {
        return clientAssertionType;
    }

    public String getRequestedTokenType() {
        return requestedTokenType;
    }

    public String getAudience() {
        return audience;
    }

    public String getResource() {
        return resource;
    }

    public String getSubjectToken() {
        return subjectToken;
    }

    public String getSubjectTokenType() {
        return subjectTokenType;
    }

    public String getAssertion() {
        return assertion;
    }

    public String getScope() {
        return scope;
    }

    public String getProxyForPrincipal() {
        return proxyForPrincipal;
    }

    public String getAuthzDetails() {
        return authzDetails;
    }

    public List<String> getProxyPrincipalsSpiffeUris() {
        return proxyPrincipalsSpiffeUris;
    }

    public int getExpiryTime() {
        return expiryTime;
    }

    public boolean isUseOpenIDIssuer() {
        return useOpenIDIssuer;
    }

    public Principal getPrincipal() {
        return principal;
    }

    public String getQueryLogData() {

        StringBuilder stringBuilder = new StringBuilder();
        if (!StringUtil.isEmpty(scope)) {
            stringBuilder.append("scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }
        if (expiryTime > 0) {
            stringBuilder.append("&expires_in=").append(expiryTime);
        }
        if (!StringUtil.isEmpty(proxyForPrincipal)) {
            stringBuilder.append("&proxy_for_principal=").append(URLEncoder.encode(proxyForPrincipal, StandardCharsets.UTF_8));
        }
        if (!StringUtil.isEmpty(authzDetails)) {
            stringBuilder.append("&authorization_details=").append(URLEncoder.encode(authzDetails, StandardCharsets.UTF_8));
        }
        if (proxyPrincipalsSpiffeUris != null && !proxyPrincipalsSpiffeUris.isEmpty()) {
            stringBuilder.append("&proxy_principal_spiffe_uris=");
            for (String uri : proxyPrincipalsSpiffeUris) {
                stringBuilder.append(URLEncoder.encode(uri, StandardCharsets.UTF_8)).append(',');
            }
            stringBuilder.setLength(stringBuilder.length() - 1);
        }

        // make sure our log line is limited to 1024 characters
        // the data is already url encoded

        stringBuilder.setLength(Math.min(stringBuilder.length(), 1024));
        return stringBuilder.toString();
    }

    String decodeString(final String encodedString) {
        try {
            return URLDecoder.decode(encodedString, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            LOGGER.error("Unable to decode: {}, error: {}", encodedString, ex.getMessage());
            return null;
        }
    }

    List<String> getProxyPrincipalSpiffeUris(final String proxyPrincipalSpiffeUris) {

        if (proxyPrincipalSpiffeUris.isEmpty()) {
            return null;
        }

        List<String> uris = Stream.of(proxyPrincipalSpiffeUris.split(","))
                .map(String::trim)
                .collect(Collectors.toList());

        // verify that all values are valid spiffe uris structurally

        for (String uri : uris) {
            if (!uri.startsWith(ZTSConsts.ZTS_CERT_SPIFFE_URI)) {
                throw new IllegalArgumentException("Invalid spiffe uri specified: " + uri);
            }

            try {
                new URI(uri);
            } catch (URISyntaxException ex) {
                throw new IllegalArgumentException("Invalid spiffe uri specified: " + uri);
            }
        }

        return uris;
    }
}
