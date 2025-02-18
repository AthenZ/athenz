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

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PublicKeyProvider;
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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AccessTokenBody {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenBody.class);

    private static final String KEY_SCOPE = "scope";
    private static final String KEY_GRANT_TYPE = "grant_type";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_PROXY_FOR_PRINCIPAL = "proxy_for_principal";
    private static final String KEY_AUTHORIZATION_DETAILS = "authorization_details";
    private static final String KEY_PROXY_PRINCIPAL_SPIFFE_URIS = "proxy_principal_spiffe_uris";
    private static final String KEY_OPENID_ISSUER = "openid_issuer";
    private static final String KEY_CLIENT_ASSERTION = "client_assertion";
    private static final String KEY_CLIENT_ASSERTION_TYPE = "client_assertion_type";

    private static final String OAUTH_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String OAUTH_GRANT_CREDENTIALS = "client_credentials";

    String grantType = null;
    String scope = null;
    String proxyForPrincipal = null;
    String authzDetails = null;
    String clientAssertion = null;
    String clientAssertionType = null;
    List<String> proxyPrincipalsSpiffeUris = null;
    Principal principal = null;
    int expiryTime = 0;
    boolean useOpenIDIssuer = false;

    public AccessTokenBody(final String body, PublicKeyProvider publicKeyProvider, final String oauth2Issuer) {

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
            }
        }

        // validate the request data

        if (!OAUTH_GRANT_CREDENTIALS.equals(grantType)) {
            throw new IllegalArgumentException("Invalid grant request: " + grantType);
        }

        // we must have scope provided so we know what access
        // the client is looking for

        if (StringUtil.isEmpty(scope)) {
            throw new IllegalArgumentException("Invalid request: no scope provided");
        }

        // if we're provided with a client assertion then we must
        // have a client assertion type as well

        if (!StringUtil.isEmpty(clientAssertion)) {

            if (StringUtil.isEmpty(clientAssertionType)) {
                throw new IllegalArgumentException("Invalid request: no client assertion type provided");
            } else if (!OAUTH_JWT_BEARER.equals(clientAssertionType)) {
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

    public String getGrantType() {
        return grantType;
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
        stringBuilder.append("scope=").append(scope);
        if (expiryTime > 0) {
            stringBuilder.append("&expires_in=").append(expiryTime);
        }
        if (proxyForPrincipal != null) {
            stringBuilder.append("&proxy_for_principal=").append(proxyForPrincipal);
        }
        if (authzDetails != null) {
            stringBuilder.append("&authorization_details=").append(authzDetails);
        }
        if (proxyPrincipalsSpiffeUris != null) {
            stringBuilder.append("&proxy_principal_spiffe_uris=");
            for (String uri : proxyPrincipalsSpiffeUris) {
                stringBuilder.append(uri).append(',');
            }
            stringBuilder.setLength(stringBuilder.length() - 1);
        }

        // make sure any CRLFs are not set to the logger and our log line
        // is limited to 1024 characters

        final String clean = stringBuilder.toString().replace('\n', '_').replace('\r', '_');
        return (clean.length() > 1024) ? clean.substring(0, 1024) : clean;
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
