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
    private static final String OAUTH_GRANT_CREDENTIALS = "client_credentials";

    String grantType = null;
    String scope = null;
    String proxyForPrincipal = null;
    String authzDetails = null;
    List<String> proxyPrincipalsSpiffeUris = null;
    int expiryTime = 0;
    boolean useOpenIDIssuer = false;

    public AccessTokenBody(String body) {

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
