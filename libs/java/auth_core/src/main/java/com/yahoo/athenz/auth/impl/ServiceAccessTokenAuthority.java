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

package com.yahoo.athenz.auth.impl;

import com.yahoo.athenz.auth.*;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServiceAccessTokenAuthority implements Authority, AuthorityKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(ServiceAccessTokenAuthority.class);

    public static final String ATHENZ_AUTH_CHALLENGE = "Basic realm=\"athenz\"";
    public static final String HTTP_HEADER = "Authorization";
    public static final String HTTP_BEARER_PREFIX = "Bearer ";

    public static final String PROP_OAUTH_ISSUER = "athenz.auth.access_token.oauth_issuer";

    private final String oauth2Issuer;
    private KeyStore keyStore;

    public ServiceAccessTokenAuthority() {
        oauth2Issuer = System.getProperty(PROP_OAUTH_ISSUER, "https://athenz.io");
    }

    @Override
    public String getID() {
        return "Auth-SvcAccessToken";
    }

    @Override
    public void initialize() {
    }

    @Override
    public String getDomain() {
        return null;
    }

    @Override
    public String getHeader() {
        return HTTP_HEADER;
    }

    @Override
    public String getAuthenticateChallenge() {
        return ATHENZ_AUTH_CHALLENGE;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {

        errMsg = errMsg == null ? new StringBuilder(512) : errMsg;

        if (StringUtils.isEmpty(creds)) {
            errMsg.append("AccessTokenAuthority:authenticate: No credentials provided");
            LOG.error(errMsg.toString());
            return null;
        }

        if (!creds.startsWith(HTTP_BEARER_PREFIX)) {
            errMsg.append("AccessTokenAuthority:authenticate: Invalid token: No Bearer prefix");
            LOG.error(errMsg.toString());
            return null;
        }

        OAuth2Token token;
        try {
            token = new OAuth2Token(creds.substring(HTTP_BEARER_PREFIX.length()), keyStore, oauth2Issuer);
        } catch (Exception ex) {
            errMsg.append("AccessTokenAuthority:authenticate: Invalid token: exc=").append(ex.getMessage());
            LOG.error(errMsg.toString());
            return null;
        }

        return SimplePrincipal.create(token.getClientIdDomainName(), token.getClientIdServiceName(),
                creds, token.getIssueTime(), this);
    }

    @Override
    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }
}
