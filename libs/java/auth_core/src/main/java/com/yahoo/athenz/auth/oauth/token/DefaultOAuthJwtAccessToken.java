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
package com.yahoo.athenz.auth.oauth.token;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.RequiredTypeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of OAuthJwtAccessToken
 */
public class DefaultOAuthJwtAccessToken implements OAuthJwtAccessToken {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOAuthJwtAccessToken.class);

    protected Claims body;
    protected String signature;

    /**
     * Create DefaultOAuthJwtAccessToken access token object
     * @param  jws JWS claims
     */
    public DefaultOAuthJwtAccessToken(Jws<Claims> jws) {
        this.body = jws.getBody();
        this.signature = jws.getSignature();
    }

    @Override
    public String getSubject() {
        return this.body.getSubject();
    }

    @Override
    public String getIssuer() {
        return this.body.getIssuer();
    }

    @Override
    public String getAudience() {
        // aud can be string or an array of strings.
        return this.body.getAudience();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> getAudiences() {
        // https://tools.ietf.org/html/rfc7519#page-9
        List<String> audiences;
        try {
            // returns null if not found
            audiences = this.body.get(Claims.AUDIENCE, ArrayList.class);
        } catch (RequiredTypeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DefaultOAuthJwtAccessToken:getAudiences treat audience as string, err: {}", e.getMessage());
            }
            // found but class mismatch
            audiences = Arrays.asList(this.body.getAudience());
        }
        return audiences;
    }

    @Override
    public String getClientId() {
        return this.body.get(OAuthJwtAccessToken.CLAIM_CLIENT_ID, String.class);
    }

    @Override
    public String getCertificateThumbprint() {
        // https://github.com/jwtk/jjwt/issues/404, custom model class not supported
        LinkedHashMap<?, ?> certConf;
        try {
            certConf = this.body.get(OAuthJwtAccessToken.CLAIM_CONFIRM, LinkedHashMap.class);
            if (certConf == null) {
                return null;
            }
        } catch (RequiredTypeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DefaultOAuthJwtAccessToken:getCertificateThumbprint expected data type to be JSON object, err: {}", e.getMessage());
            }
            return null;
        }
        return (String) certConf.get(OAuthJwtAccessToken.CLAIM_CONFIRM_X509_HASH);
    }

    @Override
    public String getScope() {
        return this.body.get(OAuthJwtAccessToken.CLAIM_SCOPE, String.class);
    }

    @Override
    public long getIssuedAt() {
        Date date = this.body.getIssuedAt();
        if (date == null) {
            return 0L;
        }
        return this.body.getIssuedAt().getTime() / 1000; // second
    }

    @Override
    public long getExpiration() {
        Date date = this.body.getExpiration();
        if (date == null) {
            return 0L;
        }
        return this.body.getExpiration().getTime() / 1000; // second
    }

    @Override
    public String getSignature() {
        return this.signature;
    }

    @Override
    public String toString() {
        return this.body.toString();
    }

}
