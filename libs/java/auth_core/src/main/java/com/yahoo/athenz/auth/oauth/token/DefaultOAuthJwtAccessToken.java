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

import java.util.Date;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of OAuthJwtAccessToken
 */
public class DefaultOAuthJwtAccessToken implements OAuthJwtAccessToken {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOAuthJwtAccessToken.class);
    private final String jwtClientIdClaimName = System.getProperty("security.jwt.claim.client_id.name", OAuthJwtAccessToken.CLAIM_CLIENT_ID);

    protected JWTClaimsSet claimsSet;

    /**
     * Create DefaultOAuthJwtAccessToken access token object
     * @param  claimsSet JWT claims
     */
    public DefaultOAuthJwtAccessToken(JWTClaimsSet claimsSet) {
        this.claimsSet = claimsSet;
    }

    @Override
    public String getSubject() {
        return claimsSet.getSubject();
    }

    @Override
    public String getIssuer() {
        return claimsSet.getIssuer();
    }

    @Override
    public String getAudience() {
        List<String> audiences = claimsSet.getAudience();
        if (audiences == null || audiences.isEmpty()) {
            return null;
        }
        if (audiences.size() == 1) {
            return audiences.get(0);
        } else {
            return audiences.toString();
        }
    }

    @Override
    public List<String> getAudiences() {
        List<String> audiences = claimsSet.getAudience();
        if (audiences == null || audiences.isEmpty()) {
            return null;
        }
        return audiences;
    }

    @Override
    public String getClientId() {
        try {
            return claimsSet.getStringClaim(jwtClientIdClaimName);
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DefaultOAuthJwtAccessToken:getClientId expected data type to be string, err: {}", ex.getMessage());
            }
        }
        return null;
    }

    @Override
    public String getCertificateThumbprint() {
        Map<String, Object> certConf;
        try {
            certConf = (Map<String, Object>) claimsSet.getClaim(OAuthJwtAccessToken.CLAIM_CONFIRM);
            if (certConf == null) {
                return null;
            }
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DefaultOAuthJwtAccessToken:getCertificateThumbprint expected data type to be JSON object, err: {}", ex.getMessage());
            }
            return null;
        }
        return (String) certConf.get(OAuthJwtAccessToken.CLAIM_CONFIRM_X509_HASH);
    }

    @Override
    public String getScope() {
        try {
            return claimsSet.getStringClaim(OAuthJwtAccessToken.CLAIM_SCOPE);
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DefaultOAuthJwtAccessToken:getScope expected data type to be string, err: {}", ex.getMessage());
            }
        }
        return null;
    }

    @Override
    public long getIssuedAt() {
        Date date = claimsSet.getIssueTime();
        if (date == null) {
            return 0L;
        }
        return date.getTime() / 1000; // second
    }

    @Override
    public long getExpiration() {
        Date date = claimsSet.getExpirationTime();
        if (date == null) {
            return 0L;
        }
        return date.getTime() / 1000; // second
    }

    @Override
    public String toString() {
        return claimsSet.toString();
    }

}
