/*
 * Copyright 2020 Yahoo Inc.
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
package com.yahoo.athenz.auth.oauth.auth0;

import java.util.LinkedHashMap;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.oauth.token.DefaultOAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.util.AthenzUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.RequiredTypeException;

/**
 * Custom for Auth0 JWT access token format
 */
public class Auth0Jwt extends DefaultOAuthJwtAccessToken {

    private static String claimClientId = "https://myapp.example.com/client_id";
    private static String claimConfirm = "https://myapp.example.com/cnf";
    private static String userDomain = "user";

    /**
     * Create Auth0 JWT access token object
     * @param  jws JWS claims
     */
    public Auth0Jwt(Jws<Claims> jws) {
        super(jws);
    }

    @Override
    public String getSubject() {
        String subject = this.body.getSubject();
        if (subject == null) {
            return null;
        }
        return AthenzUtils.getPrincipalName(Auth0Jwt.userDomain, subject.replace('|', '-'));
    }

    @Override
    public String getClientId() {
        return this.body.get(Auth0Jwt.claimClientId, String.class);
    }

    @Override
    public String getCertificateThumbprint() {
        LinkedHashMap<?, ?> certConf = null;
        try {
            certConf = this.body.get(Auth0Jwt.claimConfirm, LinkedHashMap.class);
            if (certConf == null) {
                return null;
            }
        } catch (RequiredTypeException e) {
            return null;
        }
        return (String) certConf.get(OAuthJwtAccessToken.CLAIM_CONFIRM_X509_HASH);
    }

    /**
     * set the client ID claim
     * @param claimClientId client ID claim
     */
    public static void setClaimClientId(String claimClientId) {
        Auth0Jwt.claimClientId = claimClientId;
    }

    /**
     * set the confirm claim
     * @param claimConfirm confirm claim
     */
    public static void setClaimConfirm(String claimConfirm) {
        Auth0Jwt.claimConfirm = claimConfirm;
    }

    /**
     * set the user domain (user principal format: <user_domain>.<auth0_jwt_subject>)
     * @param userDomain Athenz user domain
     */
    public static void setUserDomain(String userDomain) {
        Auth0Jwt.userDomain = userDomain;
    }

    public static String getClaimClientId() {
        return Auth0Jwt.claimClientId;
    }
    public static String getClaimConfirm() {
        return Auth0Jwt.claimConfirm;
    }
    public static String getUserDomain() {
        return Auth0Jwt.userDomain;
    }

}
