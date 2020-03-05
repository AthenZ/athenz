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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.oauth.parser.DefaultOAuthJwtAccessTokenParser;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * Parse Auth0 JWT access token
 */
public class Auth0JwtParser extends DefaultOAuthJwtAccessTokenParser {

    /**
     * Create parser for Auth0Jwt
     * @param  keyStore                 key store get the JWT public keys
     * @param  jwksUrl                  JWKS URL to download the JWT public keys
     * @throws IllegalArgumentException key store or JWKS error
     */
    public Auth0JwtParser(KeyStore keyStore, String jwksUrl) throws IllegalArgumentException {
        super(keyStore, jwksUrl);
    }

    @Override
    public OAuthJwtAccessToken parse(String jwtString) throws OAuthJwtAccessTokenException {
        OAuthJwtAccessToken accessToken = null;
        try {
            Jws<Claims> jws = this.parser.parseClaimsJws(jwtString);
            accessToken = new Auth0Jwt(jws);
        } catch (Exception ex) {
            throw new OAuthJwtAccessTokenException(ex);
        }
        return accessToken;
    }

}
