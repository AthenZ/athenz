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
package com.yahoo.athenz.auth.oauth.parser;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.oauth.token.DefaultOAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

/**
 * Default implementation of OAuthJwtAccessTokenParser
 */
public class DefaultOAuthJwtAccessTokenParser implements OAuthJwtAccessTokenParser {

    public static final int ALLOWED_CLOCK_SKEW_SECONDS = 60;

    protected JwtParser parser;

    /**
     * Create parser for DefaultOAuthJwtAccessToken
     * @param  keyStore                 key store get the JWT public keys
     * @param  jwksUrl                  JWKS URL to download the JWT public keys
     * @throws IllegalArgumentException key store or JWKS error
     */
    public DefaultOAuthJwtAccessTokenParser(KeyStore keyStore, String jwksUrl) throws IllegalArgumentException {
        if (keyStore == null) {
            throw new IllegalArgumentException("DefaultOAuthJwtAccessTokenParser: keyStore is null");
        }

        SigningKeyResolver signingKeyResolver = new KeyStoreJwkKeyResolver(keyStore, jwksUrl, null);
        this.parser = Jwts.parserBuilder()
            .setSigningKeyResolver(signingKeyResolver)
            .setAllowedClockSkewSeconds(ALLOWED_CLOCK_SKEW_SECONDS)
            .build();
    }

    @Override
    public OAuthJwtAccessToken parse(String jwtString) throws OAuthJwtAccessTokenException {
        OAuthJwtAccessToken accessToken;
        try {
            Jws<Claims> jws = this.parser.parseClaimsJws(jwtString);
            accessToken = new DefaultOAuthJwtAccessToken(jws);
        } catch (Exception ex) {
            throw new OAuthJwtAccessTokenException(ex);
        }
        return accessToken;
    }

}
