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
package com.yahoo.athenz.auth.oauth.parser;

import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;

/**
 * OAuth2 JWT access token parser interface
 */
public interface OAuthJwtAccessTokenParser {

    /**
     * Parse encoded JWT string to OAuthJwtAccessToken
     * @param  jwtString                    encoded JWT string
     * @return                              OAuthJwtAccessToken
     * @throws OAuthJwtAccessTokenException parse error
     */
    public OAuthJwtAccessToken parse(String jwtString) throws OAuthJwtAccessTokenException;
}
