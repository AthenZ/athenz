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

import java.util.function.BiFunction;
import com.yahoo.athenz.auth.KeyStore;

/**
 * Default implementation of OAuthJwtAccessTokenParserFactory
 */
public class DefaultOAuthJwtAccessTokenParserFactory implements OAuthJwtAccessTokenParserFactory {

    public static final String SYSTEM_PROP_PREFIX = "athenz.auth.oauth.jwt.parser.";
    public static final String JWKS_URL = "jwks_url";
    public static final BiFunction<String, String, String> GET_PROPERTY =
            (String key, String def) -> System.getProperty(SYSTEM_PROP_PREFIX + key, def);

    @Override
    public OAuthJwtAccessTokenParser create(KeyStore keyStore) throws IllegalArgumentException {
        final String jwksUrl = GET_PROPERTY.apply(JWKS_URL, null);
        return new DefaultOAuthJwtAccessTokenParser(keyStore, jwksUrl);
    }

}
