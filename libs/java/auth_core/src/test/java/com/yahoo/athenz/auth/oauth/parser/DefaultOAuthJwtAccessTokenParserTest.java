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

import static org.testng.Assert.*;

import java.lang.reflect.Field;
import java.util.function.BiFunction;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.oauth.token.DefaultOAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class DefaultOAuthJwtAccessTokenParserTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test
    public void testDefaultOAuthJwtAccessTokenParser() throws OAuthJwtAccessTokenException {
        BiFunction<Field, DefaultOAuthJwtAccessTokenParser, Object> getFieldValue = (f, object) -> {
            try {
                f.setAccessible(true);
                return f.get(object);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        };

        // new error
        assertThrows(OAuthJwtAccessTokenException.class, () -> new DefaultOAuthJwtAccessTokenParser(null));
        assertThrows(OAuthJwtAccessTokenException.class, () -> new DefaultOAuthJwtAccessTokenParser(""));

        // new with file JWKS
        DefaultOAuthJwtAccessTokenParser parser = new DefaultOAuthJwtAccessTokenParser(classLoader.getResource("jwt_jwks.json").toString());
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            if (f.getName().equals("jwtProcessor")) {
                assertNotNull(getFieldValue.apply(f, parser));
            }
        }

        // new with HTTPS JWKS
        parser = new DefaultOAuthJwtAccessTokenParser("https://athenz-oauth-example.auth0.com/.well-known/jwks.json");
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            if (f.getName().equals("jwtProcessor")) {
                assertNotNull(getFieldValue.apply(f, parser));
            }
        }
    }

    @Test
    @SuppressWarnings("rawtypes")
    public void testParse() throws Exception {
        // mock internal parser
        DefaultOAuthJwtAccessTokenParser parser = new DefaultOAuthJwtAccessTokenParser(classLoader.getResource("jwt_jwks.json").toString());
        ConfigurableJWTProcessor jwtProcessorMock = Mockito.mock(ConfigurableJWTProcessor.class);
        Field f = parser.getClass().getDeclaredField("jwtProcessor");
        f.setAccessible(true);
        f.set(parser, jwtProcessorMock);

        // parse error
        Mockito.when(jwtProcessorMock.process((String) null, null)).thenThrow(new NullPointerException());
        assertThrows(OAuthJwtAccessTokenException.class, () -> parser.parse(null));

        // parse success
        String jwtString = "dummy-jwt-string";
        JWTClaimsSet jws = Mockito.mock(JWTClaimsSet.class);
        Mockito.when(jwtProcessorMock.process(jwtString, null)).thenReturn(jws);
        OAuthJwtAccessToken token = parser.parse(jwtString);
        assertNotNull(token);
        assertTrue(token instanceof DefaultOAuthJwtAccessToken);
    }

}
