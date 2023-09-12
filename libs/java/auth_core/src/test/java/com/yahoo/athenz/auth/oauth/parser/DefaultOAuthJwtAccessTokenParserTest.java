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
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.oauth.token.DefaultOAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;

public class DefaultOAuthJwtAccessTokenParserTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final KeyStore baseKeyStore = (domain, service, keyId) -> null;

    @Test
    public void testDefaultOAuthJwtAccessTokenParser() {
        BiFunction<Field, DefaultOAuthJwtAccessTokenParser, Object> getFieldValue = (f, object) -> {
            try {
                f.setAccessible(true);
                return f.get(object);
            } catch (IllegalArgumentException | IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        };

        // new error
        assertThrows(IllegalArgumentException.class, () -> new DefaultOAuthJwtAccessTokenParser(null, null));

        // new with null/empty URL
        DefaultOAuthJwtAccessTokenParser parser = new DefaultOAuthJwtAccessTokenParser(baseKeyStore, null);
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "parser":
                    assertNotNull(getFieldValue.apply(f, parser));
                    break;
            }
        }
        parser = new DefaultOAuthJwtAccessTokenParser(baseKeyStore, "");
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "parser":
                    assertNotNull(getFieldValue.apply(f, parser));
                    break;
            }
        }

        // new with file JWKS
        parser = new DefaultOAuthJwtAccessTokenParser(baseKeyStore, this.classLoader.getResource("jwt_jwks.json").toString());
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "parser":
                    assertNotNull(getFieldValue.apply(f, parser));
                    break;
            }
        }

        // new with HTTPS JWKS
        parser = new DefaultOAuthJwtAccessTokenParser(baseKeyStore, "https://athenz-oauth-example.auth0.com/.well-known/jwks.json");
        assertNotNull(parser);
        for (Field f : parser.getClass().getDeclaredFields()) {
            switch (f.getName()) {
                case "parser":
                    assertNotNull(getFieldValue.apply(f, parser));
                    break;
            }
        }
    }

    @Test
    @SuppressWarnings("rawtypes")
    public void testParse() throws Exception {
        // mock internal parser
        DefaultOAuthJwtAccessTokenParser parser = new DefaultOAuthJwtAccessTokenParser(baseKeyStore, this.classLoader.getResource("jwt_jwks.json").toString());
        JwtParser jwtParserMock = Mockito.mock(JwtParser.class);
        Field f = parser.getClass().getDeclaredField("parser");
        f.setAccessible(true);
        f.set(parser, jwtParserMock);

        // parse error
        Mockito.when(jwtParserMock.parseClaimsJws(null)).thenThrow(new NullPointerException());
        assertThrows(OAuthJwtAccessTokenException.class, () -> parser.parse(null));

        // parse success
        String jwtString = "dummy-jwt-string";
        Jws<Claims> jws = new Jws<>() {
            public JwsHeader getHeader() {
                return null;
            }

            public Claims getBody() {
                return null;
            }

            @Override
            public String getSignature() {
                return "dummy-jwt-signature";
            }
        };
        Mockito.when(jwtParserMock.parseClaimsJws(jwtString)).thenReturn(jws);
        OAuthJwtAccessToken token = parser.parse(jwtString);
        assertNotNull(token);
        assertTrue(token instanceof DefaultOAuthJwtAccessToken);
        assertEquals(token.getSignature(), "dummy-jwt-signature");
    }

}
