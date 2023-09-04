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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import org.testng.annotations.Test;

public class DefaultOAuthJwtAccessTokenParserFactoryTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final KeyStore baseKeyStore = (domain, service, keyId) -> null;

    @Test
    public void testCreate() throws OAuthJwtAccessTokenException {
        DefaultOAuthJwtAccessTokenParserFactory factory = new DefaultOAuthJwtAccessTokenParserFactory();

        // check internal
        assertThrows(IllegalArgumentException.class, () -> factory.create(null));

        // check default
        OAuthJwtAccessTokenParser parser = factory.create(baseKeyStore);
        assertNotNull(parser);

        // check custom property
        String jwtString = "eyJraWQiOiJjOTk4NmVlMy03YjJhLTRkMjAtYjg2YS0wODM5ODU2ZjI1NDEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJEZWZhdWx0T0F1dGhKd3RBY2Nlc3NUb2tlblBhcnNlckZhY3RvcnlUZXN0In0.UalqjyBTDNnEqA0NaOeOhTn_H96vFo9TsCTq58r1YT2p5Hf3xjZLn25puWjcoGZOp1N2xBrvKwmcysHtib5Gq70ulBV7zQXHVzoLB56Ey2LDJJ3QH5sejPCXuapu2i21hSp4PEVvqndULdMipcFYngN97uISrwj-cki8XVgEQDs3OiuHNpyLPYHbCOrbncU9cy29K7l1wYS9gG_OYUB_gy0vdQDhbdbtWs6iwYWQZ3UWJcLp_j1hZyeRhmrSeAmHEBUa8mZs8EuySd3cxUYtV5qje_GPQ47BP2sFWSM6an4Gw6llSWp395O9zJPHRwcqSeIop_wV9Lb7C7v1pRDQDGDsSXH4UbxvEw-Yb0fg4jos3z2cLtk8NR4qzLCVnzHt1uD9QpzB3dXNB22nn8coZ0ay78lMahje6xw162pyjWZUD2YrRpPxUgngdsVJEN-DBQzKQyieHWTWMEgZ2uUsXtPKTKYcW9XfHSXE7gEQwNP9Qz03oP4bz9oP1aLpeQIMQ790NsMfSOv3yRpH5RswZ5rd9NJZgH-n57AlS8Oqz1-wIwTehGdnRlEveU0xoVfuQOonooPHACXA0DR2pV-zo6VT4BOLUMmhU8-TDvP05VXC-maNljjjtL4H7pX6ob9eLTAbj96RqHOkey89WwgKlS1a6LnoMRxcuVJPPmcerdY";
        System.setProperty("athenz.auth.oauth.jwt.parser.jwks_url", this.classLoader.getResource("jwt_jwks.json").toString());
        parser = factory.create(baseKeyStore);
        System.clearProperty("athenz.auth.oauth.jwt.parser.jwks_url");
        OAuthJwtAccessToken token = parser.parse(jwtString);
        assertEquals(token.getIssuer(), "DefaultOAuthJwtAccessTokenParserFactoryTest");
    }

}
