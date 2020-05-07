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

import static org.testng.Assert.*;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.oauth.parser.OAuthJwtAccessTokenParser;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessToken;
import com.yahoo.athenz.auth.oauth.token.OAuthJwtAccessTokenException;
import org.testng.annotations.Test;

public class Auth0JwtParserFactoryTest {

    private final ClassLoader classLoader = this.getClass().getClassLoader();
    private final KeyStore baseKeyStore = new KeyStore() {
        @Override
        public String getPublicKey(String domain, String service, String keyId) {
            return null;
        }
    };

    @Test
    public void testAuth0JwtParserFactory() throws OAuthJwtAccessTokenException {
        OAuthJwtAccessTokenParser parser = null;
        Auth0JwtParserFactory factory = new Auth0JwtParserFactory();

        // check internal
        assertThrows(IllegalArgumentException.class, () -> factory.create(null));

        // check default
        parser = factory.create(baseKeyStore);
        assertNotNull(parser);

        String claimClientIdCache = Auth0Jwt.getClaimClientId();
        // default client ID claim
        System.clearProperty("athenz.auth.oauth.jwt.parser.auth0.claim_client_id");
        parser = factory.create(baseKeyStore);
        assertEquals(Auth0Jwt.getClaimClientId(), "https://myapp.example.com/client_id");
        // custom client ID claim
        System.setProperty("athenz.auth.oauth.jwt.parser.auth0.claim_client_id", "https://Auth0JwtParserFactory.test/client_id");
        parser = factory.create(baseKeyStore);
        System.clearProperty("athenz.auth.oauth.jwt.parser.auth0.claim_client_id");
        assertEquals(Auth0Jwt.getClaimClientId(), "https://Auth0JwtParserFactory.test/client_id");
        Auth0Jwt.setClaimClientId(claimClientIdCache); // restore

        String claimConfirmCache = Auth0Jwt.getClaimConfirm();
        // default cnf claim
        System.clearProperty("athenz.auth.oauth.jwt.parser.auth0.claim_confirm");
        parser = factory.create(baseKeyStore);
        assertEquals(Auth0Jwt.getClaimConfirm(), "https://myapp.example.com/cnf");
        // custom cnf claim
        System.setProperty("athenz.auth.oauth.jwt.parser.auth0.claim_confirm", "https://Auth0JwtParserFactory.test/cnf");
        parser = factory.create(baseKeyStore);
        System.clearProperty("athenz.auth.oauth.jwt.parser.auth0.claim_confirm");
        assertEquals(Auth0Jwt.getClaimConfirm(), "https://Auth0JwtParserFactory.test/cnf");
        Auth0Jwt.setClaimConfirm(claimConfirmCache); // restore

        String userDomainCache = Auth0Jwt.getUserDomain();
        // default user domain
        System.clearProperty("athenz.user_domain");
        parser = factory.create(baseKeyStore);
        assertEquals(Auth0Jwt.getUserDomain(), "user");
        // custom user domain
        System.setProperty("athenz.user_domain", "test_user");
        parser = factory.create(baseKeyStore);
        System.clearProperty("athenz.user_domain");
        assertEquals(Auth0Jwt.getUserDomain(), "test_user");
        Auth0Jwt.setUserDomain(userDomainCache); // restore

        // test JWKS URL
        String jwtString = "eyJraWQiOiJjOTk4NmVlMy03YjJhLTRkMjAtYjg2YS0wODM5ODU2ZjI1NDEiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJBdXRoMEp3dFBhcnNlckZhY3RvcnlUZXN0In0.FymtIiPJa_9R3xnHkint7sldcJaVdZvy4Y8ENX1SHh4-4tAfGSRVZThwwJhTuqQT8F2HyN-2fynI_lqv58a095MoNarUlLaFmywrmRnmW98fyrnAYNo-bOB7M_x_xnW8ei77y-kXVViK2k2PWAcLYlRUq3Un8XvO5HnzTpF9GjqZzOKdOpRIGFaDTchQ0Fj-gdfGoWfhhjIV4cFF6mJNaEzxgVaWE_f0gCoXNwM0dcgKAhQb1CzwvVMGaAPdqomgwXTOd_wyjIaLSXqMrv66fomjDxg7Kv99HB7P4suQAJUIRUF5gkcXWDrDUTvRqoWWHUVMH-9wOaYcILCybk3gP1ahIfecF6eaQz8P8mEqMMK-EPk6g2m-Tbybv1HS_-LzvCYDCFES8KtZ2FNUljOWW7eIr9Z6TUXKEr-DTs8tIh_SjNhqLM4d1dmZkNa48aHqjTyNqapj2AjWbyzKPqFxkVrs1IuNqH51ofIkRFZmqsBbwim3Ol_R4H78eim1zhISmiJxNuGdU9hCV0XnFm152t-U51MvFvRadm0Puxfw-uYThet2D42qPzA5vC2qLOLoa7NcvfCPxhPaG-yQNo0bHksJI3vkVCNB4vvJvWa112fbl4-Ds5NFQmIkNovg79MYgFmVBWl9FJ4UaSCH8nqB9nHaHQNFkRBzicGmRDiKu88";
        System.setProperty("athenz.auth.oauth.jwt.parser.jwks_url", this.classLoader.getResource("jwt_jwks.json").toString());
        parser = factory.create(baseKeyStore);
        System.clearProperty("athenz.auth.oauth.jwt.parser.jwks_url");
        OAuthJwtAccessToken token = parser.parse(jwtString);
        assertEquals(token.getIssuer(), "Auth0JwtParserFactoryTest");
    }

}
