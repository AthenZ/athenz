/*
 * Copyright 2020 Verizon Media
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
package com.yahoo.athenz.auth.token.jwts;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;
import static org.testng.Assert.*;

public class JwtsHelperTest {

    @Test
    public void testExtractJwksUri() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\",\"jwks_uri\":\"https://localhost/oauth2/keys\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertEquals(helper.extractJwksUri("localhost", null), "https://localhost/oauth2/keys");
        assertNull(helper.extractJwksUri(null, null));
        assertNull(helper.extractJwksUri("", null));
    }

    @Test
    public void testExtractJwksNullUri() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertNull(helper.extractJwksUri("localhost", null));
    }

    @Test
    public void testExtractJwksEmptyUri() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/token\",\"jwks_uri\":\"\"}");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertTrue(helper.extractJwksUri("localhost", null).isEmpty());
    }

    @Test
    public void testExtractJwksUriNullData() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertNull(helper.extractJwksUri("localhost", null));
    }

    @Test
    public void testExtractJwksUriInvalidData() {

        MockJwtsHelper.setResponseCode(200);
        MockJwtsHelper.setResponseBody("{\"token_endpoint\":\"https://localhost/oauth2/");
        MockJwtsHelper helper = new MockJwtsHelper();

        assertNull(helper.extractJwksUri("localhost", null));
    }

    @Test
    public void testGetSocketFactory() {
        SSLContext sslContext = Mockito.mock(SSLContext.class);
        JwtsHelper helper = new JwtsHelper();
        assertNull(helper.getSocketFactory(sslContext));
    }
}
