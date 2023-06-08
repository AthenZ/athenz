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

package com.yahoo.athenz.zts;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class OIDCResponseTest {

    @Test
    public void testOIDCResponse() {

        OIDCResponse resp1 = new OIDCResponse();
        OIDCResponse resp2 = new OIDCResponse();

        resp1.setId_token("idtoken1");
        resp1.setSuccess(true);
        resp1.setVersion(1);
        resp1.setExpiration_time(1000);
        resp1.setToken_type("id-token");

        resp2.setId_token("idtoken1");
        resp2.setSuccess(true);
        resp2.setVersion(1);
        resp2.setExpiration_time(1000);
        resp2.setToken_type("id-token");

        assertEquals(resp1, resp2);
        assertEquals(resp1, resp1);
        assertNotEquals(null, resp1);
        assertNotEquals("oidcresponse", resp1);

        assertEquals("idtoken1", resp1.getId_token());
        assertTrue(resp1.getSuccess());
        assertEquals(1, resp1.getVersion());
        assertEquals(1000, resp1.getExpiration_time());
        assertEquals("id-token", resp1.getToken_type());

        resp2.setId_token("idtoken2");
        assertNotEquals(resp1, resp2);
        resp2.setId_token(null);
        assertNotEquals(resp1, resp2);
        resp2.setId_token("idtoken1");

        resp2.setToken_type("id-token2");
        assertNotEquals(resp1, resp2);
        resp2.setToken_type(null);
        assertNotEquals(resp1, resp2);
        resp2.setToken_type("id-token");

        resp2.setVersion(2);
        assertNotEquals(resp1, resp2);
        resp2.setVersion(1);

        resp2.setExpiration_time(1001);
        assertNotEquals(resp1, resp2);
        resp2.setExpiration_time(1000);

        resp2.setSuccess(false);
        assertNotEquals(resp1, resp2);
        resp2.setSuccess(true);

        assertEquals(resp1, resp2);
    }
}
