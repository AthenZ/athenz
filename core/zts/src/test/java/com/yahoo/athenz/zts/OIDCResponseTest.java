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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class OIDCResponseTest {

    @Test
    public void testOIDCResponse() {

        OIDCResponse resp1 = new OIDCResponse();
        OIDCResponse resp2 = new OIDCResponse();

        resp1.setLocation("https://localhost:4443/zts");
        resp2.setLocation("https://localhost:4443/zts");

        assertEquals(resp1, resp2);
        assertEquals(resp1, resp1);
        assertNotEquals(null, resp1);
        assertNotEquals("oidcresponse", resp1);

        assertEquals("https://localhost:4443/zts", resp1.getLocation());

        resp2.setLocation("https://localhost:8443/zts");
        assertNotEquals(resp1, resp2);
        resp2.setLocation(null);
        assertNotEquals(resp1, resp2);
        resp2.setLocation("https://localhost:4443/zts");

        assertEquals(resp1, resp2);
    }
}
