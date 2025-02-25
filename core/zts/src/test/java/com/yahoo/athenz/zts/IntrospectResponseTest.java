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

public class IntrospectResponseTest {

    @Test
    public void testIntrospectResponse() {

        IntrospectResponse resp1 = new IntrospectResponse();
        IntrospectResponse resp2 = new IntrospectResponse();

        resp1.setActive(true);
        resp1.setAud("aud");
        resp1.setClient_id("client-id");
        resp1.setExp(100L);
        resp1.setIat(100L);
        resp1.setIss("iss");
        resp1.setJti("jti");
        resp1.setScope("scope");
        resp1.setSub("sub");
        resp1.setAuth_time(100L);
        resp1.setAuthorization_details("details");
        resp1.setProxy("proxy");
        resp1.setUid("uid");
        resp1.setVer(1);

        resp2.setActive(true);
        resp2.setAud("aud");
        resp2.setClient_id("client-id");
        resp2.setExp(100L);
        resp2.setIat(100L);
        resp2.setIss("iss");
        resp2.setJti("jti");
        resp2.setScope("scope");
        resp2.setSub("sub");
        resp2.setAuth_time(100L);
        resp2.setAuthorization_details("details");
        resp2.setProxy("proxy");
        resp2.setUid("uid");
        resp2.setVer(1);

        assertEquals(resp1, resp2);
        assertEquals(resp1, resp1);
        assertNotEquals(null, resp1);
        assertNotEquals("InstrospectResponse", resp1);

        assertTrue(resp1.getActive());
        assertEquals(resp1.getAud(), "aud");
        assertEquals(resp1.getClient_id(), "client-id");
        assertEquals(resp1.getExp(), 100L);
        assertEquals(resp1.getIat(), 100L);
        assertEquals(resp1.getIss(), "iss");
        assertEquals(resp1.getJti(), "jti");
        assertEquals(resp1.getScope(), "scope");
        assertEquals(resp1.getSub(), "sub");
        assertEquals(resp1.getAuth_time(), 100L);
        assertEquals(resp1.getAuthorization_details(), "details");
        assertEquals(resp1.getProxy(), "proxy");
        assertEquals(resp1.getUid(), "uid");
        assertEquals(resp1.getVer(), 1);

        resp2.setAud("aud2");
        assertNotEquals(resp1, resp2);
        resp2.setAud(null);
        assertNotEquals(resp1, resp2);
        resp2.setAud("aud");

        resp2.setClient_id("client-id2");
        assertNotEquals(resp1, resp2);
        resp2.setClient_id(null);
        assertNotEquals(resp1, resp2);
        resp2.setClient_id("client-id");

        resp2.setExp(200L);
        assertNotEquals(resp1, resp2);
        resp2.setExp(100L);

        resp2.setIat(200L);
        assertNotEquals(resp1, resp2);
        resp2.setIat(100L);

        resp2.setIss("iss2");
        assertNotEquals(resp1, resp2);
        resp2.setIss(null);
        assertNotEquals(resp1, resp2);
        resp2.setIss("iss");

        resp2.setJti("jti2");
        assertNotEquals(resp1, resp2);
        resp2.setJti(null);
        assertNotEquals(resp1, resp2);
        resp2.setJti("jti");

        resp2.setScope("scope2");
        assertNotEquals(resp1, resp2);
        resp2.setScope(null);
        assertNotEquals(resp1, resp2);
        resp2.setScope("scope");

        resp2.setSub("sub2");
        assertNotEquals(resp1, resp2);
        resp2.setSub(null);
        assertNotEquals(resp1, resp2);
        resp2.setSub("sub");

        resp2.setAuth_time(200L);
        assertNotEquals(resp1, resp2);
        resp2.setAuth_time(100L);

        resp2.setAuthorization_details("details2");
        assertNotEquals(resp1, resp2);
        resp2.setAuthorization_details(null);
        assertNotEquals(resp1, resp2);
        resp2.setAuthorization_details("details");

        resp2.setProxy("proxy2");
        assertNotEquals(resp1, resp2);
        resp2.setProxy(null);
        assertNotEquals(resp1, resp2);
        resp2.setProxy("proxy");

        resp2.setUid("uid2");
        assertNotEquals(resp1, resp2);
        resp2.setUid(null);
        assertNotEquals(resp1, resp2);
        resp2.setUid("uid");

        resp2.setVer(2);
        assertNotEquals(resp1, resp2);
        resp2.setVer(1);

        resp2.setActive(false);
        assertNotEquals(resp1, resp2);
        resp2.setActive(true);
    }
}
