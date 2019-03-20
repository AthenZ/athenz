/*
 * Copyright 2019 Oath Holdings Inc.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class IdTokenTest {

    @Test
    public void testIdToken() {

        IdToken key1 = new IdToken();
        IdToken key2 = new IdToken();

        List<String> scopes = Collections.singletonList("scope1");

        key1.setVer(1);
        key1.setAud("aud");
        key1.setExp(100001);
        key1.setIat(100000);
        key1.setIss("iss");
        key1.setSub("sub");
        key1.setAcr("acr");
        key1.setAmr("amr");
        key1.setAuth_time(100002L);
        key1.setAzp("azp");
        key1.setNonce("nonce");

        key2.setVer(1);
        key2.setAud("aud");
        key2.setExp(100001);
        key2.setIat(100000);
        key2.setIss("iss");
        key2.setSub("sub");
        key2.setAcr("acr");
        key2.setAmr("amr");
        key2.setAuth_time(100002L);
        key2.setAzp("azp");
        key2.setNonce("nonce");

        assertEquals(key1, key2);
        assertEquals(key1, key1);
        assertNotEquals(null, key1);
        assertNotEquals("accesstoken", key1);

        assertEquals(1, key1.getVer());
        assertEquals("aud", key1.getAud());
        assertEquals(100001, key1.getExp());
        assertEquals(100000, key1.getIat());
        assertEquals("iss", key1.getIss());
        assertEquals("sub", key1.getSub());
        assertEquals("acr", key1.getAcr());
        assertEquals("amr", key1.getAmr());
        assertEquals(100002L, key1.getAuth_time().longValue());
        assertEquals("azp", key1.getAzp());
        assertEquals("nonce", key1.getNonce());

        key2.setVer(2);
        assertNotEquals(key1, key2);
        key2.setVer(1);

        key2.setAcr("acr2");
        assertNotEquals(key1, key2);
        key2.setAcr(null);
        assertNotEquals(key1, key2);
        key2.setAcr("acr");

        key2.setAmr("amr2");
        assertNotEquals(key1, key2);
        key2.setAmr(null);
        assertNotEquals(key1, key2);
        key2.setAmr("amr");

        key2.setAzp("azp2");
        assertNotEquals(key1, key2);
        key2.setAzp(null);
        assertNotEquals(key1, key2);
        key2.setAzp("azp");

        key2.setNonce("nonce2");
        assertNotEquals(key1, key2);
        key2.setNonce(null);
        assertNotEquals(key1, key2);
        key2.setNonce("nonce");

        key2.setAuth_time(100003L);
        assertNotEquals(key1, key2);
        key2.setAuth_time(null);
        assertNotEquals(key1, key2);
        key2.setAuth_time(100002L);

        key2.setAud("aud2");
        assertNotEquals(key1, key2);
        key2.setAud(null);
        assertNotEquals(key1, key2);
        key2.setAud("aud");

        key2.setExp(100002);
        assertNotEquals(key1, key2);
        key2.setExp(100001);

        key2.setIat(100001);
        assertNotEquals(key1, key2);
        key2.setIat(100000);

        key2.setIss("iss2");
        assertNotEquals(key1, key2);
        key2.setIss(null);
        assertNotEquals(key1, key2);
        key2.setIss("iss");

        key2.setSub("sub2");
        assertNotEquals(key1, key2);
        key2.setSub(null);
        assertNotEquals(key1, key2);
        key2.setSub("sub");
    }
}
