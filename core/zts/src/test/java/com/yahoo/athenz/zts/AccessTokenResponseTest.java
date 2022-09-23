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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class AccessTokenResponseTest {

    @Test
    public void testAccessTokenResponse() {

        AccessTokenResponse key1 = new AccessTokenResponse();
        AccessTokenResponse key2 = new AccessTokenResponse();

        key1.setToken_type("type");
        key1.setExpires_in(10000);
        key1.setAccess_token("access");
        key1.setRefresh_token("refresh");
        key1.setScope("scope");
        key1.setId_token("id");

        key2.setToken_type("type");
        key2.setExpires_in(10000);
        key2.setAccess_token("access");
        key2.setRefresh_token("refresh");
        key2.setScope("scope");
        key2.setId_token("id");

        assertEquals(key1, key2);
        assertEquals(key1, key1);
        assertNotEquals(null, key1);
        assertNotEquals("accesstokenresponse", key1);

        assertEquals("type", key1.getToken_type());
        assertEquals(new Integer(10000), key1.getExpires_in());
        assertEquals("access", key1.getAccess_token());
        assertEquals("refresh", key1.getRefresh_token());
        assertEquals("scope", key1.getScope());
        assertEquals("id", key1.getId_token());

        key2.setToken_type("type2");
        assertNotEquals(key1, key2);
        key2.setToken_type(null);
        assertNotEquals(key1, key2);
        key2.setToken_type("type");

        key2.setExpires_in(10001);
        assertNotEquals(key1, key2);
        key2.setExpires_in(null);
        assertNotEquals(key1, key2);
        key2.setExpires_in(10000);

        key2.setId_token("id2");
        assertNotEquals(key1, key2);
        key2.setId_token(null);
        assertNotEquals(key1, key2);
        key2.setId_token("id");

        key2.setAccess_token("access2");
        assertNotEquals(key1, key2);
        key2.setAccess_token(null);
        assertNotEquals(key1, key2);
        key2.setAccess_token("access");

        key2.setRefresh_token("refresh2");
        assertNotEquals(key1, key2);
        key2.setRefresh_token(null);
        assertNotEquals(key1, key2);
        key2.setRefresh_token("refresh");

        key2.setScope("scope2");
        assertNotEquals(key1, key2);
        key2.setScope(null);
        assertNotEquals(key1, key2);
        key2.setScope("scope");
    }
}
