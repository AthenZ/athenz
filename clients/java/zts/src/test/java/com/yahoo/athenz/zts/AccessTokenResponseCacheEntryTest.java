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

public class AccessTokenResponseCacheEntryTest {

    @Test
    public void testAccessTokenResponseCacheEntry() throws InterruptedException {

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setExpires_in(100);
        tokenResponse.setScope("scope");
        tokenResponse.setRefresh_token("refresh");
        tokenResponse.setToken_type("Bearer");
        tokenResponse.setId_token("id");
        tokenResponse.setAccess_token("access");

        AccessTokenResponseCacheEntry entry = new AccessTokenResponseCacheEntry(tokenResponse);

        Thread.sleep(1000);

        AccessTokenResponse response = entry.accessTokenResponse();
        assertEquals("scope", response.getScope());
        assertEquals("refresh", response.getRefresh_token());
        assertEquals("Bearer", response.getToken_type());
        assertEquals("id", response.getId_token());
        assertEquals("access", response.getAccess_token());

        int expiry = response.getExpires_in();
        assertTrue(expiry < 100, response.getExpires_in().toString());
    }

    @Test
    public void testAccessTokenResponseCacheEntryIsExpired() throws InterruptedException {

        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setExpires_in(100);

        AccessTokenResponseCacheEntry entry = new AccessTokenResponseCacheEntry(tokenResponse);
        assertFalse(entry.isExpired(100));
        assertFalse(entry.isExpired(200));
        assertFalse(entry.isExpired(-1));
        assertFalse(entry.isExpired(0));
        assertTrue(entry.isExpired(500));

        AccessTokenResponse tokenResponse2 = new AccessTokenResponse();
        tokenResponse2.setExpires_in(1);

        AccessTokenResponseCacheEntry entry2 = new AccessTokenResponseCacheEntry(tokenResponse2);
        Thread.sleep(2000);

        assertTrue(entry2.isExpired(100));
        assertTrue(entry2.isExpired(200));
        assertTrue(entry2.isExpired(-1));
        assertTrue(entry2.isExpired(500));
        assertTrue(entry2.isExpired(0));

        AccessTokenResponse tokenResponse3 = new AccessTokenResponse();
        tokenResponse3.setExpires_in(4);

        AccessTokenResponseCacheEntry entry3 = new AccessTokenResponseCacheEntry(tokenResponse3);
        Thread.sleep(2000);

        assertFalse(entry3.isExpired(4));
        assertFalse(entry3.isExpired(0));

        Thread.sleep(2000);

        assertTrue(entry3.isExpired(4));
        assertTrue(entry3.isExpired(0));
    }
}
