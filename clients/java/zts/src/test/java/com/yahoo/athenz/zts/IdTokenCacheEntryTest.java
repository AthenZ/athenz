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

public class IdTokenCacheEntryTest {

    @Test
    public void testIdTokenCacheEntryConstructor() {
        String token = "test-id-token";
        long expiryTime = System.currentTimeMillis() / 1000 + 3600; // 1 hour from now

        IdTokenCacheEntry entry = new IdTokenCacheEntry(token, expiryTime);

        assertNotNull(entry);
        assertEquals(entry.getIdToken(), token);
    }

    @Test
    public void testGetIdToken() {
        String token1 = "token-1";
        String token2 = "token-2";
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;

        IdTokenCacheEntry entry1 = new IdTokenCacheEntry(token1, expiryTime);
        IdTokenCacheEntry entry2 = new IdTokenCacheEntry(token2, expiryTime);

        assertEquals(entry1.getIdToken(), token1);
        assertEquals(entry2.getIdToken(), token2);
        assertNotEquals(entry1.getIdToken(), entry2.getIdToken());
    }

    @Test
    public void testIsExpiredWithExpirySecondsMinusOne() {
        // When expirySeconds is -1, token is expired if expiryTime <= now
        long now = System.currentTimeMillis() / 1000;
        long futureExpiry = now + 3600; // 1 hour in future
        long pastExpiry = now - 3600; // 1 hour in past

        IdTokenCacheEntry futureEntry = new IdTokenCacheEntry("token", futureExpiry);
        IdTokenCacheEntry pastEntry = new IdTokenCacheEntry("token", pastExpiry);

        // Token with future expiry should not be expired when expirySeconds is -1
        assertFalse(futureEntry.isExpired(-1), "Token with future expiry should not be expired when expirySeconds is -1");

        // Token with past expiry should be expired when expirySeconds is -1
        assertTrue(pastEntry.isExpired(-1), "Token with past expiry should be expired when expirySeconds is -1");

        // Token expiring exactly now should be expired
        IdTokenCacheEntry nowEntry = new IdTokenCacheEntry("token", now);
        assertTrue(nowEntry.isExpired(-1), "Token expiring exactly now should be expired when expirySeconds is -1");
    }

    @Test
    public void testIsExpiredWithPositiveExpirySeconds() {
        long now = System.currentTimeMillis() / 1000;
        long expirySeconds = 400; // 400 seconds
        
        // Token expires in 150 seconds (more than 1/4 of 400 = 100 seconds)
        long futureExpiry = now + 150;
        IdTokenCacheEntry entry1 = new IdTokenCacheEntry("token", futureExpiry);
        assertFalse(entry1.isExpired(expirySeconds), "Token with more than 1/4 time left should not be expired");

        // Token expires in 50 seconds (less than 1/4 of 400 = 100 seconds)
        long nearExpiry = now + 50;
        IdTokenCacheEntry entry2 = new IdTokenCacheEntry("token", nearExpiry);
        assertTrue(entry2.isExpired(expirySeconds), "Token with less than 1/4 time left should be expired");

        // Token already expired
        long pastExpiry = now - 100;
        IdTokenCacheEntry entry3 = new IdTokenCacheEntry("token", pastExpiry);
        assertTrue(entry3.isExpired(expirySeconds), "Already expired token should be expired");
    }

    @Test
    public void testIsExpiredWithZeroExpirySeconds() {
        long now = System.currentTimeMillis() / 1000;
        long futureExpiry = now + 3600;

        IdTokenCacheEntry entry = new IdTokenCacheEntry("token", futureExpiry);
        
        // With 0 expirySeconds, 1/4 is 0, so token should be expired if expiryTime < now + 0
        // Since expiryTime is in future, it should not be expired
        assertFalse(entry.isExpired(0), "Token with future expiry should not be expired with 0 expirySeconds");

        long pastExpiry = now - 100;
        IdTokenCacheEntry pastEntry = new IdTokenCacheEntry("token", pastExpiry);
        assertTrue(pastEntry.isExpired(0), "Already expired token should be expired with 0 expirySeconds");
    }

    @Test
    public void testIsExpiredWithLargeExpirySeconds() {
        long now = System.currentTimeMillis() / 1000;
        long expirySeconds = 3600; // 1 hour (1/4 = 15 minutes)

        // Token expires in 20 minutes (more than 15 minutes)
        long futureExpiry = now + 1200;
        IdTokenCacheEntry entry1 = new IdTokenCacheEntry("token", futureExpiry);
        assertFalse(entry1.isExpired(expirySeconds), "Token with more than 1/4 time left should not be expired");

        // Token expires in 10 minutes (less than 15 minutes)
        long nearExpiry = now + 600;
        IdTokenCacheEntry entry2 = new IdTokenCacheEntry("token", nearExpiry);
        assertTrue(entry2.isExpired(expirySeconds), "Token with less than 1/4 time left should be expired");
    }

    @Test
    public void testIsExpiredTimeProgression() throws InterruptedException {
        long now = System.currentTimeMillis() / 1000;
        long expirySeconds = 400; // 400 seconds total (1/4 = 100 seconds)

        // Create token that expires in 120 seconds (more than 1/4 time = 100 seconds)
        long expiryTime = now + 120;
        IdTokenCacheEntry entry = new IdTokenCacheEntry("token", expiryTime);

        // Initially should not be expired
        assertFalse(entry.isExpired(expirySeconds), "Token should not be expired initially");

        // Wait for time to pass (simulate time progression)
        // After waiting, the remaining time should be less than 1/4
        Thread.sleep(25000); // Wait 25 seconds

        // Now the token should be expired (expires in ~95 seconds, less than 100 seconds)
        assertTrue(entry.isExpired(expirySeconds), "Token should be expired after time passes");
    }

    @Test
    public void testIsExpiredWithNullToken() {
        long expiryTime = System.currentTimeMillis() / 1000 + 3600;
        
        IdTokenCacheEntry entry = new IdTokenCacheEntry(null, expiryTime);
        
        assertNull(entry.getIdToken(), "IdToken should be null");
        assertFalse(entry.isExpired(3600), "Expiry check should work even with null token");
    }

    @Test
    public void testIsExpiredEdgeCases() {
        long now = System.currentTimeMillis() / 1000;

        // Token expiring in 1 second (very short expiry)
        long shortExpiry = now + 1;
        IdTokenCacheEntry shortEntry = new IdTokenCacheEntry("token", shortExpiry);
        assertTrue(shortEntry.isExpired(400), "Token expiring in 1 second should be expired");
    }
}

