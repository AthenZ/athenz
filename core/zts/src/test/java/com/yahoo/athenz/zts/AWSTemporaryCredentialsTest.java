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

import com.yahoo.rdl.Timestamp;

import static org.testng.Assert.*;

public class AWSTemporaryCredentialsTest {

    @Test
    public void testIdentity() {
        AWSTemporaryCredentials i1 = new AWSTemporaryCredentials();
        AWSTemporaryCredentials i2 = new AWSTemporaryCredentials();

        // set
        i1.setAccessKeyId("key01");
        i1.setSecretAccessKey("test_secret");
        i1.setSessionToken("test_token");
        i1.setExpiration(Timestamp.fromMillis(123456789123L));

        i2.setAccessKeyId("key01");
        i2.setSecretAccessKey("test_secret");
        i2.setSessionToken("test_token");
        i2.setExpiration(Timestamp.fromMillis(123456789123L));

        // getter assertion
        assertEquals(i1.getAccessKeyId(), "key01");
        assertEquals(i1.getSecretAccessKey(), "test_secret");
        assertEquals(i1.getSessionToken(), "test_token");
        assertEquals(i1.getExpiration(), Timestamp.fromMillis(123456789123L));

        assertEquals(i1, i2);
        assertEquals(i1, i1);

        i1.setAccessKeyId("key02");
        assertNotEquals(i2, i1);
        i1.setAccessKeyId(null);
        assertNotEquals(i2, i1);
        i1.setAccessKeyId("key01");
        assertEquals(i2, i1);

        i1.setSecretAccessKey("test_secret1");
        assertNotEquals(i2, i1);
        i1.setSecretAccessKey(null);
        assertNotEquals(i2, i1);
        i1.setSecretAccessKey("test_secret");
        assertEquals(i2, i1);

        i1.setSessionToken("test_token1");
        assertNotEquals(i2, i1);
        i1.setSessionToken(null);
        assertNotEquals(i2, i1);
        i1.setSessionToken("test_token");
        assertEquals(i2, i1);

        i1.setExpiration(Timestamp.fromMillis(123456789124L));
        assertNotEquals(i2, i1);
        i1.setExpiration(null);
        assertNotEquals(i2, i1);
        i1.setExpiration(Timestamp.fromMillis(123456789123L));
        assertEquals(i2, i1);

        assertNotEquals(i2, null);
        assertNotEquals("i1", i1);
    }
}
