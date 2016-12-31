/**
 * Copyright 2016 Yahoo Inc.
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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import org.testng.annotations.Test;

import com.yahoo.rdl.Timestamp;

public class AWSTemporaryCredentialsTest {

    @Test
    public void testIdentity() {
        AWSTemporaryCredentials i = new AWSTemporaryCredentials();
        AWSTemporaryCredentials i2 = new AWSTemporaryCredentials();

        // set
        i.setAccessKeyId("key01");
        i.setSecretAccessKey("test_secret");
        i.setSessionToken("test_token");
        i.setExpiration(Timestamp.fromMillis(123456789123L));
        i2.setAccessKeyId("key01");
        i2.setSecretAccessKey("test_secret");
        i2.setSessionToken("test_token");

        // getter assertion
        assertEquals(i.getAccessKeyId(), "key01");
        assertEquals(i.getSecretAccessKey(), "test_secret");
        assertEquals(i.getSessionToken(), "test_token");
        assertEquals(i.getExpiration(), Timestamp.fromMillis(123456789123L));

        assertTrue(i.equals(i));
        
        assertFalse(i2.equals(i));
        i2.setSessionToken(null);
        assertFalse(i2.equals(i));
        i2.setSecretAccessKey(null);
        assertFalse(i2.equals(i));
        i2.setAccessKeyId(null);
        assertFalse(i2.equals(i));
        
        assertFalse(i.equals(new String()));

    }

}
