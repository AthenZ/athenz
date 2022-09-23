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

public class PublicKeyEntryTest {

    @Test
    public void testRoleToken() {
        PublicKeyEntry pkey1 = new PublicKeyEntry();
        PublicKeyEntry pkey2 = new PublicKeyEntry();

        // set
        pkey1.setKey("key").setId("id");
        pkey2.setKey("key").setId("id");

        // getter
        assertEquals(pkey1.getId(), "id");
        assertEquals(pkey1.getKey(), "key");

        assertEquals(pkey1, pkey1);
        assertEquals(pkey1, pkey2);

        pkey1.setKey(null);
        assertNotEquals(pkey2, pkey1);
        pkey1.setKey("key1");
        assertNotEquals(pkey2, pkey1);
        pkey1.setKey("key");
        assertEquals(pkey2, pkey1);

        pkey1.setId(null);
        assertNotEquals(pkey2, pkey1);
        pkey1.setId("id1");
        assertNotEquals(pkey2, pkey1);
        pkey1.setId("id");
        assertEquals(pkey2, pkey1);

        assertNotEquals(pkey2, null);
        assertNotEquals("", pkey1);
    }
}
