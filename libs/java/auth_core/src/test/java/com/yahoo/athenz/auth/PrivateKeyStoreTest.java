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
package com.yahoo.athenz.auth;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class PrivateKeyStoreTest {

    @Test
    public void testPrivateKeyStore() {

        PrivateKeyStore keyStore = new PrivateKeyStore() {
        };

        assertEquals("key1".toCharArray(), keyStore.getSecret("jdbc", "key1"));
        assertNull(keyStore.getPrivateKey("service", "host1", null));
        assertNull(keyStore.getPrivateKey("service", "host1", "us-west-2", "rsa"));
    }
}
