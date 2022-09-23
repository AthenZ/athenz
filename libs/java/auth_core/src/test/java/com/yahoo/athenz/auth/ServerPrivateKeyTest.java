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

import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.SignatureAlgorithm;
import org.testng.annotations.Test;

import java.io.File;
import java.security.PrivateKey;

import static org.testng.Assert.*;

public class ServerPrivateKeyTest {

    @Test
    public void testServerPrivateKeyRSA() {

        final File rsaPrivateKey = new File("./src/test/resources/unit_test_rsa_private.key");
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);

        ServerPrivateKey key = new ServerPrivateKey(privateKey, "zms.1");
        assertEquals(key.getKey(), privateKey);
        assertEquals(key.getId(), "zms.1");
        assertEquals(key.getAlgorithm(), SignatureAlgorithm.RS256);
    }

    @Test
    public void testServerPrivateKeyEC() {

        final File rsaPrivateKey = new File("./src/test/resources/unit_test_ec_private.key");
        PrivateKey privateKey = Crypto.loadPrivateKey(rsaPrivateKey);

        ServerPrivateKey key = new ServerPrivateKey(privateKey, "zms.2");
        assertEquals(key.getKey(), privateKey);
        assertEquals(key.getId(), "zms.2");
        assertEquals(key.getAlgorithm(), SignatureAlgorithm.ES256);
    }
}
