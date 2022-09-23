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
package com.yahoo.athenz.auth.token.jwts;

import org.testng.annotations.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static org.testng.Assert.*;

public class TestKey {

    @Test
    public void testRSAKey() throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        Key key = new Key();
        key.setKid("0");
        key.setAlg("RS256");
        key.setKty("RSA");
        key.setUse("sig");
        key.setE("AQAB");
        key.setN("AMV3cnZXxYJL-A0TYY8Fy245HKSOBCYt9atNAUQVtbEwx9QaZGj8moYIe4nXgx72Ktwg0Gruh8sS7GQLBizCXg7fCk62sDV_MZINnwON9gsKbxxgn9mLFeYSaatUzk-VRphDoHNIBC-qeDtYnZhsHYcV9Jp0GPkLNquhN1TXA7gT");

        assertNotNull(key.getPublicKey());

        assertEquals("0", key.getKid());
        assertEquals("RS256", key.getAlg());
        assertEquals("RSA", key.getKty());
        assertEquals("sig", key.getUse());
        assertEquals("AQAB", key.getE());
        assertEquals("AMV3cnZXxYJL-A0TYY8Fy245HKSOBCYt9atNAUQVtbEwx9QaZGj8moYIe4nXgx72Ktwg0Gruh8sS7GQLBizCXg7fCk62sDV_MZINnwON9gsKbxxgn9mLFeYSaatUzk-VRphDoHNIBC-qeDtYnZhsHYcV9Jp0GPkLNquhN1TXA7gT", key.getN());
    }

    @Test
    public void testECKey() throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeySpecException {
        Key key = new Key();
        key.setKid("eckey1");
        key.setAlg("ES256");
        key.setKty("EC");
        key.setUse("sig");
        key.setCrv("prime256v1");
        key.setX("AI0x6wEUk5T0hslaT83DNVy5r98XnG7HAjQynjCrcdCe");
        key.setY("ATdV2ebpefqBli_SXZwvL3-7OiD3MTryGbR-zRSFZ_s=");

        assertNotNull(key.getPublicKey());

        assertEquals("eckey1", key.getKid());
        assertEquals("ES256", key.getAlg());
        assertEquals("EC", key.getKty());
        assertEquals("sig", key.getUse());
        assertEquals("prime256v1", key.getCrv());
        assertEquals("AI0x6wEUk5T0hslaT83DNVy5r98XnG7HAjQynjCrcdCe", key.getX());
        assertEquals("ATdV2ebpefqBli_SXZwvL3-7OiD3MTryGbR-zRSFZ_s=", key.getY());
    }

    @Test
    public void testUnknownKey() {

        Key key = new Key();
        key.setKty("ATHENZ");

        try {
            key.getPublicKey();
            fail();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException ex) {
            assertTrue(ex instanceof NoSuchAlgorithmException);
        }
    }
}
