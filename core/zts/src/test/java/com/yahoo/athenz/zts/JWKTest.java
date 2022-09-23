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

public class JWKTest {

    @Test
    public void testJWK() {

        JWK key1 = new JWK();
        JWK key2 = new JWK();

        key1.setUse("use");
        key1.setKid("kid");
        key1.setCrv("crv");
        key1.setAlg("alg");
        key1.setX("x");
        key1.setKty("kty");
        key1.setE("e");
        key1.setN("n");
        key1.setY("y");

        key2.setUse("use");
        key2.setKid("kid");
        key2.setCrv("crv");
        key2.setAlg("alg");
        key2.setX("x");
        key2.setKty("kty");
        key2.setE("e");
        key2.setN("n");
        key2.setY("y");

        assertEquals(key1, key2);
        assertEquals(key1, key1);
        assertNotEquals(null, key1);
        assertNotEquals("jwk", key1);

        //getters
        assertEquals("use", key1.getUse());
        assertEquals("kid", key1.getKid());
        assertEquals("crv", key1.getCrv());
        assertEquals("alg", key1.getAlg());
        assertEquals("x", key1.getX());
        assertEquals("kty", key1.getKty());
        assertEquals("e", key1.getE());
        assertEquals("n", key1.getN());
        assertEquals("y", key1.getY());

        key2.setUse("nomatch");
        assertNotEquals(key2, key1);
        key2.setUse(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setUse("use");

        key2.setKid("nomatch");
        assertNotEquals(key2, key1);
        key2.setKid(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setKid("kid");

        key2.setCrv("nomatch");
        assertNotEquals(key2, key1);
        key2.setCrv(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setCrv("crv");

        key2.setAlg("nomatch");
        assertNotEquals(key2, key1);
        key2.setAlg(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setAlg("alg");

        key2.setX("nomatch");
        assertNotEquals(key2, key1);
        key2.setX(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setX("x");

        key2.setKty("nomatch");
        assertNotEquals(key2, key1);
        key2.setKty(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setKty("kty");

        key2.setE("nomatch");
        assertNotEquals(key2, key1);
        key2.setE(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setE("e");

        key2.setN("nomatch");
        assertNotEquals(key2, key1);
        key2.setN(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setN("n");

        key2.setY("nomatch");
        assertNotEquals(key2, key1);
        key2.setY(null);
        assertNotEquals(key2, key1);
        assertNotEquals(key1, key2);
        key2.setY("y");
    }
}
