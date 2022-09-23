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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class JWKListTest {

    @Test
    public void testJWKList() {

        JWKList list1 = new JWKList();
        JWKList list2 = new JWKList();

        List<JWK> keys = new ArrayList<>();

        list1.setKeys(keys);
        list2.setKeys(keys);

        assertEquals(list1, list2);
        assertEquals(list1, list1);

        assertNotEquals(null, list1);
        assertNotEquals("jwklist", list1);

        //getters
        assertEquals(keys, list1.getKeys());

        List<JWK> keys2 = new ArrayList<>();
        keys2.add(new JWK());

        list2.setKeys(keys2);
        assertNotEquals(list2, list1);
        list2.setKeys(null);
        assertNotEquals(list2, list1);
        assertNotEquals(list1, list2);
    }

    @Test
    public void testJWKListEquals() {
        JWK key1 = createJWKey();
        JWK key2 = createJWKey();

        JWKList l1 = new JWKList().setKeys(Collections.singletonList(key1));
        JWKList l2 = new JWKList().setKeys(Collections.singletonList(key2));
        assertEquals(l1, l2);

        JWK key3 = new JWK().setAlg("dummy");
        JWK key4 = new JWK().setAlg("dummy");

        l1 = new JWKList().setKeys(Arrays.asList(key2, key3, key1));
        l2 = new JWKList().setKeys(Arrays.asList(key1, key2, key4));
        assertNotEquals(l1, l2);
        assertTrue(l1.getKeys().containsAll(l2.getKeys()));
    }

    private JWK createJWKey() {
        JWK key = new JWK();
        key.setUse("use");
        key.setKid("kid");
        key.setCrv("crv");
        key.setAlg("alg");
        key.setX("x");
        key.setKty("kty");
        key.setE("e");
        key.setN("n");
        key.setY("y");
        return key;
    }
}
