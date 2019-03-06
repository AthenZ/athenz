/*
 * Copyright 2019 Oath Holdings Inc.
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
import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

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
}
