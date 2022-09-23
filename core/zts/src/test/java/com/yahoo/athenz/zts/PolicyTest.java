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

import com.yahoo.rdl.Timestamp;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class PolicyTest {

    @Test
    public void testPolicy() {

        Policy policy1 = new Policy();
        policy1.setName("name");
        policy1.setVersion("0");
        policy1.setActive(true);
        policy1.setModified(Timestamp.fromMillis(100));
        policy1.setCaseSensitive(false);
        policy1.setAssertions(Collections.emptyList());

        Policy policy2 = new Policy();
        policy2.setName("name");
        policy2.setVersion("0");
        policy2.setActive(true);
        policy2.setModified(Timestamp.fromMillis(100));
        policy2.setCaseSensitive(false);
        policy2.setAssertions(Collections.emptyList());

        assertEquals(policy1, policy2);
        assertEquals(policy1, policy1);
        assertNotEquals(null, policy1);
        assertNotEquals("policy", policy1);

        //getters
        assertEquals(policy1.getName(), "name");
        assertEquals(policy1.getVersion(), "0");
        assertTrue(policy1.getActive());
        assertFalse(policy1.getCaseSensitive());
        assertEquals(Timestamp.fromMillis(100), policy1.getModified());
        assertEquals(Collections.emptyList(), policy1.getAssertions());

        policy2.setName("name2");
        assertNotEquals(policy1, policy2);
        policy2.setName(null);
        assertNotEquals(policy1, policy2);
        policy2.setName("name");
        assertEquals(policy1, policy2);

        policy2.setVersion("1");
        assertNotEquals(policy1, policy2);
        policy2.setVersion(null);
        assertNotEquals(policy1, policy2);
        policy2.setVersion("0");
        assertEquals(policy1, policy2);

        policy2.setActive(false);
        assertNotEquals(policy1, policy2);
        policy2.setActive(null);
        assertNotEquals(policy1, policy2);
        policy2.setActive(true);
        assertEquals(policy1, policy2);

        policy2.setCaseSensitive(true);
        assertNotEquals(policy1, policy2);
        policy2.setCaseSensitive(null);
        assertNotEquals(policy1, policy2);
        policy2.setCaseSensitive(false);
        assertEquals(policy1, policy2);

        policy2.setModified(Timestamp.fromMillis(101));
        assertNotEquals(policy1, policy2);
        policy2.setModified(null);
        assertNotEquals(policy1, policy2);
        policy2.setModified(Timestamp.fromMillis(100));
        assertEquals(policy1, policy2);

        List<Assertion> list = new ArrayList<>();
        list.add(new Assertion());
        policy2.setAssertions(list);
        assertNotEquals(policy1, policy2);
        policy2.setAssertions(null);
        assertNotEquals(policy1, policy2);
        policy2.setAssertions(Collections.emptyList());
        assertEquals(policy1, policy2);
    }
}
