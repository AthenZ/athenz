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
package com.yahoo.athenz.common.server.util;

import org.testng.annotations.Test;

import java.util.Set;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class UtilsTest {

    @Test
    public void testAssertionDomainCheck() {
        assertNull(Utils.assertionDomainCheck("", "resource.value"));
        assertNull(Utils.assertionDomainCheck("", ":resource.value"));
        assertNull(Utils.assertionDomainCheck("role.value", "athenz:resource.value"));
        assertNull(Utils.assertionDomainCheck(":role.value", "athenz:resource.value"));
        assertNull(Utils.assertionDomainCheck("ads:role.value", "athenz:resource.value"));
        assertNull(Utils.assertionDomainCheck("sports:role.value", "athenz:resource.value"));
        assertEquals(Utils.assertionDomainCheck("athenz:role.value", "athenz:resource.value"), "athenz");
    }

    @Test
    public void testParseAwsAccountsNull() {
        assertTrue(Utils.parseAwsAccounts(null).isEmpty());
    }

    @Test
    public void testParseAwsAccountsEmpty() {
        assertTrue(Utils.parseAwsAccounts("").isEmpty());
    }

    @Test
    public void testParseAwsAccountsSingle() {
        assertEquals(Utils.parseAwsAccounts("1234"), Set.of("1234"));
    }

    @Test
    public void testParseAwsAccountsMultiple() {
        assertEquals(Utils.parseAwsAccounts("1234,5678"), Set.of("1234", "5678"));
    }

    @Test
    public void testParseAwsAccountsWhitespace() {
        assertEquals(Utils.parseAwsAccounts(" 1234 , 5678 "), Set.of("1234", "5678"));
    }

    @Test
    public void testParseAwsAccountsTrailingComma() {
        assertEquals(Utils.parseAwsAccounts("1234,5678,"), Set.of("1234", "5678"));
    }

    @Test
    public void testParseAwsAccountsBlankElements() {
        assertEquals(Utils.parseAwsAccounts("1234,,5678"), Set.of("1234", "5678"));
    }

    @Test
    public void testParseAwsAccountsOnlyCommas() {
        assertTrue(Utils.parseAwsAccounts(",,,").isEmpty());
    }
}

@Test
public void testParseCsvListNull() {
    assertTrue(Utils.parseCsvList(null).isEmpty());
}

@Test
public void testParseCsvListEmpty() {
    assertTrue(Utils.parseCsvList("").isEmpty());
}

@Test
public void testParseCsvListSingle() {
    assertEquals(Utils.parseCsvList("1112432545"), Set.of("1112432545"));
}

@Test
public void testParseCsvListMultiple() {
    assertEquals(Utils.parseCsvList("proj-a,proj-b"), Set.of("proj-a", "proj-b"));
}

@Test
public void testParseCsvListWhitespace() {
    assertEquals(Utils.parseCsvList(" proj-a, proj-b "), Set.of("proj-a", "proj-b"));
}

@Test
public void testParseCsvListTrailingComma() {
    assertEquals(Utils.parseCsvList("123456789,456789012,"), Set.of("123456789", "456789012"));
}

@Test
public void testParseCsvListBlankElements() {
    assertEquals(Utils.parseCsvList("proj-a,,proj-b"), Set.of("proj-a", "proj-b"));
}

@Test
public void testParseCsvListOnlyCommas() {
    assertTrue(Utils.parseCsvList(",,,").isEmpty());
}

@Test
public void testParseCsvListDeduplicates() {
    assertEquals(Utils.parseCsvList("proj-a,proj-a,proj-b"), Set.of("proj-a", "proj-b"));
}