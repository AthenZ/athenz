/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.auth.util;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.testng.annotations.Test;

public class StringUtilsTest {
    
    @Test
    public void testPatternFromGlob() {
        assertEquals("^abc$", StringUtils.patternFromGlob("abc"));
        assertEquals("^abc.*$", StringUtils.patternFromGlob("abc*"));
        assertEquals("^abc.$", StringUtils.patternFromGlob("abc?"));
        assertEquals("^.*abc.$", StringUtils.patternFromGlob("*abc?"));
        assertEquals("^abc\\.abc:.*$", StringUtils.patternFromGlob("abc.abc:*"));
        assertEquals("^ab\\[a-c]c$", StringUtils.patternFromGlob("ab[a-c]c"));
        assertEquals("^ab.*\\.\\(\\)\\^\\$c$", StringUtils.patternFromGlob("ab*.()^$c"));
        assertEquals("^abc\\\\test\\\\$", StringUtils.patternFromGlob("abc\\test\\"));
        assertEquals("^ab\\{\\|c\\+$", StringUtils.patternFromGlob("ab{|c+"));
        assertEquals("^\\^\\$\\[\\(\\)\\\\\\+\\{\\..*.\\|$", StringUtils.patternFromGlob("^$[()\\+{.*?|"));
    }
    
    @Test
    public void testContainsMatchCharacter() {
        assertTrue(StringUtils.containsMatchCharacter("abc*"));
        assertTrue(StringUtils.containsMatchCharacter("*abc"));
        assertTrue(StringUtils.containsMatchCharacter("abc*abc"));
        assertTrue(StringUtils.containsMatchCharacter("*"));
        assertTrue(StringUtils.containsMatchCharacter("?abc"));
        assertTrue(StringUtils.containsMatchCharacter("abc?"));
        assertTrue(StringUtils.containsMatchCharacter("abc?abc"));
        assertTrue(StringUtils.containsMatchCharacter("?"));

        assertFalse(StringUtils.containsMatchCharacter("abc"));
        assertFalse(StringUtils.containsMatchCharacter("a.bc[ab]"));
        assertFalse(StringUtils.containsMatchCharacter("a(ab)[ab]"));
        assertFalse(StringUtils.containsMatchCharacter("domain:role.rolename"));
    }
    
    @Test
    public void testContainsControlCharacter() {
        assertFalse(StringUtils.containsControlCharacter("abcd"));
        assertFalse(StringUtils.containsControlCharacter("abc td"));
        assertFalse(StringUtils.containsControlCharacter("abc2345423540908d"));
        assertFalse(StringUtils.containsControlCharacter("abcd!@#$#@%$$^%&%*()_+=="));
        assertFalse(StringUtils.containsControlCharacter("abc\\][\\|}{|}d"));
        assertFalse(StringUtils.containsControlCharacter("abc\":\":\";;';';;d"));
        assertFalse(StringUtils.containsControlCharacter("ab,./<>?cd"));
        assertFalse(StringUtils.containsControlCharacter("abcd`~!@#$%^&*()_+-="));
        
        assertTrue(StringUtils.containsControlCharacter("abc\t"));
        assertTrue(StringUtils.containsControlCharacter("abc\n"));
        assertTrue(StringUtils.containsControlCharacter("abc\b"));
        assertTrue(StringUtils.containsControlCharacter("abc\r"));
        assertTrue(StringUtils.containsControlCharacter("abc\t\r\b\t\n"));
    }
    
    @Test
    public void testRequestUriMatch() {
        assertFalse(StringUtils.requestUriMatch("/zts/v1/schema", null, null));
        assertFalse(StringUtils.requestUriMatch("/zts/v1/schema", Collections.emptySet(), null));
        assertFalse(StringUtils.requestUriMatch("/zts/v1/schema", null, Collections.emptyList()));
        
        Set<String> uriSet = new HashSet<>();
        uriSet.add("/zts/v1/domain");
        uriSet.add("/zts/v1/schema");
        assertFalse(StringUtils.requestUriMatch("/zts/v1/token", uriSet, null));
        assertTrue(StringUtils.requestUriMatch("/zts/v1/domain", uriSet, null));
        assertTrue(StringUtils.requestUriMatch("/zts/v1/schema", uriSet, null));
        
        List<Pattern> uriList = new ArrayList<>();
        uriList.add(Pattern.compile("/zts/v1/domain/.+/service/.+/publickey/.+"));
        assertFalse(StringUtils.requestUriMatch("/zts/v1/domain/athenz/service/zms/publickey/", uriSet, uriList));
        assertFalse(StringUtils.requestUriMatch("/zts/v1/domain/athenz", uriSet, uriList));
        assertFalse(StringUtils.requestUriMatch("/zts/v1/domain/athenz/token", uriSet, uriList));
        assertFalse(StringUtils.requestUriMatch("/zts/v1/domain/athenz/service/zms", uriSet, uriList));
        assertTrue(StringUtils.requestUriMatch("/zts/v1/domain/athenz/service/zms/publickey/zms1", uriSet, uriList));
    }
    
    @Test
    public void testCountMatches() {
        assertEquals(StringUtils.countMatches("user", '.'), 0);
        assertEquals(StringUtils.countMatches("user.joe", '.'), 1);
        assertEquals(StringUtils.countMatches("home.joe.service", '.'), 2);
    }
}
