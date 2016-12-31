/**
 * Copyright 2016 Yahoo Inc.
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

import static org.testng.Assert.*;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.util.StringUtils;

public class StringUtilsTest {

    @Test
    public void testRemoveLeadingAndTrailingQuotes() {
        
        assertEquals(StringUtils.removeLeadingAndTrailingQuotes("abc"), "abc");
        assertEquals(StringUtils.removeLeadingAndTrailingQuotes("\"abc"), "abc");
        assertEquals(StringUtils.removeLeadingAndTrailingQuotes("abc\""), "abc");
        assertEquals(StringUtils.removeLeadingAndTrailingQuotes("\"abc\""), "abc");
        assertEquals(StringUtils.removeLeadingAndTrailingQuotes("\"a\"bc\""), "a\"bc");
    }
    
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
}
