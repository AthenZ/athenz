/*
 *  Copyright 2020 Verizon Media
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

import org.testng.annotations.Test;

import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

public class GlobStringsMatcherTest {

    @Test
    public void testGlobStringMatcher() {
        String globStrings =
                "aaa.bbb.ccc.ddd, "
                + "???.ddd, "
                + "*.bbb.*.ddd, "
                + "aaa.??, ";

        String systemProperty = "athenz.zts.notification_cert_fail_ignored_services_list";
        System.setProperty(systemProperty, globStrings);
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(systemProperty);

        assertTrue(globStringsMatcher.isMatch("aaa.bbb.ccc.ddd"));
        assertTrue(globStringsMatcher.isMatch("ccc.ddd"));
        assertTrue(globStringsMatcher.isMatch("aaa.yy"));
        assertTrue(globStringsMatcher.isMatch("1.2.bbb.444.555.ddd"));

        assertFalse(globStringsMatcher.isMatch("1.2.3.ddd"));
        assertFalse(globStringsMatcher.isMatch("ddd"));
        assertFalse(globStringsMatcher.isMatch("ccc"));
        assertFalse(globStringsMatcher.isMatch("bbb"));
        assertFalse(globStringsMatcher.isMatch("bbb.ccc"));
        assertFalse(globStringsMatcher.isMatch("1.2.ddd.3"));
        assertFalse(globStringsMatcher.isMatch("something.else"));

        System.clearProperty(systemProperty);
    }

    @Test
    public void testIsEmptyPatternsList() {
        String globStrings =
                "aaa.bbb.ccc.ddd, "
                        + "???.ddd, "
                        + "*.bbb.*.ddd, "
                        + "aaa.??, ";

        String systemProperty = "athenz.zts.notification_cert_fail_ignored_services_list";
        System.setProperty(systemProperty, globStrings);
        GlobStringsMatcher globStringsMatcher = new GlobStringsMatcher(systemProperty);
        assertFalse(globStringsMatcher.isEmptyPatternsList());

        System.setProperty(systemProperty, "");
        globStringsMatcher = new GlobStringsMatcher(systemProperty);
        assertTrue(globStringsMatcher.isEmptyPatternsList());

        globStringsMatcher = new GlobStringsMatcher("some.other.property");
        assertTrue(globStringsMatcher.isEmptyPatternsList());

        System.clearProperty(systemProperty);
    }
}
