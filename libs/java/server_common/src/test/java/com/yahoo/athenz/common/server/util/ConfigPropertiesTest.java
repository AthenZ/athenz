/*
 * Copyright 2017 Yahoo Holdings Inc.
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

import static org.testng.Assert.assertEquals;

import org.testng.annotations.Test;

public class ConfigPropertiesTest {

    @Test
    public void testGetPortNumberDefault() {
        assertEquals(ConfigProperties.getPortNumber("NotExistantProperty", 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberValid() {
        System.setProperty("athenz.port", "4085");
        assertEquals(ConfigProperties.getPortNumber("athenz.port", 4080), 4085);
    }
    
    @Test
    public void testGetPortNumberInvalidFormat() {
        System.setProperty("athenz.port", "abc");
        assertEquals(ConfigProperties.getPortNumber("athenz.port", 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberOutOfRangeNegative() {
        System.setProperty("athenz.port", "-1");
        assertEquals(ConfigProperties.getPortNumber("athenz.port", 4080), 4080);
    }
    
    @Test
    public void testGetPortNumberOutOfRangePositive() {
        System.setProperty("athenz.port", "65536");
        assertEquals(ConfigProperties.getPortNumber("athenz.port", 4080), 4080);
    }
}
