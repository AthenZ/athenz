/*
 * Copyright The Athenz Authors.
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
import static org.testng.Assert.assertThrows;

import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;

public class ConfigPropertiesTest {

    private static String ROOT_DIR;
    public static final String STR_DEF_ROOT     = "/home/athenz";
    private static final String CONFIG_TEST_PROP_ROOT_DIR = "athenz.config.properties.test.root.dir";
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

    @SuppressWarnings("deprecation")
    @Test
    public void testLoadProperties() throws IOException {
        assertThrows(RuntimeException.class, () -> ConfigProperties.loadProperties("FailFile.txt"));

        File currentDirectory = new File(new File(".").getAbsolutePath());

        assertThrows(RuntimeException.class, () -> ConfigProperties.loadProperties(currentDirectory.getCanonicalPath() + "/src/test/resources/testFileConfigEmpty.properties"));

        ConfigProperties.loadProperties(currentDirectory.getCanonicalPath() + "/src/test/resources/testFileConfig.properties");
    }

    @Test
    public void testRetrieveConfigValueNull() {
        assertEquals(ConfigProperties.retrieveConfigSetting("unknown", 10), 10);
    }

    @Test
    public void testRetrieveConfigValue() {
        System.setProperty("athenz.port", "4443");
        assertEquals(ConfigProperties.retrieveConfigSetting("athenz.port", 4080), 4443);

        System.setProperty("athenz.port", "-4443");
        assertEquals(ConfigProperties.retrieveConfigSetting("athenz.port", 4080), 4080);

        System.setProperty("athenz.port", "data");
        assertEquals(ConfigProperties.retrieveConfigSetting("athenz.port", 4080), 4080);
    }

    public static String getRootDir() {

        if (ROOT_DIR == null) {
            ROOT_DIR = System.getProperty(CONFIG_TEST_PROP_ROOT_DIR, STR_DEF_ROOT);
        }

        return ROOT_DIR;
    }
}
