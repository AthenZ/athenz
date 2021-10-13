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

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigProperties {
 
    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigProperties.class);

    /**
     * @deprecated Use {@link com.yahoo.athenz.common.server.util.config.ConfigManager} <br>
     *     For example - instead of this:<pre>{@code
     *              ConfigProperties.loadProperties("config-1.conf");
     *              ConfigProperties.loadProperties("config-2.conf");
     *         }</pre>
     *     Do this:<pre>{@code
     *              new ConfigManager()
     *                      .addConfigSource("aws-param-store://config-1.conf")
     *                      .addConfigSource("aws-param-store://config-2.conf");
     *         }</pre>
     */
    @Deprecated
    public static void loadProperties(String propFile) {
        
        Properties prop = new Properties();
        try (InputStream is = new FileInputStream(propFile)) {
            prop.load(is);
        } catch (Exception ex) {
            throw new RuntimeException("Error while loading " + propFile, ex);
        }
        
        if (prop.isEmpty()) {
            throw new RuntimeException("No data set in " + propFile);
        }
        
        LOGGER.info("Loading system properties from {}...", propFile);
        Enumeration<?> enumeration = prop.propertyNames();
        while (enumeration.hasMoreElements()) {
            String key = (String) enumeration.nextElement();
            String value = prop.getProperty(key);
            
            if (!value.isEmpty()) {
                System.setProperty(key, value);
                LOGGER.info("property name={}, value={}", key, value);
            }
        }
    }
    
    public static int getPortNumber(String property, int defaultValue) {
        
        String propValue = System.getProperty(property);
        if (propValue == null) {
            return defaultValue;
        }
        
        int port;
        try {
            // first try to convert the string property to integer
            
            port = Integer.parseInt(propValue);
            
            // now verify that it's a valid port number
            
            if (port < 0 || port > 65535) {
                throw new NumberFormatException();
            }
            
        } catch (NumberFormatException ex) {
            LOGGER.info("invalid port: {}. Using default port: {}", propValue, defaultValue);
            port = defaultValue;
        }
        
        return port;
    }

    public static int retrieveConfigSetting(String property, int defaultValue) {

        int settingValue;
        try {
            String propValue = System.getProperty(property);
            if (propValue == null) {
                return defaultValue;
            }

            settingValue = Integer.parseInt(propValue);

            if (settingValue <= 0) {
                LOGGER.error("Invalid {} value: {}, defaulting to {}", property, propValue, defaultValue);
                settingValue = defaultValue;
            }
        } catch (Exception ex) {
            LOGGER.error("Invalid {} value, defaulting to {}: {}", property, defaultValue, ex.getMessage());
            settingValue = defaultValue;
        }

        return settingValue;
    }
}
