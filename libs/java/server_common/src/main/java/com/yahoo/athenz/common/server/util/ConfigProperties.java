/*
 * Copyright 2017 Yahoo Inc.
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
    private static final String ROOT_DIR = "${ROOT}";
    private static final String CURRENT_USER = "${USER}";
    
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
        
        final String rootDir = System.getenv("ROOT");
        final String currentUser = System.getenv("USER");
        
        LOGGER.info("Loading system properties from {}...", propFile);
        Enumeration<?> enumeration = prop.propertyNames();
        while (enumeration.hasMoreElements()) {
            String key = (String) enumeration.nextElement();
            String value = prop.getProperty(key);
            
            // we only support 2 system environment variables in our
            // properties file - ROOT and USER. So whenever we encounter
            // with one of these values, we'll be replace them with
            // their corresponding environment values
            
            if (rootDir != null) {
                value = value.replace(ROOT_DIR, rootDir);
            }
            if (currentUser != null) {
                value = value.replace(CURRENT_USER, currentUser);
            }
            
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
            LOGGER.info("invalid port: " + propValue + ". Using default port: " + defaultValue);
            port = defaultValue;
        }
        
        return port;
    }
}
