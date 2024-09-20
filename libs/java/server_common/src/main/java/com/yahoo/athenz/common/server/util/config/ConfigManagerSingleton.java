/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  
 */

package com.yahoo.athenz.common.server.util.config;

import com.yahoo.athenz.common.server.util.config.providers.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

public class ConfigManagerSingleton {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigManagerSingleton.class);

    /** A singleton ConfigManager that resolves all system-property values */
    public static final ConfigManager CONFIG_MANAGER = new AthenzConfigManager();
    public static final String ATHENZ_CONFIG_PROVIDERS = "athenz.config.providers";

    private static class AthenzConfigManager extends ConfigManager {
        AthenzConfigManager() {
            super("reload-configs-seconds", 60, TimeUnit.SECONDS);
            addConfigProviders();
        }
    }

    private static void addConfigProviders() {
        String providerClasses = System.getProperty(ATHENZ_CONFIG_PROVIDERS);
        if (providerClasses != null && !providerClasses.isEmpty()) {
            String[] providerClassList = providerClasses.split(",");
            for (String providerClass : providerClassList) {
                ConfigProvider configProvider;
                try {
                    configProvider = (ConfigProvider) Class.forName(providerClass).getDeclaredConstructor().newInstance();
                } catch (Exception ex) {
                    LOGGER.error("unable to initialize config provider for: {}", providerClass, ex);
                    throw new IllegalArgumentException("unable to initialize config provider for: " + providerClass);
                }
                CONFIG_MANAGER.addProvider(configProvider);
            }
        }
    }
}
