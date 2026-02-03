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
package com.yahoo.athenz.container.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

/**
 * Singleton manager for port-uri configuration.
 * Loads and caches the port-uri.json configuration file.
 * This singleton ensures the configuration is parsed only once and shared
 * across Jetty connectors and filters.
 * Configuration file path is read from system property 'athenz.port_uri_config'
 * with default '/opt/zts/conf/port-uri.json'.
 */
public class PortUriConfigurationManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(PortUriConfigurationManager.class);
    private static final String DEFAULT_CONFIG_PATH = "/opt/zts/conf/port-uri.json";

    // Eager initialization - thread-safe by JVM specification (Bill Pugh singleton)
    private static final PortUriConfigurationManager INSTANCE = new PortUriConfigurationManager();


    // Mutable configuration for testability (volatile for thread-safety)
    private volatile PortUriConfiguration configuration;

    /**
     * Private constructor that loads configuration from system property.
     * If configuration file is not found or cannot be parsed, configuration will be null.
     */
    private PortUriConfigurationManager() {
        loadConfiguration();
    }

    /**
     * Load or reload configuration from system property.
     * Reads the file path from system property 'athenz.port_uri_config'.
     * Always ensures configuration is non-null (empty if file not found or parse error).
     */
    private void loadConfiguration() {
        String filePath = System.getProperty(
                com.yahoo.athenz.container.AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                DEFAULT_CONFIG_PATH);

        PortUriConfiguration config;

        File configFile = new File(filePath);
        if (configFile.exists()) {
            try {
                ObjectMapper mapper = new ObjectMapper();
                config = mapper.readValue(configFile, PortUriConfiguration.class);
                LOGGER.info("Successfully loaded port-uri configuration from {}", filePath);
                logConfigurationSummary(config);
            } catch (IOException e) {
                LOGGER.warn("Failed to parse port-uri configuration from {}: {} - {}, using empty configuration",
                        filePath, e.getClass().getSimpleName(), e.getMessage());
                config = new PortUriConfiguration(); // Empty configuration
            }
        } else {
            LOGGER.info("Port-uri configuration file not found at {}, using empty configuration", filePath);
            config = new PortUriConfiguration(); // Empty configuration
        }

        this.configuration = config;
    }

    /**
     * Get singleton instance
     *
     * @return singleton instance
     */
    public static PortUriConfigurationManager getInstance() {
        return INSTANCE;
    }


    /**
     * Get the loaded configuration
     *
     * @return configuration object (never null, may have empty ports list)
     */
    public PortUriConfiguration getConfiguration() {
        return configuration;
    }

    /**
     * Check if port list is configured
     *
     * @return true if configuration has at least one port configured
     */
    public boolean isPortListConfigured() {
        return !configuration.getPorts().isEmpty();
    }

    /**
     * Get port configuration for specific port
     *
     * @param port port number
     * @return PortConfig for the port, or null if not found
     */
    public PortConfig getPortConfig(int port) {
        return configuration.getPortConfig(port);
    }

    /**
     * Check if mTLS is required for a port
     *
     * @param port port number
     * @return true if mTLS is required, false otherwise
     */
    public boolean isMtlsRequired(int port) {
        PortConfig config = getPortConfig(port);
        return config != null && config.isMtlsRequired();
    }

    /**
     * Reload configuration for testing.
     * Keeps the singleton instance but reloads configuration from current system property value.
     * This method should NEVER be called in production code.
     * Since we are using eager initialization for singleton, and the tests would need to simulate the state in
     * AthenzJettyContainer and PortFilter, we need a way to reset the configuration for testing.
     */
    public static void resetForTesting() {
        INSTANCE.loadConfiguration();
    }

    /**
     * Log configuration summary for debugging
     *
     * @param config the configuration to log (never null)
     */
    private void logConfigurationSummary(PortUriConfiguration config) {
        if (config.getPorts().isEmpty()) {
            LOGGER.info("Port-URI Configuration Summary: No ports configured");
            return;
        }

        LOGGER.info("Port-URI Configuration Summary:");
        for (PortConfig portConfig : config.getPorts()) {
            int endpointCount = portConfig.getAllowedEndpoints() != null ?
                    portConfig.getAllowedEndpoints().size() : 0;

            String restriction = endpointCount == 0 ? "unrestricted (all endpoints allowed)" :
                    endpointCount + " allowed endpoint(s)";

            LOGGER.info("  Port {}: {} (mTLS: {}) - {}",
                    portConfig.getPort(),
                    restriction,
                    portConfig.isMtlsRequired() ? "required" : "not required",
                    portConfig.getDescription() != null ? portConfig.getDescription() : "");
        }
    }
}
