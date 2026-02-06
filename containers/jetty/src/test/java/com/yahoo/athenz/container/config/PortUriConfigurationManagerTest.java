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

import com.yahoo.athenz.container.AthenzConsts;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class PortUriConfigurationManagerTest {

    @BeforeMethod
    public void setUp() {
        // Clear system property before each test
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG);
    }

    @AfterMethod
    public void tearDown() {
        // Clear system property after each test
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG);
    }

    @Test
    public void testGetInstanceReturnsSingleton() {
        PortUriConfigurationManager instance1 = PortUriConfigurationManager.getInstance();
        PortUriConfigurationManager instance2 = PortUriConfigurationManager.getInstance();

        assertNotNull(instance1);
        assertNotNull(instance2);
        assertSame(instance1, instance2, "getInstance should return the same singleton instance");
    }

    @Test
    public void testConfigurationLoadedFromSystemProperty() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        // Reset to load configuration from new system property
        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertTrue(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        assertEquals(manager.getConfiguration().getPorts().size(), 3);
        assertNotNull(manager.getConfiguration().getPorts().get(0).getDescription());
    }

    @Test
    public void testConfigurationFileNotFound() {
        String configPath = "src/test/resources/port-uri-configs/non-existent-file.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        assertTrue(manager.getConfiguration().getPorts().isEmpty());
    }

    @Test
    public void testConfigurationInvalidJson() {
        String configPath = "src/test/resources/port-uri-configs/invalid-json.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        assertTrue(manager.getConfiguration().getPorts().isEmpty());
    }

    @Test
    public void testGetConfigurationNotLoaded() {
        // Don't set system property, so no configuration file is specified
        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        assertTrue(manager.getConfiguration().getPorts().isEmpty());
    }

    @Test
    public void testGetPortConfig() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        PortConfig portConfig = manager.getPortConfig(9443);
        assertNotNull(portConfig);
        assertEquals(portConfig.getPort(), 9443);
        assertFalse(portConfig.isMtlsRequired());
    }

    @Test
    public void testGetPortConfigNotFound() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        PortConfig portConfig = manager.getPortConfig(9999);
        assertNull(portConfig);
    }

    @Test
    public void testGetPortConfigNotLoaded() {
        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        PortConfig portConfig = manager.getPortConfig(9443);
        assertNull(portConfig);
    }

    @Test
    public void testIsMtlsRequired() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isMtlsRequired(9443));
        assertTrue(manager.isMtlsRequired(4443));
        assertFalse(manager.isMtlsRequired(9999)); // Port not found returns false
    }

    @Test
    public void testIsMtlsRequiredNotLoaded() {
        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isMtlsRequired(9443));
    }

    @Test
    public void testLoadMinimalConfiguration() {
        String configPath = "src/test/resources/port-uri-configs/minimal-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertTrue(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        assertEquals(manager.getConfiguration().getPorts().size(), 1);

        PortConfig portConfig = manager.getPortConfig(443);
        assertNotNull(portConfig);
        assertEquals(portConfig.getPort(), 443);
        assertFalse(portConfig.isMtlsRequired());
    }

    @Test
    public void testLoadEmptyConfiguration() {
        String configPath = "src/test/resources/port-uri-configs/empty-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        assertTrue(manager.getConfiguration().getPorts().isEmpty());
    }

    @Test
    public void testLoadTrulyEmptyConfiguration() {
        String configPath = "src/test/resources/port-uri-configs/truly-empty-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        assertFalse(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
        // With no "ports" field in JSON, Jackson leaves it as empty list due to our initialization
        assertNotNull(manager.getConfiguration().getPorts());
        assertTrue(manager.getConfiguration().getPorts().isEmpty());
    }

    @Test
    public void testThreadSafeSingletonCreation() throws InterruptedException {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        // Reset to ensure we start fresh
        PortUriConfigurationManager.resetForTesting();

        final PortUriConfigurationManager[] instances = new PortUriConfigurationManager[10];
        Thread[] threads = new Thread[10];

        // Create multiple threads that try to get instance simultaneously
        for (int i = 0; i < 10; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                instances[index] = PortUriConfigurationManager.getInstance();
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all instances are the same
        PortUriConfigurationManager firstInstance = instances[0];
        assertNotNull(firstInstance);

        for (int i = 1; i < 10; i++) {
            assertSame(instances[i], firstInstance, "All instances should be the same singleton");
        }
    }

    @Test
    public void testResetForTesting() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();
        assertTrue(manager.isPortListConfigured());

        // Clear property and reset
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG);
        PortUriConfigurationManager.resetForTesting();

        // Get new instance should have clean state (empty configuration)
        PortUriConfigurationManager newManager = PortUriConfigurationManager.getInstance();
        assertFalse(newManager.isPortListConfigured());
        assertNotNull(newManager.getConfiguration());
        assertTrue(newManager.getConfiguration().getPorts().isEmpty());
    }

    @Test
    public void testGetPortConfigWithNullConfiguration() {
        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        // Configuration not loaded
        assertFalse(manager.isPortListConfigured());

        PortConfig config = manager.getPortConfig(443);
        assertNull(config);
    }

    @Test
    public void testIsMtlsRequiredWithNullPortConfig() {
        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        // Port config doesn't exist
        assertFalse(manager.isMtlsRequired(9999));
    }

    @Test
    public void testLoadConfigurationWithCompleteStructure() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        // Port 9443: instance registration, mtls_required false, one endpoint
        PortConfig portConfig = manager.getPortConfig(9443);
        assertNotNull(portConfig);
        assertFalse(portConfig.isMtlsRequired());
        assertEquals(portConfig.getDescription(), "mTLS port for instance registration");
        assertNotNull(portConfig.getAllowedEndpoints());
        assertEquals(portConfig.getAllowedEndpoints().size(), 1);

        EndpointConfig endpoint1 = portConfig.getAllowedEndpoints().get(0);
        assertEquals(endpoint1.getPath(), "/zts/v1/instance");
        assertNotNull(endpoint1.getMethods());
        assertEquals(endpoint1.getMethods().size(), 1);
        assertTrue(endpoint1.getMethods().contains("POST"));

        // Port 4443: main HTTPS, mtls_required true, unrestricted (empty endpoints)
        PortConfig portConfig4443 = manager.getPortConfig(4443);
        assertNotNull(portConfig4443);
        assertTrue(portConfig4443.isMtlsRequired());
        assertEquals(portConfig4443.getDescription(), "Main HTTPS port - unrestricted");
        assertNotNull(portConfig4443.getAllowedEndpoints());
        assertTrue(portConfig4443.getAllowedEndpoints().isEmpty());
    }

    @Test
    public void testMultiplePortConfiguration() {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        PortUriConfigurationManager.resetForTesting();
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();

        // Test first port (9443 - instance registration, mtls not required)
        PortConfig port1 = manager.getPortConfig(9443);
        assertNotNull(port1);
        assertFalse(port1.isMtlsRequired());
        assertNotNull(port1.getAllowedEndpoints());
        assertEquals(port1.getAllowedEndpoints().size(), 1);

        // Test second port (4443 - main HTTPS, mtls required, unrestricted)
        PortConfig port2 = manager.getPortConfig(4443);
        assertNotNull(port2);
        assertTrue(port2.isMtlsRequired());
        assertNotNull(port2.getAllowedEndpoints());
        assertTrue(port2.getAllowedEndpoints().isEmpty());
    }

    @Test
    public void testConcurrentLoadConfiguration() throws InterruptedException {
        String configPath = "src/test/resources/port-uri-configs/valid-config.json";
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configPath);

        // Reset to ensure we start fresh
        PortUriConfigurationManager.resetForTesting();

        final int threadCount = 10;
        final Thread[] threads = new Thread[threadCount];
        final boolean[] results = new boolean[threadCount];

        // Create multiple threads that try to get configuration simultaneously
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();
                results[index] = manager.isPortListConfigured();
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all threads successfully accessed configuration
        for (int i = 0; i < threadCount; i++) {
            assertTrue(results[i], "Thread " + i + " should have loaded configuration");
        }

        // Verify configuration is loaded exactly once
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();
        assertTrue(manager.isPortListConfigured());
        assertNotNull(manager.getConfiguration());
    }
}