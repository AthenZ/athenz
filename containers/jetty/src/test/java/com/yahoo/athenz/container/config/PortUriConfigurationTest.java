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

import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.testng.Assert.*;

public class PortUriConfigurationTest {

    @Test
    public void testGettersAndSetters() {
        PortUriConfiguration config = new PortUriConfiguration();

        // Test initial empty list (never null)
        assertNotNull(config.getPorts());
        assertTrue(config.getPorts().isEmpty());

        // Test setters and getters
        PortConfig port1 = new PortConfig();
        port1.setPort(8443);

        List<PortConfig> ports = Collections.singletonList(port1);
        config.setPorts(ports);

        assertNotNull(config.getPorts());
        assertEquals(config.getPorts(), ports);
        assertEquals(config.getPorts().size(), 1);
    }

    @Test
    public void testGetPortConfig() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port1 = new PortConfig();
        port1.setPort(8443);
        port1.setDescription("HTTPS port");

        PortConfig port2 = new PortConfig();
        port2.setPort(8080);
        port2.setDescription("HTTP port");

        config.setPorts(Arrays.asList(port1, port2));

        // Test finding existing ports
        PortConfig found = config.getPortConfig(8443);
        assertNotNull(found);
        assertEquals(found.getPort(), 8443);
        assertEquals(found.getDescription(), "HTTPS port");

        found = config.getPortConfig(8080);
        assertNotNull(found);
        assertEquals(found.getPort(), 8080);
        assertEquals(found.getDescription(), "HTTP port");
    }

    @Test
    public void testGetPortConfigNotFound() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port1 = new PortConfig();
        port1.setPort(8443);

        config.setPorts(Collections.singletonList(port1));

        // Test non-existent port
        PortConfig found = config.getPortConfig(9999);
        assertNull(found);
    }

    @Test
    public void testGetPortConfigNullPorts() {
        PortUriConfiguration config = new PortUriConfiguration();
        config.setPorts(null);

        PortConfig found = config.getPortConfig(8443);
        assertNull(found);
    }

    @Test
    public void testGetPortConfigEmptyPorts() {
        PortUriConfiguration config = new PortUriConfiguration();
        config.setPorts(Collections.emptyList());

        PortConfig found = config.getPortConfig(8443);
        assertNull(found);
    }

    @Test
    public void testIsPortUnrestricted() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port1 = new PortConfig();
        port1.setPort(443);
        port1.setAllowedEndpoints(Collections.<EndpointConfig>emptyList());

        PortConfig port2 = new PortConfig();
        port2.setPort(8443);
        EndpointConfig endpoint = new EndpointConfig();
        endpoint.setPath("/restricted");
        port2.setAllowedEndpoints(Collections.singletonList(endpoint));

        PortConfig port3 = new PortConfig();
        port3.setPort(8080);
        port3.setAllowedEndpoints(null);

        config.setPorts(Arrays.asList(port1, port2, port3));

        // Port with empty endpoints list is unrestricted
        assertTrue(config.isPortUnrestricted(443));

        // Port with endpoints is restricted
        assertFalse(config.isPortUnrestricted(8443));

        // Port with null endpoints is unrestricted
        assertTrue(config.isPortUnrestricted(8080));
    }

    @Test
    public void testIsPortUnrestrictedNotFound() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port1 = new PortConfig();
        port1.setPort(443);

        config.setPorts(Collections.singletonList(port1));

        // Non-existent port returns false
        assertFalse(config.isPortUnrestricted(9999));
    }

    @Test
    public void testIsPortUnrestrictedNullPorts() {
        PortUriConfiguration config = new PortUriConfiguration();
        config.setPorts(null);

        assertFalse(config.isPortUnrestricted(443));
    }

    @Test
    public void testMultiplePorts() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port1 = new PortConfig();
        port1.setPort(443);
        port1.setMtlsRequired(false);

        PortConfig port2 = new PortConfig();
        port2.setPort(8443);
        port2.setMtlsRequired(true);

        PortConfig port3 = new PortConfig();
        port3.setPort(8080);
        port3.setMtlsRequired(false);

        config.setPorts(Arrays.asList(port1, port2, port3));

        assertEquals(config.getPorts().size(), 3);
        assertNotNull(config.getPortConfig(443));
        assertNotNull(config.getPortConfig(8443));
        assertNotNull(config.getPortConfig(8080));
        assertNull(config.getPortConfig(9000));
    }

    @Test
    public void testUpdatePorts() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port1 = new PortConfig();
        port1.setPort(443);
        config.setPorts(Collections.singletonList(port1));

        assertEquals(config.getPorts().size(), 1);

        PortConfig port2 = new PortConfig();
        port2.setPort(8443);
        config.setPorts(Arrays.asList(port1, port2));

        assertEquals(config.getPorts().size(), 2);
    }

    @Test
    public void testCompleteConfiguration() {
        PortUriConfiguration config = new PortUriConfiguration();

        // Port 1: Unrestricted
        PortConfig port1 = new PortConfig();
        port1.setPort(443);
        port1.setMtlsRequired(false);
        port1.setDescription("Main HTTPS port - unrestricted");
        port1.setAllowedEndpoints(Collections.<EndpointConfig>emptyList());

        // Port 2: Restricted with specific endpoints
        PortConfig port2 = new PortConfig();
        port2.setPort(8443);
        port2.setMtlsRequired(true);
        port2.setDescription("mTLS port for instance registration");

        EndpointConfig endpoint1 = new EndpointConfig();
        endpoint1.setPath("/zts/v1/instance/*");
        endpoint1.setMethods(Arrays.asList("POST", "DELETE"));

        EndpointConfig endpoint2 = new EndpointConfig();
        endpoint2.setPath("/zts/v1/status");
        endpoint2.setMethods(Collections.singletonList("GET"));

        port2.setAllowedEndpoints(Arrays.asList(endpoint1, endpoint2));

        config.setPorts(Arrays.asList(port1, port2));

        // Verify configuration
        assertEquals(config.getPorts().size(), 2);
        assertTrue(config.isPortUnrestricted(443));
        assertFalse(config.isPortUnrestricted(8443));

        PortConfig foundPort2 = config.getPortConfig(8443);
        assertNotNull(foundPort2);
        assertTrue(foundPort2.isMtlsRequired());
        assertEquals(foundPort2.getAllowedEndpoints().size(), 2);
    }

    @Test
    public void testPortConfigWithZeroPort() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port = new PortConfig();
        port.setPort(0);

        config.setPorts(Collections.singletonList(port));

        PortConfig found = config.getPortConfig(0);
        assertNotNull(found);
        assertEquals(found.getPort(), 0);
    }

    @Test
    public void testPortConfigWithHighPortNumber() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port = new PortConfig();
        port.setPort(65535);

        config.setPorts(Collections.singletonList(port));

        PortConfig found = config.getPortConfig(65535);
        assertNotNull(found);
        assertEquals(found.getPort(), 65535);
    }

    @Test
    public void testIsPortUnrestrictedWithNullEndpoints() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port = new PortConfig();
        port.setPort(443);
        port.setAllowedEndpoints(null);

        config.setPorts(Collections.singletonList(port));

        assertTrue(config.isPortUnrestricted(443));
    }

    @Test
    public void testIsPortUnrestrictedWithEmptyEndpoints() {
        PortUriConfiguration config = new PortUriConfiguration();

        PortConfig port = new PortConfig();
        port.setPort(443);
        port.setAllowedEndpoints(Collections.<EndpointConfig>emptyList());

        config.setPorts(Collections.singletonList(port));

        assertTrue(config.isPortUnrestricted(443));
    }
}