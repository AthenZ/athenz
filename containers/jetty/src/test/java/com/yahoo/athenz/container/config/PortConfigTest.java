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

public class PortConfigTest {

    @Test
    public void testGettersAndSetters() {
        PortConfig config = new PortConfig();

        // Test initial values
        assertEquals(config.getPort(), 0);
        assertFalse(config.isMtlsRequired());
        assertNull(config.getDescription());
        assertNull(config.getAllowedEndpoints());

        // Test setters and getters
        config.setPort(8443);
        assertEquals(config.getPort(), 8443);

        config.setMtlsRequired(true);
        assertTrue(config.isMtlsRequired());

        config.setDescription("Main HTTPS port");
        assertEquals(config.getDescription(), "Main HTTPS port");

        List<EndpointConfig> endpoints = Arrays.asList(new EndpointConfig());
        config.setAllowedEndpoints(endpoints);
        assertEquals(config.getAllowedEndpoints(), endpoints);
    }

    @Test
    public void testSetPort() {
        PortConfig config = new PortConfig();

        config.setPort(8443);
        assertEquals(config.getPort(), 8443);

        config.setPort(443);
        assertEquals(config.getPort(), 443);

        config.setPort(0);
        assertEquals(config.getPort(), 0);
    }

    @Test
    public void testSetMtlsRequired() {
        PortConfig config = new PortConfig();

        assertFalse(config.isMtlsRequired());

        config.setMtlsRequired(true);
        assertTrue(config.isMtlsRequired());

        config.setMtlsRequired(false);
        assertFalse(config.isMtlsRequired());
    }

    @Test
    public void testSetDescription() {
        PortConfig config = new PortConfig();

        config.setDescription("Port for mTLS connections");
        assertEquals(config.getDescription(), "Port for mTLS connections");

        config.setDescription("");
        assertEquals(config.getDescription(), "");

        config.setDescription(null);
        assertNull(config.getDescription());
    }

    @Test
    public void testSetAllowedEndpoints() {
        PortConfig config = new PortConfig();

        EndpointConfig endpoint1 = new EndpointConfig();
        endpoint1.setPath("/zts/v1/instance");

        EndpointConfig endpoint2 = new EndpointConfig();
        endpoint2.setPath("/zts/v1/status");

        List<EndpointConfig> endpoints = Arrays.asList(endpoint1, endpoint2);
        config.setAllowedEndpoints(endpoints);

        assertNotNull(config.getAllowedEndpoints());
        assertEquals(config.getAllowedEndpoints().size(), 2);
        assertEquals(config.getAllowedEndpoints().get(0).getPath(), "/zts/v1/instance");
        assertEquals(config.getAllowedEndpoints().get(1).getPath(), "/zts/v1/status");
    }

    @Test
    public void testNullAllowedEndpoints() {
        PortConfig config = new PortConfig();
        config.setAllowedEndpoints(null);
        assertNull(config.getAllowedEndpoints());
    }

    @Test
    public void testEmptyAllowedEndpoints() {
        PortConfig config = new PortConfig();
        config.setAllowedEndpoints(Collections.<EndpointConfig>emptyList());
        assertNotNull(config.getAllowedEndpoints());
        assertTrue(config.getAllowedEndpoints().isEmpty());
    }

    @Test
    public void testCompleteConfiguration() {
        PortConfig config = new PortConfig();
        config.setPort(8443);
        config.setMtlsRequired(true);
        config.setDescription("mTLS port for instance registration");

        EndpointConfig endpoint = new EndpointConfig();
        endpoint.setPath("/zts/v1/instance/*/*/*/*/*");
        endpoint.setMethods(Arrays.asList("POST", "DELETE"));
        endpoint.setDescription("Instance registration endpoint");

        config.setAllowedEndpoints(Collections.singletonList(endpoint));

        assertEquals(config.getPort(), 8443);
        assertTrue(config.isMtlsRequired());
        assertEquals(config.getDescription(), "mTLS port for instance registration");
        assertNotNull(config.getAllowedEndpoints());
        assertEquals(config.getAllowedEndpoints().size(), 1);
    }

    @Test
    public void testMultipleEndpoints() {
        PortConfig config = new PortConfig();
        config.setPort(443);

        EndpointConfig endpoint1 = new EndpointConfig();
        endpoint1.setPath("/zts/v1/instance");
        endpoint1.setMethods(Collections.singletonList("POST"));

        EndpointConfig endpoint2 = new EndpointConfig();
        endpoint2.setPath("/zts/v1/status");
        endpoint2.setMethods(Collections.singletonList("GET"));

        EndpointConfig endpoint3 = new EndpointConfig();
        endpoint3.setPath("/zts/v1/domain/*");
        endpoint3.setMethods(Arrays.asList("GET", "POST"));

        config.setAllowedEndpoints(Arrays.asList(endpoint1, endpoint2, endpoint3));

        assertEquals(config.getAllowedEndpoints().size(), 3);
    }

    @Test
    public void testMtlsRequiredFalse() {
        PortConfig config = new PortConfig();
        config.setPort(8080);
        config.setMtlsRequired(false);

        assertFalse(config.isMtlsRequired());
    }

    @Test
    public void testPortRanges() {
        PortConfig config = new PortConfig();

        // Test various valid port numbers
        config.setPort(80);
        assertEquals(config.getPort(), 80);

        config.setPort(443);
        assertEquals(config.getPort(), 443);

        config.setPort(8443);
        assertEquals(config.getPort(), 8443);

        config.setPort(65535);
        assertEquals(config.getPort(), 65535);
    }

    @Test
    public void testUpdateConfiguration() {
        PortConfig config = new PortConfig();

        // Set initial values
        config.setPort(8080);
        config.setMtlsRequired(false);
        config.setDescription("HTTP port");

        // Update values
        config.setPort(8443);
        config.setMtlsRequired(true);
        config.setDescription("HTTPS port with mTLS");

        assertEquals(config.getPort(), 8443);
        assertTrue(config.isMtlsRequired());
        assertEquals(config.getDescription(), "HTTPS port with mTLS");
    }

    @Test
    public void testUnrestrictedPort() {
        PortConfig config = new PortConfig();
        config.setPort(443);
        config.setMtlsRequired(false);
        config.setDescription("Unrestricted HTTPS port");
        config.setAllowedEndpoints(Collections.<EndpointConfig>emptyList());

        // Empty allowed endpoints means unrestricted
        assertNotNull(config.getAllowedEndpoints());
        assertTrue(config.getAllowedEndpoints().isEmpty());
    }
}