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

public class EndpointConfigTest {

    @Test
    public void testGettersAndSetters() {
        EndpointConfig config = new EndpointConfig();

        // Test initial null values
        assertNull(config.getPath());
        assertNull(config.getPathStartsWith());
        assertNull(config.getPathEndsWith());
        assertNull(config.getMethods());
        assertNull(config.getDescription());

        // Test setters and getters
        config.setPath("/zts/v1/instance");
        assertEquals(config.getPath(), "/zts/v1/instance");

        List<String> methods = Arrays.asList("GET", "POST");
        config.setMethods(methods);
        assertEquals(config.getMethods(), methods);

        config.setDescription("Instance endpoint");
        assertEquals(config.getDescription(), "Instance endpoint");

        config.setPathStartsWith("/zts/v1/");
        assertEquals(config.getPathStartsWith(), "/zts/v1/");
        config.setPathEndsWith("/keys");
        assertEquals(config.getPathEndsWith(), "/keys");
    }

    @Test
    public void testAllowsMethodWithNullMethods() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/api/resource");
        config.setMethods(null);

        // Null methods means all methods are allowed
        assertTrue(config.allowsMethod("GET"));
        assertTrue(config.allowsMethod("POST"));
        assertTrue(config.allowsMethod("PUT"));
        assertTrue(config.allowsMethod("DELETE"));
    }

    @Test
    public void testAllowsMethodWithEmptyMethods() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/api/resource");
        config.setMethods(Collections.emptyList());

        // Empty methods list means all methods are allowed
        assertTrue(config.allowsMethod("GET"));
        assertTrue(config.allowsMethod("POST"));
        assertTrue(config.allowsMethod("PUT"));
        assertTrue(config.allowsMethod("DELETE"));
    }

    @Test
    public void testAllowsMethodWithSpecificMethods() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/api/resource");
        config.setMethods(Arrays.asList("GET", "POST"));

        // Only GET and POST are allowed
        assertTrue(config.allowsMethod("GET"));
        assertTrue(config.allowsMethod("POST"));
        assertFalse(config.allowsMethod("PUT"));
        assertFalse(config.allowsMethod("DELETE"));
        assertFalse(config.allowsMethod("PATCH"));
    }

    @Test
    public void testAllowsMethodSingleMethod() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/api/resource");
        config.setMethods(Collections.singletonList("GET"));

        assertTrue(config.allowsMethod("GET"));
        assertFalse(config.allowsMethod("POST"));
        assertFalse(config.allowsMethod("PUT"));
        assertFalse(config.allowsMethod("DELETE"));
    }

    @Test
    public void testAllowsMethodCaseSensitive() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/api/resource");
        config.setMethods(Arrays.asList("GET", "POST"));

        // Methods are case-sensitive
        assertTrue(config.allowsMethod("GET"));
        assertFalse(config.allowsMethod("get"));
        assertFalse(config.allowsMethod("Get"));
    }

    @Test
    public void testSetPath() {
        EndpointConfig config = new EndpointConfig();

        config.setPath("/api/v1/resource");
        assertEquals(config.getPath(), "/api/v1/resource");

        config.setPath("/health");
        assertEquals(config.getPath(), "/health");

        config.setPath(null);
        assertNull(config.getPath());
    }

    @Test
    public void testSetMethods() {
        EndpointConfig config = new EndpointConfig();

        List<String> methods = Arrays.asList("GET", "POST", "PUT", "DELETE");
        config.setMethods(methods);
        assertEquals(config.getMethods(), methods);
        assertEquals(config.getMethods().size(), 4);
    }

    @Test
    public void testSetDescription() {
        EndpointConfig config = new EndpointConfig();

        config.setDescription("Health check endpoint");
        assertEquals(config.getDescription(), "Health check endpoint");

        config.setDescription("");
        assertEquals(config.getDescription(), "");

        config.setDescription(null);
        assertNull(config.getDescription());
    }

    @Test
    public void testCompleteEndpointConfiguration() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/zts/v1/status");
        config.setMethods(Collections.singletonList("GET"));
        config.setDescription("ZTS health status endpoint");

        assertEquals(config.getPath(), "/zts/v1/status");
        assertEquals(config.getMethods().size(), 1);
        assertTrue(config.getMethods().contains("GET"));
        assertEquals(config.getDescription(), "ZTS health status endpoint");
    }

    @Test
    public void testAllowsMethodWithAllHttpMethods() {
        EndpointConfig config = new EndpointConfig();
        config.setPath("/api/resource");
        config.setMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"));

        assertTrue(config.allowsMethod("GET"));
        assertTrue(config.allowsMethod("POST"));
        assertTrue(config.allowsMethod("PUT"));
        assertTrue(config.allowsMethod("DELETE"));
        assertTrue(config.allowsMethod("PATCH"));
        assertTrue(config.allowsMethod("HEAD"));
        assertTrue(config.allowsMethod("OPTIONS"));
    }

    @Test
    public void testMultipleUpdates() {
        EndpointConfig config = new EndpointConfig();

        config.setPath("/path1");
        config.setMethods(Arrays.asList("GET"));
        assertEquals(config.getPath(), "/path1");
        assertTrue(config.allowsMethod("GET"));

        config.setPath("/path2");
        config.setMethods(Arrays.asList("POST", "PUT"));
        assertEquals(config.getPath(), "/path2");
        assertFalse(config.allowsMethod("GET"));
        assertTrue(config.allowsMethod("POST"));
        assertTrue(config.allowsMethod("PUT"));
    }

    @Test
    public void testPathStartsWithAndPathEndsWith() {
        EndpointConfig config = new EndpointConfig();
        assertNull(config.getPathStartsWith());
        assertNull(config.getPathEndsWith());

        config.setPathStartsWith("/zts/v1/");
        assertEquals(config.getPathStartsWith(), "/zts/v1/");
        config.setPathEndsWith("/status");
        assertEquals(config.getPathEndsWith(), "/status");

        config.setPathStartsWith(null);
        config.setPathEndsWith(null);
        assertNull(config.getPathStartsWith());
        assertNull(config.getPathEndsWith());
    }
}