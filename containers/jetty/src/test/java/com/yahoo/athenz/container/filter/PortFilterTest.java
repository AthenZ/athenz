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
package com.yahoo.athenz.container.filter;

import com.yahoo.athenz.container.AthenzConsts;
import com.yahoo.athenz.container.config.PortUriConfigurationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.slf4j.LoggerFactory;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class PortFilterTest {

    private Level originalLogLevel;

    @BeforeMethod
    public void setUp() {
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG);
        PortUriConfigurationManager.resetForTesting();

        // Enable DEBUG logging for PortFilter to get 100% coverage
        Logger portFilterLogger = (Logger) LoggerFactory.getLogger(PortFilter.class);
        originalLogLevel = portFilterLogger.getLevel();
        portFilterLogger.setLevel(Level.DEBUG);
    }

    @AfterMethod
    public void tearDown() {
        PortUriConfigurationManager.resetForTesting();
        System.clearProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG);

        Logger portFilterLogger = (Logger) LoggerFactory.getLogger(PortFilter.class);
        if (originalLogLevel != null) {
            portFilterLogger.setLevel(originalLogLevel);
        }
    }

    @Test
    public void testInitWithValidConfiguration() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");
        // Reload configuration with new property
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        // Configuration should be loaded
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();
        assertTrue(manager.isPortListConfigured());
    }

    @Test
    public void testNoConfigurationPassThrough() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/non-existent-config.json");
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        assertFalse(PortUriConfigurationManager.getInstance().isPortListConfigured());

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/any/path");
        when(request.getMethod()).thenReturn("GET");
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain, times(1)).doFilter(request, response);
    }

    @Test
    public void testInitNoConfiguration() throws ServletException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/non-existent-config.json");

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        // No configuration loaded
        PortUriConfigurationManager manager = PortUriConfigurationManager.getInstance();
        assertFalse(manager.isPortListConfigured());
    }

    @Test
    public void testConfigurationBasedFilteringAllowRequest() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/zts/v1/instance");
        when(request.getMethod()).thenReturn("POST");
        when(request.getLocalPort()).thenReturn(9443);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        // Should allow the request
        verify(chain, times(1)).doFilter(request, response);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    public void testConfigurationBasedFilteringRejectRequest() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");

        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/unauthorized/endpoint");
        when(request.getMethod()).thenReturn("GET");
        when(request.getLocalPort()).thenReturn(9443);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        // Should reject the request
        verify(chain, never()).doFilter(request, response);
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_NOT_FOUND),
                eq("Endpoint not available on this port"));
    }

    @Test
    public void testConfigurationBasedUnrestrictedPort() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");

        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/any/endpoint");
        when(request.getMethod()).thenReturn("GET");
        when(request.getLocalPort()).thenReturn(4443); // Port 4443 is unrestricted in test config

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        // Should allow the request (unrestricted port)
        verify(chain, times(1)).doFilter(request, response);
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    public void testMethodNotAllowedForEndpoint() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/zts/v1/instance");
        when(request.getMethod()).thenReturn("GET");
        when(request.getLocalPort()).thenReturn(9443);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        // Endpoint only allows POST, so GET is rejected
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_NOT_FOUND),
                eq("Endpoint not available on this port"));
    }

    @Test
    public void testConfigurationBasedStatusPortAllowsZtsStatusAndLegacyStatus() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // GET /zts/v1/status on 8443 (ZTS API status - returns JSON, feature parity with legacy)
        HttpServletRequest requestZts = mock(HttpServletRequest.class);
        when(requestZts.getServletPath()).thenReturn("");
        when(requestZts.getPathInfo()).thenReturn("/zts/v1/status");
        when(requestZts.getMethod()).thenReturn("GET");
        when(requestZts.getLocalPort()).thenReturn(8443);
        filter.doFilter(requestZts, response, chain);
        verify(chain).doFilter(requestZts, response);
        verify(response, never()).sendError(anyInt(), anyString());

        // GET /status on 8443 (legacy file-based health check returning OK)
        HttpServletRequest requestStatus = mock(HttpServletRequest.class);
        when(requestStatus.getServletPath()).thenReturn("");
        when(requestStatus.getPathInfo()).thenReturn("/status");
        when(requestStatus.getMethod()).thenReturn("GET");
        when(requestStatus.getLocalPort()).thenReturn(8443);
        filter.doFilter(requestStatus, response, chain);
        verify(chain, times(2)).doFilter(any(), any());
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    public void testDestroy() throws ServletException {
        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);
        filter.destroy();
        // Should not throw exception
    }

    @Test
    public void testHttpMethodFiltering() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        // Test POST allowed on /zts/v1/instance (port 9443 in valid-config.json)
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/zts/v1/instance");
        when(request.getMethod()).thenReturn("POST");
        when(request.getLocalPort()).thenReturn(9443);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);

        // Test GET not allowed for /zts/v1/instance
        reset(chain, response);
        when(request.getMethod()).thenReturn("GET");

        filter.doFilter(request, response, chain);
        verify(chain, never()).doFilter(request, response);
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_NOT_FOUND),
                eq("Endpoint not available on this port"));
    }

    @Test
    public void testExactPathMatching() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/valid-config.json");
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        // valid-config.json: port 9443 has exact path /zts/v1/instance (POST only)
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        when(request.getLocalPort()).thenReturn(9443);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // Exact match: path in config is "/zts/v1/instance", POST allowed
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/zts/v1/instance");
        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(request, response);

        // Path not in config is rejected
        reset(chain, response);
        when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/other/path");
        filter.doFilter(request, response, chain);
        verify(chain, never()).doFilter(request, response);
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_NOT_FOUND),
                eq("Endpoint not available on this port"));
    }

    @Test
    public void testConfigurationBasedPortWithNullAllowedEndpoints() throws ServletException, IOException {
        // Test the null/empty allowed_endpoints branch (unrestricted port) by creating a config with no endpoints
        String customConfig = "{\n" +
                "  \"ports\": [\n" +
                "    {\n" +
                "      \"port\": 9447,\n" +
                "      \"mtls_required\": false,\n" +
                "      \"description\": \"Test port with no endpoints\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        Path configFile = Files.createTempFile("port-uri-null-endpoints", ".json");
        Files.write(configFile, customConfig.getBytes());

        try {
            System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configFile.toString());
            PortUriConfigurationManager.resetForTesting();

            FilterConfig filterConfig = mock(FilterConfig.class);
            PortFilter filter = new PortFilter();
            filter.init(filterConfig);

            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/any/path");
            when(request.getMethod()).thenReturn("GET");
            when(request.getLocalPort()).thenReturn(9447);

            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);

            filter.doFilter(request, response, chain);

            // Should allow since allowed_endpoints is null (unrestricted)
            verify(chain, times(1)).doFilter(request, response);
            verify(response, never()).sendError(anyInt(), anyString());
        } finally {
            Files.deleteIfExists(configFile);
            PortUriConfigurationManager.resetForTesting();
        }
    }

    @Test
    public void testPathStartsWithAndPathEndsWithMatching() throws ServletException, IOException {
        System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                "src/test/resources/port-uri-configs/path-prefix-suffix-config.json");
        PortUriConfigurationManager.resetForTesting();

        FilterConfig filterConfig = mock(FilterConfig.class);
        PortFilter filter = new PortFilter();
        filter.init(filterConfig);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        // path_starts_with "/zts/v1/" allows /zts/v1/instance (GET)
        HttpServletRequest request1 = mock(HttpServletRequest.class);
        when(request1.getServletPath()).thenReturn("");
        when(request1.getPathInfo()).thenReturn("/zts/v1/instance");
        when(request1.getMethod()).thenReturn("GET");
        when(request1.getLocalPort()).thenReturn(9444);
        filter.doFilter(request1, response, chain);
        verify(chain, times(1)).doFilter(any(), any());

        // path_ends_with "/keys" allows /zts/v1/oauth2/keys (GET)
        HttpServletRequest request2 = mock(HttpServletRequest.class);
        when(request2.getServletPath()).thenReturn("");
        when(request2.getPathInfo()).thenReturn("/zts/v1/oauth2/keys");
        when(request2.getMethod()).thenReturn("GET");
        when(request2.getLocalPort()).thenReturn(9444);
        filter.doFilter(request2, response, chain);
        verify(chain, times(2)).doFilter(any(), any());

        // both path_starts_with "/zts/v1/" and path_ends_with "/status" allows /zts/v1/status (GET)
        HttpServletRequest request3 = mock(HttpServletRequest.class);
        when(request3.getServletPath()).thenReturn("");
        when(request3.getPathInfo()).thenReturn("/zts/v1/status");
        when(request3.getMethod()).thenReturn("GET");
        when(request3.getLocalPort()).thenReturn(9444);
        filter.doFilter(request3, response, chain);
        verify(chain, times(3)).doFilter(any(), any());

        // path that ends with /status but does not start with /zts/v1/ is rejected by third endpoint
        // but /zts/v1/status matches first endpoint (path_starts_with) so it's allowed - already tested
        // /other/status: no path_starts_with /zts/v1/, no path_ends_with /keys, third needs both prefix and suffix - /other/status doesn't start with /zts/v1/ -> rejected
        reset(chain, response);
        HttpServletRequest request4 = mock(HttpServletRequest.class);
        when(request4.getServletPath()).thenReturn("");
        when(request4.getPathInfo()).thenReturn("/other/status");
        when(request4.getMethod()).thenReturn("GET");
        when(request4.getLocalPort()).thenReturn(9444);
        filter.doFilter(request4, response, chain);
        verify(chain, never()).doFilter(any(), any());
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_NOT_FOUND), anyString());
    }

    @Test
    public void testExactPathTakesPrecedenceOverStartsWithEndsWith() throws ServletException, IOException {
        // When "path" is set, exact match is used; path_starts_with/path_ends_with are ignored for that endpoint
        String configWithPath = "{\n" +
                "  \"ports\": [\n" +
                "    {\n" +
                "      \"port\": 9450,\n" +
                "      \"mtls_required\": false,\n" +
                "      \"description\": \"Exact path only\",\n" +
                "      \"allowed_endpoints\": [\n" +
                "        {\n" +
                "          \"path\": \"/exact/only\",\n" +
                "          \"path_starts_with\": \"/exact\",\n" +
                "          \"methods\": [\"GET\"]\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        Path configFile = Files.createTempFile("port-uri-exact-path", ".json");
        Files.write(configFile, configWithPath.getBytes());

        try {
            System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG, configFile.toString());
            PortUriConfigurationManager.resetForTesting();

            FilterConfig filterConfig = mock(FilterConfig.class);
            PortFilter filter = new PortFilter();
            filter.init(filterConfig);

            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);

            // /exact/only matches (exact path)
            HttpServletRequest request1 = mock(HttpServletRequest.class);
            when(request1.getServletPath()).thenReturn("");
        when(request1.getPathInfo()).thenReturn("/exact/only");
            when(request1.getMethod()).thenReturn("GET");
            when(request1.getLocalPort()).thenReturn(9450);
            filter.doFilter(request1, response, chain);
            verify(chain, times(1)).doFilter(any(), any());

            // /exact/other does NOT match (path is exact /exact/only only; path_starts_with is ignored)
            reset(chain, response);
            HttpServletRequest request2 = mock(HttpServletRequest.class);
            when(request2.getServletPath()).thenReturn("");
        when(request2.getPathInfo()).thenReturn("/exact/other");
            when(request2.getMethod()).thenReturn("GET");
            when(request2.getLocalPort()).thenReturn(9450);
            filter.doFilter(request2, response, chain);
            verify(chain, never()).doFilter(any(), any());
            verify(response, times(1)).sendError(eq(HttpServletResponse.SC_NOT_FOUND), anyString());
        } finally {
            Files.deleteIfExists(configFile);
            PortUriConfigurationManager.resetForTesting();
        }
    }

    @Test
    public void testDebugLoggingDisabled() throws ServletException, IOException {
        // Save current log level
        Logger portFilterLogger = (Logger) LoggerFactory.getLogger(PortFilter.class);
        Level savedLevel = portFilterLogger.getLevel();

        try {
            // Disable DEBUG logging to cover the false branches of isDebugEnabled() checks
            portFilterLogger.setLevel(Level.INFO);

            System.setProperty(AthenzConsts.ATHENZ_PROP_PORT_URI_CONFIG,
                    "src/test/resources/port-uri-configs/valid-config.json");
            PortUriConfigurationManager.resetForTesting();

            FilterConfig filterConfig = mock(FilterConfig.class);
            PortFilter filter = new PortFilter();
            filter.init(filterConfig);

            // Test unrestricted port (4443) - debug log branch when DEBUG disabled
            HttpServletRequest request = mock(HttpServletRequest.class);
            when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/any/endpoint");
            when(request.getMethod()).thenReturn("GET");
            when(request.getLocalPort()).thenReturn(4443);

            HttpServletResponse response = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);

            filter.doFilter(request, response, chain);
            verify(chain, times(1)).doFilter(request, response);

            // Test allowed endpoint - debug log branch when DEBUG disabled
            reset(chain, response);
            when(request.getLocalPort()).thenReturn(9443);
            when(request.getServletPath()).thenReturn("");
        when(request.getPathInfo()).thenReturn("/zts/v1/instance");
            when(request.getMethod()).thenReturn("POST");

            filter.doFilter(request, response, chain);
            verify(chain, times(1)).doFilter(request, response);

        } finally {
            // Restore original log level
            portFilterLogger.setLevel(savedLevel);
            PortUriConfigurationManager.resetForTesting();
        }
    }

}