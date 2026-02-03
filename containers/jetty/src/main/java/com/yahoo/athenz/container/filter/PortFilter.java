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

import com.yahoo.athenz.container.config.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Filter for port-based access control using port-uri.json configuration.
 * When port-uri.json is configured, requests are allowed or rejected per port and path/method rules.
 * When port-uri.json is not configured, all requests are passed through (no filtering).
 */
public class PortFilter implements jakarta.servlet.Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(PortFilter.class);

    private PortUriConfigurationManager configManager;
    private boolean useConfiguration = false;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        configManager = PortUriConfigurationManager.getInstance();

        if (configManager.isPortListConfigured()) {
            useConfiguration = true;
            LOGGER.info("PortFilter initialized with port-uri.json configuration");
        } else {
            LOGGER.info("PortFilter: port-uri.json not configured, all requests will be passed through");
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (useConfiguration) {
            if (rejectByPortConfig(request, response)) {
                return;
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Apply port-uri.json configuration; reject request if it does not match allowed port/endpoint rules.
     *
     * @return true if the request was rejected (response committed), false if the request should be passed through to the chain
     */
    private boolean rejectByPortConfig(HttpServletRequest request,
                                      HttpServletResponse response) throws IOException {

        final String requestUri = getRequestPath(request);
        final String method = request.getMethod();
        final int localPort = request.getLocalPort();

        PortConfig portConfig = configManager.getPortConfig(localPort);
        // When port-uri.json is in use, only configured ports have connectors, so portConfig is never null here.

        // If port has empty allowed_endpoints, it's unrestricted
        if (portConfig.getAllowedEndpoints() == null ||
                portConfig.getAllowedEndpoints().isEmpty()) {
            LOGGER.debug("Port {} is unrestricted, allowing request to {}", localPort, requestUri);
            return false;
        }

        // Check if request matches any allowed endpoint
        for (EndpointConfig endpoint : portConfig.getAllowedEndpoints()) {
            if (matchesEndpoint(requestUri, method, endpoint)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Request {} {} allowed on port {} (matched {})",
                            method, requestUri, localPort, getMatchDescription(endpoint));
                }
                return false;
            }
        }

        // No matching endpoint found, reject
        LOGGER.error("Request {} {} rejected on port {} (no matching endpoint)", method, requestUri, localPort);

        response.sendError(HttpServletResponse.SC_NOT_FOUND,
                "Endpoint not available on this port");
        return true;
    }

    /**
     * Check if request matches an endpoint configuration.
     * If "path" is configured, exact match is used. Otherwise "path_starts_with" and/or
     * "path_ends_with" are applied (both must match when both are configured).
     */
    private boolean matchesEndpoint(String requestUri, String method, EndpointConfig endpoint) {
        if (!pathMatches(requestUri, endpoint)) {
            return false;
        }
        return endpoint.allowsMethod(method);
    }

    private boolean pathMatches(String requestUri, EndpointConfig endpoint) {
        String path = endpoint.getPath();
        if (path != null && !path.isEmpty()) {
            return path.equals(requestUri);
        }
        String startsWith = endpoint.getPathStartsWith();
        String endsWith = endpoint.getPathEndsWith();
        if ((startsWith == null || startsWith.isEmpty()) && (endsWith == null || endsWith.isEmpty())) {
            return false;
        }
        if (startsWith != null && !startsWith.isEmpty() && !requestUri.startsWith(startsWith)) {
            return false;
        }
        if (endsWith != null && !endsWith.isEmpty() && !requestUri.endsWith(endsWith)) {
            return false;
        }
        return true;
    }

    private String getMatchDescription(EndpointConfig endpoint) {
        if (endpoint.getPath() != null && !endpoint.getPath().isEmpty()) {
            return "path " + endpoint.getPath();
        }
        StringBuilder sb = new StringBuilder();
        if (endpoint.getPathStartsWith() != null && !endpoint.getPathStartsWith().isEmpty()) {
            sb.append("path_starts_with ").append(endpoint.getPathStartsWith());
        }
        if (endpoint.getPathEndsWith() != null && !endpoint.getPathEndsWith().isEmpty()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append("path_ends_with ").append(endpoint.getPathEndsWith());
        }
        return sb.length() > 0 ? sb.toString() : "endpoint";
    }

    /**
     * Returns the decoded full path (context + servlet path + path info) for the request.
     * Used for matching to avoid bypass via encoded or ambiguous URIs. Query string is not included.
     */
    private static String getRequestPath(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();
        String pathInfo = request.getPathInfo();
        return (contextPath != null ? contextPath : "")
                + (servletPath != null ? servletPath : "")
                + (pathInfo != null ? pathInfo : "");
    }

    @Override
    public void destroy() {
    }
}
