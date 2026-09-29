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
package com.yahoo.athenz.container;

import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Request;

/**
 * Stamps every request with the configured port of the connector that accepted it
 * ({@link ServletRequestUtil#CONNECTOR_PORT_ATTRIBUTE}). Behind a PROXY-protocol
 * listener Jetty reports the proxy's advertised destination port through
 * getLocalPort(), so port-based authorization (port-uri.json, status/oidc port
 * checks) must rely on this attribute instead of the socket-level local port.
 */
public class ConnectorPortCustomizer implements HttpConfiguration.Customizer {

    private final int port;

    public ConnectorPortCustomizer(int port) {
        this.port = port;
    }

    public int getPort() {
        return port;
    }

    @Override
    public Request customize(Request request, HttpFields.Mutable responseHeaders) {
        request.setAttribute(ServletRequestUtil.CONNECTOR_PORT_ATTRIBUTE, port);
        return request;
    }
}
