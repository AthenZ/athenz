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
package com.yahoo.athenz.common.server.util;

import com.yahoo.athenz.auth.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import com.google.common.net.InetAddresses;
import org.eclipse.jetty.http.HttpHeader;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServletRequestUtil {

    public static final String LOOPBACK_ADDRESS = "127.0.0.1";
    public static final String XFF_HEADER       = "X-Forwarded-For";

    /**
     * Request attribute set by the Athenz Jetty container on every request with the
     * configured port of the connector that accepted the connection. Prefer it over
     * HttpServletRequest.getLocalPort() for port-based decisions: behind a PROXY-protocol
     * listener, getLocalPort() reports the destination port advertised by the upstream
     * proxy (e.g. its public edge port), not the port the request actually arrived on.
     */
    public static final String CONNECTOR_PORT_ATTRIBUTE = "com.yahoo.athenz.connector.port";
    public static final Pattern USER_AGENT_PATTERN       = Pattern.compile("SIA-([^ ]+)([ ]+[^ ]*|$)");

    /**
      * Return the remote client IP address.
      * Detect if connection is from local proxy server by looking at XFF header.
      * If XFF header, return the last address therein since it was added by
      * the proxy server.
      * @param request http servlet request
      * @return client remote address string
     **/
    public static String getRemoteAddress(final HttpServletRequest request) {
        String addr = request.getRemoteAddr();
        if (LOOPBACK_ADDRESS.equals(addr)) {
            String xff = request.getHeader(XFF_HEADER);
            if (xff != null) {
                String[] addrs = xff.split(",");
                final String xffAddr = addrs[addrs.length - 1].trim();
                if (InetAddresses.isInetAddress(xffAddr)) {
                    addr = xffAddr;
                }
            }
        }
        return addr;
    }

    /**
     * Return the port of the server connector that accepted this request. Uses the
     * CONNECTOR_PORT_ATTRIBUTE stamped by the container when present, otherwise falls
     * back to the servlet-reported local port.
     * @param request http servlet request
     * @return connector port
     */
    public static int getConnectorPort(final HttpServletRequest request) {
        Object port = request.getAttribute(CONNECTOR_PORT_ATTRIBUTE);
        if (port instanceof Integer) {
            return (Integer) port;
        }
        return request.getLocalPort();
    }

    /**
     * Return the SIA provider from user agent header, which is set by sia agent as request header.
     * SIA agent header value is in the format 'SIA-<provider> <version> like 'SIA-FARGATE 1.32.0'.
     * It extract just the provider name from the agent header value and return that.
     * @param request http servlet request
     * @return SIA provider
     **/
    public static String getSiaProvider(final HttpServletRequest request) {
        final String userAgent = request.getHeader(HttpHeader.USER_AGENT.asString());
        if (!StringUtils.isEmpty(userAgent)) {
            Matcher matcher = USER_AGENT_PATTERN.matcher(userAgent.trim());
            if (matcher.matches()) {
                return matcher.group(1);
            }
        }
        return null;
    }
}

