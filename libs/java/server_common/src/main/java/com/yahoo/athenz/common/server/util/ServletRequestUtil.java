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

import jakarta.servlet.http.HttpServletRequest;
import com.google.common.net.InetAddresses;

public class ServletRequestUtil {

    public static final String LOOPBACK_ADDRESS = "127.0.0.1";
    public static final String XFF_HEADER       = "X-Forwarded-For";

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
}

