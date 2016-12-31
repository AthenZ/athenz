
/**
 * Copyright 2016 Yahoo Inc.
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

import javax.servlet.http.HttpServletRequest;
import org.eclipse.jetty.server.Request;

import com.yahoo.rdl.Timestamp;

public class ServletRequestUtil {

    public static final String LOOPBACK_ADDRESS = "127.0.0.1";
    public static final String XFF_HEADER       = "X-Forwarded-For";

    /**
      * Return the remote client IP address.
      * Detect if connection is from ATS by looking at XFF header.
      * If XFF header, return the last address therein since it was added by ATS.
     **/
    public static String getRemoteAddress(final HttpServletRequest request) {
        String addr = request.getRemoteAddr();
        if (LOOPBACK_ADDRESS.equals(addr)) {
            String xff = request.getHeader(XFF_HEADER);
            if (xff != null) {
                String[] addrs = xff.split(",");
                addr = addrs[addrs.length - 1].trim();
            }
        }
        return addr;
    }

    /**
      * Returns RFC3339 based time stamp String.
     **/
    public static String getTimeStamp(final Request request) {
        Timestamp ts = Timestamp.fromMillis(request.getTimeStamp());
        return ts.toString();
    }

}

