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
package com.yahoo.athenz.container.log;

import java.io.IOException;

import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;

public class AthenzRequestLog extends NCSARequestLog {

    protected static final Logger LOG = Log.getLogger(AthenzRequestLog.class);

    public static final String REQUEST_PRINCIPAL = "com.yahoo.athenz.auth.principal";
    
    public AthenzRequestLog() {
    }
    
    public AthenzRequestLog(String filename) {
        super(filename);
    }
    
    @Override
    public void logExtended(StringBuilder b, Request request, Response response)
            throws IOException {
        
        super.logExtended(b, request, response);
        
        Object principal = request.getAttribute(REQUEST_PRINCIPAL);
        if (principal == null) {
            b.append(" \"-\" ");
        } else {
            b.append(" \"");
            b.append(principal.toString());
            b.append("\" ");
        }
        
        long requestLength = request.getContentLengthLong();
        if (requestLength >= 0) {
            if (requestLength > 99999) {
                b.append(requestLength);
            } else {
                if (requestLength > 9999) {
                    b.append((char) ('0' + ((requestLength / 10000) % 10)));
                }
                if (requestLength > 999) {
                    b.append((char) ('0' + ((requestLength / 1000) % 10)));
                }
                if (requestLength > 99) {
                    b.append((char) ('0' + ((requestLength / 100) % 10)));
                }
                if (requestLength > 9) {
                    b.append((char) ('0' + ((requestLength / 10) % 10)));
                }
                b.append((char) ('0' + (requestLength) % 10));
            }
        } else {
            b.append('-');
        }
    }
}
