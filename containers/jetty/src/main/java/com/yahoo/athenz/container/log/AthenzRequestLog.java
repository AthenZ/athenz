/*
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
import java.util.Locale;

import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.DateCache;
import org.eclipse.jetty.http.HttpHeader;

public class AthenzRequestLog extends NCSARequestLog {

    private static final String REQUEST_PRINCIPAL      = "com.yahoo.athenz.auth.principal";
    private static final String REQUEST_AUTHORITY_ID   = "com.yahoo.athenz.auth.authority_id";
    private static final String REQUEST_URI_SKIP_QUERY = "com.yahoo.athenz.uri.skip_query";
    private static final String REQUEST_URI_ADDL_QUERY = "com.yahoo.athenz.uri.addl_query";

    private static final ThreadLocal<StringBuilder> TLS_BUILDER = ThreadLocal.withInitial(() -> new StringBuilder(256));

    private final String logDateFormat = "dd/MMM/yyyy:HH:mm:ss Z";
    private final String logTimeZone = "GMT";
    private transient DateCache logDateCache = new DateCache(logDateFormat, Locale.getDefault(), logTimeZone);
    
    public AthenzRequestLog(String filename) {
        super(filename);
    }

    private void logLength(StringBuilder buf, long length) {

        if (length >= 0L) {
            if (length > 99999L) {
                buf.append(length);
            } else {
                if (length > 9999L) {
                    buf.append((char) ((int) (48L + length / 10000L % 10L)));
                }

                if (length > 999L) {
                    buf.append((char) ((int) (48L + length / 1000L % 10L)));
                }

                if (length > 99L) {
                    buf.append((char) ((int) (48L + length / 100L % 10L)));
                }

                if (length > 9L) {
                    buf.append((char) ((int) (48L + length / 10L % 10L)));
                }

                buf.append((char) ((int) (48L + length % 10L)));
            }
        } else {
            buf.append('-');
        }
    }

    private void logStatus(StringBuilder buf, int status) {

        if (status >= 0) {
            buf.append((char) (48 + status / 100 % 10));
            buf.append((char) (48 + status / 10 % 10));
            buf.append((char) (48 + status % 10));
        } else {
            buf.append(status);
        }
    }

    private void logRequestUri(StringBuilder buf, Request request) {
        final Object skipQuery = request.getAttribute(REQUEST_URI_SKIP_QUERY);
        append(buf, (skipQuery == Boolean.TRUE) ? request.getRequestURI() : request.getOriginalURI());
        final Object addlQuery = request.getAttribute(REQUEST_URI_ADDL_QUERY);
        if (addlQuery != null) {
            buf.append('?');
            buf.append(addlQuery.toString());
        }
    }

    private void logPrincipal(StringBuilder buf, Request request) {
        final Object principal = request.getAttribute(REQUEST_PRINCIPAL);
        append(buf, (principal == null) ? null : principal.toString());
    }

    private void logAuthorityId(StringBuilder buf, Request request) {
        final Object authId = request.getAttribute(REQUEST_AUTHORITY_ID);
        append(buf, (authId == null) ? "Auth-None" : authId.toString());
    }

    private void append(StringBuilder buf, String str) {
        if (str != null && !str.isEmpty()) {
            buf.append(str);
        } else {
            buf.append('-');
        }
    }

    @Override
    public void log(Request request, Response response) {
        try {
            if (!this.isEnabled()) {
                return;
            }

            StringBuilder buf = TLS_BUILDER.get();
            buf.setLength(0);

            String addr = request.getHeader(HttpHeader.X_FORWARDED_FOR.toString());
            if (addr == null) {
                addr = request.getRemoteAddr();
            }
            buf.append(addr);
            buf.append(" - ");
            logPrincipal(buf, request);

            buf.append(" [");
            buf.append(logDateCache.format(request.getTimeStamp()));
            buf.append("] \"");

            append(buf, request.getMethod());
            buf.append(' ');

            logRequestUri(buf, request);
            buf.append(' ');

            append(buf, request.getProtocol());
            buf.append("\" ");

            logStatus(buf, response.getCommittedMetaData().getStatus());
            buf.append(' ');

            logLength(buf, response.getHttpChannel().getBytesWritten());
            buf.append(' ');

            logExtended(buf, request, response);

            buf.append(' ');
            logLength(buf, request.getContentLengthLong());

            buf.append(' ');
            buf.append(System.currentTimeMillis() - request.getTimeStamp());

            buf.append(' ');
            logAuthorityId(buf, request);

            write(buf.toString());

        } catch (IOException ex) {
            LOG.warn(ex);
        }
    }
}
