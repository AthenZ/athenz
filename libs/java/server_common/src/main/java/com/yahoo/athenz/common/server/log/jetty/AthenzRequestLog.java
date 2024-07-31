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
package com.yahoo.athenz.common.server.log.jetty;

import java.io.IOException;
import java.util.Locale;

import com.yahoo.athenz.common.ServerCommonConsts;
import org.apache.http.conn.util.InetAddressUtils;
import org.eclipse.jetty.server.CustomRequestLog;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.util.DateCache;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSession;

public class AthenzRequestLog extends CustomRequestLog {

    private static final Logger LOG = LoggerFactory.getLogger(AthenzRequestLog.class);

    private static final String LOOPBACK_ADDRESS       = "127.0.0.1";

    private static final ThreadLocal<StringBuilder> TLS_BUILDER = ThreadLocal.withInitial(() -> new StringBuilder(256));

    private final String logDateFormat = "dd/MMM/yyyy:HH:mm:ss Z";
    private final String logTimeZone = "GMT";
    private final transient DateCache logDateCache = new DateCache(logDateFormat, Locale.getDefault(), logTimeZone);

    private boolean logForwardedForAddr = false;

    public AthenzRequestLog(String filename) {
        super(filename);
    }

    public AthenzRequestLog(RequestLog.Writer writer) {
        super(writer, "%{client}a - %u %t \"%r\" %s %O \"%{Referer}i\" \"%{User-Agent}i\"");
    }

    public void setLogForwardedForAddr(boolean logForwardedForAddr) {
        this.logForwardedForAddr = logForwardedForAddr;
    }

    private void logLength(StringBuilder buf, long length) {

        if (length >= 0L) {
            buf.append(length);
        } else {
            buf.append('-');
        }
    }

    private void logRequestUri(StringBuilder buf, Request request) {
        final Object skipQuery = request.getAttribute(ServerCommonConsts.REQUEST_URI_SKIP_QUERY);
        append(buf, (skipQuery == Boolean.TRUE) ? request.getHttpURI().getPath() : request.getHttpURI().getPathQuery());
        final Object addlQuery = request.getAttribute(ServerCommonConsts.REQUEST_URI_ADDL_QUERY);
        if (addlQuery != null) {
            buf.append('?');
            buf.append(addlQuery);
        }
    }

    private void logPrincipal(StringBuilder buf, Request request) {
        final Object principal = request.getAttribute(ServerCommonConsts.REQUEST_PRINCIPAL);
        append(buf, (principal == null) ? null : principal.toString());
    }

    private void logAuthorityId(StringBuilder buf, Request request) {
        final Object authId = request.getAttribute(ServerCommonConsts.REQUEST_AUTHORITY_ID);
        append(buf, (authId == null) ? "Auth-None" : authId.toString());
    }

    private void logX509Serial(StringBuilder buf, Request request) {
        final Object serialNumber = request.getAttribute(ServerCommonConsts.REQUEST_X509_SERIAL);
        append(buf, (serialNumber == null) ? "-" : serialNumber.toString());
    }

    private void logTLSProtocol(StringBuilder buf, Request request) {
        SSLSession sslSession = (SSLSession) request.getAttribute(ServerCommonConsts.REQUEST_SSL_SESSION);
        append(buf, (sslSession == null) ? null : sslSession.getProtocol());
        buf.append(' ');
        append(buf, (sslSession == null) ? null : sslSession.getCipherSuite());
    }

    private void append(StringBuilder buf, String str) {
        if (StringUtil.isEmpty(str)) {
            buf.append('-');
        } else {
            buf.append(str);
        }
    }

    private void logRemoteAddr(StringBuilder buf, Request request) {

        String addr = null;
        if (logForwardedForAddr) {
            addr = request.getHeaders().get(HttpHeader.X_FORWARDED_FOR);
        }

        // if we have no x-forwarded-for header or if the value is specified,
        // but it's not a valid ipv4 or ipv6 address, we'll fall back to the
        // standard remote addr value from the request

        if (addr == null || (!InetAddressUtils.isIPv4Address(addr) && !InetAddressUtils.isIPv6Address(addr))) {
            addr = Request.getRemoteAddr(request);
        }

        if (StringUtil.isEmpty(addr)) {
            addr = LOOPBACK_ADDRESS;
        }

        buf.append(addr);
    }

    protected void logExtended(StringBuilder b, Request request) throws IOException {
        String referer = request.getHeaders().get(HttpHeader.REFERER.toString());
        if (referer == null) {
            b.append("\"-\" ");
        } else {
            b.append('"');
            b.append(referer);
            b.append("\" ");
        }

        String agent = request.getHeaders().get(HttpHeader.USER_AGENT.toString());
        if (agent == null) {
            b.append("\"-\"");
        } else {
            b.append('"');
            b.append(agent);
            b.append('"');
        }
    }

    @Override
    public void log(Request request, Response response) {
        try {
            StringBuilder buf = TLS_BUILDER.get();
            buf.setLength(0);

            logRemoteAddr(buf, request);
            buf.append(" - ");
            logPrincipal(buf, request);

            buf.append(" [");
            buf.append(logDateCache.format(Request.getTimeStamp(request)));
            buf.append("] \"");

            append(buf, request.getMethod());
            buf.append(' ');

            logRequestUri(buf, request);
            buf.append(' ');

            append(buf, request.getConnectionMetaData().getProtocol());
            buf.append("\" ");

            buf.append(response.getStatus());
            buf.append(' ');

            logLength(buf, Response.getContentBytesWritten(response));
            buf.append(' ');

            logExtended(buf, request);

            buf.append(' ');
            logLength(buf, Request.getContentBytesRead(request));

            buf.append(' ');
            buf.append(System.currentTimeMillis() - Request.getTimeStamp(request));

            buf.append(' ');
            logAuthorityId(buf, request);

            buf.append(' ');
            logTLSProtocol(buf, request);

            buf.append(' ');
            logX509Serial(buf, request);

            getWriter().write(buf.toString());

        } catch (IOException ex) {
            LOG.warn("unable to write log entry", ex);
        }
    }
}
