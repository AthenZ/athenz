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

import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.server.HttpChannel;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.http.HttpHeader;

import javax.net.ssl.SSLSession;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.testng.Assert.*;

public class AthenzRequestLogTest {

    private static final String REQUEST_PRINCIPAL      = "com.yahoo.athenz.auth.principal";
    private static final String REQUEST_AUTHORITY_ID   = "com.yahoo.athenz.auth.authority_id";
    private static final String REQUEST_URI_SKIP_QUERY = "com.yahoo.athenz.uri.skip_query";
    private static final String REQUEST_URI_ADDL_QUERY = "com.yahoo.athenz.uri.addl_query";
    private static final String REQUEST_SSL_SESSION    = "org.eclipse.jetty.servlet.request.ssl_session";

    private static final String TEST_FILE = "./unit-test-athenz.log";

    @BeforeMethod
    public void setup() throws IOException {
        // remove test file in case left over from previous runs
        File file = new File(TEST_FILE);
        Files.deleteIfExists(file.toPath());
    }

    @Test
    public void testAthenzRequestLogNotEnabled() {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        // since not enabled, nothing will be done

        athenzRequestLog.log(null, null);
    }

    @Test
    public void testAthenzRequestLogNullFields() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();

        Request request = Mockito.mock(Request.class);
        Response response = Mockito.mock(Response.class);

        Mockito.when(request.getRemoteAddr()).thenReturn("10.10.11.12");
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getOriginalURI()).thenReturn("/original-uri");
        Mockito.when(request.getProtocol()).thenReturn("HTTP/1.1");
        Mockito.when(request.getContentLengthLong()).thenReturn(-1L);

        MetaData.Response metaResponse = Mockito.mock(MetaData.Response.class);
        Mockito.when(metaResponse.getStatus()).thenReturn(-1);
        Mockito.when(response.getCommittedMetaData()).thenReturn(metaResponse);

        HttpChannel httpChannel = Mockito.mock(HttpChannel.class);
        Mockito.when(httpChannel.getBytesWritten()).thenReturn(1234L);
        Mockito.when(response.getHttpChannel()).thenReturn(httpChannel);

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.12 - - [01/Jan/1970:00:00:00 +0000] \"GET /original-uri HTTP/1.1\" -1 1234 \"-\" \"-\" -"), data);
        assertTrue(data.endsWith("Auth-None - -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogStatusValues1() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();

        Request request = Mockito.mock(Request.class);
        Response response = Mockito.mock(Response.class);

        Mockito.when(request.getRemoteAddr()).thenReturn("10.10.11.12");
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getOriginalURI()).thenReturn("/original-uri");
        Mockito.when(request.getProtocol()).thenReturn("HTTP/1.1");
        Mockito.when(request.getContentLengthLong()).thenReturn(10L);

        MetaData.Response metaResponse = Mockito.mock(MetaData.Response.class);
        Mockito.when(metaResponse.getStatus()).thenReturn(401);
        Mockito.when(response.getCommittedMetaData()).thenReturn(metaResponse);

        HttpChannel httpChannel = Mockito.mock(HttpChannel.class);
        Mockito.when(httpChannel.getBytesWritten()).thenReturn(100L);
        Mockito.when(response.getHttpChannel()).thenReturn(httpChannel);

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.12 - - [01/Jan/1970:00:00:00 +0000] \"GET /original-uri HTTP/1.1\" 401 100 \"-\" \"-\" 10"), data);
        assertTrue(data.endsWith("Auth-None - -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogStatusValues2() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();

        Request request = Mockito.mock(Request.class);
        Response response = Mockito.mock(Response.class);

        Mockito.when(request.getRemoteAddr()).thenReturn("10.10.11.12");
        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getOriginalURI()).thenReturn("/original-uri");
        Mockito.when(request.getProtocol()).thenReturn("HTTP/1.1");
        Mockito.when(request.getContentLengthLong()).thenReturn(3L);

        MetaData.Response metaResponse = Mockito.mock(MetaData.Response.class);
        Mockito.when(metaResponse.getStatus()).thenReturn(401);
        Mockito.when(response.getCommittedMetaData()).thenReturn(metaResponse);

        HttpChannel httpChannel = Mockito.mock(HttpChannel.class);
        Mockito.when(httpChannel.getBytesWritten()).thenReturn(5L);
        Mockito.when(response.getHttpChannel()).thenReturn(httpChannel);

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.12 - - [01/Jan/1970:00:00:00 +0000] \"GET /original-uri HTTP/1.1\" 401 5 \"-\" \"-\" 3"), data);
        assertTrue(data.endsWith("Auth-None - -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogAllFields() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();

        Request request = Mockito.mock(Request.class);
        Response response = Mockito.mock(Response.class);

        Mockito.when(request.getHeader(HttpHeader.X_FORWARDED_FOR.toString())).thenReturn("10.10.11.13");
        Mockito.when(request.getAttribute(REQUEST_PRINCIPAL)).thenReturn("athenz.zts");
        Mockito.when(request.getAttribute(REQUEST_AUTHORITY_ID)).thenReturn("Auth-X509");

        Mockito.when(request.getAttribute(REQUEST_URI_SKIP_QUERY)).thenReturn(Boolean.TRUE);
        Mockito.when(request.getRequestURI()).thenReturn("/request-uri");
        Mockito.when(request.getAttribute(REQUEST_URI_ADDL_QUERY)).thenReturn("query=true");

        Mockito.when(request.getMethod()).thenReturn("GET");
        Mockito.when(request.getProtocol()).thenReturn("HTTP/1.1");
        Mockito.when(request.getContentLengthLong()).thenReturn(102400L);

        MetaData.Response metaResponse = Mockito.mock(MetaData.Response.class);
        Mockito.when(metaResponse.getStatus()).thenReturn(200);
        Mockito.when(response.getCommittedMetaData()).thenReturn(metaResponse);

        HttpChannel httpChannel = Mockito.mock(HttpChannel.class);
        Mockito.when(httpChannel.getBytesWritten()).thenReturn(10240L);
        Mockito.when(response.getHttpChannel()).thenReturn(httpChannel);

        SSLSession sslSession = Mockito.mock(SSLSession.class);
        Mockito.when(request.getAttribute(REQUEST_SSL_SESSION)).thenReturn(sslSession);
        Mockito.when(sslSession.getProtocol()).thenReturn("TLSv1.2");
        Mockito.when(sslSession.getCipherSuite()).thenReturn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.13 - athenz.zts [01/Jan/1970:00:00:00 +0000] \"GET /request-uri?query=true HTTP/1.1\" 200 10240 \"-\" \"-\" 102400"), data);
        assertTrue(data.endsWith("Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n"), data);

        Files.delete(file.toPath());
    }
}
