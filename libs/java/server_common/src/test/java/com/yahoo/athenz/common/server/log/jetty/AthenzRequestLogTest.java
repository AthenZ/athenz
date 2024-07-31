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

import com.yahoo.athenz.common.ServerCommonConsts;
import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.internal.HttpChannelState;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import org.eclipse.jetty.http.HttpHeader;

import javax.net.ssl.SSLSession;

import java.io.File;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.util.Locale;

import static org.testng.Assert.*;

public class AthenzRequestLogTest {

    private static final String TEST_FILE = "./unit-test-athenz.log";

    private Locale defaultLocale;

    @BeforeMethod
    public void setup() throws IOException {
        // remove test file in case left over from previous runs
        File file = new File(TEST_FILE);
        Files.deleteIfExists(file.toPath());

        defaultLocale = Locale.getDefault();
        Locale.setDefault(Locale.ENGLISH);
    }

    @AfterMethod
    public void cleanup() {
        Locale.setDefault(defaultLocale);
    }

    @Test
    public void testAthenzRequestLogNullFields() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();
        athenzRequestLog.setLogForwardedForAddr(true);

        HttpChannelState.ChannelRequest request = Mockito.mock(HttpChannelState.ChannelRequest.class);
        HttpChannelState.ChannelResponse response = Mockito.mock(HttpChannelState.ChannelResponse.class);

        HttpFields httpFields = Mockito.mock(HttpFields.class);
        Mockito.when(request.getHeaders()).thenReturn(httpFields);

        //invalid ip so it should be ignored
        Mockito.when(httpFields.get(HttpHeader.X_FORWARDED_FOR.toString())).thenReturn("invalid-ip");

        ConnectionMetaData connectionMetaData = Mockito.mock(ConnectionMetaData.class);
        Mockito.when(request.getConnectionMetaData()).thenReturn(connectionMetaData);
        Mockito.when(connectionMetaData.getRemoteSocketAddress()).thenReturn(new SocketAddress() {
            @Override
            public String toString() {
                return "10.10.11.12";
            }});
        Mockito.when(request.getMethod()).thenReturn("GET");

        HttpURI httpURI = Mockito.mock(HttpURI.class);
        Mockito.when(request.getHttpURI()).thenReturn(httpURI);

        Mockito.when(httpURI.getPathQuery()).thenReturn("/original-uri");
        Mockito.when(connectionMetaData.getProtocol()).thenReturn("HTTP/1.1");

        Mockito.when(response.getStatus()).thenReturn(-1);

        Mockito.when(request.getContentBytesRead()).thenReturn(-1L);
        Mockito.when(response.getContentBytesWritten()).thenReturn(1234L);

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.12 - - ["), data);
        assertTrue(data.contains("] \"GET /original-uri HTTP/1.1\" -1 1234 \"-\" \"-\" -"), data);
        assertTrue(data.endsWith("Auth-None - - -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogStatusValues1() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();
        athenzRequestLog.setLogForwardedForAddr(true);

        HttpChannelState.ChannelRequest request = Mockito.mock(HttpChannelState.ChannelRequest.class);
        HttpChannelState.ChannelResponse response = Mockito.mock(HttpChannelState.ChannelResponse.class);

        // valid IPv4 value which should be accepted
        ConnectionMetaData connectionMetaData = Mockito.mock(ConnectionMetaData.class);
        Mockito.when(request.getConnectionMetaData()).thenReturn(connectionMetaData);
        Mockito.when(connectionMetaData.getRemoteSocketAddress()).thenReturn(new SocketAddress() {
            @Override
            public String toString() {
                return "10.10.11.12";
            }});

        HttpFields httpFields = Mockito.mock(HttpFields.class);
        Mockito.when(request.getHeaders()).thenReturn(httpFields);
        Mockito.when(httpFields.get(HttpHeader.X_FORWARDED_FOR)).thenReturn("10.11.12.13");

        Mockito.when(request.getMethod()).thenReturn("GET");
        HttpURI httpURI = Mockito.mock(HttpURI.class);
        Mockito.when(request.getHttpURI()).thenReturn(httpURI);

        Mockito.when(httpURI.getPathQuery()).thenReturn("/original-uri");
        Mockito.when(connectionMetaData.getProtocol()).thenReturn("HTTP/1.1");

        Mockito.when(request.getContentBytesRead()).thenReturn(10L);
        Mockito.when(response.getContentBytesWritten()).thenReturn(100L);
        Mockito.when(response.getStatus()).thenReturn(401);

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.11.12.13 - - ["), data);
        assertTrue(data.contains("] \"GET /original-uri HTTP/1.1\" 401 100 \"-\" \"-\" 10"), data);
        assertTrue(data.endsWith("Auth-None - - -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogStatusValues2() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();
        athenzRequestLog.setLogForwardedForAddr(true);

        HttpChannelState.ChannelRequest request = Mockito.mock(HttpChannelState.ChannelRequest.class);
        HttpChannelState.ChannelResponse response = Mockito.mock(HttpChannelState.ChannelResponse.class);

        ConnectionMetaData connectionMetaData = Mockito.mock(ConnectionMetaData.class);
        Mockito.when(request.getConnectionMetaData()).thenReturn(connectionMetaData);
        Mockito.when(connectionMetaData.getRemoteSocketAddress()).thenReturn(new SocketAddress() {
            @Override
            public String toString() {
                return "10.10.11.12";
            }});

        // valid IPv6 value which should be accepted
        HttpFields httpFields = Mockito.mock(HttpFields.class);
        Mockito.when(request.getHeaders()).thenReturn(httpFields);
        Mockito.when(httpFields.get(HttpHeader.X_FORWARDED_FOR)).thenReturn("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

        Mockito.when(request.getMethod()).thenReturn("GET");
        HttpURI httpURI = Mockito.mock(HttpURI.class);
        Mockito.when(request.getHttpURI()).thenReturn(httpURI);

        Mockito.when(httpURI.getPathQuery()).thenReturn("/original-uri");
        Mockito.when(connectionMetaData.getProtocol()).thenReturn("HTTP/1.1");

        Mockito.when(request.getContentBytesRead()).thenReturn(3L);
        Mockito.when(response.getContentBytesWritten()).thenReturn(5L);
        Mockito.when(response.getStatus()).thenReturn(401);

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - ["), data);
        assertTrue(data.contains("] \"GET /original-uri HTTP/1.1\" 401 5 \"-\" \"-\" 3"), data);
        assertTrue(data.endsWith("Auth-None - - -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogAllFields() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();
        athenzRequestLog.setLogForwardedForAddr(true);

        HttpChannelState.ChannelRequest request = Mockito.mock(HttpChannelState.ChannelRequest.class);
        HttpChannelState.ChannelResponse response = Mockito.mock(HttpChannelState.ChannelResponse.class);

        ConnectionMetaData connectionMetaData = Mockito.mock(ConnectionMetaData.class);
        Mockito.when(request.getConnectionMetaData()).thenReturn(connectionMetaData);
        Mockito.when(connectionMetaData.getRemoteSocketAddress()).thenReturn(new SocketAddress() {
            @Override
            public String toString() {
                return "10.10.11.12";
            }});

        HttpFields httpFields = Mockito.mock(HttpFields.class);
        Mockito.when(request.getHeaders()).thenReturn(httpFields);
        Mockito.when(httpFields.get(HttpHeader.X_FORWARDED_FOR)).thenReturn("10.10.11.13");

        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_PRINCIPAL)).thenReturn("athenz.zts");
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_AUTHORITY_ID)).thenReturn("Auth-X509");

        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_URI_SKIP_QUERY)).thenReturn(Boolean.TRUE);
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_URI_ADDL_QUERY)).thenReturn("query=true");
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_X509_SERIAL)).thenReturn("777");

        Mockito.when(request.getMethod()).thenReturn("GET");
        HttpURI httpURI = Mockito.mock(HttpURI.class);
        Mockito.when(request.getHttpURI()).thenReturn(httpURI);
        Mockito.when(httpURI.getPath()).thenReturn("/request-uri");
        Mockito.when(connectionMetaData.getProtocol()).thenReturn("HTTP/1.1");

        Mockito.when(request.getContentBytesRead()).thenReturn(102400L);
        Mockito.when(response.getContentBytesWritten()).thenReturn(10240L);
        Mockito.when(response.getStatus()).thenReturn(200);

        SSLSession sslSession = Mockito.mock(SSLSession.class);
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_SSL_SESSION)).thenReturn(sslSession);
        Mockito.when(sslSession.getProtocol()).thenReturn("TLSv1.2");
        Mockito.when(sslSession.getCipherSuite()).thenReturn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.13 - athenz.zts ["), data);
        assertTrue(data.contains("] \"GET /request-uri?query=true HTTP/1.1\" 200 10240 \"-\" \"-\" 102400"), data);
        assertTrue(data.endsWith("Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 777\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogXForwardedForDisabled() throws Exception {

        AthenzRequestLog athenzRequestLog = new AthenzRequestLog(TEST_FILE);
        assertNotNull(athenzRequestLog);

        athenzRequestLog.start();
        athenzRequestLog.setLogForwardedForAddr(false);

        HttpChannelState.ChannelRequest request = Mockito.mock(HttpChannelState.ChannelRequest.class);
        HttpChannelState.ChannelResponse response = Mockito.mock(HttpChannelState.ChannelResponse.class);

        ConnectionMetaData connectionMetaData = Mockito.mock(ConnectionMetaData.class);
        Mockito.when(request.getConnectionMetaData()).thenReturn(connectionMetaData);
        Mockito.when(connectionMetaData.getRemoteSocketAddress()).thenReturn(new SocketAddress() {
            @Override
            public String toString() {
                return "10.10.11.12";
            }});

        HttpFields httpFields = Mockito.mock(HttpFields.class);
        Mockito.when(request.getHeaders()).thenReturn(httpFields);
        Mockito.when(httpFields.get(HttpHeader.X_FORWARDED_FOR)).thenReturn("10.10.11.13");

        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_PRINCIPAL)).thenReturn("athenz.zts");
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_AUTHORITY_ID)).thenReturn("Auth-X509");

        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_URI_SKIP_QUERY)).thenReturn(Boolean.TRUE);
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_URI_ADDL_QUERY)).thenReturn("query=true");

        Mockito.when(request.getMethod()).thenReturn("GET");
        HttpURI httpURI = Mockito.mock(HttpURI.class);
        Mockito.when(request.getHttpURI()).thenReturn(httpURI);
        Mockito.when(httpURI.getPath()).thenReturn("/request-uri");
        Mockito.when(connectionMetaData.getProtocol()).thenReturn("HTTP/1.1");

        Mockito.when(request.getContentBytesRead()).thenReturn(102400L);
        Mockito.when(response.getContentBytesWritten()).thenReturn(10240L);
        Mockito.when(response.getStatus()).thenReturn(200);

        SSLSession sslSession = Mockito.mock(SSLSession.class);
        Mockito.when(request.getAttribute(ServerCommonConsts.REQUEST_SSL_SESSION)).thenReturn(sslSession);
        Mockito.when(sslSession.getProtocol()).thenReturn("TLSv1.2");
        Mockito.when(sslSession.getCipherSuite()).thenReturn("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        athenzRequestLog.log(request, response);
        athenzRequestLog.stop();

        File file = new File(TEST_FILE);
        final String data = new String(Files.readAllBytes(file.toPath()));

        assertTrue(data.startsWith("10.10.11.12 - athenz.zts ["), data);
        assertTrue(data.contains("] \"GET /request-uri?query=true HTTP/1.1\" 200 10240 \"-\" \"-\" 102400"), data);
        assertTrue(data.endsWith("Auth-X509 TLSv1.2 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -\n"), data);

        Files.delete(file.toPath());
    }

    @Test
    public void testAthenzRequestLogWithWriter() {
        RequestLogWriter logWriter = new RequestLogWriter(TEST_FILE);
        logWriter.setTimeZone("GMT");
        logWriter.setRetainDays(7);

        AthenzRequestLog requestLog = new AthenzRequestLog(logWriter);
        assertNotNull(requestLog);
    }
}
