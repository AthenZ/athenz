/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.log.jetty;

import com.yahoo.athenz.common.metrics.Metric;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.SocketChannelEndPoint;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.io.ssl.SslHandshakeListener;
import org.testng.annotations.Test;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import static com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger.GENERAL_SSL_ERROR;
import static com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger.CONNECTION_LOGGER_METRIC_DEFAULT_NAME;
import static org.mockito.Mockito.when;

import static org.testng.Assert.*;

public class JettyConnectionLoggerTest {

    @Test
    public void testStartStopConnectionFailedHandshake() throws Exception {
        // First start 2 connections
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);

        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);
        jettyConnectionLogger.doStart();

        MockedConnection failedMockedConnection = getMockConnection();
        SslConnection mockConnection2 = failedMockedConnection.sslConnection;

        AthenzConnectionListener athenzConnectionListener = new AthenzConnectionListener();
        athenzConnectionListener.onOpened(mockConnection2);
        
        // Now simulate handshake failure for mockConnection2
        SslHandshakeListener.Event event = Mockito.mock(SslHandshakeListener.Event.class);
        when(event.getSSLEngine()).thenReturn(failedMockedConnection.sslEngine);
        SSLHandshakeException sslHandshakeException = new SSLHandshakeException("no cipher suites in common");

        ArgumentCaptor<ConnectionLogEntry> connectionLogEntryArgumentCaptor = ArgumentCaptor.forClass(ConnectionLogEntry.class);
        ArgumentCaptor<String[]> metricArgumentCaptor = ArgumentCaptor.forClass(String[].class);
        when(mockConnection2.getEndPoint().isOpen()).thenReturn(false);

        jettyConnectionLogger.handshakeFailed(event, sslHandshakeException);
        
        Mockito.verify(connectionLog, Mockito.times(1)).log(connectionLogEntryArgumentCaptor.capture());
        Mockito.verify(metric, Mockito.times(1)).increment(Mockito.eq(CONNECTION_LOGGER_METRIC_DEFAULT_NAME), metricArgumentCaptor.capture());
        assertEquals("no cipher suites in common", connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureMessage().get());
        assertFalse(connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureCause().isPresent());
        List<String[]> allMetricValues = metricArgumentCaptor.getAllValues();
        assertEquals(allMetricValues.size(), 1);
        String[] testValue = allMetricValues.get(0);
        assertEquals(testValue.length, 4);
        assertEquals("failureType", testValue[0]);
        assertEquals("INCOMPATIBLE_CLIENT_CIPHER_SUITES", testValue[1]);
        assertEquals("athenzPrincipal", testValue[2]);
        assertEquals("unknown", testValue[3]);

        athenzConnectionListener.onClosed(mockConnection2);
        athenzConnectionListener.shutdown();
        jettyConnectionLogger.doStop();
    }

    @Test
    public void testFailedHandshakeInnerCause() throws Exception {
        // First start q connection
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);
        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);
        jettyConnectionLogger.doStart();

        MockedConnection failedMockedConnection = getMockConnection();
        SslConnection mockConnection = failedMockedConnection.sslConnection;

        AthenzConnectionListener athenzConnectionListener = new AthenzConnectionListener();
        athenzConnectionListener.onOpened(mockConnection);
        
        // Now simulate handshake failure for mockConnection
        SslHandshakeListener.Event event = Mockito.mock(SslHandshakeListener.Event.class);
        when(event.getSSLEngine()).thenReturn(failedMockedConnection.sslEngine);
        SSLHandshakeException sslHandshakeException = new SSLHandshakeException(GENERAL_SSL_ERROR);
        SSLHandshakeException innerCause1 = new SSLHandshakeException(GENERAL_SSL_ERROR);
        SSLHandshakeException innerCause2 = new SSLHandshakeException(GENERAL_SSL_ERROR);
        SSLHandshakeException innerCause3 = new SSLHandshakeException("Last cause (most specific reason)");
        innerCause2.initCause(innerCause3);
        innerCause1.initCause(innerCause2);
        sslHandshakeException.initCause(innerCause1);

        ArgumentCaptor<ConnectionLogEntry> connectionLogEntryArgumentCaptor = ArgumentCaptor.forClass(ConnectionLogEntry.class);
        when(mockConnection.getEndPoint().isOpen()).thenReturn(false);

        jettyConnectionLogger.handshakeFailed(event, sslHandshakeException);

        Mockito.verify(connectionLog, Mockito.times(1)).log(connectionLogEntryArgumentCaptor.capture());
        assertEquals(GENERAL_SSL_ERROR, connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureMessage().get());
        assertEquals("Last cause (most specific reason)", connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureCause().get());

        athenzConnectionListener.onClosed(mockConnection);
        athenzConnectionListener.shutdown();
        jettyConnectionLogger.doStop();
    }

    static MockedConnection getMockConnection() throws Exception {
        MockedConnection mockedConnection = new MockedConnection();
        SSLEngine sslEngine = Mockito.mock(SSLEngine.class);
        mockedConnection.sslEngine = sslEngine;
        SslConnection sslConnection = Mockito.mock(SslConnection.class);
        when(sslConnection.getSSLEngine()).thenReturn(sslEngine);
        SocketChannelEndPoint socketChannelEndPoint = Mockito.mock(SocketChannelEndPoint.class);
        when(socketChannelEndPoint.getLocalAddress()).thenReturn(new InetSocketAddress(InetAddress.getLocalHost(), 4444));
        when(socketChannelEndPoint.getRemoteAddress()).thenReturn(new InetSocketAddress(InetAddress.getLocalHost(), 5555));
        when(sslConnection.getEndPoint()).thenReturn(socketChannelEndPoint);
        mockedConnection.endpoint = socketChannelEndPoint;
        mockedConnection.sslConnection = sslConnection;
        return mockedConnection;
    }

    static class MockedConnection {
        SSLEngine sslEngine;
        SslConnection sslConnection;
        EndPoint endpoint;
    }
}
