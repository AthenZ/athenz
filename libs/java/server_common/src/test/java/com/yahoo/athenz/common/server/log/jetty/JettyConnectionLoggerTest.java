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
import com.yahoo.athenz.common.server.log.jetty.ConnectionLog;
import com.yahoo.athenz.common.server.log.jetty.ConnectionLogEntry;
import com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.SocketChannelEndPoint;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.eclipse.jetty.io.ssl.SslHandshakeListener;
import org.eclipse.jetty.server.ProxyConnectionFactory;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import static com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger.GENERAL_SSL_ERROR;
import static com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger.METRIC_NAME;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class JettyConnectionLoggerTest {

    @Test
    public void testStartConnection() throws Exception {
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);
        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);
        SslConnection mockConnection = getMockConnection().sslConnection;
        jettyConnectionLogger.onOpened(mockConnection);
        Mockito.verify(mockConnection, Mockito.times(2)).getEndPoint();
        Mockito.verify(mockConnection.getEndPoint(), Mockito.times(1)).getLocalAddress();
        Mockito.verify(mockConnection.getEndPoint(), Mockito.times(1)).getRemoteAddress();
        Mockito.verify(mockConnection.getEndPoint(), Mockito.times(1)).getCreatedTimeStamp();
        Mockito.verify(mockConnection, Mockito.times(1)).getSSLEngine();
    }

    @Test
    public void testStartStopConnectionSuccessfulHandshake() throws Exception {
        // First start 2 connections
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);
        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);
        jettyConnectionLogger.doStart();
        SslConnection mockConnection1 = getMockConnection().sslConnection;
        jettyConnectionLogger.onOpened(mockConnection1);

        MockedConnection mockConnectionSuccessful = getMockConnection();
        SslConnection mockConnection2 = mockConnectionSuccessful.sslConnection;
        jettyConnectionLogger.onOpened(mockConnection1);
        jettyConnectionLogger.onOpened(mockConnection2);

        // Now keep endpoint open for mockConnection1 and verify it isn't logged
        when(mockConnection1.getEndPoint().isOpen()).thenReturn(true);
        jettyConnectionLogger.onClosed(mockConnection1);
        Mockito.verify(connectionLog, Mockito.times(0)).log(any());

        // Now close endpoint for mockConnection2 and verify it isn'g logged because the handshake was successful
        SslHandshakeListener.Event event = Mockito.mock(SslHandshakeListener.Event.class);
        when(event.getSSLEngine()).thenReturn(mockConnectionSuccessful.sslEngine);
        jettyConnectionLogger.handshakeSucceeded(event);

        when(mockConnection2.getEndPoint().isOpen()).thenReturn(false);
        jettyConnectionLogger.onClosed(mockConnection2);
        Mockito.verify(connectionLog, Mockito.times(0)).log(any());
        jettyConnectionLogger.doStop();
    }

    @Test
    public void testStartStopConnectionFailedHandshake() throws Exception {
        // First start 2 connections
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);

        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);
        SslConnection mockConnection1 = getMockConnection().sslConnection;
        jettyConnectionLogger.onOpened(mockConnection1);

        MockedConnection failedMockedConnection = getMockConnection();
        SslConnection mockConnection2 = failedMockedConnection.sslConnection;
        jettyConnectionLogger.onOpened(mockConnection2);

        // Now simulate handshake failure for mockConnection2
        SslHandshakeListener.Event event = Mockito.mock(SslHandshakeListener.Event.class);
        when(event.getSSLEngine()).thenReturn(failedMockedConnection.sslEngine);
        SSLHandshakeException sslHandshakeException = new SSLHandshakeException("no cipher suites in common");
        jettyConnectionLogger.handshakeFailed(event, sslHandshakeException);

        // Now keep endpoint open for mockConnection1 and verify it isn't logged
        when(mockConnection1.getEndPoint().isOpen()).thenReturn(true);
        jettyConnectionLogger.onClosed(mockConnection1);
        Mockito.verify(connectionLog, Mockito.times(0)).log(any());

        // Now close endpoint for mockConnection2 and verify it is logged (due to the failed handshake)
        ArgumentCaptor<ConnectionLogEntry> connectionLogEntryArgumentCaptor = ArgumentCaptor.forClass(ConnectionLogEntry.class);
        ArgumentCaptor<String[]> metricArgumentCaptor = ArgumentCaptor.forClass(String[].class);
        when(mockConnection2.getEndPoint().isOpen()).thenReturn(false);
        jettyConnectionLogger.onClosed(mockConnection2);
        Mockito.verify(connectionLog, Mockito.times(1)).log(connectionLogEntryArgumentCaptor.capture());
        Mockito.verify(metric, Mockito.times(1)).increment(Mockito.eq(METRIC_NAME), metricArgumentCaptor.capture());
        assertEquals("no cipher suites in common", connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureMessage().get());
        assertFalse(connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureCause().isPresent());
        assertFalse(connectionLogEntryArgumentCaptor.getValue().remoteAddress().isPresent());
        List<String[]> allMetricValues = metricArgumentCaptor.getAllValues();
        assertEquals(4, allMetricValues.size());
        assertEquals("peerAddress", allMetricValues.get(0));
        assertNotNull(allMetricValues.get(1));
        assertEquals("failureType", allMetricValues.get(2));
        assertEquals("INCOMPATIBLE_CLIENT_CIPHER_SUITES", allMetricValues.get(3));
    }

    @Test
    public void testStartStopConnectionFailedHandshakeClosedTwice() throws Exception {
        // First start a connections
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);

        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);

        MockedConnection failedMockedConnection = getMockConnection();
        SslConnection mockConnection = failedMockedConnection.sslConnection;
        jettyConnectionLogger.onOpened(mockConnection);

        // Now simulate handshake failure for mockConnection
        SslHandshakeListener.Event event = Mockito.mock(SslHandshakeListener.Event.class);
        when(event.getSSLEngine()).thenReturn(failedMockedConnection.sslEngine);
        SSLHandshakeException sslHandshakeException = new SSLHandshakeException("no cipher suites in common");
        jettyConnectionLogger.handshakeFailed(event, sslHandshakeException);

        // Now close endpoint for mockConnection twice and verify it is logged only once
        ArgumentCaptor<ConnectionLogEntry> connectionLogEntryArgumentCaptor = ArgumentCaptor.forClass(ConnectionLogEntry.class);
        ArgumentCaptor<String[]> metricArgumentCaptor = ArgumentCaptor.forClass(String[].class);
        when(mockConnection.getEndPoint().isOpen()).thenReturn(false);
        jettyConnectionLogger.onClosed(mockConnection);
        jettyConnectionLogger.onClosed(mockConnection);
        Mockito.verify(connectionLog, Mockito.times(1)).log(connectionLogEntryArgumentCaptor.capture());
        Mockito.verify(metric, Mockito.times(1)).increment(Mockito.eq(METRIC_NAME), metricArgumentCaptor.capture());
        assertEquals("no cipher suites in common", connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureMessage().get());
        assertFalse(connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureCause().isPresent());
        assertFalse(connectionLogEntryArgumentCaptor.getValue().remoteAddress().isPresent());
        List<String[]> allMetricValues = metricArgumentCaptor.getAllValues();
        assertEquals(4, allMetricValues.size());
        assertEquals("peerAddress", allMetricValues.get(0));
        assertNotNull(allMetricValues.get(1));
        assertEquals("failureType", allMetricValues.get(2));
        assertEquals("INCOMPATIBLE_CLIENT_CIPHER_SUITES", allMetricValues.get(3));
    }

    @Test
    public void testStartStopConnectionFailedHandshakeProxy() throws Exception {
        // First start 2 connections
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);

        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);
        SslConnection mockConnection1 = getMockedProxyConncetion().sslConnection;
        jettyConnectionLogger.onOpened(mockConnection1);

        MockedConnection failedMockedConnection = getMockedProxyConncetion();
        SslConnection mockConnection2 = failedMockedConnection.sslConnection;
        jettyConnectionLogger.onOpened(mockConnection2);

        // Now simulate handshake failure for mockConnection2
        SslHandshakeListener.Event event = Mockito.mock(SslHandshakeListener.Event.class);
        when(event.getSSLEngine()).thenReturn(failedMockedConnection.sslEngine);
        SSLHandshakeException sslHandshakeException = new SSLHandshakeException("no cipher suites in common");
        jettyConnectionLogger.handshakeFailed(event, sslHandshakeException);

        // Now keep endpoint open for mockConnection1 and verify it isn't logged
        when(mockConnection1.getEndPoint().isOpen()).thenReturn(true);
        jettyConnectionLogger.onClosed(mockConnection1);
        Mockito.verify(connectionLog, Mockito.times(0)).log(any());

        // Now close endpoint for mockConnection2 and verify it is logged (due to the failed handshake)
        ArgumentCaptor<ConnectionLogEntry> connectionLogEntryArgumentCaptor = ArgumentCaptor.forClass(ConnectionLogEntry.class);
        ArgumentCaptor<String[]> metricArgumentCaptor = ArgumentCaptor.forClass(String[].class);
        when(mockConnection2.getEndPoint().isOpen()).thenReturn(false);
        jettyConnectionLogger.onClosed(mockConnection2);
        Mockito.verify(connectionLog, Mockito.times(1)).log(connectionLogEntryArgumentCaptor.capture());
        Mockito.verify(metric, Mockito.times(1)).increment(Mockito.eq(METRIC_NAME), metricArgumentCaptor.capture());
        assertEquals("no cipher suites in common", connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureMessage().get());
        assertFalse(connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureCause().isPresent());
        assertTrue(connectionLogEntryArgumentCaptor.getValue().remoteAddress().isPresent());
        List<String[]> allMetricValues = metricArgumentCaptor.getAllValues();
        assertEquals(4, allMetricValues.size());
        assertEquals("peerAddress", allMetricValues.get(0));
        assertNotNull(allMetricValues.get(1));
        assertEquals("failureType", allMetricValues.get(2));
        assertEquals("INCOMPATIBLE_CLIENT_CIPHER_SUITES", allMetricValues.get(3));
    }

    @Test
    public void testFailedHandshakeInnerCause() throws Exception {
        // First start q connection
        ConnectionLog connectionLog = Mockito.mock(ConnectionLog.class);
        Metric metric = Mockito.mock(Metric.class);
        JettyConnectionLogger jettyConnectionLogger = new JettyConnectionLogger(connectionLog, metric);

        MockedConnection failedMockedConnection = getMockConnection();
        SslConnection mockConnection = failedMockedConnection.sslConnection;
        jettyConnectionLogger.onOpened(mockConnection);

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
        jettyConnectionLogger.handshakeFailed(event, sslHandshakeException);

        // Now close endpoint for mockConnection and verify it is logged (due to the failed handshake)
        ArgumentCaptor<ConnectionLogEntry> connectionLogEntryArgumentCaptor = ArgumentCaptor.forClass(ConnectionLogEntry.class);
        when(mockConnection.getEndPoint().isOpen()).thenReturn(false);
        jettyConnectionLogger.onClosed(mockConnection);
        Mockito.verify(connectionLog, Mockito.times(1)).log(connectionLogEntryArgumentCaptor.capture());
        assertEquals(GENERAL_SSL_ERROR, connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureMessage().get());
        assertEquals("Last cause (most specific reason)", connectionLogEntryArgumentCaptor.getValue().sslHandshakeFailureCause().get());
    }

    private MockedConnection getMockConnection() throws Exception {
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

    private MockedConnection getMockedProxyConncetion() throws Exception {
        MockedConnection mockedConnection = new MockedConnection();
        SSLEngine sslEngine = Mockito.mock(SSLEngine.class);
        mockedConnection.sslEngine = sslEngine;
        SslConnection sslConnection = Mockito.mock(SslConnection.class);
        when(sslConnection.getSSLEngine()).thenReturn(sslEngine);

        SocketChannelEndPoint socketChannelEndPoint = Mockito.mock(SocketChannelEndPoint.class);
        when(socketChannelEndPoint.getLocalAddress()).thenReturn(new InetSocketAddress(InetAddress.getLocalHost(), 4444));
        when(socketChannelEndPoint.getRemoteAddress()).thenReturn(new InetSocketAddress(InetAddress.getLocalHost(), 5555));
        ProxyConnectionFactory.ProxyEndPoint proxyEndPoint = Mockito.mock(ProxyConnectionFactory.ProxyEndPoint.class);
        when(proxyEndPoint.getRemoteAddress()).thenReturn(new InetSocketAddress(InetAddress.getLocalHost(), 3333));
        when(proxyEndPoint.unwrap()).thenReturn(socketChannelEndPoint);

        when(sslConnection.getEndPoint()).thenReturn(proxyEndPoint);
        mockedConnection.endpoint = proxyEndPoint;
        mockedConnection.sslConnection = sslConnection;
        return mockedConnection;

    }

    private class MockedConnection {
        SSLEngine sslEngine;
        SslConnection sslConnection;
        EndPoint endpoint;
    }
}
