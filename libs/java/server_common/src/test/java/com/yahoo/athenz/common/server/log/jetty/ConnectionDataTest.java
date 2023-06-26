package com.yahoo.athenz.common.server.log.jetty;

import org.eclipse.jetty.io.ssl.SslConnection;
import org.testng.annotations.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import java.util.Optional;

import static com.yahoo.athenz.common.server.log.jetty.JettyConnectionLogger.GENERAL_SSL_ERROR;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.*;

public class ConnectionDataTest {
    
    @Test
    public void connectionDataTest() {
        SslConnection mockSslConnection = mock(SslConnection.class);
        SSLEngine mockSSLEngine = mock(SSLEngine.class);
        when(mockSslConnection.getSSLEngine()).thenReturn(mockSSLEngine);
        when(mockSSLEngine.getPeerHost()).thenReturn("host");
        when(mockSSLEngine.getPeerPort()).thenReturn(1234);
        ConnectionData connectionData = new ConnectionData(mockSslConnection);
        connectionData.athenzPrincipal = "athenz.principal";
        
        ConnectionLogEntry en = connectionData.toLogEntry();
        assertNotNull(en);
        assertEquals(en.athenzPrincipal(), Optional.of("athenz.principal"));
        assertEquals(en.peerAddress(), Optional.of("host"));
        assertEquals(en.peerPort(), Optional.of(1234));

        SSLHandshakeException sslHandshakeException = new SSLHandshakeException(GENERAL_SSL_ERROR);
        SSLHandshakeException innerCause1 = new SSLHandshakeException(GENERAL_SSL_ERROR);
        SSLHandshakeException innerCause2 = new SSLHandshakeException(GENERAL_SSL_ERROR);
        innerCause1.initCause(innerCause2);
        sslHandshakeException.initCause(innerCause1);
        connectionData.setSslHandshakeFailure(sslHandshakeException);
        assertTrue(connectionData.toString().contains("athenz.principal"));
        
        String[] metric = connectionData.toMetric();
        assertEquals(metric[0], "failureType");
        assertEquals(metric[1], "UNKNOWN");
        assertEquals(metric[2], "athenzPrincipal");
        assertEquals(metric[3], "athenz.principal");
    }

}
