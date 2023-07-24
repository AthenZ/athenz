package com.yahoo.athenz.common.server.log.jetty;

import org.eclipse.jetty.io.ssl.SslConnection;
import org.testng.annotations.Test;

import static com.yahoo.athenz.common.server.log.jetty.AthenzConnectionListener.ATHENZ_PROP_CLEANUP_CLOSED_CONNECTION_INTERVAL;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNull;

public class AthenzConnectionListenerTest {
    
    @Test
    public void testCleanerThread() throws Exception {
        System.setProperty(ATHENZ_PROP_CLEANUP_CLOSED_CONNECTION_INTERVAL, "500");
        JettyConnectionLoggerTest.MockedConnection mockedConnection = JettyConnectionLoggerTest.getMockConnection();
        SslConnection mockConnection = mockedConnection.sslConnection;

        AthenzConnectionListener athenzConnectionListener = new AthenzConnectionListener();
        athenzConnectionListener.onOpened(mockConnection);
        ConnectionData con = AthenzConnectionListener.getConnectionDataBySslEngine(mockConnection.getSSLEngine());
        assertEquals(con.sslConnection, mockConnection);

        // ensure cleaner thread clean the map
        Thread.sleep(1000);
        con = AthenzConnectionListener.getConnectionDataBySslEngine(mockConnection.getSSLEngine());
        assertNull(con);
        athenzConnectionListener.shutdown();
        System.clearProperty(ATHENZ_PROP_CLEANUP_CLOSED_CONNECTION_INTERVAL);
    }

    @Test
    public void testOnCloseMapCleanup() throws Exception {
        JettyConnectionLoggerTest.MockedConnection mockedConnection = JettyConnectionLoggerTest.getMockConnection();
        SslConnection mockConnection = mockedConnection.sslConnection;

        AthenzConnectionListener athenzConnectionListener = new AthenzConnectionListener();
        athenzConnectionListener.onOpened(mockConnection);
        ConnectionData con = AthenzConnectionListener.getConnectionDataBySslEngine(mockConnection.getSSLEngine());
        assertEquals(con.sslConnection, mockConnection);

        // ensure onClose clean the map
        athenzConnectionListener.onClosed(mockConnection);

        con = AthenzConnectionListener.getConnectionDataBySslEngine(mockConnection.getSSLEngine());
        assertNull(con);
        athenzConnectionListener.shutdown();
    }
}