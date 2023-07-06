package com.yahoo.athenz.container;

import com.yahoo.athenz.common.server.log.jetty.AthenzConnectionListener;
import com.yahoo.athenz.common.server.log.jetty.ConnectionData;
import org.eclipse.jetty.io.ssl.SslConnection;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class AthenzTrustManagerProxyTest {

    @Mock
    private X509ExtendedTrustManager x509ExtendedTrustManager;

    @BeforeMethod
    public void setUp(){
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testCheckClientTrustedWithCert() {
        
        AthenzConnectionListener athenzConnectionListener = new AthenzConnectionListener();
        SslConnection mockSslConnection = mock(SslConnection.class);
        SSLEngine mockSSLEngine = mock(SSLEngine.class);
        when(mockSslConnection.getSSLEngine()).thenReturn(mockSSLEngine);
        athenzConnectionListener.onOpened(mockSslConnection);

        try (InputStream inStream = new FileInputStream("src/test/resources/x509_client_certificate_with_ca.pem")) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = cert;
            AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
            athenzTrustManagerProxy.checkClientTrusted(certs, "cert", mockSSLEngine);
            ConnectionData connectionData = AthenzConnectionListener.getConnectionDataBySslEngine(mockSSLEngine);
            assertNotNull(connectionData);
            assertEquals(connectionData.athenzPrincipal, "athenz.syncer");
        } catch (Exception e) {
            fail();
        }
        
    }
    
    @Test
    public void testCheckClientTrusted() throws CertificateException {
        AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
        athenzTrustManagerProxy.checkClientTrusted(null, "cert");
        Mockito.verify(x509ExtendedTrustManager, Mockito.times(1)).checkClientTrusted(null, "cert");
    }

    @Test
    public void testCheckClientTrustedSocket() throws CertificateException {
        AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
        athenzTrustManagerProxy.checkClientTrusted(null, "cert", (Socket) null);
        Mockito.verify(x509ExtendedTrustManager, Mockito.times(1)).checkClientTrusted(null, "cert", (Socket) null);
    }
    

    @Test
    public void testCheckServerTrusted() throws CertificateException {
        AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
        athenzTrustManagerProxy.checkServerTrusted(null, "cert");
        Mockito.verify(x509ExtendedTrustManager, Mockito.times(1)).checkServerTrusted(null, "cert");
    }

    @Test
    public void testCheckServerTrustedSocket() throws CertificateException {
        AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
        athenzTrustManagerProxy.checkServerTrusted(null, "cert", (Socket) null);
        Mockito.verify(x509ExtendedTrustManager, Mockito.times(1)).checkServerTrusted(null, "cert", (Socket) null);
    }

    @Test
    public void testCheckServerTrustedSSLEngine() throws CertificateException {
        AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
        athenzTrustManagerProxy.checkServerTrusted(null, "cert", (SSLEngine) null);
        Mockito.verify(x509ExtendedTrustManager, Mockito.times(1)).checkServerTrusted(null, "cert", (SSLEngine) null);
    }

    @Test
    public void testGetAcceptedIssuers() {
        AthenzTrustManagerProxy athenzTrustManagerProxy = new AthenzTrustManagerProxy(x509ExtendedTrustManager);
        athenzTrustManagerProxy.getAcceptedIssuers();
        Mockito.verify(x509ExtendedTrustManager, Mockito.times(1)).getAcceptedIssuers();
    }
    
}