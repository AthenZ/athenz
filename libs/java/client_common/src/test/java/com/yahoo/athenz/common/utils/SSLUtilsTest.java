package com.yahoo.athenz.common.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.utils.SSLUtils.ClientSSLContextBuilder;

/**
 * ca.pkcs12 was generate with the following commands:
 * openssl genrsa -out ca.key 2048
 * openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.pem
 * openssl pkcs12 -export -out ca.pkcs12 -in ca.pem -inkey ca.key
 * 
 * keytool -list -v -keystore ca/ca.pkcs12 
 * 
 * Certificate[1]:
 * Owner: CN=Self-CA, O=Oath, L=LA, ST=CA, C=US
 * Issuer: CN=Self-CA, O=Oath, L=LA, ST=CA, C=US
 * 
 * 
 * server.pkcs12 was generate with:
 * 
 * openssl genrsa -out server.key 2048
 * openssl req -new -key server.key -out server.csr
 * openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 1024 -sha256
 * openssl pkcs12 -export -out server.pkcs12 -in server.pem -inkey server.key
 * 
 * keytool -list -v -keystore server/server.pkcs12
 * 
 * Certificate[1]:
 * Owner: CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
 * Issuer: CN=Self-CA, O=Oath, L=LA, ST=CA, C=US
 * 
 * client.pkcs12 was generate with:
 * 
 * openssl genrsa -out client.key 2048
 * openssl req -new -key client.key -out client.csr
 * openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 1024 -sha256
 * openssl pkcs12 -export -out client.pkcs12 -in client.pem -inkey client.key
 * 
 * keytool -list -v -keystore client/client.pkcs12
 * 
 * Certificate[1]:
 * Owner: O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
 * Issuer: CN=Self-CA, O=Oath, L=LA, ST=CA, C=US
 * 
 * client_multiple_keys.pkcs12 was generate by combining two pkcs12 files signed by two different CAs:
 * 
 * keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore 
 * client_multiple_keys.pkcs12 -srckeystore client2.pkcs12 -srcstoretype PKCS12 -srcstorepass changeit -alias client2
 * 
 * @author charlesk
 *
 */
public class SSLUtilsTest {

    private static final String DEFAULT_CERT_PWD = "changeit";
    private static final String DEFAULT_SSL_PROTOCOL = "TLSv1.2";
    private static final String DEFAULT_SSL_STORE_TYPE = "pkcs12";
    private static final String DEFAULT_CA_TRUST_STORE = "src/test/resources/certs/ca/ca.pkcs12";
    private static final String DEFAULT_SERVER_KEY_STORE = "src/test/resources/certs/server/server.pkcs12";
    
    @Test
    public void testClientSSLContextBuilder() {
        String protocol = DEFAULT_SSL_PROTOCOL;
        SSLContext sslContext = new SSLUtils.ClientSSLContextBuilder(protocol)
                .keyStorePath(DEFAULT_SERVER_KEY_STORE)
                .keyManagerPassword(DEFAULT_CERT_PWD.toCharArray())
                .keyStorePassword(DEFAULT_CERT_PWD.toCharArray())
                .build();
        Assert.assertEquals(sslContext.getProtocol(), protocol);
        
        sslContext = new SSLUtils.ClientSSLContextBuilder(protocol).build();
        Assert.assertNull(sslContext);
    }    
    
    @Test
    public void testLoadServicePrivateKey() {
        PrivateKeyStore keyStore = SSLUtils.loadServicePrivateKey("com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        Assert.assertNotNull(keyStore);
    }
    
    @DataProvider(name = "ClientSSLContext")
    public static Object[][] clientSSLContext() {
          return new Object[][] { 
              { false, DEFAULT_SSL_PROTOCOL, DEFAULT_CA_TRUST_STORE, "src/test/resources/certs/client/client.pkcs12", "", null }, 
              { true, "TLS", DEFAULT_CA_TRUST_STORE, "src/test/resources/certs/client/client.pkcs12", "", null },
              { true, DEFAULT_SSL_PROTOCOL, DEFAULT_CA_TRUST_STORE, "src/test/resources/certs/client/client.pkcs12", "", null },
              { true, DEFAULT_SSL_PROTOCOL, DEFAULT_CA_TRUST_STORE, null, "bad_certificate", null },
              { true, DEFAULT_SSL_PROTOCOL, DEFAULT_CA_TRUST_STORE, "src/test/resources/certs/client/client_wrong_ca.pkcs12", "bad_certificate", null },
              { true, DEFAULT_SSL_PROTOCOL, DEFAULT_CA_TRUST_STORE, "src/test/resources/certs/client/client_multiple_keys.pkcs12", "", "client1" },
              { true, DEFAULT_SSL_PROTOCOL, DEFAULT_CA_TRUST_STORE, "src/test/resources/certs/client/client_multiple_keys.pkcs12", "bad_certificate", "client2" },
          };
    }
    
    @Test(dataProvider = "ClientSSLContext")
    public void testSSLUtilsClient(boolean clientAuth, String sslProtocol, String trustPath, String keyStorePath, String expectedFailureMessage, String alias) throws Exception {
        JettyServer jettyServer = createHttpsJettyServer(clientAuth);
        jettyServer.server.start();
        ClientSSLContextBuilder builder = new SSLUtils.ClientSSLContextBuilder(sslProtocol)
                .trustStorePath(trustPath)
                .trustStorePassword(DEFAULT_CERT_PWD.toCharArray());
        if (null != keyStorePath) {
            builder.keyStorePath(keyStorePath)
                .keyStorePassword(DEFAULT_CERT_PWD.toCharArray())
                .keyManagerPassword("test".toCharArray());
        }
        if (null != alias && !alias.isEmpty()) {
            builder.certAlias(alias);
        }
        SSLContext sslContext = builder.build();
        String httpsUrl = "https://localhost:" + jettyServer.port + "/";
        URL url = new URL(httpsUrl);
        HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
        con.setDoOutput(true);
        con.setSSLSocketFactory(sslContext.getSocketFactory());
        try {
            handleInputStream(con);
            if (!expectedFailureMessage.isEmpty()) {
                Assert.fail("Expected failure");
            }
        } catch (Throwable t) {
            Assert.assertFalse(expectedFailureMessage.isEmpty());
        } finally {
            jettyServer.server.stop();
       }
    }
    
    private static String handleInputStream(HttpURLConnection con) throws IOException {
        StringBuilder outPut = new StringBuilder();
        String line;

        try (InputStream errorStream = con.getErrorStream()) {
            if (null != errorStream) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(errorStream))) {
                    while (null != (line =  br.readLine())) {
                        outPut.append(line);
                    }
                    return null;
                }
            }
        }

        try (InputStream in = con.getInputStream()) {
            if (null != in) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
                    while (null != (line = br.readLine())) {
                        outPut.append(line);
                    }
                }
            }
        }

        return outPut.toString();
    }
    
    
    private static JettyServer createHttpsJettyServer(boolean clientAuth) throws IOException {
        Server server = new Server();
        HttpConfiguration https_config = new HttpConfiguration();
        https_config.setSecureScheme("https");
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        https_config.setSecurePort(port);
        https_config.setOutputBufferSize(32768);

        SslContextFactory sslContextFactory = new SslContextFactory();
        File keystoreFile = new File(DEFAULT_SERVER_KEY_STORE);
        if (!keystoreFile.exists()) {
            throw new FileNotFoundException();
        }
        
        String trustStorePath = DEFAULT_CA_TRUST_STORE;
        File trustStoreFile = new File(trustStorePath);
        if (!trustStoreFile.exists()) {
            throw new FileNotFoundException();
        }

        sslContextFactory.setEndpointIdentificationAlgorithm(null);

        sslContextFactory.setTrustStorePath(trustStorePath);
        sslContextFactory.setTrustStoreType(DEFAULT_SSL_STORE_TYPE);
        sslContextFactory.setTrustStorePassword(DEFAULT_CERT_PWD);

        sslContextFactory.setKeyStorePath(keystoreFile.getAbsolutePath());
        sslContextFactory.setKeyStoreType(DEFAULT_SSL_STORE_TYPE);
        sslContextFactory.setKeyStorePassword(DEFAULT_CERT_PWD);

        sslContextFactory.setProtocol(DEFAULT_SSL_PROTOCOL);
        sslContextFactory.setNeedClientAuth(clientAuth);

        ServerConnector https = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory,HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(https_config));
        https.setPort(port);
        https.setIdleTimeout(500000);
        server.setConnectors(new Connector[] { https });
        HandlerList handlers = new HandlerList();
        ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setBaseResource(Resource.newResource("."));
        handlers.setHandlers(new Handler[]
        { resourceHandler, new DefaultHandler() });
        server.setHandler(handlers);
        return new JettyServer(server, port);
    }
    
    static class JettyServer {
        public Server server;
        public int port;
        public JettyServer(Server server, int port) {
            this.server = server;
            this.port = port;
        }
    }

}
