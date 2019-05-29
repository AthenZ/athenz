/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
package com.oath.auth;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

/**
 * this test validates that when the server changes the keyManager on the fly, no existing connections are broken
 * and that new connections use the new SSL context.
 */
public class SocketTest {

    private final int listenPort = 2000;
    private final boolean running = true;
    private KeyRefresher keyRefresher;

    @Before
    public void setup() throws Exception {
        ClassLoader classLoader = this.getClass().getClassLoader();
        keyRefresher = Utils.generateKeyRefresher(
                classLoader.getResource("truststore.jks").getPath(), //trust store
                "123456".toCharArray(),
                classLoader.getResource("gdpr.aws.core.cert.pem").getPath(), //public
                classLoader.getResource("gdpr.aws.core.key.pem").getPath() //private
        );

        try {
            runPingServer(listenPort, keyRefresher);
        } catch (IOException e) {
            throw new RuntimeException("Can't listen to port: " + listenPort, e);
        }
    }

    private void runPingServer(int port, KeyRefresher keyRefresher) throws Exception {
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(), keyRefresher.getTrustManagerProxy());
        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);

        new Thread(() -> {
            //noinspection InfiniteLoopStatement
            while(running) {
                try {
                    final Socket s = sslServerSocket.accept();

                    new Thread(() -> {
                        try {
                            BufferedReader is = new BufferedReader(new InputStreamReader(s.getInputStream()));
                            OutputStream os = s.getOutputStream();

                            //noinspection ConstantConditions,InfiniteLoopStatement
                            while(running) {
                                String line = is.readLine();
                                if (line.equals("ping")) {
                                    os.write("pong\n".getBytes());
                                }
                            }

                        } catch (IOException ignored) {
                            // die
                        }

                    }).start();

                } catch (IOException ignored) {
                    //die.
                }
            }
        }).start();
    }

    @Test
    public void test() throws Exception {

        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };

        //setup socket for first call
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());

        SSLSocketFactory factory = sslContext.getSocketFactory();
        SSLSocket s = (SSLSocket) factory.createSocket("localhost", listenPort);
        //send first call
        s.getOutputStream().write("ping\n".getBytes());
        String response = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        assertEquals("pong", response);
        assertEquals("athenz.production", getCN(s.getSession().getPeerCertificates()));

        //update the ssl context on the server
        ClassLoader classLoader = this.getClass().getClassLoader();
        keyRefresher.getKeyManagerProxy().setKeyManager(Utils.getKeyManagers(
                classLoader.getResource("gdpr.aws.core.cert.pem").getPath(),
                classLoader.getResource("gdpr.aws.core.key.pem").getPath()));

        //setup socket for the second call
        SSLContext sslContext2 = SSLContext.getInstance("TLSv1.2");
        sslContext2.init(null, new TrustManager[] { tm }, null);
        SSLSocketFactory factory2 = sslContext2.getSocketFactory();
        SSLSocket s2 = (SSLSocket) factory2.createSocket("localhost",listenPort);
        //send second call
        s.getOutputStream().write("ping\n".getBytes());
        response = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        assertEquals("pong", response);
        assertEquals("athenz.production", getCN(s2.getSession().getPeerCertificates()));

        //retry the first call, it should still pass
        s.getOutputStream().write("ping\n".getBytes());
        response = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        assertEquals("pong", response);
        assertEquals("athenz.production", getCN(s.getSession().getPeerCertificates()));
    }

    private String getCN(Certificate[] certificates) throws CertificateEncodingException {
        final X509Certificate[] clientCerts = (X509Certificate[])certificates;
        final X500Name certificateHolder = new JcaX509CertificateHolder(clientCerts[0]).getSubject();
        final RDN commonName = certificateHolder.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(commonName.getFirst().getValue());
    }
}
