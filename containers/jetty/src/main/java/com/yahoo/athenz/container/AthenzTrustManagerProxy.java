/*
 *
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.yahoo.athenz.container;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.server.log.jetty.AthenzConnectionListener;
import com.yahoo.athenz.common.server.log.jetty.ConnectionData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.lang.invoke.MethodHandles;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * This class intercepts the existing X509ExtendedTrustManager.
 * It is used to extract the Athenz principal from the client certificate during the SSL handshake,
 * and store it in the {@link ConnectionData} object.
 */
public class AthenzTrustManagerProxy extends X509ExtendedTrustManager {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    
    private final X509ExtendedTrustManager trustManager;

    public AthenzTrustManagerProxy(X509ExtendedTrustManager trustManager) {
        this.trustManager = trustManager;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (chain.length > 0) {
            String athenzPrincipal = null;
            try {
                athenzPrincipal = Crypto.extractX509CertCommonName(chain[0]);
            } catch (Exception ignored) {
            }
            if (athenzPrincipal != null) {
                ConnectionData connectionData = AthenzConnectionListener.getConnectionDataBySslEngine(engine);
                if (connectionData == null) {
                    LOG.warn("Jetty request: Can't find connection-data by SSLEngine hash-code {} while checking if [{}] can be trusted", engine.hashCode(), athenzPrincipal);
                } else {
                    connectionData.athenzPrincipal = athenzPrincipal;
                }
            }
        }

        trustManager.checkClientTrusted(chain, authType, engine);
    }
    
    
    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkClientTrusted(x509Certificates, s);
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkServerTrusted(x509Certificates, s);
    }
    
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }
    
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType, socket);
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType, socket);
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType, engine);
    }
}
