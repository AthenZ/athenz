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

import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.security.KeyStore;
import java.security.cert.CRL;
import java.util.Collection;

/**
 * This class is used to extend the default Jetty TrustManager with {@link AthenzTrustManagerProxy}
 */
public class AthenzSslContextFactory extends SslContextFactory.Server {

    public TrustManager[] getTrustManagers(KeyStore trustStore, Collection<? extends CRL> crls) throws Exception {
        TrustManager[] trustManagers = super.getTrustManagers(trustStore, crls);
        
        for (int i = 0; i < trustManagers.length; i++) {
            if (trustManagers[i] instanceof X509ExtendedTrustManager) {
                trustManagers[i] = new AthenzTrustManagerProxy((X509ExtendedTrustManager) trustManagers[i]);
            }
        }
        return trustManagers;
    }
        
}
