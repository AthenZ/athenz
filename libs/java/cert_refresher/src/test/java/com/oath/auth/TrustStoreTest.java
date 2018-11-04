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

import static org.junit.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import com.google.common.io.Resources;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.junit.Test;

public class TrustStoreTest {

    @Test
    public void builtFromJKSFile() throws Exception {

        String filePath = Resources.getResource("truststore.jks").getFile();

        JavaKeyStoreProvider provider = new JavaKeyStoreProvider(filePath, "123456".toCharArray());
        TrustStore trustStore = new TrustStore(filePath, provider);

        assertEquals(filePath, trustStore.getFilePath());
        TrustManager[] trustManagers = trustStore.getTrustManagers();
        assertEquals(1, trustManagers.length);
        X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        assertEquals(1, acceptedIssuers.length);
        X509Certificate certificate = acceptedIssuers[0];
        assertEquals("CN=athenz.production,OU=Testing Domain,O=Athenz,ST=CA,C=US",
            certificate.getIssuerX500Principal().getName());
    }

    @Test
    public void builtFromCaCert() throws Exception {

        String filePath = Resources.getResource("ca.cert.pem").getFile();

        CaCertKeyStoreProvider provider = new CaCertKeyStoreProvider(filePath);
        TrustStore trustStore = new TrustStore(filePath, provider);

        assertEquals(filePath, trustStore.getFilePath());
        TrustManager[] trustManagers = trustStore.getTrustManagers();
        assertEquals(1, trustManagers.length);
        X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        assertEquals(1, acceptedIssuers.length);
        X509Certificate certificate = acceptedIssuers[0];
        assertEquals("CN=athenz.production,OU=Testing Domain,O=Athenz,ST=CA,C=US",
            certificate.getIssuerX500Principal().getName());
    }

    @Test
    public void builtFromMultipleCaCert() throws Exception {

        String filePath = Resources.getResource("ca.certs.pem").getFile();

        CaCertKeyStoreProvider provider = new CaCertKeyStoreProvider(filePath);
        TrustStore trustStore = new TrustStore(filePath, provider);

        assertEquals(filePath, trustStore.getFilePath());
        TrustManager[] trustManagers = trustStore.getTrustManagers();
        assertEquals(1, trustManagers.length);
        X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        assertEquals(3, acceptedIssuers.length);
        Set<String> issuers = new HashSet<>();
        for (X509Certificate cert : acceptedIssuers) {
            issuers.add(cert.getIssuerX500Principal().getName());
        }
        assertTrue(issuers.contains("CN=athenz.production,OU=Testing Domain,O=Athenz,ST=CA,C=US"));
        assertTrue(issuers.contains("CN=athenz.production1,OU=Testing Domain,O=Athenz,ST=CA,C=US"));
        assertTrue(issuers.contains("CN=athenz.production2,OU=Testing Domain,O=Athenz,ST=CA,C=US"));
    }
}
