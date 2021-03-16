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

package com.yahoo.athenz.container;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.*;

public class AthenzServerTest {

    @Test
    public void testGetTrustManagers() throws Exception {
        AthenzServer athenzServer = new AthenzServer();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        TrustManager[] trustManagers = athenzServer.getTrustManagers(keyStore, null);
        assertEquals(trustManagers.length, 1);
        assertTrue(X509TrustManager.class.isAssignableFrom(trustManagers[0].getClass()));
    }

    @Test
    public void testGetTrustManagersNullTruststore() throws Exception {
        AthenzServer athenzServer = new AthenzServer();
        assertNull(athenzServer.getTrustManagers(null, null));
    }

    @Test
    public void testX509TrustManagerWithLogs() throws Exception {
        X509TrustManager x509TrustManager = Mockito.mock(X509TrustManager.class);
        AthenzServer.X509TrustManagerWithLogs x509TrustManagerWithLogs = new AthenzServer.X509TrustManagerWithLogs(x509TrustManager);
        x509TrustManagerWithLogs.checkClientTrusted(null, null);
        x509TrustManagerWithLogs.checkServerTrusted(null, null);
        x509TrustManagerWithLogs.getAcceptedIssuers();
    }

    @Test
    public void testX509TrustManagerWithLogsFailure() throws Exception {
        X509TrustManager x509TrustManager = Mockito.mock(X509TrustManager.class);
        doThrow(new CertificateException("client cert error")).when(x509TrustManager).checkClientTrusted(any(), any());
        doThrow(new CertificateException("server cert error")).when(x509TrustManager).checkServerTrusted(any(), any());
        AthenzServer.X509TrustManagerWithLogs x509TrustManagerWithLogs = new AthenzServer.X509TrustManagerWithLogs(x509TrustManager);
        X509Certificate[] x509Certificates = new X509Certificate[1];
        x509Certificates[0] = Mockito.mock(X509Certificate.class);
        when(x509Certificates[0].getIssuerDN()).thenReturn(() -> "issuer");
        when(x509Certificates[0].getSubjectDN()).thenReturn(() -> "subjectDN");
        try {
            x509TrustManagerWithLogs.checkClientTrusted(x509Certificates, null);
            fail();
        } catch (CertificateException ex) {
            assertEquals("client cert error", ex.getMessage());
        }
        try {
            x509TrustManagerWithLogs.checkServerTrusted(x509Certificates, null);
            fail();
        } catch (CertificateException ex) {
            assertEquals("server cert error", ex.getMessage());
        }
        x509TrustManagerWithLogs.getAcceptedIssuers();
    }
}
