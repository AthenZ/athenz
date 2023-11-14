/*
 * Copyright The Athenz Authors
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
package com.yahoo.athenz.instance.provider;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.util.Crypto;

public class ProviderHostnameVerifierTest {

    @Test
    public void testHostnameVerifier() throws IOException {
        
        SSLSession session = Mockito.mock(SSLSession.class);
        Path path = Paths.get("src/test/resources/athenz.instanceid.pem");
        String pem = new String(Files.readAllBytes(path));
        X509Certificate cert = Crypto.loadX509Certificate(pem);
        
        Certificate[] certs = new Certificate[1];
        certs[0] = cert;
        Mockito.when(session.getPeerCertificates()).thenReturn(certs);
        
        ProviderHostnameVerifier verifier1 = new ProviderHostnameVerifier("athenz.production");
        assertTrue(verifier1.verify("athenz", session));
        
        ProviderHostnameVerifier verifier2 = new ProviderHostnameVerifier("athenz.production2");
        assertFalse(verifier2.verify("athenz", session));
    }
    
    @Test
    public void testHostnameVerifierNullCerts() throws IOException {
        
        SSLSession session = Mockito.mock(SSLSession.class);
        Mockito.when(session.getPeerCertificates()).thenReturn(null);
        
        ProviderHostnameVerifier verifier1 = new ProviderHostnameVerifier("athenz.production");
        assertFalse(verifier1.verify("athenz", session));
    }

    @Test
    public void testVerifyWithException() throws SSLPeerUnverifiedException {

        SSLSession session = Mockito.mock(SSLSession.class);
        Mockito.when(session.getPeerCertificates()).thenThrow(new SSLPeerUnverifiedException("invalid certs"));

        ProviderHostnameVerifier verifier1 = new ProviderHostnameVerifier("athenz.production");
        assertFalse(verifier1.verify("athenz", session));
    }
}
