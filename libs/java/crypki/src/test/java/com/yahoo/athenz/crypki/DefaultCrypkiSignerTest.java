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
package com.yahoo.athenz.crypki;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.crypki.signer.DefaultCrypkiSigner;
import com.yahoo.athenz.crypki.signer.SigningKey;
import com.yahoo.athenz.crypki.x509.X509CertificateMinter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.testng.annotations.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class DefaultCrypkiSignerTest {

    static SigningKey selfSigned(String id) throws Exception {
        PrivateKey caKey = Crypto.generateRSAPrivateKey(2048);
        String csrPem = Crypto.generateX509CSR(caKey, "CN=Athenz Test CA,O=Athenz,C=US", null);
        PKCS10CertificationRequest csr = Crypto.getPKCS10CertRequest(csrPem);
        X509Certificate caCert = Crypto.generateX509Certificate(csr, caKey,
                new X500Name("CN=Athenz Test CA,O=Athenz,C=US"), 365 * 24 * 60, true);
        return new SigningKey(id, caKey, caCert);
    }

    @Test
    public void testSignAndGetCa() throws Exception {
        SigningKey ca = selfSigned("x509-key");
        DefaultCrypkiSigner signer = new DefaultCrypkiSigner(keyId -> ca);
        PrivateKey leafKey = Crypto.generateRSAPrivateKey(2048);
        String csr = Crypto.generateX509CSR(leafKey, "CN=athenz.service.client,O=Athenz,C=US", null);
        X509SignRequest request = X509SignRequest.builder()
                .keyId("x509-key")
                .csrPem(csr)
                .validitySeconds(3600)
                .extKeyUsage(java.util.List.of(X509CertificateMinter.EKU_CLIENT_AUTH))
                .build();
        String pem = signer.sign(request);
        assertTrue(pem.contains("BEGIN CERTIFICATE"));
        assertTrue(signer.getCACertificate("x509-key").contains("BEGIN CERTIFICATE"));
        assertTrue(signer.getMaxCertExpiryTimeMins() > 0);
        expectThrows(NullPointerException.class, () -> new SigningKey(null, ca.getPrivateKey(), ca.getCaCertificate()));
    }
}
